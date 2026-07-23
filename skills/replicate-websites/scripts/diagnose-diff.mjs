#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { resolveRuntimePackage } from './lib/runtime-dependencies.mjs';

function usage() {
  return `Rank pixel-diff bands and map them to inspected DOM elements.

Usage:
  node diagnose-diff.mjs --report REPORT_DIR [options]

Options:
  --candidate-contract DIR    inspect-page output for the candidate
  --baseline-contract DIR     inspect-page output for the baseline
  --out FILE                  Write JSON diagnosis
  --merge-gap N               Merge changed bands separated by N rows (default: 3)
  --top N                     Retain N row/column bands per viewport (default: 30)
  --help                      Show this message
`;
}

function integer(value, option, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${option} expects an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

function parseArguments(argv) {
  const options = {
    report: null,
    candidateContract: null,
    baselineContract: null,
    out: null,
    mergeGap: 3,
    top: 30,
    help: false
  };
  const take = (index, option) => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${option} requires a value.`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--report': options.report = resolve(take(index, argument)); index += 1; break;
      case '--candidate-contract': options.candidateContract = resolve(take(index, argument)); index += 1; break;
      case '--baseline-contract': options.baselineContract = resolve(take(index, argument)); index += 1; break;
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--merge-gap': options.mergeGap = integer(take(index, argument), argument, 0, 1000); index += 1; break;
      case '--top': options.top = integer(take(index, argument), argument, 1, 1000); index += 1; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && !options.report) throw new Error('--report is required.');
  return options;
}

async function optionalJson(pathname) {
  if (!pathname) return null;
  try {
    return JSON.parse(await fs.readFile(pathname, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function axisCounts(image, axis) {
  const size = axis === 'row' ? image.height : image.width;
  const breadth = axis === 'row' ? image.width : image.height;
  const counts = Array.from({ length: size }, () => ({ changed: 0, antialias: 0 }));
  for (let position = 0; position < size; position += 1) {
    for (let across = 0; across < breadth; across += 1) {
      const x = axis === 'row' ? across : position;
      const y = axis === 'row' ? position : across;
      const offset = (y * image.width + x) * 4;
      if (image.data[offset + 3] === 0) continue;
      const amber = image.data[offset] === 255 && image.data[offset + 1] >= 150;
      if (amber) counts[position].antialias += 1;
      else counts[position].changed += 1;
    }
  }
  return counts;
}

function makeBands(counts, mergeGap) {
  const active = counts
    .map((count, index) => ({ index, ...count }))
    .filter((entry) => entry.changed > 0 || entry.antialias > 0);
  if (!active.length) return [];
  const bands = [];
  let current = {
    start: active[0].index,
    end: active[0].index,
    changedPixels: active[0].changed,
    antialiasPixels: active[0].antialias,
    peakPixels: active[0].changed + active[0].antialias
  };
  for (const entry of active.slice(1)) {
    if (entry.index - current.end <= mergeGap + 1) {
      current.end = entry.index;
      current.changedPixels += entry.changed;
      current.antialiasPixels += entry.antialias;
      current.peakPixels = Math.max(current.peakPixels, entry.changed + entry.antialias);
    } else {
      bands.push(current);
      current = {
        start: entry.index,
        end: entry.index,
        changedPixels: entry.changed,
        antialiasPixels: entry.antialias,
        peakPixels: entry.changed + entry.antialias
      };
    }
  }
  bands.push(current);
  return bands.map((band) => ({
    ...band,
    size: band.end - band.start + 1,
    totalPixels: band.changedPixels + band.antialiasPixels
  }));
}

function intersectingElements(contract, axis, band) {
  const elements = contract?.contract?.elements || contract?.elements || [];
  const startField = axis === 'row' ? 'y' : 'x';
  const sizeField = axis === 'row' ? 'height' : 'width';
  return elements
    .filter((element) => {
      const start = Number(element.rect?.[startField]);
      const end = start + Number(element.rect?.[sizeField]);
      return Number.isFinite(start) && start <= band.end && end >= band.start;
    })
    .sort((left, right) => {
      const leftArea = Number(left.rect?.width || 0) * Number(left.rect?.height || 0);
      const rightArea = Number(right.rect?.width || 0) * Number(right.rect?.height || 0);
      return leftArea - rightArea;
    })
    .slice(0, 8)
    .map((element) => ({
      path: element.path,
      tag: element.tag,
      text: element.text,
      rect: element.rect
    }));
}

async function diagnoseViewport(PNG, reportDirectory, viewportResult, options) {
  const name = viewportResult.viewport.name;
  const image = PNG.sync.read(await fs.readFile(join(reportDirectory, name, 'diff.png')));
  const [candidateContract, baselineContract] = await Promise.all([
    optionalJson(options.candidateContract ? join(options.candidateContract, name, 'contract.json') : null),
    optionalJson(options.baselineContract ? join(options.baselineContract, name, 'contract.json') : null)
  ]);
  const rank = (bands) => bands
    .sort((left, right) => right.totalPixels - left.totalPixels || left.start - right.start)
    .slice(0, options.top);
  const rows = rank(makeBands(axisCounts(image, 'row'), options.mergeGap));
  const columns = rank(makeBands(axisCounts(image, 'column'), options.mergeGap));
  for (const band of rows) {
    band.candidateElements = intersectingElements(candidateContract, 'row', band);
    band.baselineElements = intersectingElements(baselineContract, 'row', band);
  }
  for (const band of columns) {
    band.candidateElements = intersectingElements(candidateContract, 'column', band);
    band.baselineElements = intersectingElements(baselineContract, 'column', band);
  }
  return {
    viewport: viewportResult.viewport,
    metrics: viewportResult.pixel,
    rowBands: rows,
    columnBands: columns
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  const summary = JSON.parse(await fs.readFile(join(options.report, 'summary.json'), 'utf8'));
  const pngModule = await import(pathToFileURL(resolveRuntimePackage('pngjs')).href);
  const PNG = pngModule.PNG || pngModule.default?.PNG;
  if (!PNG) throw new Error('Resolved pngjs package has unexpected exports.');
  const results = [];
  for (const viewportResult of summary.results || []) {
    results.push(await diagnoseViewport(PNG, options.report, viewportResult, options));
  }
  const diagnosis = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    report: options.report,
    results
  };
  const serialized = `${JSON.stringify(diagnosis, null, 2)}\n`;
  if (options.out) await fs.writeFile(options.out, serialized);
  process.stdout.write(serialized);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
