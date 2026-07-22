#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));

function parseArguments(argv) {
  const options = {
    baseline: null,
    candidate: null,
    out: null,
    iteration: null,
    policy: null,
    readySelector: null,
    baselineReadySelector: null,
    candidateReadySelector: null,
    viewports: [],
    waitMs: 750,
    allowRegression: false,
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
      case '--baseline': options.baseline = take(index, argument); index += 1; break;
      case '--candidate': options.candidate = take(index, argument); index += 1; break;
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--iteration': options.iteration = take(index, argument); index += 1; break;
      case '--policy': options.policy = resolve(take(index, argument)); index += 1; break;
      case '--ready-selector': options.readySelector = take(index, argument); index += 1; break;
      case '--baseline-ready-selector': options.baselineReadySelector = take(index, argument); index += 1; break;
      case '--candidate-ready-selector': options.candidateReadySelector = take(index, argument); index += 1; break;
      case '--viewport': options.viewports.push(take(index, argument)); index += 1; break;
      case '--wait-ms': options.waitMs = Number(take(index, argument)); index += 1; break;
      case '--allow-regression': options.allowRegression = true; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && (!options.baseline || !options.candidate || !options.out || !options.iteration)) {
    throw new Error('--baseline, --candidate, --out, and --iteration are required.');
  }
  if (options.iteration && !/^[a-z0-9._-]+$/i.test(options.iteration)) throw new Error('--iteration contains unsupported characters.');
  return options;
}

function run(command, args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { stdio: 'inherit' });
    child.on('error', rejectRun);
    child.on('exit', (code, signal) => resolveRun({ code: code ?? 1, signal }));
  });
}

async function readJson(pathname, fallback = null) {
  try { return JSON.parse(await fs.readFile(pathname, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}

function vector(score) {
  const results = score.results || [];
  return [
    results.reduce((total, result) => total + (result.metrics.dimensionsMatch ? 0 : 1), 0),
    results.reduce((total, result) => total + Number(result.metrics.unapprovedSemanticMismatchCount || 0), 0),
    Math.max(...results.map((result) => Number(result.metrics.tolerantDiffPercent || 0))),
    results.reduce((total, result) => total + Number(result.metrics.tolerantDiffPercent || 0), 0),
    results.reduce((total, result) => total + Number(result.metrics.strictDiffPercent || 0), 0)
  ];
}

function compareVectors(left, right) {
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const difference = Number(left[index] || 0) - Number(right[index] || 0);
    if (Math.abs(difference) > 1e-12) return difference;
  }
  return 0;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node run-fidelity-loop.mjs --baseline URL --candidate URL --out DIR --iteration ID [options]\n');
    return;
  }
  const ledgerPath = join(options.out, 'series.json');
  const ledger = await readJson(ledgerPath, { schemaVersion: 1, iterations: [], bestIteration: null });
  if (ledger.iterations.some((entry) => entry.id === options.iteration)) {
    throw new Error(`Iteration already exists: ${options.iteration}`);
  }
  const iterationsDirectory = join(options.out, 'iterations');
  const iterationDirectory = join(iterationsDirectory, options.iteration);
  try {
    await fs.lstat(iterationDirectory);
    throw new Error(`Iteration directory already exists: ${iterationDirectory}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fs.mkdir(iterationsDirectory, { recursive: true });
  const stagingDirectory = join(iterationsDirectory, `.${options.iteration}.staging-${process.pid}-${Date.now()}`);
  await fs.mkdir(stagingDirectory);
  const reportDirectory = join(stagingDirectory, 'comparison');
  let promoted = false;
  try {
  const compareArguments = [
    join(scriptDirectory, 'compare-pages.mjs'),
    '--baseline', options.baseline,
    '--candidate', options.candidate,
    '--out', reportDirectory,
    '--wait-ms', String(options.waitMs)
  ];
  if (options.readySelector) compareArguments.push('--ready-selector', options.readySelector);
  if (options.baselineReadySelector) compareArguments.push('--baseline-ready-selector', options.baselineReadySelector);
  if (options.candidateReadySelector) compareArguments.push('--candidate-ready-selector', options.candidateReadySelector);
  for (const viewport of options.viewports) compareArguments.push('--viewport', viewport);
  const comparison = await run(process.execPath, compareArguments);
  if (comparison.code !== 0) throw new Error(`compare-pages failed with exit ${comparison.code}.`);
  const scorePath = join(stagingDirectory, 'score.json');
  const assertArguments = [
    join(scriptDirectory, 'assert-fidelity.mjs'),
    '--summary', join(reportDirectory, 'summary.json'),
    '--out', scorePath
  ];
  if (options.policy) assertArguments.push('--policy', options.policy);
  const assertion = await run(process.execPath, assertArguments);
  if (![0, 2].includes(assertion.code)) throw new Error(`assert-fidelity failed with exit ${assertion.code}.`);
  const diagnosisPath = join(stagingDirectory, 'diagnosis.json');
  const diagnosis = await run(process.execPath, [
    join(scriptDirectory, 'diagnose-diff.mjs'),
    '--report', reportDirectory,
    '--out', diagnosisPath
  ]);
  if (diagnosis.code !== 0) throw new Error(`diagnose-diff failed with exit ${diagnosis.code}.`);
  const score = await readJson(scorePath);
  await fs.rename(stagingDirectory, iterationDirectory);
  promoted = true;
  const finalReportDirectory = join(iterationDirectory, 'comparison');
  const finalScorePath = join(iterationDirectory, 'score.json');
  const finalDiagnosisPath = join(iterationDirectory, 'diagnosis.json');
  const entry = {
    id: options.iteration,
    generatedAt: new Date().toISOString(),
    report: finalReportDirectory,
    score: finalScorePath,
    diagnosis: finalDiagnosisPath,
    pass: score.pass,
    vector: vector(score)
  };
  const best = ledger.bestIteration
    ? ledger.iterations.find((candidate) => candidate.id === ledger.bestIteration)
    : null;
  const regression = best ? compareVectors(entry.vector, best.vector) > 0 : false;
  entry.regressionAgainstBest = regression;
  ledger.iterations.push(entry);
  if (!best || compareVectors(entry.vector, best.vector) < 0) ledger.bestIteration = entry.id;
  await fs.writeFile(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`);
  process.stdout.write(`Series: ${ledgerPath}\nBest: ${ledger.bestIteration}\n`);
  if (regression && !options.allowRegression) {
    process.stderr.write(`Iteration ${entry.id} regressed against best ${best.id}; restore the checkpoint or justify --allow-regression.\n`);
    process.exitCode = 3;
  } else if (!score.pass) {
    process.exitCode = 2;
  }
  } finally {
    if (!promoted) await fs.rm(stagingDirectory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
