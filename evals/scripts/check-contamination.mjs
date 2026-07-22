#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import { dirname, extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const defaultTargetsPath = join(repositoryRoot, 'evals/targets.json');
const prohibitedExtensions = new Set([
  '.avif', '.bmp', '.eot', '.gif', '.heic', '.ico', '.jpeg', '.jpg', '.mov', '.mp4',
  '.otf', '.pdf', '.png', '.tar', '.tif', '.tiff', '.ttf', '.webm', '.webp', '.woff',
  '.woff2', '.zip'
]);
const binaryMagic = [
  { name: 'png', test: (body) => body.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  { name: 'jpeg', test: (body) => body[0] === 0xff && body[1] === 0xd8 && body[2] === 0xff },
  { name: 'gif', test: (body) => ['GIF87a', 'GIF89a'].includes(body.subarray(0, 6).toString('ascii')) },
  { name: 'webp', test: (body) => body.subarray(0, 4).toString('ascii') === 'RIFF' && body.subarray(8, 12).toString('ascii') === 'WEBP' },
  { name: 'pdf', test: (body) => body.subarray(0, 5).toString('ascii') === '%PDF-' },
  { name: 'zip', test: (body) => body[0] === 0x50 && body[1] === 0x4b && [0x03, 0x05, 0x07].includes(body[2]) && [0x04, 0x06, 0x08].includes(body[3]) },
  { name: 'woff', test: (body) => ['wOFF', 'wOF2'].includes(body.subarray(0, 4).toString('ascii')) },
  { name: 'opentype', test: (body) => body.subarray(0, 4).toString('ascii') === 'OTTO' },
  { name: 'truetype', test: (body) => body.subarray(0, 4).equals(Buffer.from([0x00, 0x01, 0x00, 0x00])) },
  { name: 'bmp', test: (body) => body.subarray(0, 2).toString('ascii') === 'BM' },
  { name: 'tiff', test: (body) => ['49492a00', '4d4d002a'].includes(body.subarray(0, 4).toString('hex')) },
  { name: 'ico', test: (body) => ['00000100', '00000200'].includes(body.subarray(0, 4).toString('hex')) },
  { name: 'iso-media', test: (body) => body.subarray(4, 8).toString('ascii') === 'ftyp' }
];
const prohibitedGeneratedDirectories = new Set([
  'candidate-inspection', 'candidate-self', 'captures', 'comparison', 'fidelity-series',
  'screenshots', 'snapshot-assets', 'source-candidate', 'source-contract', 'source-self',
  'test-results'
]);
const encodedImagePrefixes = [
  ['iV', 'BORw0KGgo'].join(''),
  ['/9', 'j/4AAQSkZJRg'].join(''),
  ['R0l', 'GODlh'].join(''),
  ['R0l', 'GODdh'].join('')
];

function parseArguments(argv) {
  const options = {
    scanRoot: repositoryRoot,
    targetsPath: defaultTargetsPath,
    maxFileBytes: 5 * 1024 * 1024,
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
      case '--root': case '--skill': options.scanRoot = resolve(take(index, argument)); index += 1; break;
      case '--targets': options.targetsPath = resolve(take(index, argument)); index += 1; break;
      case '--max-file-bytes': {
        options.maxFileBytes = Number(take(index, argument));
        index += 1;
        if (!Number.isSafeInteger(options.maxFileBytes) || options.maxFileBytes < 1024) {
          throw new Error('--max-file-bytes must be an integer of at least 1024.');
        }
        break;
      }
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  return options;
}

function slashPath(pathname) {
  return pathname.split(sep).join('/');
}

function tokenFindings(value, tokens, file, location) {
  const lower = value.toLowerCase();
  const compact = lower.replace(/[^a-z0-9]+/g, '');
  return tokens
    .filter((token) => lower.includes(token) || compact.includes(token.replace(/[^a-z0-9]+/g, '')))
    .map((token) => ({ kind: 'benchmark-token', location, file, token }));
}

async function inventory(directory, root, tokens, findings) {
  const files = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    if (['node_modules', '.git'].includes(entry.name)) continue;
    const pathname = join(directory, entry.name);
    const file = slashPath(relative(root, pathname));
    findings.push(...tokenFindings(file, tokens, file, 'path'));
    if (entry.isSymbolicLink()) {
      findings.push({ kind: 'symlink', location: 'path', file });
    } else if (entry.isDirectory()) {
      if (prohibitedGeneratedDirectories.has(entry.name.toLowerCase())) {
        findings.push({ kind: 'prohibited-generated-directory', location: 'path', file });
      }
      files.push(...await inventory(pathname, root, tokens, findings));
    } else if (entry.isFile()) {
      files.push({ pathname, file });
    } else {
      findings.push({ kind: 'unsupported-entry', location: 'path', file });
    }
  }
  return files;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node check-contamination.mjs [--root DIR] [--targets FILE] [--max-file-bytes N]\n');
    return;
  }
  const manifest = JSON.parse(await fs.readFile(options.targetsPath, 'utf8'));
  const tokens = [...new Set((manifest.targets || []).flatMap((target) => target.contaminationTokens || []))]
    .filter((token) => String(token).length >= 5)
    .map((token) => String(token).toLowerCase());
  const findings = [];
  const files = await inventory(options.scanRoot, options.scanRoot, tokens, findings);
  const targetsRelativePath = slashPath(relative(options.scanRoot, options.targetsPath));
  let scannedBytes = 0;
  for (const { pathname, file } of files) {
    const extension = extname(file).toLowerCase();
    if (prohibitedExtensions.has(extension)) {
      findings.push({ kind: 'prohibited-asset-extension', location: 'path', file, extension });
    }
    const stat = await fs.stat(pathname);
    if (stat.size > options.maxFileBytes) {
      findings.push({ kind: 'file-too-large', location: 'content', file, bytes: stat.size, maximumBytes: options.maxFileBytes });
      continue;
    }
    const body = await fs.readFile(pathname);
    scannedBytes += body.length;
    for (const signature of binaryMagic) {
      if (body.length >= 4 && signature.test(body)) {
        findings.push({ kind: 'prohibited-binary-magic', location: 'content', file, format: signature.name });
        break;
      }
    }
    if (body.includes(0)) findings.push({ kind: 'unexpected-binary-content', location: 'content', file });
    const text = body.toString('utf8');
    if (file !== targetsRelativePath) findings.push(...tokenFindings(text, tokens, file, 'content'));
    const embeddedImages = [...text.matchAll(/data\s*:\s*image\s*\/\s*[a-z0-9.+-]+(?:\s*;[^,\s]*)*\s*,/gi)];
    for (const match of embeddedImages.slice(0, 20)) {
      findings.push({
        kind: 'embedded-image-data-uri',
        location: 'content',
        file,
        offset: match.index
      });
    }
    for (const prefix of encodedImagePrefixes) {
      const offset = text.indexOf(prefix);
      if (offset >= 0) {
        findings.push({ kind: 'base64-image-signature', location: 'content', file, offset });
        break;
      }
    }
  }
  const result = {
    schemaVersion: 1,
    scanRoot: options.scanRoot,
    scannedFiles: files.length,
    scannedBytes,
    forbiddenTokens: tokens.length,
    pass: findings.length === 0,
    findings
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.pass) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
