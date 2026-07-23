#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const templateDirectory = resolve(scriptDirectory, '../assets/replica-starter');

function parseArguments(argv) {
  const options = { out: null, name: 'website-replica', mode: 'authorized-local', help: false };
  const take = (index, option) => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${option} requires a value.`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--name': options.name = take(index, argument); index += 1; break;
      case '--mode': options.mode = take(index, argument); index += 1; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && !options.out) throw new Error('--out is required.');
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(options.name)) throw new Error('--name contains unsupported characters.');
  if (!['authorized-local', 'owned', 'public-simulation'].includes(options.mode)) {
    throw new Error('--mode must be authorized-local, owned, or public-simulation.');
  }
  return options;
}

async function directoryIsEmpty(pathname) {
  try {
    return (await fs.readdir(pathname)).length === 0;
  } catch (error) {
    if (error.code === 'ENOENT') return true;
    throw error;
  }
}

async function replaceTokens(directory, replacements) {
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const pathname = join(directory, entry.name);
    if (entry.isDirectory()) {
      await replaceTokens(pathname, replacements);
      continue;
    }
    if (!/\.(?:html|js|mjs|json|css|md)$/.test(entry.name)) continue;
    let content = await fs.readFile(pathname, 'utf8');
    for (const [token, value] of Object.entries(replacements)) content = content.replaceAll(token, value);
    await fs.writeFile(pathname, content);
  }
}

async function makeWritable(directory) {
  await fs.chmod(directory, 0o755);
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const pathname = join(directory, entry.name);
    if (entry.isDirectory()) await makeWritable(pathname);
    else await fs.chmod(pathname, entry.name.endsWith('.mjs') ? 0o755 : 0o644);
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`Usage: node scaffold-replica.mjs --out DIR [options]

Options:
  --name PACKAGE_NAME          Generated package name (default: website-replica)
  --mode MODE                  authorized-local, owned, or public-simulation
                               (default: authorized-local)
  --help                       Show this message
`);
    return;
  }
  if (!(await directoryIsEmpty(options.out))) {
    throw new Error(`Refusing to overwrite non-empty directory: ${options.out}`);
  }
  await fs.mkdir(options.out, { recursive: true });
  for (const entry of await fs.readdir(templateDirectory)) {
    await fs.cp(join(templateDirectory, entry), join(options.out, entry), {
      recursive: true,
      errorOnExist: true,
      force: false
    });
  }
  await makeWritable(options.out);
  const disclosure = options.mode === 'public-simulation'
    ? '<aside class="replica-disclosure" data-replica-disclosure role="note">Simulation — this is not the original website. Submissions stay inside this mock.</aside>'
    : '';
  await replaceTokens(options.out, {
    '{{PROJECT_NAME}}': options.name,
    '{{REPLICA_MODE}}': options.mode,
    '{{DISCLOSURE_HTML}}': disclosure
  });
  process.stdout.write(`Replica scaffold: ${options.out}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
