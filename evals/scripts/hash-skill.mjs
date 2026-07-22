#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const skillRoot = resolve(process.argv[2] || join(repositoryRoot, 'skills/replicate-websites'));

async function collect(directory) {
  const files = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    if (['node_modules', '.git'].includes(entry.name)) continue;
    const pathname = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collect(pathname));
    else files.push(pathname);
  }
  return files;
}

const files = (await collect(skillRoot)).sort();
const hash = createHash('sha256');
for (const pathname of files) {
  hash.update(relative(skillRoot, pathname));
  hash.update('\0');
  hash.update((await fs.lstat(pathname)).mode & 0o111 ? '100755' : '100644');
  hash.update('\0');
  hash.update(await fs.readFile(pathname));
  hash.update('\0');
}
process.stdout.write(`${JSON.stringify({
  schemaVersion: 1,
  skillRoot,
  fileCount: files.length,
  sha256: hash.digest('hex')
}, null, 2)}\n`);
