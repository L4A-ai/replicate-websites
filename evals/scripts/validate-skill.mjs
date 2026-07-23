#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

function parseArguments(argv) {
  const options = { skillRoot: join(repositoryRoot, 'skills/replicate-websites'), help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--skill') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new Error('--skill requires a value.');
      options.skillRoot = resolve(value);
      index += 1;
    } else if (argument === '--help' || argument === '-h') {
      options.help = true;
    } else {
      throw new Error(`Unknown option: ${argument}`);
    }
  }
  return options;
}

async function requireFile(skillRoot, relativePath, errors) {
  const pathname = join(skillRoot, relativePath);
  try {
    const stat = await fs.stat(pathname);
    if (!stat.isFile()) errors.push(`${relativePath} is not a file.`);
  } catch (error) {
    if (error.code === 'ENOENT') errors.push(`Missing ${relativePath}.`);
    else throw error;
  }
}

function parseFrontmatter(markdown, errors) {
  const lines = markdown.replaceAll('\r\n', '\n').split('\n');
  if (lines[0] !== '---') {
    errors.push('SKILL.md must begin with YAML frontmatter.');
    return {};
  }
  const closing = lines.indexOf('---', 1);
  if (closing < 0) {
    errors.push('SKILL.md frontmatter is not closed.');
    return {};
  }
  const fields = {};
  for (const line of lines.slice(1, closing)) {
    if (!line.trim()) continue;
    const match = line.match(/^([a-zA-Z][a-zA-Z0-9_-]*):\s*(.*)$/);
    if (!match) {
      errors.push(`Unsupported SKILL.md frontmatter line: ${line}`);
      continue;
    }
    fields[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2').trim();
  }
  return fields;
}

async function walkDirectories(directory) {
  const directories = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const pathname = join(directory, entry.name);
    directories.push(pathname, ...await walkDirectories(pathname));
  }
  return directories;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node validate-skill.mjs [--skill DIR]\n');
    return;
  }
  const errors = [];
  for (const required of [
    'SKILL.md',
    'LICENSE',
    'package.json',
    'assets/replica-starter/server.mjs',
    'references/safety-and-provenance.md',
    'references/workflow.md',
    'scripts/compare-pages.mjs',
    'scripts/inspect-page.mjs'
  ]) await requireFile(options.skillRoot, required, errors);

  try {
    await fs.access(join(options.skillRoot, 'README.md'));
    errors.push('README.md is extraneous inside a skill; keep user-facing documentation at repository root.');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  let frontmatter = {};
  try {
    frontmatter = parseFrontmatter(await fs.readFile(join(options.skillRoot, 'SKILL.md'), 'utf8'), errors);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const keys = Object.keys(frontmatter).sort();
  if (keys.join(',') !== 'description,name') errors.push('SKILL.md frontmatter must contain only name and description.');
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(frontmatter.name || '') || String(frontmatter.name || '').length > 64) {
    errors.push('SKILL.md name must be a lowercase hyphenated name of at most 64 characters.');
  }
  if (frontmatter.name && frontmatter.name !== options.skillRoot.split(/[\\/]/).pop()) {
    errors.push('SKILL.md name must match its directory name.');
  }
  if (!frontmatter.description || frontmatter.description.length > 1024) {
    errors.push('SKILL.md description must contain 1–1024 characters.');
  }
  if (frontmatter.description && !/(use when|replicate|recreate|mock|clone)/i.test(frontmatter.description)) {
    errors.push('SKILL.md description must explain when the skill should be used.');
  }

  try {
    const packageJson = JSON.parse(await fs.readFile(join(options.skillRoot, 'package.json'), 'utf8'));
    if (packageJson.license !== 'MIT') errors.push('package.json must declare the MIT license.');
    for (const packaged of ['SKILL.md', 'LICENSE', 'assets', 'references', 'scripts']) {
      if (!(packageJson.files || []).includes(packaged)) errors.push(`package.json files must include ${packaged}.`);
    }
    if ((packageJson.files || []).includes('README.md')) errors.push('package.json must not package an extra skill README.md.');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const nestedReferences = (await walkDirectories(join(options.skillRoot, 'references')).catch((error) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  })).map((pathname) => relative(options.skillRoot, pathname));
  if (nestedReferences.length) errors.push(`references must remain one level deep: ${nestedReferences.join(', ')}`);

  const result = {
    schemaVersion: 1,
    skillRoot: options.skillRoot,
    name: frontmatter.name || null,
    pass: errors.length === 0,
    errors
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.pass) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
