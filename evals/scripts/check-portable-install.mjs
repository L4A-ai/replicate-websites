#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const validator = join(repositoryRoot, 'evals', 'scripts', 'validate-skill.mjs');
const ansiPattern = /\u001b\[[0-?]*[ -/]*[@-~]/g;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    shell: false,
    ...options
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} exited with status ${result.status}.\n`
      + `${result.stdout || ''}${result.stderr || ''}`
    );
  }
  return result;
}

async function requireFile(pathname) {
  const stat = await fs.stat(pathname);
  if (!stat.isFile()) throw new Error(`Expected a file at ${pathname}.`);
}

async function requireAbsent(pathname) {
  try {
    await fs.access(pathname);
    throw new Error(`Portable install contains repository-only path: ${pathname}.`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

async function main() {
  const installRoot = await fs.mkdtemp(join(tmpdir(), 'replicate-websites-install-'));
  try {
    const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
    const install = run(npx, [
      '--yes',
      'skills@1.5.20',
      'add',
      repositoryRoot,
      '--skill',
      'replicate-websites',
      '--agent',
      'codex',
      '--agent',
      'claude-code',
      '--copy',
      '-y'
    ], {
      cwd: installRoot,
      env: { ...process.env, NO_COLOR: '1' }
    });
    const output = `${install.stdout || ''}${install.stderr || ''}`.replace(ansiPattern, '');
    if (!/\bFound 1 skill\b/.test(output)) {
      throw new Error(`Expected exactly one discoverable skill.\n${output}`);
    }

    const installs = [
      join(installRoot, '.agents', 'skills', 'replicate-websites'),
      join(installRoot, '.claude', 'skills', 'replicate-websites')
    ];
    for (const skillRoot of installs) {
      await requireFile(join(skillRoot, 'SKILL.md'));
      await requireFile(join(skillRoot, 'package.json'));
      await requireFile(join(skillRoot, 'scripts', 'setup-runtime.mjs'));
      await requireAbsent(join(skillRoot, 'test'));
      await requireAbsent(join(skillRoot, 'agents'));
      run(process.execPath, [validator, '--skill', skillRoot], { cwd: repositoryRoot });
    }

    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      discoveredSkills: 1,
      agents: ['codex', 'claude-code'],
      copiesValidated: installs.length,
      pass: true
    }, null, 2)}\n`);
  } finally {
    await fs.rm(installRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
