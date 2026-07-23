#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  findChromiumExecutable,
  resolveRuntimePackage
} from './lib/runtime-dependencies.mjs';

const skillDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function usage() {
  return `Install or verify the pixel-by-pixel runtime.

Usage:
  npm run setup
  npm run setup -- --skip-browser
  npm run doctor

Options:
  --check          Verify dependencies and Chromium without changing anything
  --skip-browser   Install npm dependencies without downloading Chromium
  --help           Show this message
`;
}

function parseArguments(argv) {
  const options = { check: false, skipBrowser: false, help: false };
  for (const argument of argv) {
    if (argument === '--check') options.check = true;
    else if (argument === '--skip-browser') options.skipBrowser = true;
    else if (argument === '--help' || argument === '-h') options.help = true;
    else throw new Error(`Unknown option: ${argument}`);
  }
  if (options.check && options.skipBrowser) {
    throw new Error('--check and --skip-browser cannot be combined.');
  }
  return options;
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: skillDirectory,
    shell: false,
    stdio: 'inherit'
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status ?? 'unknown'}.`);
  }
}

async function inspectRuntime({ requireBrowser }) {
  const dependencies = {};
  for (const name of ['playwright', 'pixelmatch', 'pngjs']) {
    try {
      dependencies[name] = { installed: true, path: resolveRuntimePackage(name) };
    } catch (error) {
      dependencies[name] = { installed: false, error: error.message };
    }
  }

  let chromium = { installed: false, path: null };
  if (dependencies.playwright.installed) {
    try {
      const module = await import(pathToFileURL(dependencies.playwright.path).href);
      const browserType = module.chromium || module.default?.chromium;
      const executable = await findChromiumExecutable(browserType);
      chromium = { installed: Boolean(executable), path: executable };
    } catch (error) {
      chromium = { installed: false, path: null, error: error.message };
    }
  }

  const nodeMajor = Number(process.versions.node.split('.')[0]);
  const result = {
    schemaVersion: 1,
    skillDirectory,
    node: {
      version: process.versions.node,
      supported: Number.isInteger(nodeMajor) && nodeMajor >= 20
    },
    dependencies,
    chromium,
    pass: false
  };
  result.pass = result.node.supported
    && Object.values(dependencies).every((dependency) => dependency.installed)
    && (!requireBrowser || chromium.installed);
  return result;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }

  const nodeMajor = Number(process.versions.node.split('.')[0]);
  if (!Number.isInteger(nodeMajor) || nodeMajor < 20) {
    throw new Error(`Node.js 20 or newer is required; found ${process.versions.node}.`);
  }

  if (!options.check) {
    const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    run(npmCommand, [
      'install',
      '--ignore-scripts',
      '--omit=dev',
      '--no-audit',
      '--no-fund'
    ]);
    if (!options.skipBrowser) {
      const playwrightCli = join(dirname(resolveRuntimePackage('playwright')), 'cli.js');
      await fs.access(playwrightCli);
      run(process.execPath, [playwrightCli, 'install', 'chromium']);
    }
  }

  const result = await inspectRuntime({ requireBrowser: !options.skipBrowser });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.pass) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
