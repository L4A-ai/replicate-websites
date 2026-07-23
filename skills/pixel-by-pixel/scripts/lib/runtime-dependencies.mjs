import { promises as fs } from 'node:fs';
import { createRequire } from 'node:module';
import { delimiter, basename, dirname, join, resolve } from 'node:path';

const localRequire = createRequire(import.meta.url);

function resolverRoot(pathname) {
  const absolute = resolve(pathname);
  return basename(absolute) === 'node_modules' ? dirname(absolute) : absolute;
}

function packageSearchRoots() {
  const roots = [process.cwd()];
  for (const variable of ['PIXEL_BY_PIXEL_NODE_MODULES', 'REPLICATE_WEBSITES_NODE_MODULES', 'NODE_PATH']) {
    for (const entry of String(process.env[variable] || '').split(delimiter).filter(Boolean)) {
      roots.push(resolverRoot(entry));
    }
  }
  return [...new Set(roots)];
}

export function resolveRuntimePackage(name) {
  try {
    return localRequire.resolve(name);
  } catch {
    // A copied skill resolves from its own node_modules. Explicit roots support managed runtimes.
  }
  for (const root of packageSearchRoots()) {
    try {
      return createRequire(join(root, '__pixel_by_pixel_runtime_resolver.cjs')).resolve(name);
    } catch {
      // Continue to the next explicit package root.
    }
  }
  throw new Error(
    `Cannot resolve ${name}. Run npm run setup in the pixel-by-pixel skill directory, `
    + 'or set PIXEL_BY_PIXEL_NODE_MODULES (legacy: REPLICATE_WEBSITES_NODE_MODULES).'
  );
}

async function existingFile(pathname) {
  if (!pathname) return null;
  try {
    const stat = await fs.stat(pathname);
    return stat.isFile() ? pathname : null;
  } catch {
    return null;
  }
}

export async function findChromiumExecutable(chromium) {
  const explicit = await existingFile(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH);
  if (explicit) return explicit;

  const packaged = await existingFile(chromium?.executablePath?.());
  if (packaged) return packaged;

  const candidates = process.platform === 'darwin'
    ? [
        '/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium'
      ]
    : process.platform === 'win32'
      ? [
          join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
          join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe')
        ]
      : [
          '/usr/bin/google-chrome',
          '/usr/bin/google-chrome-stable',
          '/usr/bin/chromium',
          '/usr/bin/chromium-browser'
        ];
  for (const candidate of candidates) {
    const found = await existingFile(candidate);
    if (found) return found;
  }
  return null;
}
