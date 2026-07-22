#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  assertSafeHttpUrl,
  blocksUnsafeDestinationBeforeProxy,
  isLoopbackHostname,
  redactReportData
} from './lib/network-safety.mjs';
import {
  createRuntimeAttemptTelemetry,
  recordRuntimeAttempt,
  runtimeAttemptInitScript
} from './lib/runtime-attempts.mjs';
import { integrityNativeInitScript } from './lib/integrity-natives.mjs';
import { createValidatingBrowserProxy } from './lib/validating-proxy.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const skillDirectory = resolve(scriptDirectory, '..');
const defaultViewports = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 390, height: 844 },
  { name: 'compact', width: 360, height: 800 }
];

function usage() {
  return `Compare two webpages with deterministic Chromium/CDP captures.

Usage:
  node compare-pages.mjs --baseline URL --candidate URL [options]

Required:
  --baseline URL                     Reference page
  --candidate URL                    Implementation under test

Options:
  --out DIR                          Output directory (default: timestamped folder)
  --viewport NAME:WIDTHxHEIGHT       Repeat to replace default desktop/mobile viewports
  --ready-selector SELECTOR          Wait for this selector on both pages
  --baseline-ready-selector SELECTOR Wait only for this baseline selector
  --candidate-ready-selector SELECTOR
                                     Wait only for this candidate selector
  --wait-ms N                        Final settling delay (default: 750)
  --timeout-ms N                     Navigation timeout (default: 30000)
  --pixel-threshold N                Pixelmatch threshold 0..1 (default: 0.10)
  --mask SELECTOR                    Mask the same selector on both pages; repeatable
  --mask-rect X,Y,WIDTH,HEIGHT       Mask the same rectangle on both pages; repeatable
  --max-diff-percent N               Exit 2 when tolerant pixel difference exceeds N
  --max-semantic-mismatches N        Exit 2 when semantic mismatch count exceeds N
  --semantic-limit N                 Max mismatch details retained per category (default: 200)
  --no-auto-scroll                   Do not pre-scroll for lazy-loaded content
  --allow-non-get                    Permit candidate writes in tests; baseline stays GET-only
  --headed                           Show Chromium
  --help                             Show this help
`;
}

function parseNumber(value, option, { minimum = -Infinity, maximum = Infinity, integer = false } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < minimum || parsed > maximum || (integer && !Number.isInteger(parsed))) {
    throw new Error(`${option} expects ${integer ? 'an integer' : 'a number'} between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

function parseViewport(value) {
  const match = String(value).match(/^([a-z0-9_-]+)[:=](\d+)x(\d+)$/i);
  if (!match) throw new Error(`Invalid viewport "${value}". Use NAME:WIDTHxHEIGHT.`);
  return {
    name: match[1],
    width: parseNumber(match[2], '--viewport width', { minimum: 1, maximum: 10000, integer: true }),
    height: parseNumber(match[3], '--viewport height', { minimum: 1, maximum: 10000, integer: true })
  };
}

function parseMaskRect(value) {
  const parts = String(value).split(',').map((part) => Number(part.trim()));
  if (parts.length !== 4 || parts.some((part) => !Number.isFinite(part)) || parts[2] <= 0 || parts[3] <= 0) {
    throw new Error(`Invalid --mask-rect "${value}". Use X,Y,WIDTH,HEIGHT.`);
  }
  return { selector: null, x: parts[0], y: parts[1], width: parts[2], height: parts[3] };
}

function parseArguments(argv) {
  const options = {
    baseline: null,
    candidate: null,
    out: null,
    viewports: [],
    readySelector: null,
    baselineReadySelector: null,
    candidateReadySelector: null,
    waitMs: 750,
    timeoutMs: 30000,
    pixelThreshold: 0.1,
    masks: [],
    maskRects: [],
    maxDiffPercent: null,
    maxSemanticMismatches: null,
    semanticLimit: 200,
    autoScroll: true,
    allowNonGet: false,
    headed: false,
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
      case '--out': options.out = take(index, argument); index += 1; break;
      case '--viewport': options.viewports.push(parseViewport(take(index, argument))); index += 1; break;
      case '--ready-selector': options.readySelector = take(index, argument); index += 1; break;
      case '--baseline-ready-selector': options.baselineReadySelector = take(index, argument); index += 1; break;
      case '--candidate-ready-selector': options.candidateReadySelector = take(index, argument); index += 1; break;
      case '--wait-ms': options.waitMs = parseNumber(take(index, argument), argument, { minimum: 0, maximum: 60000, integer: true }); index += 1; break;
      case '--timeout-ms': options.timeoutMs = parseNumber(take(index, argument), argument, { minimum: 1000, maximum: 180000, integer: true }); index += 1; break;
      case '--pixel-threshold': options.pixelThreshold = parseNumber(take(index, argument), argument, { minimum: 0, maximum: 1 }); index += 1; break;
      case '--mask': options.masks.push(take(index, argument)); index += 1; break;
      case '--mask-rect': options.maskRects.push(parseMaskRect(take(index, argument))); index += 1; break;
      case '--max-diff-percent': options.maxDiffPercent = parseNumber(take(index, argument), argument, { minimum: 0, maximum: 100 }); index += 1; break;
      case '--max-semantic-mismatches': options.maxSemanticMismatches = parseNumber(take(index, argument), argument, { minimum: 0, maximum: 100000, integer: true }); index += 1; break;
      case '--semantic-limit': options.semanticLimit = parseNumber(take(index, argument), argument, { minimum: 1, maximum: 10000, integer: true }); index += 1; break;
      case '--no-auto-scroll': options.autoScroll = false; break;
      case '--allow-non-get': options.allowNonGet = true; break;
      case '--headed': options.headed = true; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }

  if (options.help) return options;
  if (!options.baseline || !options.candidate) throw new Error('--baseline and --candidate are required.');
  assertSafeHttpUrl(options.baseline, 'baseline');
  const candidateUrl = assertSafeHttpUrl(options.candidate, 'candidate');
  if (options.allowNonGet && !isLoopbackHostname(candidateUrl.hostname)) {
    throw new Error('--allow-non-get requires a loopback candidate (127/8, ::1, or localhost).');
  }
  options.viewports = options.viewports.length ? options.viewports : defaultViewports;
  options.baselineReadySelector ||= options.readySelector;
  options.candidateReadySelector ||= options.readySelector;
  const duplicate = options.viewports.find((viewport, index) => options.viewports.findIndex((candidate) => candidate.name === viewport.name) !== index);
  if (duplicate) throw new Error(`Viewport names must be unique; duplicate: ${duplicate.name}`);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  options.out = resolve(options.out || `webpage-fidelity-${stamp}`);
  return options;
}

function packageSearchRoots() {
  const roots = [skillDirectory, process.cwd()];
  if (process.env.CODEX_NODE_MODULES) roots.push(dirname(resolve(process.env.CODEX_NODE_MODULES)));
  if (process.env.NODE_PATH) {
    for (const entry of process.env.NODE_PATH.split(delimiter).filter(Boolean)) roots.push(dirname(resolve(entry)));
  }
  roots.push(join(homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node'));
  return [...new Set(roots)];
}

function resolvePackage(name) {
  const direct = createRequire(import.meta.url);
  try {
    return direct.resolve(name);
  } catch {
    // Search the skill, current project, an explicit runtime, then Codex's bundled runtime.
  }
  for (const root of packageSearchRoots()) {
    try {
      return createRequire(join(root, '__webpage_fidelity_resolver.cjs')).resolve(name);
    } catch {
      // Continue to the next deterministic package root.
    }
  }
  throw new Error(`Cannot resolve ${name}. Install playwright, pixelmatch, and pngjs, or set CODEX_NODE_MODULES.`);
}

async function loadDependencies() {
  const [playwrightModule, pixelmatchModule, pngModule] = await Promise.all([
    import(pathToFileURL(resolvePackage('playwright')).href),
    import(pathToFileURL(resolvePackage('pixelmatch')).href),
    import(pathToFileURL(resolvePackage('pngjs')).href)
  ]);
  const chromium = playwrightModule.chromium || playwrightModule.default?.chromium;
  const pixelmatch = pixelmatchModule.default || pixelmatchModule;
  const PNG = pngModule.PNG || pngModule.default?.PNG;
  if (!chromium || typeof pixelmatch !== 'function' || !PNG) throw new Error('Resolved comparison dependencies have unexpected exports.');
  return { chromium, pixelmatch, PNG };
}

async function existingFile(pathname) {
  if (!pathname) return null;
  try {
    await fs.access(pathname);
    return pathname;
  } catch {
    return null;
  }
}

async function findChromiumExecutable(chromium) {
  const explicit = await existingFile(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH);
  if (explicit) return explicit;
  const packaged = await existingFile(chromium.executablePath());
  if (packaged) return packaged;

  const agentBrowserRoot = join(homedir(), '.agent-browser', 'browsers');
  try {
    const versions = (await fs.readdir(agentBrowserRoot, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory() && entry.name.startsWith('chrome-'))
      .map((entry) => entry.name)
      .sort()
      .reverse();
    for (const version of versions) {
      const macCandidate = await existingFile(join(agentBrowserRoot, version, 'Google Chrome for Testing.app', 'Contents', 'MacOS', 'Google Chrome for Testing'));
      if (macCandidate) return macCandidate;
      const linuxCandidate = await existingFile(join(agentBrowserRoot, version, 'chrome'));
      if (linuxCandidate) return linuxCandidate;
    }
  } catch {
    // Agent Browser is optional.
  }

  const systemCandidates = process.platform === 'darwin'
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
      : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  for (const candidate of systemCandidates) {
    const found = await existingFile(candidate);
    if (found) return found;
  }
  return null;
}

const normalizeText = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
const sha256 = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

async function settlePage(page, options, warnings) {
  try {
    await page.waitForLoadState('networkidle', { timeout: Math.min(options.timeoutMs, 8000) });
  } catch {
    warnings.push('networkidle timed out; continued after explicit font/image/layout settling');
  }

  if (options.readySelector) {
    await page.locator(options.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
  }

  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation-delay: 0s !important;
        animation-duration: 0s !important;
        animation-iteration-count: 1 !important;
        caret-color: transparent !important;
        scroll-behavior: auto !important;
        transition-delay: 0s !important;
        transition-duration: 0s !important;
      }
    `
  });

  await page.evaluate(async () => {
    const natives = globalThis.__replicaIntegrityNatives;
    const queryAll = (root, selector) => natives ? natives.queryAll(root, selector) : Array.from(root.querySelectorAll(selector));
    const shadowRootOf = (element) => natives ? natives.shadowRoot(element) : element.shadowRoot;
    const matches = (element, selector) => natives ? natives.matches(element, selector) : element.matches(selector);
    const activeElements = [];
    const shadowRoots = [];
    const collect = (root) => {
      const elements = queryAll(root, '*');
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        activeElements.push(element);
        const shadowRoot = shadowRootOf(element);
        if (shadowRoot) {
          shadowRoots.push(shadowRoot);
          collect(shadowRoot);
        }
      }
    };
    collect(document);
    const freezeCss = '*,*::before,*::after{animation-delay:0s!important;animation-duration:0s!important;animation-iteration-count:1!important;caret-color:transparent!important;scroll-behavior:auto!important;transition-delay:0s!important;transition-duration:0s!important}';
    for (const root of shadowRoots) {
      const style = document.createElement('style');
      style.setAttribute('data-replica-capture-freeze', '');
      style.textContent = freezeCss;
      root.append(style);
    }
    for (const root of [document, ...shadowRoots]) {
      for (const animation of root.getAnimations?.({ subtree: true }) || []) animation.finish?.();
    }
    const mediaElements = natives ? natives.arrayFilter(activeElements, (element) => matches(element, 'video, audio')) : activeElements.filter((element) => matches(element, 'video, audio'));
    for (let index = 0; index < mediaElements.length; index += 1) mediaElements[index].pause?.();
    if (document.fonts?.ready) {
      await Promise.race([document.fonts.ready, new Promise((resolveWait) => setTimeout(resolveWait, 5000))]);
    }
    const images = natives ? natives.arrayFilter(activeElements, (element) => matches(element, 'img')) : activeElements.filter((element) => matches(element, 'img'));
    const decode = natives ? natives.arrayMap(images, (image) => {
      if (image.complete) return image.decode?.().catch(() => {}) || Promise.resolve();
      return new Promise((resolveImage) => {
        image.addEventListener('load', resolveImage, { once: true });
        image.addEventListener('error', resolveImage, { once: true });
      });
    }) : images.map((image) => image.decode?.().catch(() => {}) || Promise.resolve());
    await Promise.race([Promise.all(decode), new Promise((resolveWait) => setTimeout(resolveWait, 5000))]);
  });

  if (options.autoScroll) {
    await page.evaluate(async () => {
      const maximum = Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0);
      const step = Math.max(400, Math.floor(window.innerHeight * 0.8));
      let steps = 0;
      for (let y = 0; y < maximum && steps < 500; y += step, steps += 1) {
        window.scrollTo(0, y);
        await new Promise((resolveScroll) => setTimeout(resolveScroll, 16));
      }
      window.scrollTo(0, 0);
    });
  }

  if (options.waitMs) await page.waitForTimeout(options.waitMs);
  await page.evaluate(async () => {
    const natives = globalThis.__replicaIntegrityNatives;
    const queryAll = (root, selector) => natives ? natives.queryAll(root, selector) : Array.from(root.querySelectorAll(selector));
    const shadowRootOf = (element) => natives ? natives.shadowRoot(element) : element.shadowRoot;
    const matches = (element, selector) => natives ? natives.matches(element, selector) : element.matches(selector);
    const activeElements = [];
    const shadowRoots = [];
    const collect = (root) => {
      const elements = queryAll(root, '*');
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        activeElements.push(element);
        const shadowRoot = shadowRootOf(element);
        if (shadowRoot) {
          shadowRoots.push(shadowRoot);
          collect(shadowRoot);
        }
      }
    };
    collect(document);
    const freezeCss = '*,*::before,*::after{animation-delay:0s!important;animation-duration:0s!important;animation-iteration-count:1!important;caret-color:transparent!important;scroll-behavior:auto!important;transition-delay:0s!important;transition-duration:0s!important}';
    for (const root of shadowRoots) {
      if (!(natives ? natives.queryOne(root, 'style[data-replica-capture-freeze]') : root.querySelector('style[data-replica-capture-freeze]'))) {
        const style = document.createElement('style');
        style.setAttribute('data-replica-capture-freeze', '');
        style.textContent = freezeCss;
        root.append(style);
      }
    }
    for (const root of [document, ...shadowRoots]) {
      for (const animation of root.getAnimations?.({ subtree: true }) || []) animation.finish?.();
    }
    const mediaElements = natives ? natives.arrayFilter(activeElements, (element) => matches(element, 'video, audio')) : activeElements.filter((element) => matches(element, 'video, audio'));
    for (let index = 0; index < mediaElements.length; index += 1) mediaElements[index].pause?.();
    const images = natives ? natives.arrayFilter(activeElements, (element) => matches(element, 'img')) : activeElements.filter((element) => matches(element, 'img'));
    await Promise.race([
      Promise.all(natives
        ? natives.arrayMap(images, (image) => image.decode?.().catch(() => {}) || Promise.resolve())
        : images.map((image) => image.decode?.().catch(() => {}) || Promise.resolve())),
      new Promise((resolveWait) => setTimeout(resolveWait, 5000))
    ]);
  });
}

async function sampleLayoutStability(page) {
  const samples = [];
  for (let index = 0; index < 4; index += 1) {
    samples.push(await page.evaluate(() => {
      const nativeRect = globalThis.__replicaIntegrityNatives;
      const rect = document.body
        ? (nativeRect ? nativeRect.getBoundingClientRect(document.body) : document.body.getBoundingClientRect())
        : { width: 0, height: 0 };
      return {
        scrollWidth: Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0),
        scrollHeight: Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0),
        bodyWidth: Math.round((rect.width || 0) * 1000) / 1000,
        bodyHeight: Math.round((rect.height || 0) * 1000) / 1000
      };
    }));
    if (index < 3) await page.waitForTimeout(150);
  }
  const signature = (sample) => JSON.stringify(sample);
  const stable = signature(samples[1]) === signature(samples[2]) && signature(samples[2]) === signature(samples[3]);
  return { stable, samples };
}

async function resolveMaskSelectors(page, selectors) {
  const rectangles = [];
  const geometry = [];
  for (const selector of selectors) {
    const locator = page.locator(selector);
    const count = await locator.count();
    if (!count) throw new Error(`Mask selector not found: ${selector}`);
    const matches = [];
    for (let index = 0; index < count; index += 1) {
      const box = await locator.nth(index).boundingBox();
      if (!box) throw new Error(`Mask selector is not rendered: ${selector} (match ${index + 1})`);
      const rectangle = { selector, x: box.x, y: box.y, width: box.width, height: box.height };
      rectangles.push(rectangle);
      matches.push(rectangle);
    }
    geometry.push({ selector, count, rectangles: matches });
  }
  return { rectangles, geometry };
}

async function captureDomSemantics(page) {
  return page.evaluate(() => {
    const integrityNatives = globalThis.__replicaIntegrityNatives;
    const queryAll = (root, selector) => integrityNatives
      ? integrityNatives.queryAll(root, selector)
      : [...root.querySelectorAll(selector)];
    const queryOne = (root, selector) => integrityNatives
      ? integrityNatives.queryOne(root, selector)
      : root.querySelector(selector);
    const toArray = (value) => integrityNatives ? integrityNatives.toArray(value) : Array.from(value || []);
    const mapArray = (value, callback) => integrityNatives
      ? integrityNatives.arrayMap(value, callback)
      : value.map(callback);
    const filterArray = (value, callback) => integrityNatives
      ? integrityNatives.arrayFilter(value, callback)
      : value.filter(callback);
    const findArray = (value, callback) => integrityNatives
      ? integrityNatives.arrayFind(value, callback)
      : value.find(callback);
    const pushArray = (value, ...entries) => integrityNatives
      ? integrityNatives.arrayPush(value, ...entries)
      : value.push(...entries);
    const matches = (element, selector) => integrityNatives
      ? integrityNatives.matches(element, selector)
      : element.matches(selector);
    const getAttribute = (element, name) => integrityNatives
      ? integrityNatives.getAttribute(element, name)
      : element.getAttribute(name);
    const getRootNode = (node) => integrityNatives
      ? integrityNatives.getRootNode(node)
      : node.getRootNode();
    const shadowRootOf = (element) => integrityNatives
      ? integrityNatives.shadowRoot(element)
      : element.shadowRoot;
    const closest = (element, selector) => integrityNatives
      ? integrityNatives.closest(element, selector)
      : element.closest(selector);
    const getComputedStyle = (element, pseudo = null) => integrityNatives
      ? integrityNatives.getComputedStyle(element, pseudo)
      : globalThis.getComputedStyle(element, pseudo);
    const boundingRect = (element) => integrityNatives
      ? integrityNatives.getBoundingClientRect(element)
      : element.getBoundingClientRect();
    const nativeFormAction = (form) => integrityNatives
      ? integrityNatives.formAction(form)
      : form.action;
    const nativeFormMethod = (form) => integrityNatives
      ? integrityNatives.formMethod(form)
      : form.method;
    const nativeFormEnctype = (form) => integrityNatives
      ? integrityNatives.formEnctype(form)
      : form.enctype;
    const clean = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
    const activeElements = [];
    const collectActiveElements = (root) => {
      const elements = queryAll(root, '*');
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        pushArray(activeElements, element);
        const shadowRoot = shadowRootOf(element);
        if (shadowRoot) collectActiveElements(shadowRoot);
      }
    };
    collectActiveElements(document);
    const queryActive = (selector) => filterArray(activeElements, (element) => matches(element, selector));
    const elementById = (element, id) => {
      const root = getRootNode(element);
      return integrityNatives?.getElementById(root, id)
        || integrityNatives?.getElementById(document, id)
        || root?.getElementById?.(id)
        || document.getElementById(id);
    };
    const pseudo = (element, which) => {
      if (!element) return '';
      const content = getComputedStyle(element, which).content;
      if (!content || content === 'none' || content === 'normal') return '';
      return clean(content.replace(/^(["'])|(["'])$/g, ''));
    };
    const numericAlpha = (color) => {
      const normalized = String(color || '').trim().toLowerCase();
      if (!normalized || normalized === 'transparent') return normalized === 'transparent' ? 0 : 1;
      const slashAlpha = normalized.match(/\/\s*(-?(?:\d+\.?\d*|\.\d+)%?)\s*\)$/);
      if (slashAlpha) {
        const value = Number.parseFloat(slashAlpha[1]);
        return slashAlpha[1].endsWith('%') ? value / 100 : value;
      }
      const commaAlpha = normalized.match(/rgba?\([^)]*,\s*(-?(?:\d+\.?\d*|\.\d+)%?)\s*\)$/);
      if (commaAlpha && normalized.startsWith('rgba')) {
        const value = Number.parseFloat(commaAlpha[1]);
        return commaAlpha[1].endsWith('%') ? value / 100 : value;
      }
      return 1;
    };
    const insetValues = (value, rect) => {
      const match = String(value || '').match(/^inset\(([^)]*)\)/i);
      if (!match) return null;
      const tokens = match[1].split(/\s+round\s+/i)[0].split(/\s+/).filter(Boolean);
      if (!tokens.length || tokens.some((token) => !/^-?(?:\d+\.?\d*|\.\d+)(?:px|%)?$/.test(token))) return null;
      const expanded = tokens.length === 1
        ? [tokens[0], tokens[0], tokens[0], tokens[0]]
        : tokens.length === 2
          ? [tokens[0], tokens[1], tokens[0], tokens[1]]
          : tokens.length === 3
            ? [tokens[0], tokens[1], tokens[2], tokens[1]]
            : tokens.slice(0, 4);
      return expanded.map((token, index) => {
        const valueNumber = Number.parseFloat(token);
        return token.endsWith('%') ? valueNumber / 100 * (index % 2 ? rect.width : rect.height) : valueNumber;
      });
    };
    const hasZeroClip = (style, rect) => {
      const legacy = String(style.clip || '').trim().toLowerCase();
      const legacyMatch = legacy.match(/^rect\(\s*(-?[\d.]+)(?:px)?[,\s]+(-?[\d.]+)(?:px)?[,\s]+(-?[\d.]+)(?:px)?[,\s]+(-?[\d.]+)(?:px)?\s*\)$/);
      if (legacyMatch) {
        const [, top, right, bottom, left] = legacyMatch.map(Number);
        if (right <= left || bottom <= top) return true;
      }
      const clipPath = String(style.clipPath || style.webkitClipPath || '').trim().toLowerCase();
      if (!clipPath || clipPath === 'none') return false;
      const inset = insetValues(clipPath, rect);
      if (inset && (inset[1] + inset[3] >= rect.width || inset[0] + inset[2] >= rect.height)) return true;
      if (/^(?:circle|ellipse)\(\s*0(?:px|%)?(?:\s+0(?:px|%)?)?(?:\s+at\b|\s*\))/i.test(clipPath)) return true;
      const polygon = clipPath.match(/^polygon\((.*)\)$/i);
      if (polygon) {
        const points = [...polygon[1].matchAll(/(-?[\d.]+%?)\s+(-?[\d.]+%?)/g)].map((match) => `${match[1]} ${match[2]}`);
        if (points.length && new Set(points).size === 1) return true;
      }
      return false;
    };
    const intersectAxis = (range, start, end) => ({ start: Math.max(range.start, start), end: Math.min(range.end, end) });
    const filterIsTransparent = (filter) => [...String(filter || '').matchAll(/opacity\(\s*(-?(?:\d+\.?\d*|\.\d+)%?)\s*\)/gi)].some((match) => {
      const value = Number.parseFloat(match[1]);
      return (match[1].endsWith('%') ? value / 100 : value) <= 0.001;
    });
    const visible = (element) => {
      if (!element) return false;
      const box = boundingRect(element);
      if (box.width <= 0 || box.height <= 0) return false;
      let horizontal = { start: box.left, end: box.right };
      let vertical = { start: box.top, end: box.bottom };
      let cumulativeOpacity = 1;
      let current = element;
      while (current && current.nodeType === Node.ELEMENT_NODE) {
        const style = getComputedStyle(current);
        const currentRect = boundingRect(current);
        const opacity = Number.parseFloat(style.opacity || '1');
        cumulativeOpacity *= Number.isFinite(opacity) ? opacity : 1;
        if (current.hidden
          || style.display === 'none'
          || ['hidden', 'collapse'].includes(style.visibility)
          || style.contentVisibility === 'hidden'
          || filterIsTransparent(style.filter)
          || cumulativeOpacity <= 0.001
          || hasZeroClip(style, currentRect)) return false;
        if (current !== element && ![document.documentElement, document.body].includes(current)) {
          if (['hidden', 'clip'].includes(style.overflowX)) horizontal = intersectAxis(horizontal, currentRect.left, currentRect.right);
          if (['hidden', 'clip'].includes(style.overflowY)) vertical = intersectAxis(vertical, currentRect.top, currentRect.bottom);
          if (horizontal.end <= horizontal.start || vertical.end <= vertical.start) return false;
        }
        const root = getRootNode(current);
        current = current.parentElement || (root instanceof ShadowRoot ? root.host : null);
      }
      const style = getComputedStyle(element);
      if (Number.parseFloat(style.fontSize || '0') <= 0.01) return false;
      if (numericAlpha(style.color) <= 0.001 || numericAlpha(style.webkitTextFillColor) <= 0.001) return false;
      return true;
    };
    const labelsFor = (element) => toArray(element.labels || []);
    const labelledByText = (element) => {
      const ids = filterArray((getAttribute(element, 'aria-labelledby') || '').split(/\s+/), Boolean);
      return clean(mapArray(ids, (id) => elementById(element, id)?.textContent || '').join(' '));
    };
    const questionElement = (element) => {
      const labelledGroup = closest(element, '[role="group"][aria-labelledby], [role="radiogroup"][aria-labelledby]');
      if (labelledGroup) {
        const labelled = findArray(
          mapArray((getAttribute(labelledGroup, 'aria-labelledby') || '').split(/\s+/), (id) => elementById(element, id)),
          Boolean
        );
        if (labelled) return labelled;
      }
      const root = closest(element, 'fieldset, .application-question, .lever-question, [data-question]');
      if (!root) return null;
      if (matches(root, 'fieldset')) return queryOne(root, ':scope > legend');
      return queryOne(root, [
        ':scope > .application-label',
        ':scope > .lever-application-label',
        ':scope > label',
        ':scope > legend',
        ':scope > div > .application-label',
        ':scope > div > .lever-application-label',
        '.application-label',
        '.lever-application-label'
      ].join(', '));
    };
    const accessibleName = (element) => {
      const aria = clean(getAttribute(element, 'aria-label')) || labelledByText(element);
      if (aria) return aria;
      const labelText = clean(mapArray(labelsFor(element), (label) => label.textContent).join(' '));
      if (labelText) return labelText;
      if (matches(element, 'button, a')) return clean(element.textContent);
      if (matches(element, 'input[type="button"], input[type="submit"]')) return clean(element.value);
      return clean(getAttribute(element, 'placeholder') || getAttribute(element, 'title') || getAttribute(element, 'alt'));
    };

    const valueClassification = (type, value) => {
      if (!value) return 'empty';
      if (type === 'hidden') return 'hidden-present';
      if (['checkbox', 'radio'].includes(type)) return value === 'on' ? 'default-choice' : 'opaque-choice';
      if (['button', 'submit', 'reset'].includes(type)) return 'visible-control-label';
      if (type === 'select') return 'selected-option';
      return 'freeform-present';
    };
    const optionValueClassification = (value, text) => {
      if (!value) return 'empty';
      if (clean(value).toLowerCase() === clean(text).toLowerCase()) return 'same-as-visible-text';
      if (/^(?:yes|no|true|false|on|off|none|null|0|1)$/i.test(value)) return 'common-enum';
      return 'opaque';
    };
    const safeValueMetadata = (type, rawValue) => {
      const value = String(rawValue || '');
      return {
        valuePresent: value.length > 0,
        valueLength: value.length,
        valueClassification: valueClassification(type, value)
      };
    };
    const controls = mapArray(queryActive('input, select, textarea, button'), (element, ordinal) => {
      const tag = element.tagName.toLowerCase();
      const type = tag === 'input' || tag === 'button' ? clean(element.type || tag) : tag;
      const labels = labelsFor(element);
      const question = questionElement(element);
      const options = tag === 'select' ? mapArray(toArray(element.options), (option) => {
        const optionValue = String(option.value || '');
        return {
          text: clean(option.textContent),
          valuePresent: optionValue.length > 0,
          valueLength: optionValue.length,
          valueClassification: optionValueClassification(optionValue, option.textContent),
          disabled: Boolean(option.disabled)
        };
      }) : [];
      const valueMetadata = safeValueMetadata(type, element.value);
      const choiceMetadata = ['checkbox', 'radio', 'button', 'submit'].includes(type)
        ? valueMetadata
        : { valuePresent: false, valueLength: 0, valueClassification: 'not-choice' };
      return {
        ordinal,
        tag,
        type,
        name: String(getAttribute(element, 'name') || ''),
        idPresent: Boolean(element.id),
        role: String(getAttribute(element, 'role') || ''),
        required: Boolean(element.required),
        ariaRequired: String(getAttribute(element, 'aria-required') || ''),
        disabled: Boolean(element.disabled),
        readOnly: Boolean(element.readOnly),
        multiple: Boolean(element.multiple),
        hiddenAttribute: Boolean(element.hidden),
        ariaHidden: String(getAttribute(element, 'aria-hidden') || ''),
        tabIndex: element.tabIndex,
        visible: visible(element),
        checked: ['checkbox', 'radio'].includes(type) ? Boolean(element.checked) : null,
        choiceValuePresent: choiceMetadata.valuePresent,
        choiceValueLength: choiceMetadata.valueLength,
        choiceValueClassification: choiceMetadata.valueClassification,
        valuePresent: type === 'hidden' ? null : valueMetadata.valuePresent,
        valueLength: type === 'hidden' ? null : valueMetadata.valueLength,
        valueClassification: type === 'hidden' ? null : valueMetadata.valueClassification,
        placeholder: String(getAttribute(element, 'placeholder') || ''),
        autocomplete: String(getAttribute(element, 'autocomplete') || ''),
        accept: String(getAttribute(element, 'accept') || ''),
        min: String(getAttribute(element, 'min') || ''),
        max: String(getAttribute(element, 'max') || ''),
        maxLength: Number.isInteger(element.maxLength) ? element.maxLength : -1,
        hiddenValuePresent: type === 'hidden' ? Boolean(element.value) : null,
        hiddenValueLength: type === 'hidden' ? String(element.value || '').length : null,
        accessibleName: accessibleName(element),
        labelText: clean(mapArray(labels, (label) => label.textContent).join(' ')),
        labelVisibleText: clean(mapArray(labels, (label) => label.innerText).join(' ')),
        labelPseudoBefore: clean(mapArray(labels, (label) => pseudo(label, '::before')).join(' ')),
        labelPseudoAfter: clean(mapArray(labels, (label) => pseudo(label, '::after')).join(' ')),
        questionText: clean(question?.textContent),
        questionVisibleText: clean(question?.innerText),
        questionPseudoBefore: pseudo(question, '::before'),
        questionPseudoAfter: pseudo(question, '::after'),
        selectedOptionTexts: tag === 'select' ? mapArray(toArray(element.selectedOptions), (option) => clean(option.textContent)) : [],
        options
      };
    });

    const labels = mapArray(queryActive('label, .application-label, .lever-application-label'), (element, ordinal) => {
      const questionRoot = closest(element, 'fieldset, .application-question, .lever-question, [data-question]');
      const directlyLabelsControl = matches(element, 'label') && Boolean(element.htmlFor || queryOne(element, 'input, select, textarea, button'));
      const target = element.htmlFor
        ? elementById(element, element.htmlFor)
        : queryOne(element, 'input, select, textarea, button') || (questionRoot ? queryOne(questionRoot, 'input, select, textarea, button') : null);
      const targetType = target ? (target.tagName.toLowerCase() === 'input' ? target.type : target.tagName.toLowerCase()) : '';
      const choiceValue = directlyLabelsControl && ['checkbox', 'radio'].includes(targetType) ? String(target?.value || '') : '';
      return {
        ordinal,
        text: clean(element.textContent),
        visibleText: clean(element.innerText),
        pseudoBefore: pseudo(element, '::before'),
        pseudoAfter: pseudo(element, '::after'),
        kind: directlyLabelsControl ? 'control' : 'question',
        controlName: target ? String(getAttribute(target, 'name') || '') : '',
        controlType: targetType,
        choiceValuePresent: choiceValue.length > 0,
        choiceValueLength: choiceValue.length,
        choiceValueClassification: choiceValue ? valueClassification(targetType, choiceValue) : 'not-choice',
        visible: visible(element)
      };
    });

    const links = mapArray(queryActive('a'), (element, ordinal) => ({
      ordinal,
      text: clean(element.textContent),
      visibleText: clean(element.innerText),
      ariaLabel: clean(getAttribute(element, 'aria-label')),
      href: element.href,
      target: String(getAttribute(element, 'target') || ''),
      rel: String(getAttribute(element, 'rel') || ''),
      visible: visible(element)
    }));

    const headings = mapArray(queryActive('h1, h2, h3, h4, h5, h6, [role="heading"]'), (element, ordinal) => ({
      ordinal,
      level: Number(getAttribute(element, 'aria-level') || element.tagName.slice(1) || 0),
      text: clean(element.textContent),
      visibleText: clean(element.innerText),
      visible: visible(element)
    }));

    const forms = mapArray(queryActive('form'), (element, ordinal) => ({
      ordinal,
      methodAttribute: getAttribute(element, 'method'),
      method: String(nativeFormMethod(element) || 'get').toLowerCase(),
      actionAttribute: getAttribute(element, 'action'),
      action: String(nativeFormAction(element) || ''),
      enctypeAttribute: getAttribute(element, 'enctype'),
      enctype: String(nativeFormEnctype(element) || '').toLowerCase(),
      targetAttribute: getAttribute(element, 'target'),
      controlCount: element.elements.length
    }));

    return {
      controls,
      labels,
      links,
      headings,
      forms,
      nativeApiTampering: integrityNatives
        ? integrityNatives.auditElements(activeElements, 1000)
        : ['integrity-native-snapshot-missing']
    };
  });
}

async function captureAccessibilityTree(cdp) {
  const response = await cdp.send('Accessibility.getFullAXTree');
  const usefulRoles = new Set([
    'button', 'checkbox', 'combobox', 'form', 'group', 'heading', 'link', 'listbox',
    'radio', 'radiogroup', 'searchbox', 'slider', 'spinbutton', 'switch', 'tab',
    'tabpanel', 'textbox'
  ]);
  return response.nodes
    .filter((node) => !node.ignored && usefulRoles.has(node.role?.value))
    .map((node, ordinal) => {
      const properties = {};
      for (const property of node.properties || []) {
        if (['required', 'disabled', 'checked', 'selected', 'expanded', 'invalid', 'level'].includes(property.name)) {
          properties[property.name] = property.value?.value ?? null;
        }
      }
      return {
        ordinal,
        role: String(node.role?.value || ''),
        name: normalizeText(node.name?.value),
        properties
      };
    });
}

async function captureSide(browser, side, url, viewport, directory, options) {
  const readySelector = side === 'baseline' ? options.baselineReadySelector : options.candidateReadySelector;
  const sideOptions = { ...options, readySelector };
  const allowSideWrites = side === 'candidate' && options.allowNonGet;
  const parsedUrl = new URL(url);
  const transport = await createValidatingBrowserProxy({
    allowedLoopbackUrl: isLoopbackHostname(parsedUrl.hostname) ? parsedUrl.href : null
  });
  let context;
  try {
  context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    deviceScaleFactor: 1,
    locale: 'en-US',
    timezoneId: 'UTC',
    colorScheme: 'light',
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
    acceptDownloads: false,
    proxy: transport.playwright
  });

  const blockedWrites = [];
  const blockedPrivateReads = [];
  const runtimeAttempts = createRuntimeAttemptTelemetry();
  const allowedOrigin = parsedUrl.origin;
  await context.route('**/*', async (route) => {
    const request = route.request();
    if (blocksUnsafeDestinationBeforeProxy(request.url(), allowedOrigin)) {
      blockedPrivateReads.push({ method: request.method(), resourceType: request.resourceType() });
      return route.abort('blockedbyclient');
    }
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method())) return route.continue();
    if (allowSideWrites && new URL(request.url()).origin === allowedOrigin) return route.continue();
    blockedWrites.push({ method: request.method(), resourceType: request.resourceType() });
    return route.abort('blockedbyclient');
  });
  if (typeof context.routeWebSocket === 'function') {
    await context.routeWebSocket('**/*', (socket) => {
      recordRuntimeAttempt(runtimeAttempts, 'websocket', {
        url: typeof socket.url === 'function' ? socket.url() : '',
        observedBy: 'route'
      });
      socket.close();
    });
  }

  const page = await context.newPage();
  const telemetry = {
    consoleWarnings: 0,
    consoleErrors: 0,
    consoleWarningSamples: [],
    consoleErrorSamples: [],
    pageErrors: 0,
    pageErrorSamples: [],
    failedGetResources: 0,
    failedGetResourcesByType: {},
    runtimeAttempts
  };
  page.on('console', (message) => {
    if (message.type() === 'warning') {
      telemetry.consoleWarnings += 1;
      if (telemetry.consoleWarningSamples.length < 50) telemetry.consoleWarningSamples.push(message.text());
    }
    if (message.type() === 'error') {
      telemetry.consoleErrors += 1;
      if (telemetry.consoleErrorSamples.length < 50) telemetry.consoleErrorSamples.push(message.text());
    }
  });
  page.on('pageerror', (error) => {
    telemetry.pageErrors += 1;
    if (telemetry.pageErrorSamples.length < 50) telemetry.pageErrorSamples.push(error.message);
  });
  page.on('requestfailed', (request) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) return;
    telemetry.failedGetResources += 1;
    const type = request.resourceType();
    telemetry.failedGetResourcesByType[type] = (telemetry.failedGetResourcesByType[type] || 0) + 1;
  });
  page.on('popup', (popup) => {
    recordRuntimeAttempt(runtimeAttempts, 'popup', { url: popup.url(), observedBy: 'page-event' });
    popup.close().catch(() => {});
  });
  page.on('download', (download) => {
    recordRuntimeAttempt(runtimeAttempts, 'download', { url: download.url(), observedBy: 'page-event' });
    download.cancel().catch(() => {});
  });

  await page.exposeBinding('__replicaReportRuntimeAttempt', (_source, attempt) => {
    recordRuntimeAttempt(runtimeAttempts, attempt?.kind, {
      url: attempt?.url || '',
      target: attempt?.target || '',
      scope: attempt?.scope || '',
      payloadPresent: attempt?.payloadPresent === true,
      configurationPresent: attempt?.configurationPresent === true,
      iceServerCount: Number.isSafeInteger(attempt?.iceServerCount) ? attempt.iceServerCount : 0,
      labelPresent: attempt?.labelPresent === true,
      negotiated: attempt?.negotiated === true,
      protocolPresent: attempt?.protocolPresent === true,
      observedBy: 'init-script'
    });
  });
  await page.addInitScript(integrityNativeInitScript);
  await page.addInitScript(runtimeAttemptInitScript, { blockEffects: !allowSideWrites });

  if (!allowSideWrites) {
    await page.addInitScript(() => {
      const blockSubmit = () => { throw new Error('Live form submission blocked by replicate-websites.'); };
      try { HTMLFormElement.prototype.submit = blockSubmit; } catch {}
      try { HTMLFormElement.prototype.requestSubmit = blockSubmit; } catch {}
    });
  }

  const warnings = [];
  let response = null;
  let navigationError = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs });
      navigationError = null;
      break;
    } catch (error) {
      navigationError = error;
      if (attempt === 3) break;
      warnings.push(`navigation attempt ${attempt} failed; retrying a read-only GET`);
      await page.waitForTimeout(attempt * 750);
    }
  }
  if (navigationError) throw navigationError;
  if (!response) throw new Error(`${side} navigation returned no response.`);
  if (!response.ok()) throw new Error(`${side} navigation returned HTTP ${response.status()}.`);
  await settlePage(page, sideOptions, warnings);

  const criticalFailureCount = () => ['document', 'stylesheet', 'font']
    .reduce((total, type) => total + (telemetry.failedGetResourcesByType[type] || 0), 0);
  for (let retry = 1; retry <= 2 && criticalFailureCount() > 0; retry += 1) {
    warnings.push(`critical GET resources failed; recapturing page (attempt ${retry + 1})`);
    telemetry.failedGetResources = 0;
    telemetry.failedGetResourcesByType = {};
    response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs });
    if (!response?.ok()) throw new Error(`${side} resource-retry navigation returned HTTP ${response?.status() ?? 'unknown'}.`);
    await settlePage(page, sideOptions, warnings);
  }
  if (criticalFailureCount() > 0) warnings.push('capture retained failed document/stylesheet/font requests after retries');
  const stability = await sampleLayoutStability(page);
  if (!stability.stable) warnings.push('document dimensions did not stabilize across the final three samples');

  const masks = await resolveMaskSelectors(page, options.masks);
  const dom = await captureDomSemantics(page);
  const cdp = await context.newCDPSession(page);
  const [layout, accessibility] = await Promise.all([
    cdp.send('Page.getLayoutMetrics'),
    captureAccessibilityTree(cdp)
  ]);
  const content = layout.cssContentSize || layout.contentSize;
  const width = Math.max(1, Math.ceil(content.width));
  const height = Math.max(1, Math.ceil(content.height));
  const screenshotPath = join(directory, `${side}.png`);

  try {
    const screenshot = await cdp.send('Page.captureScreenshot', {
      format: 'png',
      fromSurface: true,
      captureBeyondViewport: true,
      clip: { x: 0, y: 0, width, height, scale: 1 }
    });
    await fs.writeFile(screenshotPath, Buffer.from(screenshot.data, 'base64'));
  } catch (error) {
    warnings.push(`CDP capture failed (${error.message}); used Playwright full-page capture`);
    await page.screenshot({ path: screenshotPath, fullPage: true, animations: 'disabled', caret: 'hide', scale: 'css' });
  }

  const title = await page.title();
  await cdp.detach();
  if (transport.stats.rejectedDestinations > 0) {
    blockedPrivateReads.push({
      method: 'PROXY',
      resourceType: 'transport',
      count: transport.stats.rejectedDestinations
    });
  }
  return {
    side,
    url,
    screenshotPath,
    httpStatus: response.status(),
    title,
    layout: {
      width,
      height,
      viewportWidth: viewport.width,
      viewportHeight: viewport.height,
      pageScaleFactor: layout.cssVisualViewport?.scale ?? layout.visualViewport?.scale ?? 1
    },
    masks: [...masks.rectangles, ...options.maskRects],
    maskGeometry: masks.geometry,
    semantic: { ...dom, accessibility },
    stability,
    telemetry: {
      ...telemetry,
      blockedWrites,
      blockedPrivateReads,
      validatingProxy: { ...transport.stats }
    },
    warnings
  };
  } finally {
    await context?.close().catch(() => {});
    await transport.close().catch(() => {});
  }
}

function controlKey(control, occurrences) {
  let base;
  if (control.name) {
    base = `name:${control.name}|${control.tag}:${control.type}`;
    if (['checkbox', 'radio'].includes(control.type)) {
      base += `|choice:${control.choiceValueClassification}:${control.choiceValueLength}|label:${control.accessibleName}`;
    }
  } else if (control.accessibleName) {
    base = `anonymous:${control.tag}:${control.type}|name:${control.accessibleName}`;
  } else {
    base = `anonymous:${control.tag}:${control.type}`;
  }
  const occurrence = occurrences.get(base) || 0;
  occurrences.set(base, occurrence + 1);
  return `${base}|#${occurrence}`;
}

function normalizeSemanticSnapshot(snapshot) {
  const occurrences = new Map();
  const controls = snapshot.controls.map((control) => ({
    ...control,
    key: controlKey(control, occurrences),
    optionCount: control.options.length,
    optionsHash: sha256(control.options)
  }));
  const labelOccurrences = new Map();
  const labels = snapshot.labels.map((label) => {
    const base = label.controlName
      ? `label:${label.kind}|name:${label.controlName}|type:${label.controlType}|choice:${label.choiceValueClassification}:${label.choiceValueLength}`
      : `label:${label.kind}|text:${label.text}`;
    const occurrence = labelOccurrences.get(base) || 0;
    labelOccurrences.set(base, occurrence + 1);
    return { ...label, key: `${base}|#${occurrence}` };
  });
  const linkOccurrences = new Map();
  const links = snapshot.links.map((link) => {
    const base = `link:name:${link.ariaLabel || link.text}`;
    const occurrence = linkOccurrences.get(base) || 0;
    linkOccurrences.set(base, occurrence + 1);
    return { ...link, key: `${base}|#${occurrence}` };
  });
  const headingOccurrences = new Map();
  const headings = snapshot.headings.map((heading) => {
    const base = `heading:level:${heading.level}|text:${heading.text}`;
    const occurrence = headingOccurrences.get(base) || 0;
    headingOccurrences.set(base, occurrence + 1);
    return { ...heading, key: `${base}|#${occurrence}` };
  });
  const forms = snapshot.forms.map((form, index) => ({ ...form, key: `form:#${index}` }));
  const accessibilityOccurrences = new Map();
  const accessibility = snapshot.accessibility.map((node) => {
    const base = `ax:${node.role}|name:${node.name}`;
    const occurrence = accessibilityOccurrences.get(base) || 0;
    accessibilityOccurrences.set(base, occurrence + 1);
    return { ...node, key: `${base}|#${occurrence}` };
  });
  return { controls, labels, links, headings, forms, accessibility, nativeApiTampering: snapshot.nativeApiTampering || [] };
}

function optionDifferences(baseline, candidate, limit = 20) {
  const differences = [];
  const maximum = Math.max(baseline.length, candidate.length);
  for (let index = 0; index < maximum && differences.length < limit; index += 1) {
    const left = baseline[index] ?? null;
    const right = candidate[index] ?? null;
    if (JSON.stringify(left) !== JSON.stringify(right)) differences.push({ index, baseline: left, candidate: right });
  }
  return differences;
}

function compareCollection(kind, baseline, candidate, properties, limit) {
  const left = new Map(baseline.map((record) => [record.key, record]));
  const right = new Map(candidate.map((record) => [record.key, record]));
  const missing = [];
  const extra = [];
  const changed = [];

  for (const [key, record] of left) {
    if (!right.has(key)) {
      missing.push({ key, baseline: compactRecord(record) });
      continue;
    }
    const candidateRecord = right.get(key);
    const changes = {};
    for (const property of properties) {
      if (JSON.stringify(record[property]) !== JSON.stringify(candidateRecord[property])) {
        changes[property] = { baseline: record[property], candidate: candidateRecord[property] };
      }
    }
    if (kind === 'controls' && record.optionsHash !== candidateRecord.optionsHash) {
      changes.options = {
        baselineCount: record.optionCount,
        candidateCount: candidateRecord.optionCount,
        firstDifferences: optionDifferences(record.options, candidateRecord.options)
      };
    }
    if (Object.keys(changes).length) changed.push({ key, changes });
  }
  for (const [key, record] of right) {
    if (!left.has(key)) extra.push({ key, candidate: compactRecord(record) });
  }

  const mismatchCount = missing.length + extra.length + changed.length;
  return {
    kind,
    baselineCount: baseline.length,
    candidateCount: candidate.length,
    mismatchCount,
    missing: missing.slice(0, limit),
    extra: extra.slice(0, limit),
    changed: changed.slice(0, limit),
    truncated: missing.length > limit || extra.length > limit || changed.length > limit
  };
}

function compactRecord(record) {
  const copy = { ...record };
  delete copy.options;
  return copy;
}

function compareSemantics(baselineRaw, candidateRaw, limit) {
  const baseline = normalizeSemanticSnapshot(baselineRaw);
  const candidate = normalizeSemanticSnapshot(candidateRaw);
  const categories = [
    compareCollection('controls', baseline.controls, candidate.controls, [
      'tag', 'type', 'name', 'role', 'required', 'ariaRequired', 'disabled', 'readOnly',
      'multiple', 'hiddenAttribute', 'ariaHidden', 'tabIndex', 'visible', 'checked',
      'choiceValuePresent', 'choiceValueLength', 'choiceValueClassification',
      'valuePresent', 'valueLength', 'valueClassification', 'placeholder', 'autocomplete',
      'accept', 'min', 'max', 'maxLength', 'accessibleName', 'labelText', 'labelVisibleText',
      'hiddenValuePresent', 'hiddenValueLength',
      'labelPseudoBefore', 'labelPseudoAfter', 'questionText', 'questionVisibleText',
      'questionPseudoBefore', 'questionPseudoAfter', 'selectedOptionTexts', 'optionCount', 'optionsHash'
    ], limit),
    compareCollection('labels', baseline.labels, candidate.labels, [
      'text', 'visibleText', 'pseudoBefore', 'pseudoAfter', 'kind', 'controlName', 'controlType',
      'choiceValuePresent', 'choiceValueLength', 'choiceValueClassification', 'visible'
    ], limit),
    compareCollection('links', baseline.links, candidate.links, [
      'text', 'visibleText', 'ariaLabel', 'href', 'target', 'rel', 'visible'
    ], limit),
    compareCollection('headings', baseline.headings, candidate.headings, [
      'level', 'text', 'visibleText', 'visible'
    ], limit),
    compareCollection('forms', baseline.forms, candidate.forms, [
      'methodAttribute', 'method', 'actionAttribute', 'action', 'enctypeAttribute', 'enctype', 'targetAttribute', 'controlCount'
    ], limit),
    compareCollection('accessibility', baseline.accessibility, candidate.accessibility, [
      'role', 'name', 'properties'
    ], limit)
  ];
  const allCritical = criticalSemanticFindings(categories, Number.POSITIVE_INFINITY);
  const captureIntegrity = {
    baseline: baseline.nativeApiTampering,
    candidate: candidate.nativeApiTampering,
    valid: baseline.nativeApiTampering.length === 0 && candidate.nativeApiTampering.length === 0
  };
  return {
    mismatchCount: categories.reduce((total, category) => total + category.mismatchCount, 0),
    criticalMismatchCount: allCritical.length,
    critical: allCritical.slice(0, limit),
    captureIntegrity,
    categories,
    snapshots: {
      baseline: compactSnapshot(baseline),
      candidate: compactSnapshot(candidate)
    }
  };
}

function criticalSemanticFindings(categories, limit) {
  const importantProperties = new Set([
    'required', 'ariaRequired', 'disabled', 'readOnly', 'multiple', 'hiddenAttribute',
    'ariaHidden', 'tabIndex', 'visible', 'checked', 'choiceValuePresent', 'choiceValueLength',
    'choiceValueClassification', 'valuePresent', 'valueLength',
    'valueClassification', 'accept',
    'accessibleName', 'labelText', 'labelVisibleText', 'labelPseudoBefore',
    'labelPseudoAfter', 'questionText', 'questionVisibleText', 'questionPseudoBefore',
    'questionPseudoAfter', 'selectedOptionTexts', 'optionCount', 'optionsHash', 'options',
    'text', 'visibleText', 'pseudoBefore', 'pseudoAfter', 'controlName', 'controlType',
    'href', 'target', 'rel', 'level', 'method', 'action', 'enctype', 'controlCount',
    'hiddenValuePresent', 'hiddenValueLength'
  ]);
  const findings = [];
  for (const category of categories) {
    if (category.kind === 'accessibility') continue;
    for (const change of category.changed) {
      const changes = Object.fromEntries(Object.entries(change.changes).filter(([property]) => importantProperties.has(property)));
      if (Object.keys(changes).length) findings.push({ category: category.kind, key: change.key, changes });
      if (findings.length >= limit) return findings;
    }
    for (const missing of category.missing) {
      findings.push({ category: category.kind, key: missing.key, missing: true, baseline: missing.baseline });
      if (findings.length >= limit) return findings;
    }
    for (const extra of category.extra) {
      findings.push({ category: category.kind, key: extra.key, extra: true, candidate: extra.candidate });
      if (findings.length >= limit) return findings;
    }
  }
  return findings;
}

function compactSnapshot(snapshot) {
  return {
    controls: snapshot.controls.map(compactRecord),
    labels: snapshot.labels,
    links: snapshot.links,
    headings: snapshot.headings,
    forms: snapshot.forms,
    accessibility: snapshot.accessibility,
    nativeApiTampering: snapshot.nativeApiTampering || []
  };
}

function paddedPng(PNG, source, width, height, padding = [1, 2, 3, 255]) {
  const output = new PNG({ width, height });
  for (let index = 0; index < output.data.length; index += 4) {
    output.data[index] = padding[0];
    output.data[index + 1] = padding[1];
    output.data[index + 2] = padding[2];
    output.data[index + 3] = padding[3];
  }
  const rowBytes = source.width * 4;
  for (let y = 0; y < source.height; y += 1) {
    source.data.copy(output.data, y * width * 4, y * source.width * 4, y * source.width * 4 + rowBytes);
  }
  return output;
}

function paintMasks(png, rectangles, color = [255, 0, 255, 255]) {
  const bitmap = new Uint8Array(png.width * png.height);
  for (const rectangle of rectangles) {
    const x0 = Math.max(0, Math.floor(rectangle.x));
    const y0 = Math.max(0, Math.floor(rectangle.y));
    const x1 = Math.min(png.width, Math.ceil(rectangle.x + rectangle.width));
    const y1 = Math.min(png.height, Math.ceil(rectangle.y + rectangle.height));
    for (let y = y0; y < y1; y += 1) {
      for (let x = x0; x < x1; x += 1) {
        const pixel = y * png.width + x;
        const offset = pixel * 4;
        bitmap[pixel] = 1;
        png.data[offset] = color[0];
        png.data[offset + 1] = color[1];
        png.data[offset + 2] = color[2];
        png.data[offset + 3] = color[3];
      }
    }
  }
  return bitmap;
}

function changedBoundingBox(diff) {
  let minX = diff.width;
  let minY = diff.height;
  let maxX = -1;
  let maxY = -1;
  for (let y = 0; y < diff.height; y += 1) {
    for (let x = 0; x < diff.width; x += 1) {
      if (diff.data[(y * diff.width + x) * 4 + 3] === 0) continue;
      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x);
      maxY = Math.max(maxY, y);
    }
  }
  return maxX < 0 ? null : { x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1 };
}

function compareMaskGeometry(baseline, candidate) {
  const changes = [];
  const right = new Map(candidate.map((item) => [item.selector, item]));
  for (const left of baseline) {
    const match = right.get(left.selector);
    if (!match || JSON.stringify(left.rectangles) !== JSON.stringify(match.rectangles)) {
      changes.push({ selector: left.selector, baseline: left.rectangles, candidate: match?.rectangles || null });
    }
  }
  return changes;
}

async function comparePixels(PNG, pixelmatch, baselineCapture, candidateCapture, directory, options) {
  const baselineOriginal = PNG.sync.read(await fs.readFile(baselineCapture.screenshotPath));
  const candidateOriginal = PNG.sync.read(await fs.readFile(candidateCapture.screenshotPath));
  const width = Math.max(baselineOriginal.width, candidateOriginal.width);
  const height = Math.max(baselineOriginal.height, candidateOriginal.height);
  const baseline = paddedPng(PNG, baselineOriginal, width, height);
  const candidate = paddedPng(PNG, candidateOriginal, width, height);
  const baselineMask = paintMasks(baseline, baselineCapture.masks);
  const candidateMask = paintMasks(candidate, candidateCapture.masks);

  let maskedOnBoth = 0;
  let maskedOnEither = 0;
  for (let index = 0; index < baselineMask.length; index += 1) {
    if (baselineMask[index] && candidateMask[index]) maskedOnBoth += 1;
    if (baselineMask[index] || candidateMask[index]) maskedOnEither += 1;
  }
  const comparablePixels = Math.max(1, width * height - maskedOnBoth);

  const strictDiff = new PNG({ width, height });
  let strictChangedPixels = 0;
  for (let pixel = 0; pixel < width * height; pixel += 1) {
    if (baselineMask[pixel] && candidateMask[pixel]) continue;
    const offset = pixel * 4;
    const changed = baseline.data[offset] !== candidate.data[offset]
      || baseline.data[offset + 1] !== candidate.data[offset + 1]
      || baseline.data[offset + 2] !== candidate.data[offset + 2]
      || baseline.data[offset + 3] !== candidate.data[offset + 3];
    if (!changed) continue;
    strictChangedPixels += 1;
    strictDiff.data[offset] = 255;
    strictDiff.data[offset + 1] = 0;
    strictDiff.data[offset + 2] = 0;
    strictDiff.data[offset + 3] = 255;
  }

  const tolerantDiff = new PNG({ width, height });
  const tolerantChangedPixels = pixelmatch(
    baseline.data,
    candidate.data,
    tolerantDiff.data,
    width,
    height,
    {
      threshold: options.pixelThreshold,
      includeAA: false,
      diffColor: [255, 0, 0],
      aaColor: [255, 196, 0],
      diffMask: true
    }
  );

  const overlay = new PNG({ width, height });
  for (let index = 0; index < overlay.data.length; index += 4) {
    overlay.data[index] = Math.round((baseline.data[index] + candidate.data[index]) / 2);
    overlay.data[index + 1] = Math.round((baseline.data[index + 1] + candidate.data[index + 1]) / 2);
    overlay.data[index + 2] = Math.round((baseline.data[index + 2] + candidate.data[index + 2]) / 2);
    overlay.data[index + 3] = 255;
  }

  const maskImage = new PNG({ width, height });
  for (let pixel = 0; pixel < width * height; pixel += 1) {
    const offset = pixel * 4;
    if (!baselineMask[pixel] && !candidateMask[pixel]) continue;
    const both = baselineMask[pixel] && candidateMask[pixel];
    maskImage.data[offset] = both ? 0 : 255;
    maskImage.data[offset + 1] = both ? 180 : 120;
    maskImage.data[offset + 2] = both ? 255 : 0;
    maskImage.data[offset + 3] = 220;
  }

  await Promise.all([
    fs.writeFile(join(directory, 'strict-diff.png'), PNG.sync.write(strictDiff)),
    fs.writeFile(join(directory, 'diff.png'), PNG.sync.write(tolerantDiff)),
    fs.writeFile(join(directory, 'overlay.png'), PNG.sync.write(overlay)),
    fs.writeFile(join(directory, 'mask.png'), PNG.sync.write(maskImage))
  ]);

  return {
    canvas: { width, height },
    baselineDimensions: { width: baselineOriginal.width, height: baselineOriginal.height },
    candidateDimensions: { width: candidateOriginal.width, height: candidateOriginal.height },
    dimensionsMatch: baselineOriginal.width === candidateOriginal.width && baselineOriginal.height === candidateOriginal.height,
    comparablePixels,
    strictChangedPixels,
    strictDiffPercent: strictChangedPixels / comparablePixels * 100,
    tolerantChangedPixels,
    tolerantDiffPercent: tolerantChangedPixels / comparablePixels * 100,
    tolerantBoundingBox: changedBoundingBox(tolerantDiff),
    pixelThreshold: options.pixelThreshold,
    maskedOnBothPixels: maskedOnBoth,
    maskedOnEitherPixels: maskedOnEither,
    maskPercent: maskedOnEither / (width * height) * 100,
    maskGeometryChanges: compareMaskGeometry(baselineCapture.maskGeometry, candidateCapture.maskGeometry)
  };
}

const escapeHtml = (value) => String(value ?? '')
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;');

function mismatchPreview(semantic) {
  const rows = [];
  for (const category of semantic.categories) {
    for (const item of category.changed.slice(0, 20)) {
      rows.push(`<tr><td>${escapeHtml(category.kind)}</td><td><code>${escapeHtml(item.key)}</code></td><td><pre>${escapeHtml(JSON.stringify(item.changes, null, 2))}</pre></td></tr>`);
    }
    for (const item of category.missing.slice(0, 10)) {
      rows.push(`<tr><td>${escapeHtml(category.kind)}</td><td><code>${escapeHtml(item.key)}</code></td><td>Missing from candidate</td></tr>`);
    }
    for (const item of category.extra.slice(0, 10)) {
      rows.push(`<tr><td>${escapeHtml(category.kind)}</td><td><code>${escapeHtml(item.key)}</code></td><td>Extra in candidate</td></tr>`);
    }
  }
  return rows.length ? rows.join('\n') : '<tr><td colspan="3">No semantic mismatches.</td></tr>';
}

function renderHtml(summary) {
  const sections = summary.results.map((result) => {
    const pixel = result.pixel;
    return `<section>
      <h2>${escapeHtml(result.viewport.name)} — ${result.viewport.width}×${result.viewport.height}</h2>
      <div class="metrics">
        <div><strong>Dimensions</strong><span>${pixel.baselineDimensions.width}×${pixel.baselineDimensions.height} → ${pixel.candidateDimensions.width}×${pixel.candidateDimensions.height}</span></div>
        <div><strong>Strict diff</strong><span>${pixel.strictDiffPercent.toFixed(4)}%</span></div>
        <div><strong>Tolerant diff</strong><span>${pixel.tolerantDiffPercent.toFixed(4)}%</span></div>
        <div><strong>Semantic mismatches</strong><span>${result.semantic.mismatchCount}</span></div>
        <div><strong>Critical semantic findings</strong><span>${result.semantic.criticalMismatchCount}</span></div>
        <div><strong>Stable</strong><span>${result.baseline.stability.stable && result.candidate.stability.stable ? 'yes' : 'no'}</span></div>
        <div><strong>Masked</strong><span>${pixel.maskPercent.toFixed(4)}%</span></div>
      </div>
      <div class="images">
        <figure><figcaption>Baseline</figcaption><img src="${escapeHtml(result.viewport.name)}/baseline.png"></figure>
        <figure><figcaption>Candidate</figcaption><img src="${escapeHtml(result.viewport.name)}/candidate.png"></figure>
        <figure><figcaption>Tolerant diff</figcaption><img class="checker" src="${escapeHtml(result.viewport.name)}/diff.png"></figure>
        <figure><figcaption>50/50 overlay</figcaption><img src="${escapeHtml(result.viewport.name)}/overlay.png"></figure>
      </div>
      <details open><summary>Semantic differences</summary>
        <table><thead><tr><th>Category</th><th>Key</th><th>Difference</th></tr></thead><tbody>${mismatchPreview(result.semantic)}</tbody></table>
      </details>
      <details><summary>Capture warnings and telemetry</summary><pre>${escapeHtml(JSON.stringify({ baseline: { warnings: result.baseline.warnings, telemetry: result.baseline.telemetry }, candidate: { warnings: result.candidate.warnings, telemetry: result.candidate.telemetry } }, null, 2))}</pre></details>
    </section>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Webpage fidelity report</title>
<style>
  :root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#172033;background:#f5f7fb}body{max-width:1500px;margin:auto;padding:24px}h1,h2{letter-spacing:-.02em}code,pre{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}.summary,section{background:#fff;border:1px solid #dce2ec;border-radius:12px;padding:20px;margin:18px 0;box-shadow:0 8px 30px #1720330b}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}.metrics div{display:grid;gap:3px;padding:12px;background:#f7f9fc;border-radius:8px}.metrics span{font-variant-numeric:tabular-nums}.images{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:18px 0}figure{margin:0}figcaption{font-weight:700;margin:0 0 6px}img{display:block;width:100%;height:auto;border:1px solid #dce2ec;background:#fff}.checker{background:repeating-conic-gradient(#eee 0 25%,#fff 0 50%) 0/18px 18px}table{border-collapse:collapse;width:100%;table-layout:fixed}th,td{border-top:1px solid #e6eaf0;padding:8px;text-align:left;vertical-align:top}th:first-child{width:110px}th:nth-child(2){width:32%}details{margin-top:16px}summary{cursor:pointer;font-weight:700}@media(max-width:800px){.images{grid-template-columns:1fr}body{padding:12px}}
</style></head><body>
<h1>Webpage fidelity report</h1>
<div class="summary"><p><strong>Baseline:</strong> ${escapeHtml(summary.baseline)}</p><p><strong>Candidate:</strong> ${escapeHtml(summary.candidate)}</p><p>Generated ${escapeHtml(summary.generatedAt)} with ${escapeHtml(summary.browserVersion)}. Baseline writes were blocked; candidate writes were ${summary.options.allowNonGet ? 'allowed' : 'blocked'}.</p></div>
${sections}
</body></html>`;
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    console.error(usage());
    process.exitCode = 1;
    return;
  }
  if (options.help) {
    console.log(usage());
    return;
  }
  const { chromium, pixelmatch, PNG } = await loadDependencies();
  await fs.mkdir(options.out, { recursive: true });
  const launchOptions = {
    headless: !options.headed,
    chromiumSandbox: true,
    args: [
      '--disable-gpu',
      '--disable-quic',
      '--disable-webrtc',
      '--disable-features=WebTransport',
      '--force-color-profile=srgb',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--webrtc-ip-handling-policy=disable_non_proxied_udp'
    ]
  };
  const chromiumExecutable = await findChromiumExecutable(chromium);
  if (chromiumExecutable) launchOptions.executablePath = chromiumExecutable;
  const browser = await chromium.launch(launchOptions);
  const browserVersion = await browser.version();
  const results = [];

  try {
    for (const viewport of options.viewports) {
      const directory = join(options.out, viewport.name);
      await fs.mkdir(directory, { recursive: true });
      console.log(`[${viewport.name}] capturing baseline`);
      const baseline = await captureSide(browser, 'baseline', options.baseline, viewport, directory, options);
      console.log(`[${viewport.name}] capturing candidate`);
      const candidate = await captureSide(browser, 'candidate', options.candidate, viewport, directory, options);
      const pixel = await comparePixels(PNG, pixelmatch, baseline, candidate, directory, options);
      const semantic = compareSemantics(baseline.semantic, candidate.semantic, options.semanticLimit);
      results.push({ viewport, baseline: compactCapture(baseline), candidate: compactCapture(candidate), pixel, semantic });
      console.log(`[${viewport.name}] tolerant diff ${pixel.tolerantDiffPercent.toFixed(4)}%; semantic mismatches ${semantic.mismatchCount}`);
    }
  } finally {
    await browser.close();
  }

  const summary = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    baseline: options.baseline,
    candidate: options.candidate,
    browserVersion,
    chromiumExecutable,
    options: {
      viewports: options.viewports,
      readySelector: options.readySelector,
      baselineReadySelector: options.baselineReadySelector,
      candidateReadySelector: options.candidateReadySelector,
      waitMs: options.waitMs,
      timeoutMs: options.timeoutMs,
      pixelThreshold: options.pixelThreshold,
      masks: options.masks,
      maskRects: options.maskRects,
      autoScroll: options.autoScroll,
      allowNonGet: options.allowNonGet,
      maxDiffPercent: options.maxDiffPercent,
      maxSemanticMismatches: options.maxSemanticMismatches
    },
    results
  };
  const persistedSummary = redactReportData(summary);
  await Promise.all([
    fs.writeFile(join(options.out, 'summary.json'), `${JSON.stringify(persistedSummary, null, 2)}\n`),
    fs.writeFile(join(options.out, 'index.html'), renderHtml(persistedSummary))
  ]);

  console.log(`Report: ${join(options.out, 'index.html')}`);
  printTopSemanticFindings(persistedSummary.results);

  const failedDiff = options.maxDiffPercent !== null && results.some((result) => result.pixel.tolerantDiffPercent > options.maxDiffPercent);
  const failedSemantic = options.maxSemanticMismatches !== null && results.some((result) => result.semantic.mismatchCount > options.maxSemanticMismatches);
  const failedCaptureIntegrity = results.some((result) => result.semantic.captureIntegrity.valid !== true);
  if (failedDiff || failedSemantic || failedCaptureIntegrity) process.exitCode = 2;
}

function compactCapture(capture) {
  return {
    side: capture.side,
    url: capture.url,
    httpStatus: capture.httpStatus,
    layout: capture.layout,
    maskGeometry: capture.maskGeometry,
    stability: capture.stability,
    telemetry: capture.telemetry,
    warnings: capture.warnings
  };
}

function printTopSemanticFindings(results) {
  for (const result of results) {
    const findings = result.semantic.critical.slice(0, 10);
    if (!findings.length) continue;
    console.log(`[${result.viewport.name}] first critical semantic findings:`);
    for (const finding of findings) console.log(`  - ${finding.category} ${finding.key}: ${JSON.stringify(finding.changes || { missing: finding.missing, extra: finding.extra })}`);
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
