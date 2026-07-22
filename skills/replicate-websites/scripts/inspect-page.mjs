#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { promises as fs } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  assertSafeHttpUrl,
  blocksUnsafeDestinationBeforeProxy,
  credentialLikeUrlIssue,
  isLoopbackHostname,
  redactReportData,
  redactSensitiveUrl
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
const bundledStarterAppPath = resolve(skillDirectory, 'assets/replica-starter/public/app.js');
const scriptResponseLimit = 100;
const scriptBodyByteLimit = 256 * 1024;
const scriptTotalBodyByteLimit = 2 * 1024 * 1024;
const stylesheetResponseLimit = 300;
const stylesheetBodyByteLimit = 1024 * 1024;
const stylesheetTotalBodyByteLimit = 8 * 1024 * 1024;
const executableStyleRequestLimit = 600;
const executableStyleQuietWindowMs = 150;
const responseBodyReadTimeoutMs = 2000;
const delayedPersistenceSampleMs = 500;
const mediaPersistenceSampleMs = 40;
const publicDisclosureMediaVariants = Object.freeze([
  { name: 'light-reduce-dpr1', colorScheme: 'light', reducedMotion: 'reduce', deviceScaleFactor: 1 },
  { name: 'dark-reduce-dpr1', colorScheme: 'dark', reducedMotion: 'reduce', deviceScaleFactor: 1 },
  { name: 'light-no-preference-dpr1', colorScheme: 'light', reducedMotion: 'no-preference', deviceScaleFactor: 1 },
  { name: 'dark-no-preference-dpr1', colorScheme: 'dark', reducedMotion: 'no-preference', deviceScaleFactor: 1 },
  { name: 'light-reduce-dpr2', colorScheme: 'light', reducedMotion: 'reduce', deviceScaleFactor: 2 },
  { name: 'dark-reduce-dpr2', colorScheme: 'dark', reducedMotion: 'reduce', deviceScaleFactor: 2 },
  { name: 'light-no-preference-dpr2', colorScheme: 'light', reducedMotion: 'no-preference', deviceScaleFactor: 2 },
  { name: 'dark-no-preference-dpr2', colorScheme: 'dark', reducedMotion: 'no-preference', deviceScaleFactor: 2 }
]);
const defaultViewports = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 390, height: 844 },
  { name: 'compact', width: 360, height: 800 }
];

function usage() {
  return `Capture a read-only rendered-page contract.

Usage:
  node inspect-page.mjs --url URL --out DIR [options]

Options:
  --viewport NAME:WIDTHxHEIGHT  Repeat to replace desktop/mobile defaults
  --ready-selector SELECTOR     Wait for a stable rendered marker
  --wait-ms N                   Extra settle delay (default: 750)
  --timeout-ms N                Navigation timeout (default: 30000)
  --max-elements N              Maximum visible element records (default: 6000)
  --no-auto-scroll              Disable lazy-content pre-scroll
  --headed                      Show Chromium
  --help                        Show this message
`;
}

function parseInteger(value, option, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${option} expects an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

function parseViewport(value) {
  const match = String(value).match(/^([a-z0-9_-]+)[:=](\d+)x(\d+)$/i);
  if (!match) throw new Error(`Invalid viewport "${value}". Use NAME:WIDTHxHEIGHT.`);
  return {
    name: match[1].toLowerCase(),
    width: parseInteger(match[2], '--viewport width', 1, 10000),
    height: parseInteger(match[3], '--viewport height', 1, 10000)
  };
}

function parseArguments(argv) {
  const options = {
    url: null,
    out: null,
    viewports: [],
    readySelector: null,
    waitMs: 750,
    timeoutMs: 30000,
    maxElements: 6000,
    autoScroll: true,
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
      case '--url': options.url = take(index, argument); index += 1; break;
      case '--out': options.out = take(index, argument); index += 1; break;
      case '--viewport': options.viewports.push(parseViewport(take(index, argument))); index += 1; break;
      case '--ready-selector': options.readySelector = take(index, argument); index += 1; break;
      case '--wait-ms': options.waitMs = parseInteger(take(index, argument), argument, 0, 60000); index += 1; break;
      case '--timeout-ms': options.timeoutMs = parseInteger(take(index, argument), argument, 1000, 180000); index += 1; break;
      case '--max-elements': options.maxElements = parseInteger(take(index, argument), argument, 1, 50000); index += 1; break;
      case '--no-auto-scroll': options.autoScroll = false; break;
      case '--headed': options.headed = true; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (options.help) return options;
  if (!options.url || !options.out) throw new Error('--url and --out are required.');
  assertSafeHttpUrl(options.url, '--url');
  options.out = resolve(options.out);
  options.viewports = options.viewports.length ? options.viewports : defaultViewports;
  if (new Set(options.viewports.map((viewport) => viewport.name)).size !== options.viewports.length) {
    throw new Error('--viewport names must be unique.');
  }
  return options;
}

const cspHeaderLengthLimit = 16 * 1024;
const selectedCspDirectives = new Map([
  ['script-src', 'scriptSrc'],
  ['script-src-elem', 'scriptSrcElem'],
  ['script-src-attr', 'scriptSrcAttr'],
  ['connect-src', 'connectSrc'],
  ['form-action', 'formAction'],
  ['object-src', 'objectSrc'],
  ['frame-ancestors', 'frameAncestors']
]);

function cspSourceMode(tokens) {
  const normalized = tokens.map((token) => String(token).trim().toLowerCase()).filter(Boolean);
  if (normalized.length !== 1) return 'other';
  if (normalized[0] === "'none'") return 'none';
  if (normalized[0] === "'self'") return 'self';
  return 'other';
}

function summarizeCspPolicy(rawPolicy) {
  const summary = Object.fromEntries([...selectedCspDirectives.values()].map((name) => [name, {
    present: false,
    duplicate: false,
    mode: 'missing'
  }]));
  const counts = new Map();
  for (const segment of String(rawPolicy || '').split(';')) {
    const parts = segment.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) continue;
    const selectedName = selectedCspDirectives.get(parts[0].toLowerCase());
    if (!selectedName) continue;
    const count = (counts.get(selectedName) || 0) + 1;
    counts.set(selectedName, count);
    summary[selectedName] = {
      present: true,
      duplicate: count > 1,
      mode: count > 1 ? 'other' : cspSourceMode(parts.slice(1))
    };
  }
  return summary;
}

function summarizeMainResponseSecurityHeaders(response) {
  const headers = response.headers();
  const csp = String(headers['content-security-policy'] || '');
  const cspOverLimit = csp.length > cspHeaderLengthLimit;
  const xFrameOptions = String(headers['x-frame-options'] || '').trim().toLowerCase();
  const refresh = String(headers.refresh || '');
  return {
    contentSecurityPolicy: {
      present: Boolean(csp),
      length: csp.length,
      overLimit: cspOverLimit,
      policies: !csp || cspOverLimit
        ? []
        : csp.split(',').map(summarizeCspPolicy).slice(0, 20),
      policyLimitReached: !cspOverLimit && csp.split(',').length > 20
    },
    xFrameOptions: {
      present: Boolean(xFrameOptions),
      disposition: xFrameOptions === 'deny'
        ? 'deny'
        : xFrameOptions === 'sameorigin' ? 'sameorigin' : xFrameOptions ? 'other' : 'missing'
    },
    refresh: {
      present: Boolean(refresh),
      length: refresh.length,
      hasUrlDirective: /(?:^|;)\s*url\s*=/i.test(refresh)
    }
  };
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
  try {
    return createRequire(import.meta.url).resolve(name);
  } catch {
    // Search the skill, caller, then the bundled Codex runtime.
  }
  for (const root of packageSearchRoots()) {
    try {
      return createRequire(join(root, '__replica_inspector_resolver.cjs')).resolve(name);
    } catch {
      // Continue.
    }
  }
  throw new Error(`Cannot resolve ${name}. Run npm install in the skill repository.`);
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
      : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  for (const candidate of candidates) {
    const found = await existingFile(candidate);
    if (found) return found;
  }
  return null;
}

async function settlePage(page, options, warnings) {
  try {
    await page.waitForLoadState('networkidle', { timeout: Math.min(options.timeoutMs, 8000) });
  } catch {
    warnings.push('networkidle timed out; explicit settling continued');
  }
  if (options.readySelector) {
    await page.locator(options.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
  }
  await page.addStyleTag({ content: `
    *, *::before, *::after {
      animation-delay: 0s !important;
      animation-duration: 0s !important;
      animation-iteration-count: 1 !important;
      caret-color: transparent !important;
      scroll-behavior: auto !important;
      transition-delay: 0s !important;
      transition-duration: 0s !important;
    }
  ` });
  await page.evaluate(async () => {
    const activeElements = [];
    const shadowRoots = [];
    const collect = (root) => {
      for (const element of root.querySelectorAll('*')) {
        activeElements.push(element);
        if (element.shadowRoot) {
          shadowRoots.push(element.shadowRoot);
          collect(element.shadowRoot);
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
    for (const media of activeElements.filter((element) => element.matches('video, audio'))) media.pause?.();
    if (document.fonts?.ready) {
      await Promise.race([document.fonts.ready, new Promise((resolveWait) => setTimeout(resolveWait, 5000))]);
    }
    await Promise.race([
      Promise.all(activeElements.filter((element) => element.matches('img'))
        .map((image) => image.decode?.().catch(() => {}) || Promise.resolve())),
      new Promise((resolveWait) => setTimeout(resolveWait, 5000))
    ]);
  });
  if (options.autoScroll) {
    await page.evaluate(async () => {
      const maximum = Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0);
      const step = Math.max(400, Math.floor(innerHeight * 0.8));
      let steps = 0;
      for (let y = 0; y < maximum && steps < 500; y += step, steps += 1) {
        scrollTo(0, y);
        await new Promise((resolveScroll) => setTimeout(resolveScroll, 16));
      }
      scrollTo(0, 0);
    });
  }
  if (options.waitMs) await page.waitForTimeout(options.waitMs);
  await page.evaluate(async () => {
    const activeElements = [];
    const shadowRoots = [];
    const collect = (root) => {
      for (const element of root.querySelectorAll('*')) {
        activeElements.push(element);
        if (element.shadowRoot) {
          shadowRoots.push(element.shadowRoot);
          collect(element.shadowRoot);
        }
      }
    };
    collect(document);
    const freezeCss = '*,*::before,*::after{animation-delay:0s!important;animation-duration:0s!important;animation-iteration-count:1!important;caret-color:transparent!important;scroll-behavior:auto!important;transition-delay:0s!important;transition-duration:0s!important}';
    for (const root of shadowRoots) {
      if (!root.querySelector('style[data-replica-capture-freeze]')) {
        const style = document.createElement('style');
        style.setAttribute('data-replica-capture-freeze', '');
        style.textContent = freezeCss;
        root.append(style);
      }
    }
    for (const root of [document, ...shadowRoots]) {
      for (const animation of root.getAnimations?.({ subtree: true }) || []) animation.finish?.();
    }
    for (const media of activeElements.filter((element) => element.matches('video, audio'))) media.pause?.();
    await Promise.race([
      Promise.all(activeElements.filter((element) => element.matches('img'))
        .map((image) => image.decode?.().catch(() => {}) || Promise.resolve())),
      new Promise((resolveWait) => setTimeout(resolveWait, 5000))
    ]);
  });
}

function publicResourceDescriptor(rawUrl, allowedOrigin) {
  try {
    const parsed = new URL(rawUrl);
    const persistedUrl = credentialLikeUrlIssue(parsed.href)
      ? redactSensitiveUrl(parsed.href)
      : parsed.href;
    const persisted = new URL(persistedUrl);
    return {
      url: persisted.href,
      sameOrigin: parsed.origin === allowedOrigin,
      pathname: persisted.pathname,
      searchPresent: Boolean(parsed.search),
      hashPresent: Boolean(parsed.hash)
    };
  } catch {
    return {
      url: '[malformed URL omitted]',
      sameOrigin: false,
      pathname: '',
      searchPresent: false,
      hashPresent: false
    };
  }
}

function createExecutableStyleRequestTracker(page, allowedOrigin) {
  const active = new Map();
  const started = { script: 0, stylesheet: 0 };
  const finished = { script: 0, stylesheet: 0 };
  const failed = { script: 0, stylesheet: 0 };
  const retainedFailures = [];
  let recordsTruncated = false;
  let lastActivityAt = Date.now();
  const relevantKind = (request) => {
    const kind = request.resourceType();
    return kind === 'script' || kind === 'stylesheet' ? kind : null;
  };
  page.on('request', (request) => {
    const kind = relevantKind(request);
    if (!kind) return;
    started[kind] += 1;
    active.set(request, {
      kind,
      ...publicResourceDescriptor(request.url(), allowedOrigin)
    });
    lastActivityAt = Date.now();
  });
  page.on('requestfinished', (request) => {
    const entry = active.get(request);
    if (!entry) return;
    active.delete(request);
    finished[entry.kind] += 1;
    lastActivityAt = Date.now();
  });
  page.on('requestfailed', (request) => {
    const entry = active.get(request);
    if (!entry) return;
    active.delete(request);
    failed[entry.kind] += 1;
    if (retainedFailures.length < executableStyleRequestLimit) {
      retainedFailures.push({
        ...entry,
        error: String(request.failure()?.errorText || '').slice(0, 240)
      });
    } else {
      recordsTruncated = true;
    }
    lastActivityAt = Date.now();
  });
  return {
    active,
    get lastActivityAt() { return lastActivityAt; },
    snapshot() {
      const pending = [...active.values()].slice(0, executableStyleRequestLimit);
      return {
        quietWindowMs: executableStyleQuietWindowMs,
        started: { ...started },
        finished: { ...finished },
        failed: { ...failed },
        pendingCount: active.size,
        pending,
        failures: retainedFailures,
        recordsTruncated: recordsTruncated || active.size > pending.length,
        quietForMs: Math.max(0, Date.now() - lastActivityAt)
      };
    }
  };
}

async function waitForExecutableStyleQuiescence(page, tracker, timeoutMs) {
  const startedAt = Date.now();
  while (Date.now() - startedAt <= timeoutMs) {
    if (tracker.active.size === 0
      && Date.now() - tracker.lastActivityAt >= executableStyleQuietWindowMs) {
      return { completed: true, waitedMs: Date.now() - startedAt, ...tracker.snapshot() };
    }
    await page.waitForTimeout(25);
  }
  return { completed: false, waitedMs: Date.now() - startedAt, ...tracker.snapshot() };
}

async function captureContract(page, maxElements) {
  return page.evaluate((limit) => {
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
    const pushArray = (value, ...entries) => integrityNatives
      ? integrityNatives.arrayPush(value, ...entries)
      : value.push(...entries);
    const sliceArray = (value, start, end) => integrityNatives
      ? integrityNatives.arraySlice(value, start, end)
      : value.slice(start, end);
    const sortArray = (value, callback) => integrityNatives
      ? integrityNatives.arraySort(value, callback)
      : value.sort(callback);
    const matches = (element, selector) => integrityNatives
      ? integrityNatives.matches(element, selector)
      : element.matches(selector);
    const getRootNode = (node) => integrityNatives
      ? integrityNatives.getRootNode(node)
      : node.getRootNode();
    const shadowRootOf = (element) => integrityNatives
      ? integrityNatives.shadowRoot(element)
      : element.shadowRoot;
    const getAttribute = (element, name) => integrityNatives
      ? integrityNatives.getAttribute(element, name)
      : element.getAttribute(name);
    const getAttributeNS = (element, namespace, name) => integrityNatives
      ? integrityNatives.getAttributeNS(element, namespace, name)
      : element.getAttributeNS(namespace, name);
    const hasAttribute = (element, name) => integrityNatives
      ? integrityNatives.hasAttribute(element, name)
      : element.hasAttribute(name);
    const nativeFormAction = (form) => integrityNatives
      ? integrityNatives.formAction(form)
      : form.action;
    const nativeFormMethod = (form) => integrityNatives
      ? integrityNatives.formMethod(form)
      : form.method;
    const nativeFormEnctype = (form) => integrityNatives
      ? integrityNatives.formEnctype(form)
      : form.enctype;
    const getComputedStyle = (element, pseudo = null) => integrityNatives
      ? integrityNatives.getComputedStyle(element, pseudo)
      : globalThis.getComputedStyle(element, pseudo);
    const boundingRect = (element) => integrityNatives
      ? integrityNatives.getBoundingClientRect(element)
      : element.getBoundingClientRect();
    const performanceEntries = (type) => integrityNatives
      ? integrityNatives.getEntriesByType(type)
      : performance.getEntriesByType(type);
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
    const composedInsideBody = (element) => {
      let current = element;
      while (current && current.nodeType === Node.ELEMENT_NODE) {
        if (current === document.body) return true;
        const root = getRootNode(current);
        current = current.parentElement || (root instanceof ShadowRoot ? root.host : null);
      }
      return false;
    };
    const round = (value) => Math.round(Number(value || 0) * 1000) / 1000;
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
            : sliceArray(tokens, 0, 4);
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
    const renderedRect = (element, suppliedRect = null) => {
      if (!element) return null;
      const rect = suppliedRect || boundingRect(element);
      if (rect.width <= 0 || rect.height <= 0) return null;
      let horizontal = { start: rect.left, end: rect.right };
      let vertical = { start: rect.top, end: rect.bottom };
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
          || hasZeroClip(style, currentRect)) return null;
        if (current !== element && ![document.documentElement, document.body].includes(current)) {
          if (['hidden', 'clip'].includes(style.overflowX)) horizontal = intersectAxis(horizontal, currentRect.left, currentRect.right);
          if (['hidden', 'clip'].includes(style.overflowY)) vertical = intersectAxis(vertical, currentRect.top, currentRect.bottom);
          if (horizontal.end <= horizontal.start || vertical.end <= vertical.start) return null;
        }
        const root = getRootNode(current);
        current = current.parentElement || (root instanceof ShadowRoot ? root.host : null);
      }
      return {
        x: horizontal.start,
        y: vertical.start,
        left: horizontal.start,
        top: vertical.start,
        right: horizontal.end,
        bottom: vertical.end,
        width: horizontal.end - horizontal.start,
        height: vertical.end - vertical.start
      };
    };
    const rendered = (element, suppliedRect = null) => Boolean(renderedRect(element, suppliedRect));
    const visible = (element) => {
      if (!rendered(element)) return false;
      const style = getComputedStyle(element);
      if (Number.parseFloat(style.fontSize || '0') <= 0.01) return false;
      if (numericAlpha(style.color) <= 0.001 || numericAlpha(style.webkitTextFillColor) <= 0.001) return false;
      return true;
    };
    const extractCssUrls = (backgroundImage) => {
      const urls = [];
      const pattern = /url\(\s*(?:(["'])(.*?)\1|([^)]*?))\s*\)/gi;
      for (const match of String(backgroundImage || '').matchAll(pattern)) {
        const value = clean(match[2] ?? match[3] ?? '');
        if (value) pushArray(urls, value);
      }
      const css = String(backgroundImage || '');
      const functionPattern = /(?:-webkit-)?image-set\(/gi;
      for (const functionMatch of css.matchAll(functionPattern)) {
        const bodyStart = functionMatch.index + functionMatch[0].length;
        let depth = 1;
        let quote = '';
        let escaped = false;
        let bodyEnd = css.length;
        for (let index = bodyStart; index < css.length; index += 1) {
          const character = css[index];
          if (quote) {
            if (escaped) escaped = false;
            else if (character === '\\') escaped = true;
            else if (character === quote) quote = '';
            continue;
          }
          if (character === '"' || character === "'") quote = character;
          else if (character === '(') depth += 1;
          else if (character === ')' && --depth === 0) { bodyEnd = index; break; }
        }
        const body = css.slice(bodyStart, bodyEnd);
        for (const entry of body.matchAll(/(?:^|,)\s*(["'])(.*?)\1/gi)) {
          const value = clean(entry[2]);
          if (value) pushArray(urls, value);
        }
      }
      return [...new Set(urls)];
    };
    const pixelLength = (value) => {
      const match = String(value || '').trim().match(/^(-?(?:\d+\.?\d*|\.\d+))px$/);
      return match ? Number(match[1]) : null;
    };
    const pseudoRect = (element, style) => {
      const owner = boundingRect(element);
      if (!['fixed', 'absolute'].includes(style.position)) return owner;
      let container = owner;
      if (style.position === 'fixed') {
        container = { left: 0, top: 0, right: innerWidth, bottom: innerHeight, width: innerWidth, height: innerHeight };
      } else {
        let containing = element;
        while (containing && containing !== document.documentElement) {
          const containingStyle = getComputedStyle(containing);
          if (containingStyle.position !== 'static' || containingStyle.transform !== 'none') break;
          containing = containing.parentElement;
        }
        container = boundingRect(containing || document.documentElement);
      }
      const left = pixelLength(style.left);
      const right = pixelLength(style.right);
      const top = pixelLength(style.top);
      const bottom = pixelLength(style.bottom);
      const computedWidth = pixelLength(style.width);
      const computedHeight = pixelLength(style.height);
      const width = computedWidth ?? (left !== null && right !== null ? Math.max(0, container.width - left - right) : owner.width);
      const height = computedHeight ?? (top !== null && bottom !== null ? Math.max(0, container.height - top - bottom) : owner.height);
      const x = left !== null ? container.left + left : right !== null ? container.right - right - width : owner.left;
      const y = top !== null ? container.top + top : bottom !== null ? container.bottom - bottom - height : owner.top;
      return { x, y, left: x, top: y, right: x + width, bottom: y + height, width, height };
    };
    const cssPath = (element) => {
      const parts = [];
      let current = element;
      while (current && current.nodeType === Node.ELEMENT_NODE && parts.length < 8) {
        if (current.id) {
          parts.unshift(`#${CSS.escape(current.id)}`);
          break;
        }
        const tag = current.tagName.toLowerCase();
        const siblings = current.parentElement
          ? [...current.parentElement.children].filter((candidate) => candidate.tagName === current.tagName)
          : [];
        const suffix = siblings.length > 1 ? `:nth-of-type(${siblings.indexOf(current) + 1})` : '';
        parts.unshift(`${tag}${suffix}`);
        const root = getRootNode(current);
        if (!current.parentElement && root instanceof ShadowRoot) parts.unshift('::shadow');
        current = current.parentElement || (root instanceof ShadowRoot ? root.host : null);
      }
      return parts.join(' > ');
    };
    const styleRecord = (style) => ({
      display: style.display,
      position: style.position,
      boxSizing: style.boxSizing,
      width: style.width,
      height: style.height,
      minWidth: style.minWidth,
      maxWidth: style.maxWidth,
      minHeight: style.minHeight,
      maxHeight: style.maxHeight,
      margin: style.margin,
      padding: style.padding,
      gap: style.gap,
      overflow: style.overflow,
      fontFamily: style.fontFamily,
      fontSize: style.fontSize,
      fontWeight: style.fontWeight,
      lineHeight: style.lineHeight,
      letterSpacing: style.letterSpacing,
      textAlign: style.textAlign,
      textTransform: style.textTransform,
      color: style.color,
      background: style.background,
      border: style.border,
      borderRadius: style.borderRadius,
      boxShadow: style.boxShadow,
      opacity: style.opacity,
      transform: style.transform,
      zIndex: style.zIndex
    });
    const elements = [];
    const composedElements = filterArray(activeElements, composedInsideBody);
    for (let composedIndex = 0; composedIndex < composedElements.length; composedIndex += 1) {
      const element = composedElements[composedIndex];
      const style = getComputedStyle(element);
      const rect = boundingRect(element);
      if (!rendered(element, rect)) continue;
      const before = getComputedStyle(element, '::before').content;
      const after = getComputedStyle(element, '::after').content;
      pushArray(elements, {
        path: cssPath(element),
        tag: element.tagName.toLowerCase(),
        id: element.id || '',
        classes: [...element.classList],
        role: getAttribute(element, 'role') || '',
        source: element instanceof HTMLImageElement || element instanceof HTMLScriptElement
          ? element.src
          : element instanceof HTMLLinkElement
            ? element.href
            : '',
        text: clean(element.childElementCount ? '' : element.textContent).slice(0, 240),
        rect: {
          x: round(rect.x + scrollX),
          y: round(rect.y + scrollY),
          width: round(rect.width),
          height: round(rect.height)
        },
        pseudo: {
          before: before && !['none', 'normal'].includes(before) ? before : '',
          after: after && !['none', 'normal'].includes(after) ? after : ''
        },
        style: styleRecord(style)
      });
      if (elements.length >= limit) break;
    }
    const valueClassification = (type, value) => {
      if (!value) return 'empty';
      if (type === 'hidden') return value === 'synthetic-local' ? 'synthetic-local' : 'unexpected-nonempty';
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
    const controls = mapArray(queryActive('input, select, textarea, button'), (element, ordinal) => {
      const tag = element.tagName.toLowerCase();
      const type = tag === 'input' || tag === 'button' ? element.type : tag;
      const controlValue = String(element.value || '');
      const hiddenValue = type === 'hidden' ? controlValue : null;
      const supportsFormOverrides = element instanceof HTMLInputElement || element instanceof HTMLButtonElement;
      const formActionAttribute = supportsFormOverrides ? getAttribute(element, 'formaction') : null;
      const formMethodAttribute = supportsFormOverrides ? getAttribute(element, 'formmethod') : null;
      const formEnctypeAttribute = supportsFormOverrides ? getAttribute(element, 'formenctype') : null;
      const formTargetAttribute = supportsFormOverrides ? getAttribute(element, 'formtarget') : null;
      return {
        ordinal,
        path: cssPath(element),
        tag,
        type,
        name: getAttribute(element, 'name') || '',
        id: element.id || '',
        required: Boolean(element.required),
        disabled: Boolean(element.disabled),
        checked: ['checkbox', 'radio'].includes(type) ? Boolean(element.checked) : null,
        visible: visible(element),
        accessibleName: clean(getAttribute(element, 'aria-label')
          || mapArray(toArray(element.labels || []), (label) => label.textContent).join(' ')
          || element.textContent
          || getAttribute(element, 'placeholder')
          || (['button', 'submit'].includes(type) ? element.value : '')),
        placeholder: getAttribute(element, 'placeholder') || '',
        autocomplete: getAttribute(element, 'autocomplete') || '',
        accept: getAttribute(element, 'accept') || '',
        valuePresent: type === 'hidden' ? null : controlValue.length > 0,
        valueLength: type === 'hidden' ? null : controlValue.length,
        valueClassification: type === 'hidden' ? null : valueClassification(type, controlValue),
        value: null,
        hiddenValuePresent: type === 'hidden' ? hiddenValue.length > 0 : null,
        hiddenValueLength: type === 'hidden' ? hiddenValue.length : null,
        hiddenValueClassification: type === 'hidden'
          ? hiddenValue === ''
            ? 'empty'
            : hiddenValue === 'synthetic-local'
              ? 'synthetic-local'
              : 'unexpected-nonempty'
          : null,
        formActionAttribute,
        formAction: formActionAttribute !== null ? (() => {
          try { return new URL(formActionAttribute, location.href).href; } catch { return ''; }
        })() : '',
        formMethodAttribute,
        formMethod: formMethodAttribute !== null ? String(formMethodAttribute).toLowerCase() : '',
        formEnctypeAttribute,
        formEnctype: formEnctypeAttribute !== null ? String(formEnctypeAttribute).toLowerCase() : '',
        formTargetAttribute,
        formTarget: formTargetAttribute !== null ? String(formTargetAttribute) : '',
        options: tag === 'select' ? mapArray(toArray(element.options), (option) => ({
          text: clean(option.textContent),
          valuePresent: String(option.value || '').length > 0,
          valueLength: String(option.value || '').length,
          valueClassification: optionValueClassification(String(option.value || ''), option.textContent),
          disabled: Boolean(option.disabled)
        })) : []
      };
    });
    const rootStyle = getComputedStyle(document.documentElement);
    const cssVariables = {};
    for (const property of rootStyle) {
      if (property.startsWith('--')) cssVariables[property] = rootStyle.getPropertyValue(property).trim();
    }
    const resources = performanceEntries('resource').map((entry) => ({
      name: entry.name,
      initiatorType: entry.initiatorType,
      transferSize: entry.transferSize,
      decodedBodySize: entry.decodedBodySize
    }));
    const documentWidth = Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0);
    const documentHeight = Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0);
    const coverage = (rect, boundsWidth, boundsHeight, offsetX = 0, offsetY = 0) => {
      const left = Math.max(offsetX, rect.left);
      const right = Math.min(offsetX + boundsWidth, rect.right);
      const top = Math.max(offsetY, rect.top);
      const bottom = Math.min(offsetY + boundsHeight, rect.bottom);
      return round(Math.max(0, right - left) * Math.max(0, bottom - top) / Math.max(1, boundsWidth * boundsHeight));
    };
    const rasterSurface = ({ tag, ownerTag, path, src, sources, rect, pseudo = '', cssProperty = '', ...metadata }) => {
      const documentRect = {
        left: rect.left + scrollX,
        right: rect.right + scrollX,
        top: rect.top + scrollY,
        bottom: rect.bottom + scrollY,
        width: rect.width,
        height: rect.height
      };
      return {
        tag,
        ownerTag,
        path,
        pseudo,
        cssProperty,
        src,
        sources,
        rect: {
          x: round(documentRect.left),
          y: round(documentRect.top),
          width: round(documentRect.width),
          height: round(documentRect.height)
        },
        viewportCoverage: coverage(rect, innerWidth, innerHeight),
        documentCoverage: coverage(documentRect, documentWidth, documentHeight),
        ...metadata
      };
    };
    const rasterSurfaces = [];
    const vectorSurfaces = [];
    const absoluteResource = (value) => {
      if (!value) return '';
      try { return new URL(value, document.baseURI).href; } catch { return String(value); }
    };
    const generatedImageMetadata = (value) => {
      const css = String(value || '');
      if (!css || css === 'none' || /url\s*\(/i.test(css)) return null;
      const gradientFunctions = css.match(/(?:repeating-)?(?:linear|radial|conic)-gradient\s*\(/gi) || [];
      const paintFunctions = css.match(/paint\s*\(/gi) || [];
      const crossFadeFunctions = css.match(/cross-fade\s*\(/gi) || [];
      const colorStopEstimate = (css.match(/(?:#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(|\b(?:transparent|black|white|red|green|blue)\b)/gi) || []).length;
      const complex = paintFunctions.length > 0
        || crossFadeFunctions.length > 0
        || gradientFunctions.length >= 2
        || colorStopEstimate >= 16
        || css.length > 512;
      if (!complex) return null;
      return {
        generatedImageKind: paintFunctions.length ? 'paint' : crossFadeFunctions.length ? 'cross-fade' : 'complex-gradient',
        functionCount: gradientFunctions.length + paintFunctions.length + crossFadeFunctions.length,
        colorStopEstimate,
        cssLength: css.length
      };
    };
    const nativeRasterCandidates = queryActive('img, input[type="image"], canvas, video, svg image');
    for (let surfaceIndex = 0; surfaceIndex < nativeRasterCandidates.length; surfaceIndex += 1) {
      const surface = nativeRasterCandidates[surfaceIndex];
      const rect = boundingRect(surface);
      const paintedRect = renderedRect(surface, rect);
      if (!paintedRect) continue;
      let tag = surface.tagName.toLowerCase();
      let sources = [];
      if (surface instanceof HTMLImageElement) {
        sources = [surface.currentSrc, surface.src].filter(Boolean);
      } else if (surface instanceof HTMLInputElement && surface.type === 'image') {
        tag = 'input-image';
        sources = [surface.src, getAttribute(surface, 'src')].filter(Boolean);
      } else if (surface instanceof HTMLVideoElement) {
        sources = [
          surface.currentSrc,
          surface.src,
          surface.poster,
          ...queryAll(surface, 'source[src]').map((source) => source.src || getAttribute(source, 'src'))
        ].filter(Boolean);
      } else if (typeof SVGImageElement !== 'undefined' && surface instanceof SVGImageElement) {
        tag = 'svg-image';
        sources = [absoluteResource(surface.href?.baseVal || getAttribute(surface, 'href') || getAttribute(surface, 'xlink:href'))].filter(Boolean);
      }
      sources = [...new Set(sources.map(absoluteResource).filter(Boolean))];
      const src = sources[0] || '';
      pushArray(rasterSurfaces, rasterSurface({
        tag,
        ownerTag: surface.tagName.toLowerCase(),
        path: cssPath(surface),
        src,
        sources,
        rect: paintedRect
      }));
    }
    const pseudoTargets = ['', '::before', '::after'];
    for (let elementIndex = 0; elementIndex < activeElements.length; elementIndex += 1) {
      const element = activeElements[elementIndex];
      for (let pseudoIndex = 0; pseudoIndex < pseudoTargets.length; pseudoIndex += 1) {
        const pseudo = pseudoTargets[pseudoIndex];
        const style = getComputedStyle(element, pseudo || null);
        if (pseudo && (!style.content || ['none', 'normal'].includes(style.content))) continue;
        if (style.display === 'none'
          || ['hidden', 'collapse'].includes(style.visibility)
          || style.contentVisibility === 'hidden'
          || Number.parseFloat(style.opacity || '1') <= 0.001) continue;
        const rect = pseudo ? pseudoRect(element, style) : boundingRect(element);
        const paintedRect = renderedRect(element, rect);
        if (!paintedRect || hasZeroClip(style, rect)) continue;
        const imageProperties = [
          ['background-image', style.backgroundImage, 'background'],
          ['border-image-source', style.borderImageSource, 'css-image'],
          ['mask-image', style.maskImage, 'css-image'],
          ['-webkit-mask-image', style.webkitMaskImage, 'css-image'],
          ['list-style-image', style.listStyleImage, 'css-image'],
          ...(pseudo ? [['content', style.content, 'css-image']] : [])
        ];
        const seen = new Set();
        for (let propertyIndex = 0; propertyIndex < imageProperties.length; propertyIndex += 1) {
          const [cssProperty, value, tag] = imageProperties[propertyIndex];
          const sources = extractCssUrls(value);
          const generatedImage = sources.length ? null : generatedImageMetadata(value);
          const fingerprint = `${cssProperty}:${JSON.stringify(sources)}`;
          if ((!sources.length && !generatedImage) || seen.has(fingerprint)) continue;
          seen.add(fingerprint);
          pushArray(rasterSurfaces, rasterSurface({
            tag: generatedImage ? 'css-generated-image' : tag,
            ownerTag: element.tagName.toLowerCase(),
            path: cssPath(element),
            pseudo,
            cssProperty,
            src: sources[0],
            sources,
            rect: paintedRect,
            ...generatedImage
          }));
        }
      }
    }
    const svgElements = queryActive('svg');
    for (let index = 0; index < svgElements.length; index += 1) {
      const element = svgElements[index];
      const rect = boundingRect(element);
      const paintedRect = renderedRect(element, rect);
      if (!paintedRect) continue;
      pushArray(vectorSurfaces, rasterSurface({
        tag: 'svg-root',
        ownerTag: 'svg',
        path: cssPath(element),
        src: '',
        sources: [],
        rect: paintedRect
      }));
    }
    const svgResourceElements = queryActive('svg use, svg feImage');
    for (let index = 0; index < svgResourceElements.length; index += 1) {
      const element = svgResourceElements[index];
      const rawReference = getAttribute(element, 'href') || getAttribute(element, 'xlink:href') || '';
      if (!rawReference || rawReference.trim().startsWith('#')) continue;
      const rect = boundingRect(element);
      const paintedRect = renderedRect(element, rect) || rect;
      const source = absoluteResource(rawReference);
      pushArray(vectorSurfaces, rasterSurface({
        tag: element.tagName.toLowerCase() === 'feimage' ? 'svg-feimage-resource' : 'svg-use-resource',
        ownerTag: element.tagName.toLowerCase(),
        path: cssPath(element),
        src: source,
        sources: source ? [source] : [],
        rect: paintedRect
      }));
    }
    for (let index = 0; index < activeElements.length; index += 1) {
      const element = activeElements[index];
      const style = getComputedStyle(element);
      if (!style.filter || style.filter === 'none') continue;
      const rect = boundingRect(element);
      const paintedRect = renderedRect(element, rect);
      if (!paintedRect) continue;
      const filterText = String(style.filter);
      pushArray(vectorSurfaces, rasterSurface({
        tag: 'filter-surface',
        ownerTag: element.tagName.toLowerCase(),
        path: cssPath(element),
        src: '',
        sources: [],
        rect: paintedRect,
        filterFunctionCount: (filterText.match(/[a-z-]+\s*\(/gi) || []).length,
        filterUsesUrl: /url\s*\(/i.test(filterText)
      }));
    }
    sortArray(rasterSurfaces, (left, right) => right.documentCoverage - left.documentCoverage || right.viewportCoverage - left.viewportCoverage);
    sortArray(vectorSurfaces, (left, right) => right.documentCoverage - left.documentCoverage || right.viewportCoverage - left.viewportCoverage);
    const aggregateRasterCoverage = (surfaces) => {
      if (!surfaces.length) return 0;
      const boundedDocumentWidth = Math.max(1, documentWidth);
      const boundedDocumentHeight = Math.max(1, documentHeight);
      const gridWidth = Math.max(1, Math.min(256, Math.ceil(boundedDocumentWidth)));
      const gridHeight = Math.max(1, Math.min(256, Math.ceil(boundedDocumentHeight)));
      const stride = gridWidth + 1;
      const differences = new Int32Array((gridWidth + 1) * (gridHeight + 1));
      for (let surfaceIndex = 0; surfaceIndex < surfaces.length; surfaceIndex += 1) {
        const surface = surfaces[surfaceIndex];
        const left = Math.max(0, Math.min(boundedDocumentWidth, surface.rect.x));
        const top = Math.max(0, Math.min(boundedDocumentHeight, surface.rect.y));
        const right = Math.max(left, Math.min(boundedDocumentWidth, surface.rect.x + surface.rect.width));
        const bottom = Math.max(top, Math.min(boundedDocumentHeight, surface.rect.y + surface.rect.height));
        if (right <= left || bottom <= top) continue;
        const x0 = Math.max(0, Math.min(gridWidth - 1, Math.floor(left / boundedDocumentWidth * gridWidth)));
        const y0 = Math.max(0, Math.min(gridHeight - 1, Math.floor(top / boundedDocumentHeight * gridHeight)));
        const x1 = Math.max(x0 + 1, Math.min(gridWidth, Math.ceil(right / boundedDocumentWidth * gridWidth)));
        const y1 = Math.max(y0 + 1, Math.min(gridHeight, Math.ceil(bottom / boundedDocumentHeight * gridHeight)));
        differences[y0 * stride + x0] += 1;
        differences[y0 * stride + x1] -= 1;
        differences[y1 * stride + x0] -= 1;
        differences[y1 * stride + x1] += 1;
      }
      let covered = 0;
      for (let y = 0; y < gridHeight; y += 1) {
        for (let x = 0; x < gridWidth; x += 1) {
          const index = y * stride + x;
          if (x > 0) differences[index] += differences[index - 1];
          if (y > 0) differences[index] += differences[index - stride];
          if (x > 0 && y > 0) differences[index] -= differences[index - stride - 1];
          if (differences[index] > 0) covered += 1;
        }
      }
      return round(covered / (gridWidth * gridHeight));
    };
    const rasterSurfaceLimit = 5000;
    const vectorSurfaceLimit = 5000;
    return {
      page: {
        url: location.href,
        title: document.title,
        lang: document.documentElement.lang || '',
        replicaMode: (() => {
          const meta = queryOne(document, 'meta[name="replica-mode"]');
          return meta ? getAttribute(meta, 'content') || '' : '';
        })(),
        textLength: clean(document.body?.innerText).length,
        geometry: {
          width: documentWidth,
          height: documentHeight,
          bodyWidth: round(document.body ? boundingRect(document.body).width : 0),
          bodyHeight: round(document.body ? boundingRect(document.body).height : 0)
        }
      },
      integrity: {
        nativeApiTampering: integrityNatives
          ? integrityNatives.auditElements(activeElements, 1000)
          : ['integrity-native-snapshot-missing'],
        iframeCount: queryActive('iframe').length,
        canvasCount: queryActive('canvas').length,
        imageCount: queryActive('img').length,
        svgElementCount: queryActive('svg').length,
        svgExternalResourceCount: filterArray(queryActive('svg use, svg feImage'), (element) => {
          const reference = String(getAttribute(element, 'href') || getAttribute(element, 'xlink:href') || '').trim();
          return Boolean(reference && !reference.startsWith('#'));
        }).length,
        scriptCount: queryActive('script').length,
        stylesheetCount: document.styleSheets.length,
        elementCount: activeElements.length,
        capturedVisibleElements: elements.length,
        elementLimitReached: elements.length >= limit,
        embeddedFrames: mapArray(queryActive('iframe'), (frame) => {
          const rect = boundingRect(frame);
          return {
            src: frame.src,
            rect: { x: round(rect.x + scrollX), y: round(rect.y + scrollY), width: round(rect.width), height: round(rect.height) }
          };
        }),
        embeddedObjects: mapArray(queryActive('object, embed'), (element) => {
          const rect = boundingRect(element);
          const paintedRect = renderedRect(element, rect);
          return {
            tag: element.tagName.toLowerCase(),
            source: element instanceof HTMLObjectElement ? element.data : element.src,
            type: element.type || '',
            visible: Boolean(paintedRect),
            rect: paintedRect ? {
              x: round(paintedRect.left + scrollX),
              y: round(paintedRect.top + scrollY),
              width: round(paintedRect.width),
              height: round(paintedRect.height)
            } : null
          };
        }),
        embeddedObjectCount: queryActive('object, embed').length,
        scripts: mapArray(queryActive('script'), (script) => ({
          src: script.src || '',
          srcAttribute: getAttribute(script, 'src'),
          type: script.type || '',
          inline: !script.src,
          textLength: script.src ? 0 : String(script.textContent || '').length
        })),
        metaRefreshElements: mapArray(
          filterArray(queryActive('meta[http-equiv]'), (meta) => String(getAttribute(meta, 'http-equiv') || '').trim().toLowerCase() === 'refresh'),
          (meta) => {
            const content = String(getAttribute(meta, 'content') || '');
            return {
              contentPresent: content.length > 0,
              contentLength: content.length,
              hasUrlDirective: /(?:^|;)\s*url\s*=/i.test(content)
            };
          }
        ),
        stylesheetLinks: mapArray(queryActive('link[rel~="stylesheet" i]'), (link) => ({
          href: link.href || '',
          hrefAttribute: getAttribute(link, 'href'),
          media: link.media || '',
          disabled: Boolean(link.disabled)
        })),
        baseElements: mapArray(queryActive('base'), (base) => ({
          href: base.href || '',
          hrefAttribute: getAttribute(base, 'href'),
          target: base.target || ''
        })),
        resourceTimingBufferSize: Number(globalThis.__replicaResourceTiming?.limit || 0),
        resourceTimingBufferFullEvents: Number(globalThis.__replicaResourceTiming?.bufferFullEvents || 0),
        resourceTimingOverflow: Number(globalThis.__replicaResourceTiming?.bufferFullEvents || 0) > 0,
        resourceTimingTamperAttempts: Number(globalThis.__replicaResourceTiming?.tamperAttempts || 0),
        disclosures: mapArray(queryActive('[data-replica-disclosure]'), (disclosure) => {
          const paintedRect = renderedRect(disclosure);
          return {
            text: clean(disclosure.textContent),
            visible: visible(disclosure),
            rect: paintedRect ? {
              x: round(paintedRect.left + scrollX),
              y: round(paintedRect.top + scrollY),
              width: round(paintedRect.width),
              height: round(paintedRect.height)
            } : null
          };
        }),
        replicaSourceLinks: mapArray(queryActive('[data-replica-source-link]'), (element) => ({
          path: cssPath(element),
          tag: element.tagName.toLowerCase(),
          hrefAttribute: getAttribute(element, 'href'),
          xlinkHrefAttribute: getAttribute(element, 'xlink:href')
            ?? getAttributeNS(element, 'http://www.w3.org/1999/xlink', 'href'),
          role: getAttribute(element, 'role') || '',
          visible: visible(element)
        })),
        rasterSurfaceCount: rasterSurfaces.length,
        rasterSurfacesTruncated: rasterSurfaces.length > rasterSurfaceLimit,
        aggregateRasterDocumentCoverage: aggregateRasterCoverage(rasterSurfaces),
        aggregateRasterCoverageMethod: 'conservative-256x256-document-grid',
        rasterSurfaces: sliceArray(rasterSurfaces, 0, rasterSurfaceLimit),
        vectorSurfaceCount: vectorSurfaces.length,
        vectorSurfacesTruncated: vectorSurfaces.length > vectorSurfaceLimit,
        aggregateVectorDocumentCoverage: aggregateRasterCoverage(vectorSurfaces),
        aggregateVectorCoverageMethod: 'conservative-256x256-document-grid',
        vectorSurfaces: sliceArray(vectorSurfaces, 0, vectorSurfaceLimit)
      },
      cssVariables,
      fonts: document.fonts ? [...document.fonts].map((font) => ({
        family: font.family,
        style: font.style,
        weight: font.weight,
        status: font.status
      })) : [],
      stylesheets: [...document.styleSheets].map((sheet) => ({
        href: sheet.href || '',
        media: sheet.media?.mediaText || '',
        disabled: Boolean(sheet.disabled),
        ruleCount: (() => { try { return sheet.cssRules.length; } catch { return null; } })()
      })),
      resources,
      forms: mapArray(queryActive('form'), (form, ordinal) => ({
        ordinal,
        path: cssPath(form),
        methodAttribute: getAttribute(form, 'method'),
        method: String(nativeFormMethod(form) || 'get').toLowerCase(),
        actionAttribute: getAttribute(form, 'action'),
        action: String(nativeFormAction(form) || ''),
        enctypeAttribute: getAttribute(form, 'enctype'),
        enctype: String(nativeFormEnctype(form) || '').toLowerCase(),
        targetAttribute: getAttribute(form, 'target'),
        controlCount: form.elements.length
      })),
      controls,
      headings: mapArray(queryActive('h1,h2,h3,h4,h5,h6,[role="heading"]'), (element) => ({
        path: cssPath(element),
        level: Number(getAttribute(element, 'aria-level') || element.tagName.slice(1) || 0),
        text: clean(element.textContent),
        visible: visible(element)
      })),
      links: mapArray(queryActive('a, area'), (element) => ({
        path: cssPath(element),
        tag: element.tagName.toLowerCase(),
        text: clean(element.textContent),
        href: typeof element.href === 'string' ? element.href : String(element.href?.baseVal || ''),
        hrefAttribute: getAttribute(element, 'href'),
        xlinkHrefAttribute: getAttribute(element, 'xlink:href')
          ?? getAttributeNS(element, 'http://www.w3.org/1999/xlink', 'href'),
        replicaSourceLink: hasAttribute(element, 'data-replica-source-link'),
        role: getAttribute(element, 'role') || '',
        target: getAttribute(element, 'target') || '',
        visible: visible(element)
      })),
      elements
    };
  }, maxElements);
}

async function capturePreFreezeDisclosureState(page) {
  return page.evaluate(() => {
    const natives = globalThis.__replicaIntegrityNatives;
    const queryAll = (root, selector) => natives ? natives.queryAll(root, selector) : [...root.querySelectorAll(selector)];
    const matches = (element, selector) => natives ? natives.matches(element, selector) : element.matches(selector);
    const shadowRootOf = (element) => natives ? natives.shadowRoot(element) : element.shadowRoot;
    const getRootNode = (node) => natives ? natives.getRootNode(node) : node.getRootNode();
    const styleOf = (element, pseudo = null) => natives
      ? natives.getComputedStyle(element, pseudo)
      : globalThis.getComputedStyle(element, pseudo);
    const rectOf = (element) => natives ? natives.getBoundingClientRect(element) : element.getBoundingClientRect();
    const pushArray = (value, ...entries) => natives ? natives.arrayPush(value, ...entries) : value.push(...entries);
    const mapArray = (value, callback) => natives ? natives.arrayMap(value, callback) : value.map(callback);
    const filterArray = (value, callback) => natives ? natives.arrayFilter(value, callback) : value.filter(callback);
    const disclosures = [];
    const collect = (root) => {
      const elements = queryAll(root, '*');
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        if (matches(element, '[data-replica-disclosure]')) pushArray(disclosures, element);
        const shadowRoot = shadowRootOf(element);
        if (shadowRoot) collect(shadowRoot);
      }
    };
    collect(document);
    const composedParent = (element) => {
      const root = getRootNode(element);
      return element.parentElement || (root instanceof ShadowRoot ? root.host : null);
    };
    const hasPositiveTime = (value) => {
      const values = String(value || '').split(',');
      for (let index = 0; index < values.length; index += 1) {
        const match = values[index].trim().match(/^(-?(?:\d+\.?\d*|\.\d+))(ms|s)$/i);
        if (!match) continue;
        const milliseconds = Number.parseFloat(match[1]) * (match[2].toLowerCase() === 's' ? 1000 : 1);
        if (milliseconds > 0) return true;
      }
      return false;
    };
    const alpha = (value) => {
      const normalized = String(value || '').trim().toLowerCase();
      if (!normalized || normalized === 'transparent') return 0;
      const rgba = normalized.match(/rgba?\([^)]*[,/]\s*(-?(?:\d+\.?\d*|\.\d+)%?)\s*\)$/);
      if (!rgba || normalized.startsWith('rgb(')) return 1;
      const numeric = Number.parseFloat(rgba[1]);
      return rgba[1].endsWith('%') ? numeric / 100 : numeric;
    };
    const zeroInset = (value) => /^(?:0(?:px|%|em|rem)?|auto)$/i.test(String(value || '').trim());
    const pseudoOverlayRisk = (element, pseudo, elementRect) => {
      const style = styleOf(element, pseudo);
      if (!style || !style.content || ['none', 'normal'].includes(style.content)) return false;
      const positioned = ['absolute', 'fixed'].includes(style.position);
      const insetCovers = positioned && zeroInset(style.top) && zeroInset(style.right)
        && zeroInset(style.bottom) && zeroInset(style.left);
      const percentCovers = /^(?:100%|auto)$/i.test(style.width) && /^(?:100%|auto)$/i.test(style.height);
      const width = Number.parseFloat(style.width || '0');
      const height = Number.parseFloat(style.height || '0');
      const pixelCovers = Number.isFinite(width) && Number.isFinite(height)
        && width >= elementRect.width * 0.8 && height >= elementRect.height * 0.8;
      const opaquePaint = alpha(style.backgroundColor) >= 0.8
        || (style.backgroundImage && style.backgroundImage !== 'none');
      return opaquePaint && Number.parseFloat(style.opacity || '1') >= 0.8
        && (insetCovers || percentCovers || pixelCovers);
    };
    const entries = mapArray(disclosures, (disclosure, ordinal) => {
      let animationRisk = false;
      let transitionRisk = false;
      let pseudoElementOpaqueOverlayRisk = false;
      let inspectedAncestorCount = 0;
      const disclosureRect = rectOf(disclosure);
      for (let current = disclosure; current; current = composedParent(current)) {
        inspectedAncestorCount += 1;
        const style = styleOf(current);
        if (style.animationName && style.animationName !== 'none'
          && (hasPositiveTime(style.animationDuration) || hasPositiveTime(style.animationDelay))) animationRisk = true;
        if (style.transitionProperty && style.transitionProperty !== 'none'
          && hasPositiveTime(style.transitionDuration)) transitionRisk = true;
        if (pseudoOverlayRisk(current, '::before', disclosureRect)
          || pseudoOverlayRisk(current, '::after', disclosureRect)) pseudoElementOpaqueOverlayRisk = true;
        if (current === document.documentElement) break;
      }
      return {
        ordinal,
        inspectedAncestorCount,
        animationRisk,
        transitionRisk,
        pseudoElementOpaqueOverlayRisk
      };
    });
    return {
      phase: 'after-domcontentloaded-before-freeze-css',
      disclosureCount: disclosures.length,
      entries,
      animationRiskCount: filterArray(entries, (entry) => entry.animationRisk).length,
      transitionRiskCount: filterArray(entries, (entry) => entry.transitionRisk).length,
      pseudoElementOpaqueOverlayRiskCount: filterArray(entries, (entry) => entry.pseudoElementOpaqueOverlayRisk).length
    };
  });
}

async function captureDisclosurePersistence(page, sampleDelayMs = delayedPersistenceSampleMs) {
  return page.evaluate(async (sampleDelayMs) => {
    const integrityNatives = globalThis.__replicaIntegrityNatives;
    const queryAll = (root, selector) => integrityNatives
      ? integrityNatives.queryAll(root, selector)
      : [...root.querySelectorAll(selector)];
    const matches = (element, selector) => integrityNatives
      ? integrityNatives.matches(element, selector)
      : element.matches(selector);
    const getRootNode = (node) => integrityNatives
      ? integrityNatives.getRootNode(node)
      : node.getRootNode();
    const shadowRootOf = (element) => integrityNatives
      ? integrityNatives.shadowRoot(element)
      : element.shadowRoot;
    const getComputedStyle = (element, pseudo = null) => integrityNatives
      ? integrityNatives.getComputedStyle(element, pseudo)
      : globalThis.getComputedStyle(element, pseudo);
    const boundingRect = (element) => integrityNatives
      ? integrityNatives.getBoundingClientRect(element)
      : element.getBoundingClientRect();
    const closest = (element, selector) => integrityNatives
      ? integrityNatives.closest(element, selector)
      : element.closest(selector);
    const elementsFromPoint = (root, x, y) => integrityNatives
      ? integrityNatives.elementsFromPoint(root, x, y)
      : root.elementsFromPoint(x, y);
    const pushArray = (value, ...entries) => integrityNatives
      ? integrityNatives.arrayPush(value, ...entries)
      : value.push(...entries);
    const mapArray = (value, callback) => integrityNatives
      ? integrityNatives.arrayMap(value, callback)
      : value.map(callback);
    const filterArray = (value, callback) => integrityNatives
      ? integrityNatives.arrayFilter(value, callback)
      : value.filter(callback);
    const round = (value) => Math.round(Number(value || 0) * 1000) / 1000;
    const colorIsTransparent = (value) => {
      const normalized = String(value || '').trim().toLowerCase();
      if (!normalized || normalized === 'transparent') return normalized === 'transparent';
      const alpha = normalized.match(/rgba\([^)]*,\s*(-?(?:\d+\.?\d*|\.\d+)%?)\s*\)$/);
      if (!alpha) return false;
      const numeric = Number.parseFloat(alpha[1]);
      return (alpha[1].endsWith('%') ? numeric / 100 : numeric) <= 0.001;
    };
    const disclosures = [];
    const collectDisclosures = (root) => {
      for (const element of queryAll(root, '*')) {
        if (matches(element, '[data-replica-disclosure]')) pushArray(disclosures, element);
        const shadowRoot = shadowRootOf(element);
        if (shadowRoot) collectDisclosures(shadowRoot);
      }
    };
    collectDisclosures(document);
    const clean = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
    const composedParent = (element) => {
      if (!element) return null;
      const root = getRootNode(element);
      return element.parentElement || (root instanceof ShadowRoot ? root.host : null);
    };
    const composedContains = (ancestor, element) => {
      for (let current = element; current; current = composedParent(current)) {
        if (current === ancestor) return true;
      }
      return false;
    };
    const deepestTopElement = (x, y) => {
      let top = elementsFromPoint(document, x, y)[0] || null;
      const seen = new Set();
      while (top && shadowRootOf(top) && !seen.has(top)) {
        seen.add(top);
        const nested = elementsFromPoint(shadowRootOf(top), x, y)[0] || null;
        if (!nested || nested === top) break;
        top = nested;
      }
      return top;
    };
    const intersectRect = (rect, clippingRect) => ({
      left: Math.max(rect.left, clippingRect.left),
      top: Math.max(rect.top, clippingRect.top),
      right: Math.min(rect.right, clippingRect.right),
      bottom: Math.min(rect.bottom, clippingRect.bottom)
    });
    const hasArea = (rect) => rect.right > rect.left && rect.bottom > rect.top;
    const parseColor = (value) => {
      const normalized = String(value || '').trim().toLowerCase();
      if (!normalized || normalized === 'transparent') return { r: 0, g: 0, b: 0, a: 0 };
      const numbers = normalized.match(/-?(?:\d+\.?\d*|\.\d+)%?/g) || [];
      if (!normalized.startsWith('rgb') || numbers.length < 3) return null;
      const channel = (entry) => entry.endsWith('%') ? Number.parseFloat(entry) * 2.55 : Number.parseFloat(entry);
      const alpha = numbers[3] === undefined
        ? 1
        : numbers[3].endsWith('%') ? Number.parseFloat(numbers[3]) / 100 : Number.parseFloat(numbers[3]);
      return { r: channel(numbers[0]), g: channel(numbers[1]), b: channel(numbers[2]), a: Math.max(0, Math.min(1, alpha)) };
    };
    const composite = (foreground, background) => {
      const alpha = foreground.a + background.a * (1 - foreground.a);
      if (alpha <= 0) return { r: 255, g: 255, b: 255, a: 1 };
      return {
        r: (foreground.r * foreground.a + background.r * background.a * (1 - foreground.a)) / alpha,
        g: (foreground.g * foreground.a + background.g * background.a * (1 - foreground.a)) / alpha,
        b: (foreground.b * foreground.a + background.b * background.a * (1 - foreground.a)) / alpha,
        a: alpha
      };
    };
    const luminance = (color) => {
      const linear = (channel) => {
        const value = channel / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b);
    };
    const contrastRatio = (foreground, background) => {
      const renderedForeground = composite(foreground, background);
      const lighter = Math.max(luminance(renderedForeground), luminance(background));
      const darker = Math.min(luminance(renderedForeground), luminance(background));
      return (lighter + 0.05) / (darker + 0.05);
    };
    const effectiveBackground = (element) => {
      const layers = [];
      let unknownImage = false;
      for (let current = element; current; current = composedParent(current)) {
        const style = getComputedStyle(current);
        if (style.backgroundImage && style.backgroundImage !== 'none') unknownImage = true;
        const parsed = parseColor(style.backgroundColor);
        if (parsed && parsed.a > 0) layers.push(parsed);
      }
      let color = { r: 255, g: 255, b: 255, a: 1 };
      for (const layer of layers.reverse()) color = composite(layer, color);
      return { color, unknownImage };
    };
    const filterOpacity = (filter) => {
      let opacity = 1;
      for (const match of String(filter || '').matchAll(/opacity\(\s*(-?(?:\d+\.?\d*|\.\d+)%?)\s*\)/gi)) {
        const numeric = Number.parseFloat(match[1]);
        opacity *= match[1].endsWith('%') ? numeric / 100 : numeric;
      }
      return opacity;
    };
    const visibleTextRect = (rect, parent, disclosureRect) => {
      let clipped = intersectRect(rect, disclosureRect);
      clipped = intersectRect(clipped, { left: 0, top: 0, right: innerWidth, bottom: innerHeight });
      for (let current = parent; hasArea(clipped) && current; current = composedParent(current)) {
        const style = getComputedStyle(current);
        if (/(?:hidden|clip|scroll|auto)/.test(`${style.overflow} ${style.overflowX} ${style.overflowY}`)) {
          clipped = intersectRect(clipped, boundingRect(current));
        }
        if (current === (parent ? closest(parent, '[data-replica-disclosure]') : null)) break;
      }
      return clipped;
    };
    const textStyleVisibility = (parent, disclosure) => {
      let opacity = 1;
      for (let current = parent; current; current = composedParent(current)) {
        const style = getComputedStyle(current);
        const currentOpacity = Number.parseFloat(style.opacity || '1');
        opacity *= Number.isFinite(currentOpacity) ? currentOpacity : 1;
        opacity *= filterOpacity(style.filter);
        let collapsedTransform = false;
        if (style.transform && style.transform !== 'none') {
          try {
            const matrix = new DOMMatrix(style.transform);
            const scaleX = Math.hypot(matrix.m11, matrix.m12, matrix.m13);
            const scaleY = Math.hypot(matrix.m21, matrix.m22, matrix.m23);
            collapsedTransform = Math.min(scaleX, scaleY) < 0.5;
          } catch {}
        }
        const illegibleBlur = [...String(style.filter || '').matchAll(/blur\(\s*(-?(?:\d+\.?\d*|\.\d+))px\s*\)/gi)]
          .some((match) => Number.parseFloat(match[1]) >= 2);
        if (current.hidden
          || style.display === 'none'
          || ['hidden', 'collapse'].includes(style.visibility)
          || style.contentVisibility === 'hidden'
          || opacity <= 0.01
          || collapsedTransform
          || illegibleBlur
          || /inset\(\s*50%/i.test(style.clipPath)
          || /circle\(\s*0(?:px|%|em|rem)?\b/i.test(style.clipPath)
          || /rect\(\s*0(?:px)?(?:\s*,?\s*0(?:px)?){3}\s*\)/i.test(style.clip)
          || (style.maskImage && style.maskImage !== 'none')) return { visible: false, contrast: 0 };
        if (current === disclosure) break;
      }
      const style = getComputedStyle(parent);
      const foreground = parseColor(style.webkitTextFillColor) || parseColor(style.color);
      const background = effectiveBackground(parent);
      const contrast = foreground && !background.unknownImage
        ? contrastRatio({ ...foreground, a: foreground.a * opacity }, background.color)
        : 0;
      return {
        visible: Number.parseFloat(style.fontSize || '0') >= 8
          && !colorIsTransparent(style.color)
          && !colorIsTransparent(style.webkitTextFillColor)
          && contrast >= 3,
        contrast
      };
    };
    const pointSamples = (rect) => {
      const clipped = intersectRect(rect, { left: 0, top: 0, right: innerWidth, bottom: innerHeight });
      if (!hasArea(clipped)) return [];
      const point = (xRatio, yRatio) => ({
        x: clipped.left + (clipped.right - clipped.left) * xRatio,
        y: clipped.top + (clipped.bottom - clipped.top) * yRatio
      });
      return [point(0.5, 0.5), point(0.15, 0.2), point(0.85, 0.2), point(0.15, 0.8), point(0.85, 0.8)];
    };
    const sample = (element) => {
      const rect = boundingRect(element);
      const style = getComputedStyle(element);
      let rendered = rect.width > 0 && rect.height > 0;
      let opacity = 1;
      for (let current = element; rendered && current && current.nodeType === Node.ELEMENT_NODE; current = current.parentElement) {
        const currentStyle = getComputedStyle(current);
        const currentOpacity = Number.parseFloat(currentStyle.opacity || '1');
        opacity *= Number.isFinite(currentOpacity) ? currentOpacity : 1;
        rendered = !current.hidden
          && currentStyle.display !== 'none'
          && !['hidden', 'collapse'].includes(currentStyle.visibility)
          && currentStyle.contentVisibility !== 'hidden'
          && opacity > 0.001;
      }
      const intersectsViewport = rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight;
      const visible = rendered
        && intersectsViewport
        && Number.parseFloat(style.fontSize || '0') > 0.01
        && !colorIsTransparent(style.color)
        && !colorIsTransparent(style.webkitTextFillColor);
      const occlusionPoints = pointSamples(rect);
      const unoccludedSampleCount = visible ? filterArray(occlusionPoints, ({ x, y }) => {
        const top = deepestTopElement(x, y);
        return Boolean(top && composedContains(element, top));
      }).length : 0;
      const requiredUnoccludedSamples = Math.min(3, occlusionPoints.length);
      const unoccluded = visible
        && requiredUnoccludedSamples > 0
        && unoccludedSampleCount >= requiredUnoccludedSamples;
      const geometricText = [];
      const hitTestedText = [];
      let geometricGlyphArea = 0;
      let hitTestedGlyphArea = 0;
      let minimumEffectiveGlyphHeight = Number.POSITIVE_INFINITY;
      let minimumTextContrastRatio = Number.POSITIVE_INFINITY;
      const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        const text = clean(node.nodeValue);
        const parent = node.parentElement;
        if (!text || !parent) continue;
        const textVisibility = textStyleVisibility(parent, element);
        if (!textVisibility.visible) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        const rectangles = filterArray(
          mapArray([...range.getClientRects()], (textRect) => visibleTextRect(textRect, parent, rect)),
          (textRect) => hasArea(textRect) && textRect.bottom - textRect.top >= 8
        );
        range.detach?.();
        if (!rectangles.length) continue;
        const glyphArea = rectangles.reduce((total, textRect) => total
          + (textRect.right - textRect.left) * (textRect.bottom - textRect.top), 0);
        if (glyphArea < 16 || glyphArea / [...text].length < 4) continue;
        geometricText.push(text);
        geometricGlyphArea += glyphArea;
        minimumEffectiveGlyphHeight = Math.min(minimumEffectiveGlyphHeight, ...rectangles.map((textRect) => textRect.bottom - textRect.top));
        minimumTextContrastRatio = Math.min(minimumTextContrastRatio, textVisibility.contrast);
        const textIsHitTested = rectangles.some((textRect) => pointSamples(textRect).some(({ x, y }) => (
          deepestTopElement(x, y) === parent
        )));
        if (textIsHitTested) {
          hitTestedText.push(text);
          hitTestedGlyphArea += glyphArea;
        }
      }
      return {
        visible,
        position: style.position,
        innerText: clean(element.innerText),
        geometricVisibleText: clean(geometricText.join(' ')),
        visibleText: clean(hitTestedText.join(' ')),
        geometricGlyphArea: round(geometricGlyphArea),
        hitTestedGlyphArea: round(hitTestedGlyphArea),
        minimumEffectiveGlyphHeight: Number.isFinite(minimumEffectiveGlyphHeight) ? round(minimumEffectiveGlyphHeight) : 0,
        minimumTextContrastRatio: Number.isFinite(minimumTextContrastRatio) ? round(minimumTextContrastRatio) : 0,
        occlusionSampleCount: occlusionPoints.length,
        unoccludedSampleCount,
        requiredUnoccludedSamples,
        unoccluded,
        viewportRect: {
          x: round(rect.x),
          y: round(rect.y),
          width: round(rect.width),
          height: round(rect.height)
        }
      };
    };
    const original = { x: scrollX, y: scrollY };
    const start = mapArray(disclosures, sample);
    const maximumScrollY = Math.max(
      0,
      Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0) - innerHeight
    );
    scrollTo(original.x, maximumScrollY);
    await new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
    const end = mapArray(disclosures, sample);
    scrollTo(original.x, original.y);
    await new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
    await new Promise((resolveDelay) => setTimeout(resolveDelay, sampleDelayMs));
    const delayed = mapArray(disclosures, sample);
    return mapArray(start, (entry, index) => ({
      position: entry.position,
      visibleAtStart: entry.visible,
      visibleAtDocumentEnd: end[index]?.visible === true,
      innerTextAtStart: entry.innerText,
      innerTextAtDocumentEnd: end[index]?.innerText || '',
      geometricVisibleTextAtStart: entry.geometricVisibleText,
      geometricVisibleTextAtDocumentEnd: end[index]?.geometricVisibleText || '',
      visibleTextAtStart: entry.visibleText,
      visibleTextAtDocumentEnd: end[index]?.visibleText || '',
      geometricGlyphAreaAtStart: entry.geometricGlyphArea,
      geometricGlyphAreaAtDocumentEnd: end[index]?.geometricGlyphArea || 0,
      hitTestedGlyphAreaAtStart: entry.hitTestedGlyphArea,
      hitTestedGlyphAreaAtDocumentEnd: end[index]?.hitTestedGlyphArea || 0,
      minimumEffectiveGlyphHeightAtStart: entry.minimumEffectiveGlyphHeight,
      minimumEffectiveGlyphHeightAtDocumentEnd: end[index]?.minimumEffectiveGlyphHeight || 0,
      minimumTextContrastRatioAtStart: entry.minimumTextContrastRatio,
      minimumTextContrastRatioAtDocumentEnd: end[index]?.minimumTextContrastRatio || 0,
      occlusionSampleCountAtStart: entry.occlusionSampleCount,
      unoccludedSampleCountAtStart: entry.unoccludedSampleCount,
      requiredUnoccludedSamplesAtStart: entry.requiredUnoccludedSamples,
      occlusionSampleCountAtDocumentEnd: end[index]?.occlusionSampleCount || 0,
      unoccludedSampleCountAtDocumentEnd: end[index]?.unoccludedSampleCount || 0,
      requiredUnoccludedSamplesAtDocumentEnd: end[index]?.requiredUnoccludedSamples || 0,
      unoccludedAtStart: entry.unoccluded,
      unoccludedAtDocumentEnd: end[index]?.unoccluded === true,
      visibleAfterDelay: delayed[index]?.visible === true,
      unoccludedAfterDelay: delayed[index]?.unoccluded === true,
      innerTextAfterDelay: delayed[index]?.innerText || '',
      geometricVisibleTextAfterDelay: delayed[index]?.geometricVisibleText || '',
      visibleTextAfterDelay: delayed[index]?.visibleText || '',
      startViewportRect: entry.viewportRect,
      endViewportRect: end[index]?.viewportRect || null,
      sampledScrollRange: round(maximumScrollY),
      persistent: ['fixed', 'sticky'].includes(entry.position)
        && entry.visible
        && end[index]?.visible === true
        && delayed[index]?.visible === true
        && entry.unoccluded
        && end[index]?.unoccluded === true
        && delayed[index]?.unoccluded === true
    }));
  }, sampleDelayMs);
}

async function capturePublicDisclosureMediaMatrix(page, context, viewport, requestTracker, timeoutMs) {
  const entries = [];
  const originalUrl = page.url();
  let navigationCount = 0;
  let completed = true;
  const navigationListener = (frame) => {
    if (frame === page.mainFrame()) navigationCount += 1;
  };
  page.on('framenavigated', navigationListener);
  const cdp = await context.newCDPSession(page);
  try {
    for (const variant of publicDisclosureMediaVariants) {
      try {
        await page.emulateMedia({
          colorScheme: variant.colorScheme,
          reducedMotion: variant.reducedMotion
        });
        await cdp.send('Emulation.setDeviceMetricsOverride', {
          width: viewport.width,
          height: viewport.height,
          deviceScaleFactor: variant.deviceScaleFactor,
          mobile: false
        });
        const quiescence = await waitForExecutableStyleQuiescence(
          page,
          requestTracker,
          Math.min(timeoutMs, 250)
        );
        await page.evaluate(() => new Promise((resolveFrame) => {
          requestAnimationFrame(() => requestAnimationFrame(resolveFrame));
        }));
        const environment = await page.evaluate(() => ({
          colorScheme: matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
          reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'reduce' : 'no-preference',
          deviceScaleFactor: devicePixelRatio
        }));
        const preFreeze = await capturePreFreezeDisclosureState(page);
        const disclosures = await captureDisclosurePersistence(page, mediaPersistenceSampleMs);
        entries.push({
          variant,
          environment,
          quiescence,
          preFreeze,
          disclosures,
          completed: true
        });
        if (!quiescence.completed) completed = false;
      } catch (error) {
        completed = false;
        entries.push({
          variant,
          completed: false,
          error: String(error?.message || error).slice(0, 500)
        });
      }
    }
  } finally {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' }).catch(() => {});
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: viewport.width,
      height: viewport.height,
      deviceScaleFactor: 1,
      mobile: false
    }).catch(() => {});
    await cdp.detach().catch(() => {});
    page.off('framenavigated', navigationListener);
  }
  return {
    requiredVariantCount: publicDisclosureMediaVariants.length,
    sampleDelayMs: mediaPersistenceSampleMs,
    completed: completed && entries.length === publicDisclosureMediaVariants.length,
    navigationCount,
    urlChanged: page.url() !== originalUrl,
    entries
  };
}

async function captureStylesheetGraph(page, allowedOrigin) {
  const raw = await page.evaluate(() => {
    const sheetLimit = 600;
    const ruleLimit = 20000;
    const sheets = [];
    const unresolvedOwners = [];
    const seen = new Set();
    let totalSheetCount = 0;
    let totalRuleCount = 0;
    let sheetsTruncated = false;
    let rulesTruncated = false;
    let ruleAccessFailureCount = 0;
    const pushSheet = (sheet, relationship, ownerKind) => {
      if (!sheet || seen.has(sheet)) return;
      seen.add(sheet);
      totalSheetCount += 1;
      if (sheets.length >= sheetLimit) {
        sheetsTruncated = true;
        return;
      }
      const entry = {
        href: sheet.href || '',
        relationship,
        ownerKind,
        disabled: Boolean(sheet.disabled),
        media: sheet.media?.mediaText || '',
        ruleAccessed: false,
        ruleCount: 0
      };
      sheets.push(entry);
      let rules;
      try {
        rules = [...sheet.cssRules];
        entry.ruleAccessed = true;
        entry.ruleCount = rules.length;
      } catch {
        ruleAccessFailureCount += 1;
        return;
      }
      totalRuleCount += rules.length;
      if (totalRuleCount > ruleLimit) {
        rulesTruncated = true;
        return;
      }
      for (const rule of rules) {
        if (rule.type === CSSRule.IMPORT_RULE && rule.styleSheet) {
          pushSheet(rule.styleSheet, 'import', 'css-import');
        }
      }
    };
    const inspectRoot = (root, rootKind) => {
      const owners = root.querySelectorAll('style,link[rel~="stylesheet" i]');
      for (const owner of owners) {
        if (owner.sheet) pushSheet(owner.sheet, 'top-level', owner.tagName.toLowerCase());
        else if (unresolvedOwners.length < sheetLimit) {
          unresolvedOwners.push({
            ownerKind: owner.tagName.toLowerCase(),
            href: owner.href || '',
            media: owner.media || '',
            disabled: Boolean(owner.disabled),
            rootKind
          });
        } else {
          sheetsTruncated = true;
        }
        if (owner.shadowRoot) inspectRoot(owner.shadowRoot, 'shadow');
      }
      for (const adopted of root.adoptedStyleSheets || []) pushSheet(adopted, 'adopted', `${rootKind}-adopted`);
      for (const element of root.querySelectorAll('*')) {
        if (element.shadowRoot) inspectRoot(element.shadowRoot, 'shadow');
      }
    };
    inspectRoot(document, 'document');
    for (const sheet of document.styleSheets) pushSheet(sheet, 'top-level', 'document');
    return {
      sheetLimit,
      ruleLimit,
      totalSheetCount,
      retainedSheetCount: sheets.length,
      totalRuleCount,
      sheetsTruncated,
      rulesTruncated,
      ruleAccessFailureCount,
      unresolvedOwners,
      sheets
    };
  });
  return {
    ...raw,
    unresolvedOwners: raw.unresolvedOwners.map((entry) => ({
      ...entry,
      ...(entry.href ? publicResourceDescriptor(entry.href, allowedOrigin) : {})
    })).map(({ href: _rawHref, ...entry }) => entry),
    sheets: raw.sheets.map((entry) => ({
      ...entry,
      ...(entry.href ? publicResourceDescriptor(entry.href, allowedOrigin) : {
        url: '', sameOrigin: true, pathname: '', searchPresent: false, hashPresent: false
      })
    })).map(({ href: _rawHref, ...entry }) => entry)
  };
}

async function captureViewport(browser, options, viewport) {
  const directory = join(options.out, viewport.name);
  await fs.mkdir(directory, { recursive: true });
  const parsedUrl = new URL(options.url);
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
  const externalReads = [];
  const externalReadTypeCounts = {};
  const externalReadLimit = 2000;
  let externalReadCount = 0;
  let externalReadsTruncated = false;
  const credentialLikeExternalAssets = [];
  const credentialLikeExternalAssetLimit = 200;
  let credentialLikeExternalAssetCount = 0;
  let credentialLikeExternalAssetsTruncated = false;
  const runtimeAttempts = createRuntimeAttemptTelemetry();
  const allowedOrigin = parsedUrl.origin;
  const externalAssetTypes = new Set(['font', 'image', 'media', 'stylesheet']);
  const recordCredentialLikeExternalAsset = (rawUrl, resourceType, observedBy) => {
    const normalizedType = String(resourceType || '').toLowerCase();
    if (!externalAssetTypes.has(normalizedType)) return;
    let parsed;
    try { parsed = new URL(String(rawUrl || ''), parsedUrl); } catch { return; }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin === allowedOrigin) return;
    // The issue is intentionally transient. Persist only a generic classification
    // and a URL whose credential/PII-bearing components have already been redacted.
    if (!credentialLikeUrlIssue(parsed.href)) return;
    credentialLikeExternalAssetCount += 1;
    if (credentialLikeExternalAssets.length < credentialLikeExternalAssetLimit) {
      credentialLikeExternalAssets.push({
        resourceType: normalizedType,
        observedBy,
        url: redactSensitiveUrl(parsed.href)
      });
    } else {
      credentialLikeExternalAssetsTruncated = true;
    }
  };
  await context.route('**/*', async (route) => {
    const request = route.request();
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
      try {
        const requestUrl = new URL(request.url());
        if (['http:', 'https:'].includes(requestUrl.protocol) && requestUrl.origin !== allowedOrigin) {
          const resourceType = request.resourceType();
          recordCredentialLikeExternalAsset(requestUrl.href, resourceType, 'network-request');
          externalReadCount += 1;
          externalReadTypeCounts[resourceType] = Number(externalReadTypeCounts[resourceType] || 0) + 1;
          if (externalReads.length < externalReadLimit) {
            externalReads.push({ method: request.method(), resourceType, url: redactSensitiveUrl(requestUrl.href) });
          } else {
            externalReadsTruncated = true;
          }
        }
      } catch {}
    }
    if (blocksUnsafeDestinationBeforeProxy(request.url(), allowedOrigin)) {
      blockedPrivateReads.push({ method: request.method(), resourceType: request.resourceType(), url: request.url() });
      return route.abort('blockedbyclient');
    }
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method())) return route.continue();
    blockedWrites.push({ method: request.method(), resourceType: request.resourceType(), url: request.url() });
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
  const executableStyleRequestTracker = createExecutableStyleRequestTracker(page, allowedOrigin);
  const reportedClosedShadowRoots = [];
  await page.exposeBinding('__replicaReportClosedShadowRoot', (_source, descriptor) => {
    if (reportedClosedShadowRoots.length < 1000) reportedClosedShadowRoots.push(descriptor || {});
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
  await page.addInitScript(runtimeAttemptInitScript, { blockEffects: true });
  await page.addInitScript(() => {
    const resourceTimingLimit = 2048;
    const resourceTimingState = { limit: resourceTimingLimit, bufferFullEvents: 0, tamperAttempts: 0 };
    Object.defineProperty(globalThis, '__replicaResourceTiming', {
      configurable: false,
      get: () => ({ ...resourceTimingState })
    });
    try {
      const nativeSetBufferSize = Performance.prototype.setResourceTimingBufferSize;
      nativeSetBufferSize.call(performance, resourceTimingLimit);
      performance.addEventListener('resourcetimingbufferfull', () => {
        resourceTimingState.bufferFullEvents += 1;
      });
      Object.defineProperty(Performance.prototype, 'setResourceTimingBufferSize', {
        configurable: false,
        writable: false,
        value() { resourceTimingState.tamperAttempts += 1; }
      });
      Object.defineProperty(Performance.prototype, 'clearResourceTimings', {
        configurable: false,
        writable: false,
        value() { resourceTimingState.tamperAttempts += 1; }
      });
    } catch {}
    const reportClosedShadowRoot = globalThis.__replicaReportClosedShadowRoot;
    const nativeAttachShadow = Element.prototype.attachShadow;
    Object.defineProperty(Element.prototype, 'attachShadow', {
      configurable: true,
      writable: true,
      value(init) {
        const root = nativeAttachShadow.call(this, init);
        if (init?.mode === 'closed') {
          void reportClosedShadowRoot({
            tag: this.tagName?.toLowerCase() || '',
            id: this.id || '',
            classes: [...(this.classList || [])].slice(0, 20)
          });
        }
        return root;
      }
    });
    const blocked = () => { throw new Error('Live form submission blocked by replicate-websites.'); };
    try { HTMLFormElement.prototype.submit = blocked; } catch {}
    try { HTMLFormElement.prototype.requestSubmit = blocked; } catch {}
  });
  const telemetry = { consoleWarnings: [], consoleErrors: [], pageErrors: [], failedGets: [], runtimeAttempts };
  page.on('console', (message) => {
    if (message.type() === 'warning' && telemetry.consoleWarnings.length < 50) telemetry.consoleWarnings.push(message.text());
    if (message.type() === 'error' && telemetry.consoleErrors.length < 50) telemetry.consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => {
    if (telemetry.pageErrors.length < 50) telemetry.pageErrors.push(error.message);
  });
  page.on('requestfailed', (request) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method()) && telemetry.failedGets.length < 100) {
      telemetry.failedGets.push({ url: request.url(), type: request.resourceType(), error: request.failure()?.errorText || '' });
    }
  });
  page.on('popup', (popup) => {
    recordRuntimeAttempt(runtimeAttempts, 'popup', { url: popup.url(), observedBy: 'page-event' });
    popup.close().catch(() => {});
  });
  page.on('download', (download) => {
    recordRuntimeAttempt(runtimeAttempts, 'download', { url: download.url(), observedBy: 'page-event' });
    download.cancel().catch(() => {});
  });
  const scriptResponses = [];
  const scriptResponseTasks = [];
  const stylesheetResponses = [];
  const stylesheetResponseTasks = [];
  let scriptResponseCount = 0;
  let scriptResponseRetained = 0;
  let scriptResponsesTruncated = false;
  let scriptDeclaredBodyBytes = 0;
  let scriptBodyReadLimitReached = false;
  let stylesheetResponseCount = 0;
  let stylesheetResponseRetained = 0;
  let stylesheetResponsesTruncated = false;
  let stylesheetDeclaredBodyBytes = 0;
  let stylesheetBodyReadLimitReached = false;
  page.on('response', (resourceResponse) => {
    const kind = resourceResponse.request().resourceType();
    if (kind !== 'script' && kind !== 'stylesheet') return;
    const isScript = kind === 'script';
    if (isScript) {
      scriptResponseCount += 1;
      if (scriptResponseRetained >= scriptResponseLimit) {
        scriptResponsesTruncated = true;
        return;
      }
      scriptResponseRetained += 1;
    } else {
      stylesheetResponseCount += 1;
      if (stylesheetResponseRetained >= stylesheetResponseLimit) {
        stylesheetResponsesTruncated = true;
        return;
      }
      stylesheetResponseRetained += 1;
    }
    const task = (async () => {
      const rawUrl = resourceResponse.url();
      const headers = resourceResponse.headers();
      const contentLengthText = String(headers['content-length'] || '').trim();
      const contentLength = /^\d+$/.test(contentLengthText) ? Number(contentLengthText) : null;
      const contentEncoding = String(headers['content-encoding'] || '').trim().toLowerCase();
      const contentType = String(headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
      const singleBodyByteLimit = isScript ? scriptBodyByteLimit : stylesheetBodyByteLimit;
      const totalBodyByteLimit = isScript ? scriptTotalBodyByteLimit : stylesheetTotalBodyByteLimit;
      const declaredBodyBytes = isScript ? scriptDeclaredBodyBytes : stylesheetDeclaredBodyBytes;
      const record = {
        ...publicResourceDescriptor(rawUrl, allowedOrigin),
        status: resourceResponse.status(),
        contentType,
        contentLengthPresent: contentLength !== null,
        declaredBodyBytes: Number.isSafeInteger(contentLength) ? contentLength : null,
        contentEncodingPresent: Boolean(contentEncoding),
        bodyRead: false,
        bodyReadTimedOut: false,
        bodyWithinLimit: false,
        sha256: null,
        matchesBundledStarterApp: false
      };
      if (!Number.isSafeInteger(contentLength)
        || contentLength < 0
        || contentLength > singleBodyByteLimit
        || declaredBodyBytes + contentLength > totalBodyByteLimit
        || contentEncoding) {
        if (isScript) scriptBodyReadLimitReached = true;
        else stylesheetBodyReadLimitReached = true;
        (isScript ? scriptResponses : stylesheetResponses).push(record);
        return;
      }
      if (isScript) scriptDeclaredBodyBytes += contentLength;
      else stylesheetDeclaredBodyBytes += contentLength;
      try {
        const body = await Promise.race([
          resourceResponse.body(),
          new Promise((resolveTimeout) => setTimeout(() => resolveTimeout(null), responseBodyReadTimeoutMs))
        ]);
        if (!body) {
          record.bodyReadTimedOut = true;
          if (isScript) scriptBodyReadLimitReached = true;
          else stylesheetBodyReadLimitReached = true;
          (isScript ? scriptResponses : stylesheetResponses).push(record);
          return;
        }
        record.bodyRead = true;
        record.bodyWithinLimit = body.length <= singleBodyByteLimit
          && body.length <= totalBodyByteLimit;
        if (record.bodyWithinLimit) {
          record.sha256 = createHash('sha256').update(body).digest('hex');
          if (isScript) record.matchesBundledStarterApp = record.sha256 === options.bundledStarterAppSha256;
        } else {
          if (isScript) scriptBodyReadLimitReached = true;
          else stylesheetBodyReadLimitReached = true;
        }
      } catch {
        // An unreadable response remains unverified and fails the public gate.
      }
      (isScript ? scriptResponses : stylesheetResponses).push(record);
    })();
    (isScript ? scriptResponseTasks : stylesheetResponseTasks).push(task);
  });
  const warnings = [];
  const response = await page.goto(options.url, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs });
  if (!response?.ok()) throw new Error(`Navigation returned HTTP ${response?.status() ?? 'unknown'}.`);
  const mainResponseSecurityHeaders = summarizeMainResponseSecurityHeaders(response);
  if (options.readySelector) {
    await page.locator(options.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
  }
  const initialExecutableStyleQuiescence = await waitForExecutableStyleQuiescence(
    page,
    executableStyleRequestTracker,
    Math.min(options.timeoutMs, 2000)
  );
  const renderedReplicaMode = String(
    await page.locator('meta[name="replica-mode"]').first().getAttribute('content').catch(() => '') || ''
  ).trim().toLowerCase();
  let publicDisclosureMediaMatrix = {
    requiredVariantCount: publicDisclosureMediaVariants.length,
    sampleDelayMs: mediaPersistenceSampleMs,
    completed: false,
    navigationCount: 0,
    urlChanged: false,
    entries: []
  };
  if (renderedReplicaMode === 'public-simulation') {
    publicDisclosureMediaMatrix = await capturePublicDisclosureMediaMatrix(
      page,
      context,
      viewport,
      executableStyleRequestTracker,
      options.timeoutMs
    );
  }
  const preFreezeDisclosureState = publicDisclosureMediaMatrix.entries[0]?.preFreeze
    || await capturePreFreezeDisclosureState(page);
  await settlePage(page, options, warnings);
  const postSettleExecutableStyleQuiescence = await waitForExecutableStyleQuiescence(
    page,
    executableStyleRequestTracker,
    Math.min(options.timeoutMs, 2000)
  );
  const contract = await captureContract(page, options.maxElements);
  for (const resource of contract.resources || []) {
    const initiatorType = String(resource.initiatorType || '').toLowerCase();
    const resourceType = ['css', 'link'].includes(initiatorType)
      ? 'stylesheet'
      : ['img', 'image'].includes(initiatorType)
        ? 'image'
        : ['audio', 'video'].includes(initiatorType)
          ? 'media'
          : initiatorType === 'font'
            ? 'font'
            : '';
    recordCredentialLikeExternalAsset(resource.name, resourceType, 'resource-timing');
  }
  for (const stylesheet of [
    ...(contract.stylesheets || []),
    ...(contract.integrity?.stylesheetLinks || [])
  ]) {
    recordCredentialLikeExternalAsset(
      stylesheet.href || stylesheet.hrefAttribute,
      'stylesheet',
      'rendered-contract'
    );
  }
  for (const surface of [
    ...(contract.integrity?.rasterSurfaces || []),
    ...(contract.integrity?.vectorSurfaces || [])
  ]) {
    for (const source of surface.sources || (surface.src ? [surface.src] : [])) {
      recordCredentialLikeExternalAsset(source, 'image', 'rendered-surface');
    }
  }
  contract.integrity.mainResponseSecurityHeaders = mainResponseSecurityHeaders;
  contract.integrity.preFreezeDisclosureState = preFreezeDisclosureState;
  contract.integrity.publicDisclosureMediaMatrix = publicDisclosureMediaMatrix;
  contract.integrity.executableStyleInitialQuiescence = initialExecutableStyleQuiescence;
  contract.integrity.executableStylePostSettleQuiescence = postSettleExecutableStyleQuiescence;
  const cdp = await context.newCDPSession(page);
  const cdpClosedShadowRoots = [];
  const cdpStructuralInventory = {
    formCount: 0,
    unsafeFormCount: 0,
    navigableLinkCount: 0,
    externalLinkCount: 0,
    unsafeLinkCount: 0,
    scriptCount: 0,
    externalScriptCount: 0,
    stylesheetLinkCount: 0,
    externalStylesheetCount: 0,
    baseElementCount: 0,
    iframeCount: 0,
    embeddedObjectCount: 0,
    disclosureCount: 0,
    metaRefreshCount: 0,
    inlineScriptCount: 0,
    svgElementCount: 0,
    svgExternalResourceCount: 0
  };
  try {
    const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const finalUrl = new URL(contract.page.url);
    const attributes = (node) => {
      const result = new Map();
      for (let index = 0; index < (node.attributes || []).length; index += 2) {
        result.set(String(node.attributes[index] || '').toLowerCase(), String(node.attributes[index + 1] || ''));
      }
      return result;
    };
    const classifiedTarget = (rawValue) => {
      try {
        const target = new URL(String(rawValue || ''), finalUrl);
        if (target.username || target.password || !['http:', 'https:'].includes(target.protocol)) return 'unsafe';
        return target.origin === finalUrl.origin ? 'same-origin' : 'external';
      } catch {
        return 'unsafe';
      }
    };
    const visit = (node) => {
      const tag = String(node.localName || node.nodeName || '').toLowerCase();
      const attrs = attributes(node);
      if (tag === 'form') {
        cdpStructuralInventory.formCount += 1;
        let action;
        try { action = new URL(attrs.get('action') || finalUrl.href, finalUrl); } catch {}
        const method = String(attrs.get('method') || 'get').toLowerCase();
        const enctype = String(attrs.get('enctype') || 'application/x-www-form-urlencoded').toLowerCase();
        const target = String(attrs.get('target') || '').toLowerCase();
        if (!action
          || action.origin !== finalUrl.origin
          || action.pathname !== '/api/applications'
          || action.search
          || action.hash
          || method !== 'post'
          || !['application/x-www-form-urlencoded', 'multipart/form-data'].includes(enctype)
          || (target && target !== '_self')) cdpStructuralInventory.unsafeFormCount += 1;
      }
      if (['a', 'area'].includes(tag) && (attrs.has('href') || attrs.has('xlink:href'))) {
        cdpStructuralInventory.navigableLinkCount += 1;
        const classification = classifiedTarget(attrs.get('href') ?? attrs.get('xlink:href'));
        if (classification === 'external') cdpStructuralInventory.externalLinkCount += 1;
        if (classification === 'unsafe') cdpStructuralInventory.unsafeLinkCount += 1;
      }
      if (tag === 'script') {
        cdpStructuralInventory.scriptCount += 1;
        if (!attrs.has('src')) cdpStructuralInventory.inlineScriptCount += 1;
        if (attrs.has('src') && classifiedTarget(attrs.get('src')) === 'external') cdpStructuralInventory.externalScriptCount += 1;
      }
      if (tag === 'link' && String(attrs.get('rel') || '').toLowerCase().split(/\s+/).includes('stylesheet')) {
        cdpStructuralInventory.stylesheetLinkCount += 1;
        if (classifiedTarget(attrs.get('href')) === 'external') cdpStructuralInventory.externalStylesheetCount += 1;
      }
      if (tag === 'base') cdpStructuralInventory.baseElementCount += 1;
      if (tag === 'iframe') cdpStructuralInventory.iframeCount += 1;
      if (tag === 'object' || tag === 'embed') cdpStructuralInventory.embeddedObjectCount += 1;
      if (attrs.has('data-replica-disclosure')) cdpStructuralInventory.disclosureCount += 1;
      if (tag === 'meta' && String(attrs.get('http-equiv') || '').trim().toLowerCase() === 'refresh') {
        cdpStructuralInventory.metaRefreshCount += 1;
      }
      if (tag === 'svg') cdpStructuralInventory.svgElementCount += 1;
      if (tag === 'use' || tag === 'feimage') {
        const reference = String(attrs.get('href') ?? attrs.get('xlink:href') ?? '').trim();
        if (reference && !reference.startsWith('#')) cdpStructuralInventory.svgExternalResourceCount += 1;
      }
      for (const shadowRoot of node.shadowRoots || []) {
        if (shadowRoot.shadowRootType === 'closed') {
          cdpClosedShadowRoots.push({
            nodeId: shadowRoot.nodeId,
            backendNodeId: shadowRoot.backendNodeId,
            type: shadowRoot.shadowRootType
          });
        }
        visit(shadowRoot);
      }
      for (const child of node.children || []) visit(child);
      if (node.contentDocument) visit(node.contentDocument);
    };
    visit(root);
  } finally {
    await cdp.detach();
  }
  contract.integrity.closedShadowRoots = {
    reported: reportedClosedShadowRoots,
    cdp: cdpClosedShadowRoots
  };
  contract.integrity.cdpStructuralInventory = cdpStructuralInventory;
  contract.integrity.closedShadowRootCount = Math.max(reportedClosedShadowRoots.length, cdpClosedShadowRoots.length);
  const mainFrame = page.mainFrame();
  const browserFrames = page.frames()
    .filter((frame) => frame !== mainFrame)
    .map((frame) => ({ url: frame.url(), name: frame.name() || '' }));
  contract.integrity.browserFrames = browserFrames;
  contract.integrity.iframeCount = Math.max(contract.integrity.iframeCount || 0, browserFrames.length);
  const persistenceUrlBefore = page.url();
  let delayedNavigationCount = 0;
  let disclosurePersistenceCompleted = false;
  let disclosurePersistence = [];
  const navigationListener = (frame) => {
    if (frame === page.mainFrame()) delayedNavigationCount += 1;
  };
  page.on('framenavigated', navigationListener);
  try {
    disclosurePersistence = await captureDisclosurePersistence(page);
    disclosurePersistenceCompleted = true;
  } catch (error) {
    warnings.push(`delayed disclosure persistence sampling failed (${error.message})`);
  } finally {
    page.off('framenavigated', navigationListener);
  }
  const persistenceUrlAfter = page.url();
  contract.integrity.disclosures = (contract.integrity.disclosures || []).map((entry, index) => {
    const persistence = disclosurePersistence[index] || {
      position: '',
      visibleAtStart: false,
      visibleAtDocumentEnd: false,
      sampledScrollRange: null,
      persistent: false
    };
    return {
      ...entry,
      ...persistence,
      visible: entry.visible === true && persistence.visibleAtStart === true
    };
  });
  contract.integrity.delayedPersistenceNavigation = {
    sampleDelayMs: delayedPersistenceSampleMs,
    completed: disclosurePersistenceCompleted,
    navigationCount: delayedNavigationCount,
    urlChanged: persistenceUrlAfter !== persistenceUrlBefore
  };
  const finalExecutableStyleQuiescence = await waitForExecutableStyleQuiescence(
    page,
    executableStyleRequestTracker,
    Math.min(options.timeoutMs, 2000)
  );
  contract.integrity.executableStyleFinalQuiescence = finalExecutableStyleQuiescence;
  contract.integrity.stylesheetGraph = await captureStylesheetGraph(page, allowedOrigin);
  contract.integrity.documentPointInTime = {
    phase: 'after-media-matrix-explicit-settle-scroll-delayed-persistence-and-resource-quiescence',
    delayedSampleMs: delayedPersistenceSampleMs
  };
  const dimensions = [];
  for (let index = 0; index < 4; index += 1) {
    dimensions.push(await page.evaluate(() => ({
      width: Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0),
      height: Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0)
    })));
    if (index < 3) await page.waitForTimeout(150);
  }
  const stable = JSON.stringify(dimensions[1]) === JSON.stringify(dimensions[2])
    && JSON.stringify(dimensions[2]) === JSON.stringify(dimensions[3]);
  if (!stable) warnings.push('document dimensions did not stabilize');
  await page.screenshot({
    path: join(directory, 'page.png'),
    fullPage: true,
    animations: 'disabled',
    caret: 'hide',
    scale: 'css'
  });
  contract.integrity.executableStyleTerminalSnapshot = executableStyleRequestTracker.snapshot();
  for (let round = 0; round < 3; round += 1) {
    const taskCount = scriptResponseTasks.length + stylesheetResponseTasks.length;
    await Promise.allSettled([...scriptResponseTasks, ...stylesheetResponseTasks]);
    if (scriptResponseTasks.length + stylesheetResponseTasks.length === taskCount) break;
  }
  scriptResponses.sort((left, right) => left.url.localeCompare(right.url) || left.status - right.status);
  stylesheetResponses.sort((left, right) => left.url.localeCompare(right.url) || left.status - right.status);
  contract.integrity.scriptResponseInventory = {
    responseCount: scriptResponseCount,
    retainedCount: scriptResponses.length,
    responseLimit: scriptResponseLimit,
    responsesTruncated: scriptResponsesTruncated || scriptResponseCount > scriptResponses.length,
    singleBodyByteLimit: scriptBodyByteLimit,
    totalBodyByteLimit: scriptTotalBodyByteLimit,
    declaredBodyBytesRead: scriptDeclaredBodyBytes,
    bodyReadLimitReached: scriptBodyReadLimitReached,
    expectedBundledStarterAppSha256: options.bundledStarterAppSha256,
    responses: scriptResponses
  };
  contract.integrity.stylesheetResponseInventory = {
    responseCount: stylesheetResponseCount,
    retainedCount: stylesheetResponses.length,
    responseLimit: stylesheetResponseLimit,
    responsesTruncated: stylesheetResponsesTruncated || stylesheetResponseCount > stylesheetResponses.length,
    singleBodyByteLimit: stylesheetBodyByteLimit,
    totalBodyByteLimit: stylesheetTotalBodyByteLimit,
    declaredBodyBytesRead: stylesheetDeclaredBodyBytes,
    bodyReadLimitReached: stylesheetBodyReadLimitReached,
    responses: stylesheetResponses
  };
  if (transport.stats.rejectedDestinations > 0) {
    blockedPrivateReads.push({
      method: 'PROXY',
      resourceType: 'transport',
      count: transport.stats.rejectedDestinations
    });
  }
  const result = {
    schemaVersion: 1,
    capturedAt: new Date().toISOString(),
    viewport,
    httpStatus: response.status(),
    stability: { stable, samples: dimensions },
    telemetry: {
      ...telemetry,
      blockedWrites,
      blockedPrivateReads,
      externalReads,
      externalReadCount,
      externalReadTypeCounts,
      externalReadLimit,
      externalReadsTruncated,
      privacyRiskExternalAssets: credentialLikeExternalAssets,
      privacyRiskExternalAssetCount: credentialLikeExternalAssetCount,
      privacyRiskExternalAssetLimit: credentialLikeExternalAssetLimit,
      privacyRiskExternalAssetsTruncated: credentialLikeExternalAssetsTruncated,
      validatingProxy: { ...transport.stats }
    },
    warnings,
    contract
  };
  const persistedResult = redactReportData(result);
  await fs.writeFile(join(directory, 'contract.json'), `${JSON.stringify(persistedResult, null, 2)}\n`);
  return persistedResult;
  } finally {
    await context?.close().catch(() => {});
    await transport.close().catch(() => {});
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  options.bundledStarterAppSha256 = createHash('sha256')
    .update(await fs.readFile(bundledStarterAppPath))
    .digest('hex');
  await fs.mkdir(options.out, { recursive: true });
  const playwrightModule = await import(pathToFileURL(resolvePackage('playwright')).href);
  const chromium = playwrightModule.chromium || playwrightModule.default?.chromium;
  if (!chromium) throw new Error('Resolved Playwright package does not expose Chromium.');
  const executablePath = await findChromiumExecutable(chromium);
  const browser = await chromium.launch({
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
    ],
    ...(executablePath ? { executablePath } : {})
  });
  try {
    const results = [];
    for (const viewport of options.viewports) {
      process.stdout.write(`[${viewport.name}] inspecting ${options.url}\n`);
      results.push(await captureViewport(browser, options, viewport));
    }
    const summary = redactReportData({
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      url: options.url,
      browserVersion: browser.version(),
      results: results.map((result) => ({
        viewport: result.viewport,
        httpStatus: result.httpStatus,
        geometry: result.contract.page.geometry,
        integrity: result.contract.integrity,
        controlCount: result.contract.controls.length,
        headingCount: result.contract.headings.length,
        linkCount: result.contract.links.length,
        fontFamilies: [...new Set(result.contract.fonts.map((font) => font.family))],
        stability: result.stability,
        telemetry: result.telemetry,
        warnings: result.warnings
      }))
    });
    await fs.writeFile(join(options.out, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
    process.stdout.write(`Inspection: ${join(options.out, 'summary.json')}\n`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
