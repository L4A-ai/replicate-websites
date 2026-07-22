#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { promises as fs } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import {
  assertSafeHttpUrl,
  blocksUnsafeDestinationBeforeProxy,
  credentialLikeUrlIssue,
  isLoopbackHostname,
  redactSensitiveUrl
} from './lib/network-safety.mjs';
import {
  createValidatingBrowserProxy,
  requestPinnedHttpResource
} from './lib/validating-proxy.mjs';
import {
  createRuntimeAttemptTelemetry,
  recordRuntimeAttempt,
  runtimeAttemptInitScript
} from './lib/runtime-attempts.mjs';
import { integrityNativeInitScript } from './lib/integrity-natives.mjs';

const execFileAsync = promisify(execFile);
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const skillDirectory = resolve(scriptDirectory, '..');
const defaultAssetViewports = [
  { width: 1440, height: 1000 },
  { width: 768, height: 1024 },
  { width: 390, height: 844 },
  { width: 360, height: 800 }
];

function usage() {
  return `Bootstrap a safe, local rendered-DOM replica from an authorized GET-only capture.

Usage:
  node bootstrap-static-replica.mjs --url URL --out DIR --mode MODE [options]

Required:
  --url URL                    Public or otherwise authorized HTTP(S) source
  --out DIR                    Empty output directory
  --mode authorized-local|owned
                               Declare private local evaluation or site ownership

Options:
  --name PACKAGE_NAME          Generated package name (default: website-replica)
  --ready-selector SELECTOR    Wait for source marker (default: body)
  --viewport WIDTHxHEIGHT      Primary rendered DOM viewport (default: 1440x1000)
  --wait-ms N                  Final settle delay (default: 1500)
  --timeout-ms N               Navigation/selector timeout (default: 60000)
  --max-resource-bytes N       Per-resource capture cap (default: 15728640)
  --max-total-bytes N          Aggregate capture cap (default: 104857600)
  --max-resources N            Captured resource count cap (default: 2000)
  --max-html-bytes N           Serialized markup cap (default: 52428800)
  --max-scroll-steps N         Lazy-content scroll cap per viewport (default: 500)
  --max-network-requests N     Source request cap (default: 10000)
  --resource-timeout-ms N      Resource-body timeout (default: 15000)
  --no-auto-scroll             Do not pre-scroll lazy content
  --headed                     Show Chromium
  --help                       Show this message

The command removes source scripts and embedded frames, localizes captured visual
resources, replaces live form actions, and sanitizes opaque hidden values. It is
not a license to publish third-party content; authorized-local output stays local.
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
  const match = String(value).match(/^(\d+)x(\d+)$/i);
  if (!match) throw new Error(`Invalid viewport "${value}". Use WIDTHxHEIGHT.`);
  return {
    width: parseInteger(match[1], '--viewport width', 1, 10000),
    height: parseInteger(match[2], '--viewport height', 1, 10000)
  };
}

async function assertBootstrapPageIntegrity(page) {
  const valid = await page.evaluate(() => {
    const natives = globalThis.__replicaIntegrityNatives;
    if (!natives) return false;
    try {
      const elements = natives.queryAll(document, '*');
      return natives.auditElements(elements, 1).length === 0;
    } catch {
      return false;
    }
  });
  if (!valid) {
    throw new Error('Refusing rendered-DOM bootstrap because the source modified capture-critical browser APIs.');
  }
}

export function bootstrapSourceProvenance(rawUrl) {
  const parsedUrl = assertSafeHttpUrl(rawUrl, 'Refusing source URL:');
  return {
    parsedUrl,
    provenance: {
      source: `${parsedUrl.origin}${parsedUrl.pathname || '/'}`,
      sourceUrlSha256: createHash('sha256').update(parsedUrl.href).digest('hex'),
      queryKeys: [...new Set([...parsedUrl.searchParams.keys()])].sort(),
      hasFragment: Boolean(parsedUrl.hash)
    }
  };
}

function parseArguments(argv) {
  const options = {
    url: null,
    out: null,
    mode: null,
    name: 'website-replica',
    readySelector: 'body',
    viewport: { width: 1440, height: 1000 },
    waitMs: 1500,
    timeoutMs: 60000,
    maxResourceBytes: 15 * 1024 * 1024,
    maxTotalBytes: 100 * 1024 * 1024,
    maxResources: 2000,
    maxHtmlBytes: 50 * 1024 * 1024,
    maxScrollSteps: 500,
    maxNetworkRequests: 10000,
    resourceTimeoutMs: 15000,
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
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--mode': options.mode = take(index, argument); index += 1; break;
      case '--name': options.name = take(index, argument); index += 1; break;
      case '--ready-selector': options.readySelector = take(index, argument); index += 1; break;
      case '--viewport': options.viewport = parseViewport(take(index, argument)); index += 1; break;
      case '--wait-ms': options.waitMs = parseInteger(take(index, argument), argument, 0, 60000); index += 1; break;
      case '--timeout-ms': options.timeoutMs = parseInteger(take(index, argument), argument, 1000, 180000); index += 1; break;
      case '--max-resource-bytes': options.maxResourceBytes = parseInteger(take(index, argument), argument, 1024, 1024 * 1024 * 1024); index += 1; break;
      case '--max-total-bytes': options.maxTotalBytes = parseInteger(take(index, argument), argument, 1024, 2 * 1024 * 1024 * 1024); index += 1; break;
      case '--max-resources': options.maxResources = parseInteger(take(index, argument), argument, 1, 10000); index += 1; break;
      case '--max-html-bytes': options.maxHtmlBytes = parseInteger(take(index, argument), argument, 1024, 1024 * 1024 * 1024); index += 1; break;
      case '--max-scroll-steps': options.maxScrollSteps = parseInteger(take(index, argument), argument, 1, 5000); index += 1; break;
      case '--max-network-requests': options.maxNetworkRequests = parseInteger(take(index, argument), argument, 1, 100000); index += 1; break;
      case '--resource-timeout-ms': options.resourceTimeoutMs = parseInteger(take(index, argument), argument, 1000, 180000); index += 1; break;
      case '--no-auto-scroll': options.autoScroll = false; break;
      case '--headed': options.headed = true; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (options.help) return options;
  if (!options.url || !options.out || !options.mode) throw new Error('--url, --out, and --mode are required.');
  if (!['authorized-local', 'owned'].includes(options.mode)) {
    throw new Error('--mode must be authorized-local or owned.');
  }
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(options.name)) throw new Error('--name contains unsupported characters.');
  if (options.maxTotalBytes < options.maxResourceBytes) {
    throw new Error('--max-total-bytes must be at least --max-resource-bytes.');
  }
  const { parsedUrl, provenance } = bootstrapSourceProvenance(options.url);
  options.url = parsedUrl.href;
  options.parsedUrl = parsedUrl;
  options.provenance = provenance;
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
  try {
    return createRequire(import.meta.url).resolve(name);
  } catch {
    // Search the skill, caller, then the bundled Codex runtime.
  }
  for (const root of packageSearchRoots()) {
    try {
      return createRequire(join(root, '__replica_bootstrap_resolver.cjs')).resolve(name);
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

const extensionByType = new Map([
  ['text/css', '.css'],
  ['font/woff2', '.woff2'],
  ['font/woff', '.woff'],
  ['font/ttf', '.ttf'],
  ['font/otf', '.otf'],
  ['application/font-woff', '.woff'],
  ['application/vnd.ms-fontobject', '.eot'],
  ['image/avif', '.avif'],
  ['image/png', '.png'],
  ['image/jpeg', '.jpg'],
  ['image/svg+xml', '.svg'],
  ['image/webp', '.webp'],
  ['image/gif', '.gif'],
  ['image/x-icon', '.ico'],
  ['video/mp4', '.mp4'],
  ['video/webm', '.webm']
]);

function normalizedContentType(value) {
  return String(value || '').split(';')[0].trim().toLowerCase();
}

function extension(url, contentType) {
  const normalized = normalizedContentType(contentType);
  if (extensionByType.has(normalized)) return extensionByType.get(normalized);
  try {
    const suffix = extname(new URL(url).pathname).toLowerCase();
    if (/^\.[a-z0-9]{1,6}$/.test(suffix)) return suffix;
  } catch {
    // Fall through.
  }
  return '.bin';
}

export function publicResourceDescriptor(url) {
  try {
    // Classify while the complete URL is still transiently available. Persist only
    // a descriptor derived from the redacted URL when a path carries credentials
    // or obvious personal data. Ordinary asset paths (including job UUIDs) remain
    // intact so the snapshot is still useful for debugging capture coverage.
    const safeUrl = credentialLikeUrlIssue(url) ? redactSensitiveUrl(url) : url;
    const parsed = new URL(safeUrl);
    return { origin: parsed.origin, pathname: parsed.pathname };
  } catch {
    return { origin: '', pathname: '' };
  }
}

function exactPolicy(approvedSemanticMismatches, provenance) {
  const standardViewports = ['desktop', 'tablet', 'mobile', 'compact'];
  return {
    schemaVersion: 1,
    provenance,
    gates: {
      maxTolerantDiffPercent: 0,
      maxStrictDiffPercent: 0,
      maxUnapprovedSemanticMismatches: 0,
      requireDimensionsMatch: true,
      requireCandidateStable: true,
      maxMaskedPixels: 0,
      maxCandidateCriticalFailures: 0,
      maxCandidatePageErrors: 0,
      maxCandidateConsoleErrors: 0,
      maxCandidateBlockedWrites: 0,
      maxCandidateBlockedPrivateReads: 0
    },
    approvedSemanticMismatches: approvedSemanticMismatches.flatMap((rule) => standardViewports.map((viewport) => ({
      ...rule,
      viewport
    })))
  };
}

async function drainPending(pending) {
  while (pending.size) await Promise.allSettled([...pending]);
}

async function withTimeout(promise, timeoutMs, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((resolveWait, rejectWait) => {
        timer = setTimeout(() => rejectWait(new Error(`${label} timed out after ${timeoutMs} ms.`)), timeoutMs);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function exerciseViewport(page, viewport, autoScroll, maxScrollSteps) {
  await page.setViewportSize(viewport);
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
      if (!root.querySelector('style[data-replica-bootstrap-transient]')) {
        const style = document.createElement('style');
        style.setAttribute('data-replica-bootstrap-transient', '');
        style.textContent = freezeCss;
        root.append(style);
      }
    }
    for (const root of [document, ...shadowRoots]) {
      for (const animation of root.getAnimations?.({ subtree: true }) || []) animation.finish?.();
    }
    for (const media of activeElements.filter((element) => element.matches('video, audio'))) media.pause?.();
    if (document.fonts?.ready) {
      await Promise.race([
        document.fonts.ready,
        new Promise((resolveWait) => setTimeout(resolveWait, 5000))
      ]);
    }
    await Promise.race([
      Promise.all(activeElements.filter((element) => element.matches('img'))
        .map((image) => image.decode?.().catch(() => {}) || Promise.resolve())),
      new Promise((resolveWait) => setTimeout(resolveWait, 5000))
    ]);
  });
  if (autoScroll) {
    await page.evaluate(async (maximumSteps) => {
      const maximum = Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0);
      const step = Math.max(400, Math.floor(innerHeight * 0.8));
      let steps = 0;
      for (let y = 0; y < maximum && steps < maximumSteps; y += step, steps += 1) {
        scrollTo(0, y);
        await new Promise((resolveScroll) => setTimeout(resolveScroll, 16));
      }
      scrollTo(0, 0);
    }, maxScrollSteps);
  }
  await page.waitForTimeout(100);
}

function transformImageSetQuotedUrls(css, transform) {
  const source = String(css || '');
  const functionPattern = /(?:-webkit-)?image-set\(/gi;
  let output = '';
  let cursor = 0;
  let match;
  while ((match = functionPattern.exec(source))) {
    const bodyStart = match.index + match[0].length;
    let depth = 1;
    let quote = '';
    let escaped = false;
    let bodyEnd = -1;
    for (let index = bodyStart; index < source.length; index += 1) {
      const character = source[index];
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
    if (bodyEnd < 0) break;

    const body = source.slice(bodyStart, bodyEnd);
    let rewrittenBody = '';
    let bodyCursor = 0;
    let nestedDepth = 0;
    let entryStart = true;
    for (let index = 0; index < body.length;) {
      const character = body[index];
      if ((character === '"' || character === "'") && nestedDepth === 0) {
        const tokenQuote = character;
        let tokenEnd = index + 1;
        let tokenEscaped = false;
        for (; tokenEnd < body.length; tokenEnd += 1) {
          const tokenCharacter = body[tokenEnd];
          if (tokenEscaped) tokenEscaped = false;
          else if (tokenCharacter === '\\') tokenEscaped = true;
          else if (tokenCharacter === tokenQuote) break;
        }
        if (tokenEnd >= body.length) break;
        rewrittenBody += body.slice(bodyCursor, index);
        const raw = body.slice(index + 1, tokenEnd);
        rewrittenBody += `${tokenQuote}${entryStart ? transform(raw) : raw}${tokenQuote}`;
        bodyCursor = tokenEnd + 1;
        entryStart = false;
        index = tokenEnd + 1;
        continue;
      }
      if (character === '(') nestedDepth += 1;
      else if (character === ')') nestedDepth = Math.max(0, nestedDepth - 1);
      else if (character === ',' && nestedDepth === 0) entryStart = true;
      else if (!/\s/.test(character) && nestedDepth === 0) entryStart = false;
      index += 1;
    }
    rewrittenBody += body.slice(bodyCursor);
    output += source.slice(cursor, bodyStart) + rewrittenBody + ')';
    cursor = bodyEnd + 1;
    functionPattern.lastIndex = cursor;
  }
  return output + source.slice(cursor);
}

function rewriteCss(css, stylesheetUrl, resourceMap) {
  const localize = (raw, fallback) => {
    try {
      const absolute = new URL(raw, stylesheetUrl).href;
      if (resourceMap.has(absolute)) return resourceMap.get(absolute);
      const withoutFragment = new URL(absolute);
      const fragment = withoutFragment.hash;
      withoutFragment.hash = '';
      if (resourceMap.has(withoutFragment.href)) return `${resourceMap.get(withoutFragment.href)}${fragment}`;
      return ['http:', 'https:'].includes(withoutFragment.protocol) ? fallback : absolute;
    } catch {
      return fallback;
    }
  };
  const rewritten = css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, raw) => {
      if (!raw || raw.startsWith('data:') || raw.startsWith('#')) return match;
      return `url("${localize(raw, 'data:,')}")`;
    })
    .replace(/@import\s+(['"])(.*?)\1/gi, (match, quote, raw) => `@import "${localize(raw, 'data:text/css,')}"`);
  return transformImageSetQuotedUrls(rewritten, (raw) => {
    if (!raw || raw.startsWith('data:') || raw.startsWith('#')) return raw;
    return localize(raw, 'data:,');
  });
}

function cssDependencies(css, stylesheetUrl) {
  const urls = [];
  const add = (raw) => {
    if (!raw || raw.startsWith('data:') || raw.startsWith('#')) return;
    try {
      const resolved = new URL(raw, stylesheetUrl);
      resolved.hash = '';
      if (['http:', 'https:'].includes(resolved.protocol)) urls.push(resolved.href);
    } catch {
      // Invalid CSS URLs remain fail-closed during rewriting.
    }
  };
  css.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, raw) => { add(raw); return match; });
  css.replace(/@import\s+(['"])(.*?)\1/gi, (match, quote, raw) => { add(raw); return match; });
  transformImageSetQuotedUrls(css, (raw) => { add(raw); return raw; });
  return [...new Set(urls)];
}

export function cssDependencyReferer(rawReferer, rawDestination) {
  try {
    const referer = new URL(rawReferer);
    const destination = new URL(rawDestination);
    if (!['http:', 'https:'].includes(referer.protocol) || !['http:', 'https:'].includes(destination.protocol)) return '';
    referer.username = '';
    referer.password = '';
    referer.hash = '';
    if (referer.origin === destination.origin) return referer.href;
    return `${referer.origin}/`;
  } catch {
    return '';
  }
}

export async function fetchCssDependency(initialUrl, referer, options) {
  const aliases = [];
  let current = initialUrl;
  let allowedLoopbackUrl = null;
  try {
    const allowed = new URL(options.allowedOrigin);
    if (isLoopbackHostname(allowed.hostname)) allowedLoopbackUrl = allowed.href;
  } catch {}
  for (let redirect = 0; redirect <= 5; redirect += 1) {
    try {
      const safeReferer = cssDependencyReferer(referer, current);
      const response = await requestPinnedHttpResource(current, {
        allowedLoopbackUrl,
        resolver: options.resolver,
        addressIsBlocked: options.addressIsBlocked,
        timeoutMs: options.timeoutMs,
        maximumBytes: options.maximumBytes,
        headers: {
          accept: 'text/css,*/*;q=0.8',
          ...(safeReferer ? { referer: safeReferer } : {}),
          'user-agent': options.userAgent
        }
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.location;
        if (!location || redirect === 5) throw new Error('REDIRECT_LIMIT');
        aliases.push(current);
        current = new URL(location, current).href;
        continue;
      }
      if (response.status < 200 || response.status >= 300) throw new Error(`HTTP_${response.status}`);
      return {
        url: response.url || current,
        aliases: [...aliases, ...(current === initialUrl ? [] : [initialUrl])],
        body: response.body,
        contentType: response.headers['content-type'] || '',
        resourceType: normalizedContentType(response.headers['content-type']) === 'text/css' ? 'stylesheet' : 'asset'
      };
    } catch (error) {
      if (error?.code === 'PRIVATE_OR_RESERVED_DESTINATION') throw new Error('PRIVATE_DESTINATION');
      if (error?.code === 'RESOURCE_LIMIT') throw new Error('RESOURCE_LIMIT');
      throw error;
    }
  }
  throw new Error('REDIRECT_LIMIT');
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }

  const outputParent = dirname(options.out);
  await fs.mkdir(outputParent, { recursive: true });
  let outputExisted = false;
  try {
    const entries = await fs.readdir(options.out);
    outputExisted = true;
    if (entries.length) throw new Error(`Refusing to overwrite non-empty directory: ${options.out}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const outputDirectory = await fs.mkdtemp(join(outputParent, '.replicate-websites-staging-'));
  try {
    await execFileAsync(process.execPath, [
      join(skillDirectory, 'scripts', 'scaffold-replica.mjs'),
      '--out', outputDirectory,
      '--name', options.name,
      '--mode', options.mode
    ]);
    const assetsDirectory = join(outputDirectory, 'public', 'snapshot-assets');
    await fs.mkdir(assetsDirectory, { recursive: true });

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
        '--force-color-profile=srgb',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--webrtc-ip-handling-policy=disable_non_proxied_udp'
      ],
      ...(executablePath ? { executablePath } : {})
    });
    let context;
    let transport;
    let capturedResourceCount = 0;
    let capturedResourceBytes = 0;
    try {
    transport = await createValidatingBrowserProxy({
      allowedLoopbackUrl: isLoopbackHostname(options.parsedUrl.hostname) ? options.parsedUrl.href : null
    });
    context = await browser.newContext({
      viewport: options.viewport,
      deviceScaleFactor: 1,
      locale: 'en-US',
      timezoneId: 'UTC',
      colorScheme: 'light',
      reducedMotion: 'reduce',
      serviceWorkers: 'block',
      proxy: transport.playwright
    });
    const blockedWrites = [];
    const blockedPrivateReads = [];
    const blockedRequestLimit = [];
    const runtimeAttempts = createRuntimeAttemptTelemetry();
    let networkRequestCount = 0;
    await context.route('**/*', async (route) => {
      const request = route.request();
      networkRequestCount += 1;
      if (networkRequestCount > options.maxNetworkRequests) {
        if (blockedRequestLimit.length < 100) {
          blockedRequestLimit.push({ method: request.method(), resourceType: request.resourceType(), ...publicResourceDescriptor(request.url()) });
        }
        return route.abort('blockedbyclient');
      }
      if (blocksUnsafeDestinationBeforeProxy(request.url(), options.parsedUrl.origin)) {
        blockedPrivateReads.push({ method: request.method(), resourceType: request.resourceType(), ...publicResourceDescriptor(request.url()) });
        return route.abort('blockedbyclient');
      }
      if (['GET', 'HEAD', 'OPTIONS'].includes(request.method())) return route.continue();
      blockedWrites.push({ method: request.method(), resourceType: request.resourceType(), ...publicResourceDescriptor(request.url()) });
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
    await page.exposeBinding('__replicaReportRuntimeAttempt', (_source, attempt) => {
      recordRuntimeAttempt(runtimeAttempts, attempt?.kind, {
        url: attempt?.url || '',
        target: attempt?.target || '',
        scope: attempt?.scope || '',
        payloadPresent: attempt?.payloadPresent === true,
        observedBy: 'init-script'
      });
    });
    await page.addInitScript(integrityNativeInitScript);
    await page.addInitScript(runtimeAttemptInitScript, { blockEffects: true });
    await page.addInitScript(() => {
      try { HTMLFormElement.prototype.submit = () => {}; } catch {}
      try { HTMLFormElement.prototype.requestSubmit = () => {}; } catch {}
    });
    page.on('popup', (popup) => {
      recordRuntimeAttempt(runtimeAttempts, 'popup', { url: popup.url(), observedBy: 'page-event' });
      popup.close().catch(() => {});
    });
    page.on('download', (download) => {
      recordRuntimeAttempt(runtimeAttempts, 'download', { url: download.url(), observedBy: 'page-event' });
      download.cancel().catch(() => {});
    });

    const resources = new Map();
    const knownResourceUrls = new Set();
    const capturing = new Set();
    const pending = new Set();
    const skippedResources = [];
    let skippedResourceCount = 0;
    let totalResourceBytes = 0;
    const recordSkipped = (entry) => {
      skippedResourceCount += 1;
      if (skippedResources.length < 500) skippedResources.push(entry);
    };

    const captureResponse = async (response) => {
      const request = response.request();
      const url = response.url();
      const contentType = response.headers()['content-type'] || '';
      const type = request.resourceType();
      const captureType = ['stylesheet', 'font', 'image', 'media'].includes(type)
        || /^(?:text\/css|font\/|image\/|video\/|audio\/|application\/(?:font|vnd\.ms-fontobject))/i.test(contentType);
      if (request.method() !== 'GET' || !response.ok() || !captureType || resources.has(url) || capturing.has(url)) return;
      if (resources.size + capturing.size >= options.maxResources) {
        recordSkipped({ ...publicResourceDescriptor(url), reason: 'resource-count-limit' });
        return;
      }
      capturing.add(url);
      try {
        const declaredLength = Number(response.headers()['content-length'] || 0);
        if (declaredLength > options.maxResourceBytes) {
          recordSkipped({ ...publicResourceDescriptor(url), reason: 'declared-resource-limit', bytes: declaredLength });
          return;
        }
        const body = await withTimeout(response.body(), options.resourceTimeoutMs, `Resource body ${publicResourceDescriptor(url).pathname}`);
        if (body.length > options.maxResourceBytes) {
          recordSkipped({ ...publicResourceDescriptor(url), reason: 'resource-limit', bytes: body.length });
          return;
        }
        if (totalResourceBytes + body.length > options.maxTotalBytes) {
          recordSkipped({ ...publicResourceDescriptor(url), reason: 'aggregate-limit', bytes: body.length });
          return;
        }
        totalResourceBytes += body.length;
        const aliases = [];
        for (let prior = request.redirectedFrom(); prior; prior = prior.redirectedFrom()) aliases.push(prior.url());
        resources.set(url, { body, contentType, resourceType: type, aliases });
        knownResourceUrls.add(url);
        for (const alias of aliases) knownResourceUrls.add(alias);
      } catch {
        recordSkipped({ ...publicResourceDescriptor(url), reason: 'body-unavailable' });
      } finally {
        capturing.delete(url);
      }
    };
    page.on('response', (response) => {
      const task = captureResponse(response);
      pending.add(task);
      task.finally(() => pending.delete(task));
    });

    const navigation = await page.goto(options.url, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs });
    if (!navigation?.ok()) throw new Error(`Navigation returned HTTP ${navigation?.status() ?? 'unknown'}.`);
    try {
      await page.waitForLoadState('networkidle', { timeout: Math.min(options.timeoutMs, 10000) });
    } catch {
      // Explicit settling below is authoritative for long-polling sites.
    }
    await page.locator(options.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
    await assertBootstrapPageIntegrity(page);
    const transientStyle = await page.addStyleTag({ content: `
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
    await transientStyle.evaluate((element) => element.setAttribute('data-replica-bootstrap-transient', ''));
    await page.evaluate(() => {
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
        style.setAttribute('data-replica-bootstrap-transient', '');
        style.textContent = freezeCss;
        root.append(style);
      }
      for (const root of [document, ...shadowRoots]) {
        for (const animation of root.getAnimations?.({ subtree: true }) || []) animation.finish?.();
      }
      for (const media of activeElements.filter((element) => element.matches('video, audio'))) media.pause?.();
    });

    const uniqueViewports = [];
    for (const viewport of [options.viewport, ...defaultAssetViewports]) {
      if (!uniqueViewports.some((candidate) => candidate.width === viewport.width && candidate.height === viewport.height)) {
        uniqueViewports.push(viewport);
      }
    }
    for (const viewport of uniqueViewports) await exerciseViewport(page, viewport, options.autoScroll, options.maxScrollSteps);
    await exerciseViewport(page, options.viewport, options.autoScroll, options.maxScrollSteps);
    await page.locator(options.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
    if (options.waitMs) await page.waitForTimeout(options.waitMs);
    await drainPending(pending);

    const browserUserAgent = await page.evaluate(() => navigator.userAgent);
    const cssQueue = [...resources.entries()]
      .filter(([, resource]) => normalizedContentType(resource.contentType) === 'text/css')
      .map(([url]) => url);
    const processedCss = new Set();
    for (let queueIndex = 0; queueIndex < cssQueue.length; queueIndex += 1) {
      const stylesheetUrl = cssQueue[queueIndex];
      if (processedCss.has(stylesheetUrl)) continue;
      processedCss.add(stylesheetUrl);
      const stylesheet = resources.get(stylesheetUrl);
      if (!stylesheet) continue;
      for (const dependencyUrl of cssDependencies(stylesheet.body.toString('utf8'), stylesheetUrl)) {
        if (knownResourceUrls.has(dependencyUrl)) continue;
        if (resources.size >= options.maxResources) {
          recordSkipped({ ...publicResourceDescriptor(dependencyUrl), reason: 'resource-count-limit' });
          continue;
        }
        networkRequestCount += 1;
        if (networkRequestCount > options.maxNetworkRequests) {
          recordSkipped({ ...publicResourceDescriptor(dependencyUrl), reason: 'network-request-limit' });
          continue;
        }
        try {
          const fetched = await fetchCssDependency(dependencyUrl, stylesheetUrl, {
            allowedOrigin: options.parsedUrl.origin,
            maximumBytes: options.maxResourceBytes,
            timeoutMs: options.resourceTimeoutMs,
            userAgent: browserUserAgent
          });
          const contentType = normalizedContentType(fetched.contentType);
          const captureType = contentType === 'text/css'
            || /^(?:font\/|image\/|video\/|audio\/|application\/(?:font|vnd\.ms-fontobject))/i.test(contentType)
            || /\.(?:avif|css|eot|gif|ico|jpe?g|otf|png|svg|ttf|web[mp]|woff2?)(?:$|\?)/i.test(fetched.url);
          if (!captureType) {
            recordSkipped({ ...publicResourceDescriptor(dependencyUrl), reason: 'unsupported-content-type' });
            continue;
          }
          if (totalResourceBytes + fetched.body.length > options.maxTotalBytes) {
            recordSkipped({ ...publicResourceDescriptor(dependencyUrl), reason: 'aggregate-limit', bytes: fetched.body.length });
            continue;
          }
          totalResourceBytes += fetched.body.length;
          const aliases = [...new Set([dependencyUrl, ...fetched.aliases].filter((alias) => alias !== fetched.url))];
          resources.set(fetched.url, { ...fetched, aliases });
          knownResourceUrls.add(fetched.url);
          for (const alias of aliases) knownResourceUrls.add(alias);
          if (contentType === 'text/css') cssQueue.push(fetched.url);
        } catch (error) {
          recordSkipped({
            ...publicResourceDescriptor(dependencyUrl),
            reason: ['PRIVATE_DESTINATION', 'RESOURCE_LIMIT', 'REDIRECT_LIMIT'].includes(error.message)
              ? error.message.toLowerCase().replaceAll('_', '-')
              : 'dependency-fetch-failed'
          });
        }
      }
    }

    const resourceMap = new Map();
    for (const [url, resource] of resources) {
      const digest = createHash('sha256').update(url).digest('hex').slice(0, 20);
      const filename = `${digest}${extension(url, resource.contentType)}`;
      const local = `/snapshot-assets/${filename}`;
      resourceMap.set(url, local);
      for (const alias of resource.aliases) resourceMap.set(alias, local);
    }

    for (const [url, resource] of resources) {
      const local = resourceMap.get(url);
      const pathname = join(outputDirectory, 'public', local);
      const body = normalizedContentType(resource.contentType) === 'text/css'
        ? Buffer.from(rewriteCss(resource.body.toString('utf8'), url, resourceMap))
        : resource.body;
      await fs.writeFile(pathname, body);
    }

    await assertBootstrapPageIntegrity(page);
    const serialization = await page.evaluate(({ map, mode, safeSource, syntheticHiddenValue }) => {
      const integrityNatives = globalThis.__replicaIntegrityNatives;
      if (!integrityNatives) {
        throw new Error('Rendered-DOM bootstrap integrity state is unavailable.');
      }
      const initialElements = integrityNatives.queryAll(document, '*');
      if (integrityNatives.auditElements(initialElements, 1).length !== 0) {
        throw new Error('Rendered-DOM bootstrap integrity validation failed.');
      }
      const sourceDocument = document.documentElement;
      const clone = integrityNatives.cloneNode(sourceDocument, true);
      const originals = [];
      const copies = [];
      const pairRoot = (originalRoot, copyRoot) => {
        const originalChildren = integrityNatives.toArray(originalRoot.children);
        const copyChildren = integrityNatives.arraySlice(integrityNatives.toArray(copyRoot.children), 0, originalChildren.length);
        for (let index = 0; index < originalChildren.length; index += 1) {
          if (copyChildren[index]) pairElement(originalChildren[index], copyChildren[index]);
        }
      };
      const pairElement = (original, copy) => {
        integrityNatives.arrayPush(originals, original);
        integrityNatives.arrayPush(copies, copy);
        if (original instanceof HTMLTemplateElement && copy instanceof HTMLTemplateElement) {
          pairRoot(original.content, copy.content);
        }
        const originalChildren = integrityNatives.toArray(original.children);
        const copyChildren = integrityNatives.arraySlice(integrityNatives.toArray(copy.children), 0, originalChildren.length);
        for (let index = 0; index < originalChildren.length; index += 1) {
          if (copyChildren[index]) pairElement(originalChildren[index], copyChildren[index]);
        }
        const originalShadowRoot = integrityNatives.shadowRoot(original);
        if (originalShadowRoot?.mode === 'open') {
          const shadowTemplate = document.createElement('template');
          shadowTemplate.setAttribute('shadowrootmode', 'open');
          shadowTemplate.setAttribute('data-replica-open-shadow-root', '');
          for (const child of integrityNatives.toArray(originalShadowRoot.childNodes)) {
            integrityNatives.appendChild(shadowTemplate.content, integrityNatives.cloneNode(child, true));
          }
          integrityNatives.appendChild(copy, shadowTemplate);
          pairRoot(originalShadowRoot, shadowTemplate.content);
        }
      };
      pairElement(sourceDocument, clone);
      if (integrityNatives.auditElements(originals, 1).length !== 0
        || integrityNatives.auditElements(copies, 1).length !== 0) {
        throw new Error('Rendered-DOM bootstrap element integrity validation failed.');
      }
      const copyByOriginal = integrityNatives.createMap(integrityNatives.arrayMap(
        originals,
        (original, index) => [original, copies[index]]
      ));
      const activeOriginals = [];
      const collectActiveOriginals = (root) => {
        const elements = integrityNatives.queryAll(root, '*');
        for (let index = 0; index < elements.length; index += 1) {
          const element = elements[index];
          integrityNatives.arrayPush(activeOriginals, element);
          const shadowRoot = integrityNatives.shadowRoot(element);
          if (shadowRoot) collectActiveOriginals(shadowRoot);
        }
      };
      collectActiveOriginals(document);
      const activeForms = integrityNatives.arrayFilter(activeOriginals, (element) => integrityNatives.matches(element, 'form'));
      const absolute = (value) => {
        try {
          return integrityNatives.urlHref(integrityNatives.createUrl(value, integrityNatives.baseUri(document)));
        } catch {
          return value;
        }
      };
      const mapped = (value, fallback = 'data:,') => {
        const resolved = absolute(value);
        if (map[resolved]) return map[resolved];
        try {
          const withoutFragment = integrityNatives.createUrl(resolved);
          const fragment = integrityNatives.urlHash(withoutFragment);
          integrityNatives.setUrlHash(withoutFragment, '');
          const href = integrityNatives.urlHref(withoutFragment);
          if (map[href]) return `${map[href]}${fragment}`;
          return integrityNatives.arrayIncludes(
            ['http:', 'https:'],
            integrityNatives.urlProtocol(withoutFragment)
          ) ? fallback : resolved;
        } catch { return fallback; }
      };
      const transformImageSetQuotedUrls = (css, transform) => {
        const source = String(css || '');
        const functionPattern = /(?:-webkit-)?image-set\(/gi;
        let output = '';
        let cursor = 0;
        let match;
        while ((match = functionPattern.exec(source))) {
          const bodyStart = match.index + match[0].length;
          let depth = 1;
          let quote = '';
          let escaped = false;
          let bodyEnd = -1;
          for (let index = bodyStart; index < source.length; index += 1) {
            const character = source[index];
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
          if (bodyEnd < 0) break;
          const body = source.slice(bodyStart, bodyEnd);
          let rewrittenBody = '';
          let bodyCursor = 0;
          let nestedDepth = 0;
          let entryStart = true;
          for (let index = 0; index < body.length;) {
            const character = body[index];
            if ((character === '"' || character === "'") && nestedDepth === 0) {
              const tokenQuote = character;
              let tokenEnd = index + 1;
              let tokenEscaped = false;
              for (; tokenEnd < body.length; tokenEnd += 1) {
                const tokenCharacter = body[tokenEnd];
                if (tokenEscaped) tokenEscaped = false;
                else if (tokenCharacter === '\\') tokenEscaped = true;
                else if (tokenCharacter === tokenQuote) break;
              }
              if (tokenEnd >= body.length) break;
              rewrittenBody += body.slice(bodyCursor, index);
              const raw = body.slice(index + 1, tokenEnd);
              rewrittenBody += `${tokenQuote}${entryStart ? transform(raw) : raw}${tokenQuote}`;
              bodyCursor = tokenEnd + 1;
              entryStart = false;
              index = tokenEnd + 1;
              continue;
            }
            if (character === '(') nestedDepth += 1;
            else if (character === ')') nestedDepth = Math.max(0, nestedDepth - 1);
            else if (character === ',' && nestedDepth === 0) entryStart = true;
            else if (!/\s/.test(character) && nestedDepth === 0) entryStart = false;
            index += 1;
          }
          rewrittenBody += body.slice(bodyCursor);
          output += source.slice(cursor, bodyStart) + rewrittenBody + ')';
          cursor = bodyEnd + 1;
          functionPattern.lastIndex = cursor;
        }
        return output + source.slice(cursor);
      };
      const rewriteCssText = (css) => {
        const rewritten = css.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, raw) => {
          if (!raw || raw.startsWith('data:') || raw.startsWith('#')) return match;
          return `url("${mapped(raw)}")`;
        })
        .replace(/@import\s+(['"])(.*?)\1/gi, (match, quote, raw) => `@import "${mapped(raw, 'data:text/css,')}"`);
        return transformImageSetQuotedUrls(rewritten, (raw) => {
          if (!raw || raw.startsWith('data:') || raw.startsWith('#')) return raw;
          return mapped(raw);
        });
      };
      const clean = (value) => integrityNatives.stringTrim(
        integrityNatives.stringReplace(integrityNatives.string(value ?? ''), /\s+/g, ' ')
      );
      const carrierDepthLimit = 8;
      const carrierValueLengthLimit = 64 * 1024;
      const decodedCarrierCandidates = (value) => {
        const candidates = [];
        let current = integrityNatives.string(value ?? '');
        for (let depth = 0; depth <= 4; depth += 1) {
          if (!integrityNatives.arrayIncludes(candidates, current)) integrityNatives.arrayPush(candidates, current);
          if (current.length > carrierValueLengthLimit) break;
          try {
            const decoded = integrityNatives.decodeURIComponent(
              integrityNatives.stringReplace(current, /\+/g, '%20')
            );
            if (decoded === current) break;
            if (depth === 4) {
              candidates.decodeLimitExceeded = true;
              break;
            }
            current = decoded;
          } catch {
            break;
          }
        }
        return candidates;
      };
      const sensitiveCarrierKey = (value) => {
        const decoded = decodedCarrierCandidates(value);
        if (decoded.decodeLimitExceeded) return true;
        return integrityNatives.arraySome(decoded, (candidate) => {
          const separated = integrityNatives.arrayFilter(
            integrityNatives.stringSplit(
              integrityNatives.stringToLowerCase(
                integrityNatives.stringReplace(
                  integrityNatives.string(candidate),
                  /([a-z0-9])([A-Z])/g,
                  '$1 $2'
                )
              ),
              /[^a-z0-9]+/
            ),
            (part) => part.length > 0
          );
          const compact = integrityNatives.arrayJoin(separated, '');
          return integrityNatives.arraySome(separated, (part) => integrityNatives.arrayIncludes([
            'auth', 'authorization', 'credential', 'credentials', 'csrf', 'jwt', 'password',
            'secret', 'session', 'signature', 'sitekey', 'token'
          ], part)) || integrityNatives.arraySome([
            'accesstoken', 'apikey', 'authtoken', 'bearertoken', 'clientsecret', 'refreshtoken',
            'samlresponse', 'sessionid', 'sessiontoken', 'signedtoken'
          ], (key) => integrityNatives.stringIncludes(compact, key));
        });
      };
      const regexpMatches = (value, pattern, limit = 10000) => {
        const matches = [];
        pattern.lastIndex = 0;
        while (matches.length < limit) {
          const match = integrityNatives.regexpExec(pattern, value);
          if (!match) break;
          integrityNatives.arrayPush(matches, match);
          if (match[0] === '') pattern.lastIndex += 1;
        }
        if (matches.length === limit && integrityNatives.regexpExec(pattern, value)) {
          throw new Error('Credential carrier pattern match limit exceeded.');
        }
        return matches;
      };
      const credentialValuePattern = /(?:^|[^a-z0-9])(?:bearer\s+[a-z0-9._~+/=-]{8,}|sk_(?:live|test)_[a-z0-9]{8,}|gh[pousr]_[a-z0-9]{8,}|akia[a-z0-9]{12,}|eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,})(?:$|[^a-z0-9])/i;
      const carrierContainsCredentials = (rawValue) => {
        const inspectValue = (value, depth) => {
          if (depth > carrierDepthLimit) return true;
          if (value === null || value === undefined || value === false || value === true || typeof value === 'number') return false;
          if (integrityNatives.arrayIsArray(value)) {
            return integrityNatives.arraySome(value, (entry) => inspectValue(entry, depth + 1));
          }
          if (typeof value === 'object') {
            return integrityNatives.arraySome(
              integrityNatives.objectEntries(value),
              ([key, entry]) => (sensitiveCarrierKey(key) && integrityNatives.string(entry ?? '').length > 0)
                || inspectValue(entry, depth + 1)
            );
          }
          const source = integrityNatives.string(value);
          if (source.length > carrierValueLengthLimit) return true;
          const decoded = decodedCarrierCandidates(source);
          if (decoded.decodeLimitExceeded) return true;
          for (let candidateIndex = 0; candidateIndex < decoded.length; candidateIndex += 1) {
            const candidate = decoded[candidateIndex];
            const trimmed = integrityNatives.stringTrim(candidate);
            if (!trimmed) continue;
            if (integrityNatives.regexpTest(credentialValuePattern, trimmed)) return true;

            if (integrityNatives.regexpTest(/^[\[{]/, trimmed)) {
              try {
                if (inspectValue(integrityNatives.jsonParse(trimmed), depth + 1)) return true;
              } catch {
                const suspiciousStructuredKey = /(?:^|[,{\s])['"]?([a-z0-9_.-]{2,80})['"]?\s*:/gi;
                const structuredMatches = regexpMatches(trimmed, suspiciousStructuredKey);
                for (let index = 0; index < structuredMatches.length; index += 1) {
                  const match = structuredMatches[index];
                  if (sensitiveCarrierKey(match[1])) return true;
                }
              }
            }

            const keyValuePattern = /(?:^|[?&#;,\s{[(])['"]?([a-z0-9_.-]{2,80})['"]?\s*(?:=|:)/gi;
            const keyValueMatches = regexpMatches(trimmed, keyValuePattern);
            for (let index = 0; index < keyValueMatches.length; index += 1) {
              const match = keyValueMatches[index];
              if (sensitiveCarrierKey(match[1])) return true;
            }

            if (integrityNatives.stringIncludes(trimmed, '=')) {
              try {
                const parameters = integrityNatives.createUrlSearchParams(
                  integrityNatives.stringReplace(trimmed, /^[?#]/, '')
                );
                let parametersContainCredentials = false;
                integrityNatives.urlSearchParamsForEach(parameters, (entry, key) => {
                  if (!parametersContainCredentials
                    && ((sensitiveCarrierKey(key) && entry.length > 0) || inspectValue(entry, depth + 1))) {
                    parametersContainCredentials = true;
                  }
                });
                if (parametersContainCredentials) return true;
              } catch {
                return true;
              }
            }

            const urlCandidates = [];
            if (integrityNatives.regexpTest(/^(?:https?:\/\/|\/|\.\.?\/|\?)/i, trimmed)) {
              integrityNatives.arrayPush(urlCandidates, trimmed);
            }
            const absoluteUrlMatches = regexpMatches(trimmed, /https?:\/\/[^\s"'<>}\]]+/gi);
            for (let index = 0; index < absoluteUrlMatches.length; index += 1) {
              integrityNatives.arrayPush(urlCandidates, absoluteUrlMatches[index][0]);
            }
            const schemeRelativeMatches = regexpMatches(trimmed, /(?:^|[\s=("'])(\/\/[^\s"'<>}\]]+)/g);
            for (let index = 0; index < schemeRelativeMatches.length; index += 1) {
              integrityNatives.arrayPush(urlCandidates, schemeRelativeMatches[index][1]);
            }
            for (let urlIndex = 0; urlIndex < urlCandidates.length; urlIndex += 1) {
              const urlValue = urlCandidates[urlIndex];
              let parsed;
              try {
                parsed = integrityNatives.createUrl(urlValue, integrityNatives.baseUri(document));
              } catch {
                return true;
              }
              if (!integrityNatives.arrayIncludes(['http:', 'https:'], integrityNatives.urlProtocol(parsed))) continue;
              if (integrityNatives.urlUsername(parsed) || integrityNatives.urlPassword(parsed)) return true;
              let urlContainsCredentials = false;
              integrityNatives.urlSearchParamsForEach(integrityNatives.urlSearchParams(parsed), (entry, key) => {
                if (!urlContainsCredentials
                  && ((sensitiveCarrierKey(key) && entry.length > 0) || inspectValue(entry, depth + 1))) {
                  urlContainsCredentials = true;
                }
              });
              if (urlContainsCredentials) return true;
              const hash = integrityNatives.urlHash(parsed);
              if (hash && inspectValue(integrityNatives.stringSlice(hash, 1), depth + 1)) return true;
            }
          }
          return false;
        };
        return inspectValue(rawValue, 0);
      };
      const labelsFor = (element) => {
        const labels = [...(element.labels || [])];
        if (labels.length) return labels;
        if (!element.id) return [];
        return [...element.getRootNode().querySelectorAll('label[for]')].filter((label) => label.htmlFor === element.id);
      };
      const labelledByText = (element) => clean((element.getAttribute('aria-labelledby') || '')
        .split(/\s+/)
        .filter(Boolean)
        .map((id) => element.getRootNode()?.getElementById?.(id)?.textContent || document.getElementById(id)?.textContent || '')
        .join(' '));
      const accessibleName = (element) => {
        const aria = clean(element.getAttribute('aria-label')) || labelledByText(element);
        if (aria) return aria;
        const labelText = clean(labelsFor(element).map((label) => label.textContent).join(' '));
        if (labelText) return labelText;
        if (element.matches('button, a')) return clean(element.textContent);
        if (element.matches('input[type="button"], input[type="submit"]')) return clean(element.value);
        return clean(element.getAttribute('placeholder') || element.getAttribute('title') || element.getAttribute('alt'));
      };
      const occurrences = new Map();
      const controlKey = (control) => {
        const tag = control.tagName.toLowerCase();
        const type = tag === 'input' || tag === 'button' ? clean(control.type || tag) : tag;
        const name = String(control.getAttribute('name') || '');
        let base;
        if (name) {
          base = `name:${name}|${tag}:${type}`;
        } else if (accessibleName(control)) {
          base = `anonymous:${tag}:${type}|name:${accessibleName(control)}`;
        } else {
          base = `anonymous:${tag}:${type}`;
        }
        const occurrence = occurrences.get(base) || 0;
        occurrences.set(base, occurrence + 1);
        return { key: `${base}|#${occurrence}`, type };
      };
      const controlFingerprintByOriginal = new Map(activeOriginals
        .filter((element) => element.matches('input, select, textarea, button'))
        .map((control) => [control, controlKey(control)]));

      const approvedSemanticMismatches = [];
      const sanitization = {
        hiddenValues: 0,
        freeformValues: 0,
        choiceValues: 0,
        optionValues: 0,
        contentEditableValues: 0,
        sensitiveControls: 0,
        sensitiveAttributes: 0,
        sensitiveMetadata: 0
      };
      const linkPresentationDelta = (anchor) => {
        if (!anchor.hasAttribute('href')) return [];
        const href = anchor.getAttribute('href');
        const linkedStyle = getComputedStyle(anchor);
        const linkedValues = new Map([...linkedStyle].map((property) => [property, linkedStyle.getPropertyValue(property)]));
        anchor.removeAttribute('href');
        const inertStyle = getComputedStyle(anchor);
        const changed = [...linkedValues].filter(([property, value]) => inertStyle.getPropertyValue(property) !== value);
        anchor.setAttribute('href', href);
        return changed;
      };
      const linkPresentationByOriginal = new Map(activeOriginals
        .filter((element) => element.matches('a') && element.hasAttribute('href'))
        .map((anchor) => [anchor, linkPresentationDelta(anchor)]));
      const linkOccurrences = new Map();
      const activeAnchorKeyByOriginal = new Map(activeOriginals
        .filter((element) => element.matches('a'))
        .map((anchor) => {
          const base = `link:name:${clean(anchor.getAttribute('aria-label')) || clean(anchor.textContent)}`;
          const occurrence = linkOccurrences.get(base) || 0;
          linkOccurrences.set(base, occurrence + 1);
          return [anchor, `${base}|#${occurrence}`];
        }));
      for (const [anchor, activeKey] of activeAnchorKeyByOriginal) {
        const hasXlinkHref = anchor.hasAttribute('xlink:href')
          || anchor.hasAttributeNS('http://www.w3.org/1999/xlink', 'href');
        if (!anchor.hasAttribute('href') && !hasXlinkHref) continue;
        approvedSemanticMismatches.push({
          viewport: '*',
          category: 'links',
          kind: 'changed',
          key: activeKey,
          changeFields: ['href'],
          rationale: 'The replica removes the href so source navigation is structurally inert for every activation method.'
        });
      }
      for (const original of originals.filter((element) => element.matches?.('input, select, textarea, button'))) {
        const copy = copyByOriginal.get(original);
        const tag = original.tagName.toLowerCase();
        const fallbackType = tag === 'input' || tag === 'button' ? clean(original.type || tag) : tag;
        const fingerprint = controlFingerprintByOriginal.get(original) || { key: null, type: fallbackType };
        if (!copy) continue;
        if (fingerprint.type === 'hidden') {
          const liveHiddenValue = String(original.value || '');
          const safeHiddenValue = liveHiddenValue ? syntheticHiddenValue : '';
          copy.value = safeHiddenValue;
          copy.defaultValue = safeHiddenValue;
          copy.setAttribute('value', safeHiddenValue);
          if (liveHiddenValue || copy.getAttribute('value')) sanitization.hiddenValues += 1;
          if (liveHiddenValue && liveHiddenValue.length !== syntheticHiddenValue.length && fingerprint.key) {
            approvedSemanticMismatches.push({
              viewport: '*',
              category: 'controls',
              kind: 'changed',
              key: fingerprint.key,
              changeFields: ['hiddenValueLength'],
              rationale: 'The live opaque hidden value is replaced by a non-secret local placeholder.'
            });
          }
          continue;
        }

        const isFreeformInput = tag === 'input'
          && !['button', 'submit', 'reset', 'image', 'checkbox', 'radio', 'hidden'].includes(fingerprint.type);
        if (tag === 'textarea' || isFreeformInput) {
          const liveValue = String(original.value || '');
          try { copy.value = ''; } catch {}
          try { copy.defaultValue = ''; } catch {}
          copy.setAttribute('value', '');
          if (tag === 'textarea') copy.textContent = '';
          if (liveValue || original.getAttribute('value') || (tag === 'textarea' && original.textContent)) {
            sanitization.freeformValues += 1;
          }
          if (liveValue && fingerprint.key) {
            approvedSemanticMismatches.push({
              viewport: '*',
              category: 'controls',
              kind: 'changed',
              key: fingerprint.key,
              changeFields: ['valuePresent', 'valueLength', 'valueClassification', 'valueFingerprint'],
              rationale: 'A prefilled applicant value is removed from the local replica.'
            });
          }
          continue;
        }

        if (['checkbox', 'radio'].includes(fingerprint.type)) {
          const rawValue = String(original.value || '');
          const visibleName = accessibleName(original);
          const normalizedValue = clean(rawValue).toLowerCase();
          const valueIsVisible = normalizedValue && normalizedValue === clean(visibleName).toLowerCase();
          const commonEnum = /^(?:yes|no|true|false|on|off|none|null|0|1)$/i.test(rawValue);
          if (rawValue && !valueIsVisible && !commonEnum) {
            const safeValue = `synthetic-local-choice-${String(sanitization.choiceValues + 1).padStart(4, '0')}`;
            copy.value = safeValue;
            copy.setAttribute('value', safeValue);
            copy.checked = Boolean(original.checked);
            copy.defaultChecked = Boolean(original.defaultChecked);
            sanitization.choiceValues += 1;
          }
          continue;
        }

        if (tag === 'select') {
          const originalOptions = [...original.options];
          const copyOptions = [...copy.options];
          let sanitizedOptionCount = 0;
          let selectedValueChanged = false;
          let selectedLengthChanged = false;
          for (let optionIndex = 0; optionIndex < originalOptions.length; optionIndex += 1) {
            const originalOption = originalOptions[optionIndex];
            const copyOption = copyOptions[optionIndex];
            if (!copyOption) continue;
            const rawValue = String(originalOption.value || '');
            const normalizedValue = clean(rawValue).toLowerCase();
            const valueIsVisible = normalizedValue && normalizedValue === clean(originalOption.textContent).toLowerCase();
            const commonEnum = /^(?:yes|no|true|false|on|off|none|null|0|1)$/i.test(rawValue);
            if (!rawValue || valueIsVisible || commonEnum) continue;
            const selected = Boolean(originalOption.selected);
            const defaultSelected = Boolean(originalOption.defaultSelected);
            const safeValue = `synthetic-local-option-${String(sanitization.optionValues + 1).padStart(4, '0')}`;
            copyOption.value = safeValue;
            copyOption.setAttribute('value', safeValue);
            copyOption.selected = selected;
            copyOption.defaultSelected = defaultSelected;
            sanitization.optionValues += 1;
            sanitizedOptionCount += 1;
            if (selected) {
              selectedValueChanged = true;
              selectedLengthChanged ||= rawValue.length !== safeValue.length;
            }
          }
          if (sanitizedOptionCount && fingerprint.key) {
            const changeFields = ['optionsHash', 'options'];
            if (selectedValueChanged) changeFields.push('valueFingerprint');
            if (selectedLengthChanged) changeFields.push('valueLength');
            approvedSemanticMismatches.push({
              viewport: '*',
              category: 'controls',
              kind: 'changed',
              key: fingerprint.key,
              changeFields,
              rationale: 'Opaque option submission values are replaced with deterministic local tokens.'
            });
          }
        }
      }

      for (const original of originals.filter((element) => {
        const state = element.getAttribute?.('contenteditable');
        return state !== null && String(state).toLowerCase() !== 'false';
      })) {
        const copy = copyByOriginal.get(original);
        if (!copy) continue;
        if (copy.textContent || original.textContent) sanitization.contentEditableValues += 1;
        copy.replaceChildren();
      }

      activeForms.forEach((original, index) => {
        const copy = copyByOriginal.get(original);
        if (!copy) return;
        const changeFields = ['actionAttribute', 'action'];
        if (String(original.method || 'get').toLowerCase() !== 'post') {
          changeFields.push('methodAttribute', 'method');
        }
        approvedSemanticMismatches.push({
          viewport: '*',
          category: 'forms',
          kind: 'changed',
          key: `form:#${index}`,
          changeFields,
          rationale: 'The replica routes submission to its local synthetic endpoint.'
        });
      });

      for (let index = 0; index < copies.length; index += 1) {
        const original = originals[index];
        const copy = copies[index];
        if (!copy) continue;
        if (copy.matches?.([
          'script',
          'iframe',
          'object',
          'embed',
          'base',
          'link[rel="preload" i]',
          'link[rel="prefetch" i]',
          'link[rel="modulepreload" i]',
          'link[rel="preconnect" i]',
          'link[rel="dns-prefetch" i]',
          'link[rel="manifest" i]',
          'meta[http-equiv="refresh" i]',
          '[data-replica-bootstrap-transient]'
        ].join(', '))) {
          copy.remove();
          continue;
        }
        for (const attribute of [...(copy.attributes || [])]) {
          if (/^on/i.test(attribute.name) || ['nonce', 'integrity', 'ping', 'srcdoc'].includes(attribute.name.toLowerCase())) {
            copy.removeAttribute(attribute.name);
            continue;
          }
          if (/(?:captcha|csrf|token|secret|authorization|signature|sitekey)/i.test(attribute.name) && attribute.value) {
            copy.setAttribute(attribute.name, syntheticHiddenValue);
            sanitization.sensitiveAttributes += 1;
            continue;
          }
          if (/^data-/i.test(attribute.name) && attribute.value && carrierContainsCredentials(attribute.value)) {
            copy.setAttribute(attribute.name, syntheticHiddenValue);
            sanitization.sensitiveAttributes += 1;
          }
        }
        for (const attribute of ['src', 'href', 'poster', 'background']) {
          const value = original?.getAttribute?.(attribute);
          if (attribute === 'href' && original?.matches?.('a, area')) {
            if (!original.hasAttribute('href')) {
              copy.removeAttribute('href');
              continue;
            }
            if (/^javascript:/i.test(value || '')) {
              copy.removeAttribute(attribute);
              continue;
            }
            copy.removeAttribute(attribute);
            copy.setAttribute('data-replica-source-link', '');
            if (!copy.hasAttribute('role')) copy.setAttribute('role', 'link');
            if (!copy.hasAttribute('tabindex')) copy.setAttribute('tabindex', '0');
            for (const [property, computedValue] of linkPresentationByOriginal.get(original) || []) {
              copy.style.setProperty(property, computedValue, 'important');
            }
            continue;
          }
          if (!value) continue;
          if (/^javascript:/i.test(value)) {
            copy.removeAttribute(attribute);
            continue;
          }
          if (!value.startsWith('#')) {
            copy.setAttribute(attribute, mapped(value));
          }
        }
        const srcset = original?.getAttribute?.('srcset');
        if (srcset) {
          copy.setAttribute('srcset', srcset.split(',').map((entry) => {
            const [url, descriptor] = entry.trim().split(/\s+/, 2);
            return `${mapped(url)}${descriptor ? ` ${descriptor}` : ''}`;
          }).join(', '));
        }
        const xlinkHref = original?.getAttribute?.('xlink:href')
          ?? original?.getAttributeNS?.('http://www.w3.org/1999/xlink', 'href');
        if (original?.matches?.('a') && xlinkHref !== null && xlinkHref !== undefined) {
          copy.removeAttribute('xlink:href');
          copy.removeAttributeNS?.('http://www.w3.org/1999/xlink', 'href');
          copy.setAttribute('data-replica-source-link', '');
          if (!copy.hasAttribute('role')) copy.setAttribute('role', 'link');
          if (!copy.hasAttribute('tabindex')) copy.setAttribute('tabindex', '0');
        } else if (xlinkHref) {
          copy.setAttribute('xlink:href', xlinkHref.startsWith('#') ? xlinkHref : mapped(xlinkHref));
        }
        if (copy.matches?.('form')) {
          copy.setAttribute('action', '/api/applications');
          copy.setAttribute('method', 'post');
          copy.removeAttribute('target');
        }
        if (copy.hasAttribute?.('formaction')) copy.setAttribute('formaction', '/api/applications');
        if (copy.hasAttribute?.('formmethod')) copy.setAttribute('formmethod', 'post');
        if (copy.hasAttribute?.('formtarget')) copy.removeAttribute('formtarget');
        if (copy.matches?.('style')) copy.textContent = rewriteCssText(copy.textContent || '');
        if (copy.hasAttribute?.('style')) copy.setAttribute('style', rewriteCssText(copy.getAttribute('style') || ''));
        for (const presentationAttribute of [
          'clip-path', 'cursor', 'fill', 'filter', 'marker-end', 'marker-mid', 'marker-start', 'mask', 'stroke'
        ]) {
          if (copy.hasAttribute?.(presentationAttribute)) {
            copy.setAttribute(presentationAttribute, rewriteCssText(copy.getAttribute(presentationAttribute) || ''));
          }
        }
      }
      for (const meta of copies.filter((element) => element.matches?.('meta[http-equiv="Content-Security-Policy" i]'))) meta.remove();
      for (const meta of copies.filter((element) => element.matches?.('meta[content]'))) {
        const identity = [
          meta.getAttribute('name'), meta.getAttribute('http-equiv'), meta.getAttribute('property'), meta.getAttribute('itemprop')
        ].filter(Boolean).join(' ');
        const content = meta.getAttribute('content');
        if (content && (/(?:captcha|csrf|token|secret|authorization|signature)/i.test(identity)
          || carrierContainsCredentials(content))) {
          meta.setAttribute('content', syntheticHiddenValue);
          sanitization.sensitiveMetadata += 1;
        }
      }
      const removeComments = (root) => {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_COMMENT);
        const comments = [];
        while (walker.nextNode()) comments.push(walker.currentNode);
        for (const comment of comments) comment.remove();
        for (const template of root.querySelectorAll?.('template') || []) removeComments(template.content);
      };
      removeComments(clone);

      const policy = document.createElement('meta');
      policy.httpEquiv = 'Content-Security-Policy';
      policy.content = [
        "default-src 'self' data: blob:",
        "base-uri 'none'",
        "connect-src 'self'",
        "font-src 'self' data:",
        "form-action 'self'",
        "frame-src 'none'",
        "img-src 'self' data: blob:",
        "media-src 'self' data: blob:",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline' data:",
        "worker-src 'self' blob:"
      ].join('; ');
      clone.querySelector('head')?.prepend(policy);
      const marker = document.createElement('meta');
      marker.name = 'replica-mode';
      marker.content = mode;
      clone.querySelector('head')?.append(marker);
      const script = document.createElement('script');
      script.src = '/app.js';
      script.defer = true;
      clone.querySelector('body')?.append(script);
      clone.querySelector('body')?.setAttribute('data-replica-ready', '');
      clone.setAttribute('data-source-provenance', safeSource);
      const finalCopies = [clone];
      const cloneDescendants = integrityNatives.queryAll(clone, '*');
      for (let index = 0; index < cloneDescendants.length; index += 1) {
        integrityNatives.arrayPush(finalCopies, cloneDescendants[index]);
      }
      if (integrityNatives.auditElements(originals, 1).length !== 0
        || integrityNatives.auditElements(finalCopies, 1).length !== 0) {
        throw new Error('Rendered-DOM bootstrap integrity changed during sanitization.');
      }
      return {
        html: `<!doctype html>\n${integrityNatives.outerHTML(clone)}`,
        approvedSemanticMismatches,
        sanitization,
        formCount: activeForms.length
      };
    }, {
      map: Object.fromEntries(resourceMap),
      mode: options.mode,
      safeSource: options.provenance.source,
      syntheticHiddenValue: 'synthetic-local'
    });

    const htmlBytes = Buffer.byteLength(serialization.html);
    if (htmlBytes > options.maxHtmlBytes) {
      throw new Error(`Serialized HTML is ${htmlBytes} bytes, above --max-html-bytes ${options.maxHtmlBytes}.`);
    }
    await fs.writeFile(join(outputDirectory, 'public', 'index.html'), serialization.html);

    const manifestPath = join(outputDirectory, 'replica.manifest.json');
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    manifest.page = {
      path: options.parsedUrl.pathname || '/',
      readySelector: '[data-replica-ready]'
    };
    manifest.interaction = serialization.formCount === 0
      ? {
          notApplicable: true,
          reason: 'The captured source state contains no application form.'
        }
      : {
          notApplicable: false,
          formSelector: serialization.formCount === 1 ? 'form' : null
        };
    manifest.provenance = {
      mode: options.mode,
      ...options.provenance,
      capturedWith: 'GET-only rendered-DOM bootstrap'
    };
    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    const provenance = { mode: options.mode, ...options.provenance };
    await fs.writeFile(
      join(outputDirectory, 'fidelity-policy.json'),
      `${JSON.stringify(exactPolicy(serialization.approvedSemanticMismatches, provenance), null, 2)}\n`
    );
    if (transport.stats.rejectedDestinations > 0) {
      blockedPrivateReads.push({
        method: 'PROXY',
        resourceType: 'transport',
        count: transport.stats.rejectedDestinations
      });
    }
    await fs.writeFile(join(outputDirectory, 'snapshot.json'), `${JSON.stringify({
      schemaVersion: 1,
      ...options.provenance,
      mode: options.mode,
      primaryViewport: options.viewport,
      capturedViewports: uniqueViewports,
      resourceCount: resources.size,
      resourceBytes: totalResourceBytes,
      resources: [...resources.entries()].map(([url, resource]) => ({
        ...publicResourceDescriptor(url),
        local: resourceMap.get(url),
        bytes: resource.body.length,
        contentType: normalizedContentType(resource.contentType),
        sha256: createHash('sha256').update(resource.body).digest('hex')
      })),
      skippedResources,
      skippedResourceCount,
      networkRequestCount,
      blockedWrites,
      blockedPrivateReads,
      validatingProxy: { ...transport.stats },
      blockedRequestLimit,
      runtimeAttemptCounts: Object.fromEntries(Object.entries(runtimeAttempts).map(([field, attempts]) => [
        field,
        attempts.length
      ])),
      sanitization: serialization.sanitization
    }, null, 2)}\n`);
    capturedResourceCount = resources.size;
    capturedResourceBytes = totalResourceBytes;

    } finally {
      if (context) await context.close().catch(() => {});
      await browser.close().catch(() => {});
      await transport?.close().catch(() => {});
    }

    if (outputExisted) {
      const entries = await fs.readdir(options.out);
      if (entries.length) throw new Error(`Output directory changed during capture; refusing to replace it: ${options.out}`);
      await fs.rmdir(options.out);
    }
    await fs.rename(outputDirectory, options.out);
    process.stdout.write(`Static replica: ${options.out} (${capturedResourceCount} localized resources, ${capturedResourceBytes} bytes)\n`);
  } catch (error) {
    await fs.rm(outputDirectory, { recursive: true, force: true }).catch(() => {});
    if (outputExisted) {
      try {
        await fs.access(options.out);
      } catch {
        await fs.mkdir(options.out, { recursive: true }).catch(() => {});
      }
    }
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}
