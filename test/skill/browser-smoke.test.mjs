import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer as createHttpServer } from 'node:http';
import { createServer } from 'node:net';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);
const skillRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../skills/replicate-websites');
const repositoryRoot = resolve(skillRoot, '../..');
const script = (name) => join(skillRoot, 'scripts', name);
const auditedBackend = {
  implementation: 'replicate-websites-starter-v1',
  submitPath: '/api/applications',
  auditPath: '/api/replica-audit',
  emailEnabledByDefault: false,
  retainsApplicantValues: false
};
const integrityManifest = (mode) => ({ schemaVersion: 1, mode, backend: auditedBackend });

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const port = server.address().port;
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

async function waitForHealth(url) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function closeHttpServer(server) {
  if (!server?.listening) return;
  await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
}

async function startAutowriteFixture(requests, nestedSecret) {
  const server = createHttpServer((request, response) => {
    requests.push({ method: request.method, url: request.url });
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><body><main><h1>Read-only baseline</h1>
        <a href="/next?token=${nestedSecret}">Signed diagnostic link</a>
        <img width="1" height="1" alt="" src="/pixel.svg?signature=${nestedSecret}">
        <script>fetch('/automatic-write', { method: 'POST', body: 'synthetic' })
          .catch(() => {}).finally(() => document.body.setAttribute('data-ready', ''));</script>
      </main></body></html>`);
      return;
    }
    if (request.url?.startsWith('/pixel.svg')) {
      response.writeHead(200, { 'content-type': 'image/svg+xml' });
      response.end('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><path d="M0 0h1v1H0z"/></svg>');
      return;
    }
    if (request.url === '/automatic-write' && request.method === 'POST') {
      response.writeHead(204);
      response.end();
      return;
    }
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('not found');
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server;
}

async function startSemanticRedactionFixture(secret) {
  const server = createHttpServer((request, response) => {
    const requestUrl = new URL(request.url, 'http://127.0.0.1');
    const baseline = requestUrl.pathname === '/baseline';
    if (!baseline && requestUrl.pathname !== '/candidate') {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('not found');
      return;
    }
    const link = baseline
      ? `https://source.example.test/details?access_token=${secret}`
      : '/safe-details';
    const action = baseline
      ? `https://source.example.test/submit?signature=${secret}`
      : '/api/applications';
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html><body><main><h1>Application</h1>
      <a href="${link}">Role details</a>
      <form method="post" action="${action}"><label>Name <input name="full_name"></label><button>Apply</button></form>
    </main></body></html>`);
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server;
}

async function startResourceTimingSaturationFixture() {
  const server = createHttpServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      response.end(`<!doctype html><html><head><meta name="replica-mode" content="authorized-local"></head><body>
        <main><h1>Resource timing saturation</h1></main><script>
          Promise.allSettled(Array.from({ length: 2200 }, (_, index) => fetch('/timing-entry-' + index, { cache: 'no-store' })))
            .then(() => document.body.setAttribute('data-ready', ''));
        </script></body></html>`);
      return;
    }
    if (request.url?.startsWith('/timing-entry-')) {
      response.writeHead(204, { 'cache-control': 'no-store' });
      response.end();
      return;
    }
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('not found');
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server;
}

async function startNativeTamperFixture() {
  const server = createHttpServer((request, response) => {
    if (request.url !== '/') {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('not found');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    response.end(`<!doctype html><html><head><meta name="replica-mode" content="authorized-local"></head><body>
      <main><h1>Native inventory tamper fixture</h1>
        <a id="external-navigation" href="https://outside.example.test/collect">External navigation</a>
        <form id="unsafe-form" method="get" action="https://outside.example.test/submit">
          <button type="submit">Unsafe submit</button>
        </form>
        <div id="shadow-host"></div>
      </main><script>
        const nativeDocumentQueryAll = Document.prototype.querySelectorAll;
        const nativeMatches = Element.prototype.matches;
        const nativeStyle = globalThis.getComputedStyle;
        const nativeRect = Element.prototype.getBoundingClientRect;
        const externalNavigation = document.querySelector('#external-navigation');
        externalNavigation.getAttribute = () => null;
        const unsafeForm = document.querySelector('#unsafe-form');
        Object.defineProperty(unsafeForm, 'action', { configurable: true, value: location.origin + '/api/applications' });
        Object.defineProperty(unsafeForm, 'method', { configurable: true, value: 'post' });
        Object.defineProperty(unsafeForm, 'enctype', { configurable: true, value: 'multipart/form-data' });
        const shadowRoot = document.querySelector('#shadow-host').attachShadow({ mode: 'open' });
        shadowRoot.innerHTML = '<a id="shadow-external" href="https://shadow-outside.example.test/collect">Shadow external</a>';
        Object.defineProperty(Element.prototype, 'shadowRoot', { configurable: true, get() { return null; } });
        const heading = document.querySelector('h1');
        let arraysPatched = false;
        Object.defineProperty(heading, 'tagName', {
          configurable: true,
          get() {
            if (!arraysPatched) {
              arraysPatched = true;
              Array.prototype.map = function() { return []; };
              Array.prototype.filter = function() { return []; };
              Array.prototype.flatMap = function() { return []; };
            }
            return 'H1';
          }
        });
        Document.prototype.querySelectorAll = function(selector) {
          return [...nativeDocumentQueryAll.call(this, selector)].filter((element) => element.id !== 'external-navigation');
        };
        Element.prototype.matches = function(selector) {
          return this.id === 'external-navigation' ? false : nativeMatches.call(this, selector);
        };
        globalThis.getComputedStyle = function(element, pseudo) { return nativeStyle(element, pseudo); };
        Element.prototype.getBoundingClientRect = function() { return nativeRect.call(this); };
        Performance.prototype.getEntriesByType = function() { return []; };
      </script></body></html>`);
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server;
}

test('comparison keeps the baseline GET-only when candidate writes are explicitly enabled', { timeout: 90000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-readonly-baseline-'));
  const baselineRequests = [];
  const candidateRequests = [];
  const nestedSecret = 'NESTED_SIGNED_RESOURCE_0864ec7614f84af1';
  let baselineServer;
  let candidateServer;
  try {
    baselineServer = await startAutowriteFixture(baselineRequests, nestedSecret);
    candidateServer = await startAutowriteFixture(candidateRequests, nestedSecret);
    const baseline = `http://127.0.0.1:${baselineServer.address().port}/`;
    const candidate = `http://127.0.0.1:${candidateServer.address().port}/`;
    const comparison = join(directory, 'comparison');
    await execFileAsync(process.execPath, [
      script('compare-pages.mjs'),
      '--baseline', baseline,
      '--candidate', candidate,
      '--out', comparison,
      '--ready-selector', '[data-ready]',
      '--viewport', 'fixture:800x600',
      '--wait-ms', '0',
      '--allow-non-get'
    ], { maxBuffer: 20 * 1024 * 1024 });
    assert.equal(baselineRequests.some((request) => request.method === 'POST'), false, 'baseline writes must never leave Chromium');
    assert.equal(candidateRequests.filter((request) => request.method === 'POST').length, 1, 'the explicit option applies only to the candidate');
    const reportText = await readFile(join(comparison, 'summary.json'), 'utf8');
    assert.doesNotMatch(reportText, new RegExp(nestedSecret), 'signed nested URLs must be redacted in reports');
    const report = JSON.parse(reportText);
    assert.equal(report.results[0].baseline.telemetry.blockedWrites.length, 1);

    const sourceSelf = join(directory, 'source-self');
    await execFileAsync(process.execPath, [
      script('compare-pages.mjs'),
      '--baseline', baseline,
      '--candidate', baseline,
      '--out', sourceSelf,
      '--ready-selector', '[data-ready]',
      '--viewport', 'fixture:800x600',
      '--wait-ms', '0'
    ], { maxBuffer: 20 * 1024 * 1024 });
    const sourceSelfSummary = JSON.parse(await readFile(join(sourceSelf, 'summary.json'), 'utf8'));
    assert.equal(sourceSelfSummary.results[0].pixel.strictChangedPixels, 0);
    assert.ok(sourceSelfSummary.results[0].candidate.telemetry.blockedWrites.length >= 1);
    await execFileAsync(process.execPath, [
      script('assert-fidelity.mjs'),
      '--summary', join(sourceSelf, 'summary.json'),
      '--policy', join(repositoryRoot, 'evals', 'policies', 'source-stability.json')
    ], { maxBuffer: 20 * 1024 * 1024 });

    const inspection = join(directory, 'inspection');
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'),
      '--url', candidate,
      '--out', inspection,
      '--ready-selector', '[data-ready]',
      '--viewport', 'fixture:800x600',
      '--wait-ms', '0'
    ], { maxBuffer: 20 * 1024 * 1024 });
    assert.doesNotMatch(await readFile(join(inspection, 'fixture', 'contract.json'), 'utf8'), new RegExp(nestedSecret));
  } finally {
    await closeHttpServer(baselineServer);
    await closeHttpServer(candidateServer);
    await rm(directory, { recursive: true, force: true });
  }
});

test('comparison console findings use the redacted persisted semantic summary', { timeout: 90000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-semantic-redaction-'));
  const sentinel = 'LIVE_SEMANTIC_URL_SECRET_DO_NOT_PRINT_7d55b1d7f4';
  let server;
  try {
    server = await startSemanticRedactionFixture(sentinel);
    const origin = `http://127.0.0.1:${server.address().port}`;
    const output = join(directory, 'comparison');
    const result = await execFileAsync(process.execPath, [
      script('compare-pages.mjs'),
      '--baseline', `${origin}/baseline`,
      '--candidate', `${origin}/candidate`,
      '--out', output,
      '--ready-selector', 'body',
      '--viewport', 'fixture:800x600',
      '--wait-ms', '0'
    ], { maxBuffer: 20 * 1024 * 1024 });
    assert.match(result.stdout, /first critical semantic findings/);
    assert.match(result.stdout, /REDACTED/);
    assert.doesNotMatch(result.stdout, new RegExp(sentinel));
    assert.doesNotMatch(result.stderr, new RegExp(sentinel));
    assert.doesNotMatch(await readFile(join(output, 'summary.json'), 'utf8'), new RegExp(sentinel));
  } finally {
    await closeHttpServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test('inspection bounds resource timing and integrity rejects a saturated buffer', { timeout: 120000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-resource-timing-saturation-'));
  let server;
  try {
    server = await startResourceTimingSaturationFixture();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const inspection = join(directory, 'inspection');
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'), '--url', origin, '--out', inspection,
      '--ready-selector', '[data-ready]', '--viewport', 'fixture:800x600', '--wait-ms', '0', '--timeout-ms', '90000'
    ], { maxBuffer: 20 * 1024 * 1024, timeout: 110000 });
    const contract = JSON.parse(await readFile(join(inspection, 'fixture', 'contract.json'), 'utf8')).contract;
    assert.equal(contract.integrity.resourceTimingBufferSize, 2048);
    assert.equal(contract.integrity.resourceTimingOverflow, true);
    assert.ok(contract.integrity.resourceTimingBufferFullEvents >= 1);
    const manifest = join(directory, 'replica.manifest.json');
    await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('check-candidate-integrity.mjs'), '--inspection', inspection,
        '--source', 'https://source.example/job', '--manifest', manifest
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2 && /RESOURCE_TIMING_BUFFER_OVERFLOW/.test(error.stdout || '')
    );
  } finally {
    await closeHttpServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test('inspection uses earliest native DOM inventory and integrity rejects page monkeypatches', { timeout: 90000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-native-inventory-'));
  let server;
  try {
    server = await startNativeTamperFixture();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const inspection = join(directory, 'inspection');
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'), '--url', origin, '--out', inspection,
      '--viewport', 'fixture:800x600', '--wait-ms', '0'
    ], { maxBuffer: 20 * 1024 * 1024 });
    const inspected = JSON.parse(await readFile(join(inspection, 'fixture', 'contract.json'), 'utf8'));
    assert.ok(inspected.contract.links.some((link) => link.href.includes('outside.example.test')),
      'the native inventory must retain the external link hidden by monkeypatched DOM APIs');
    assert.ok(inspected.contract.links.some((link) => link.href.includes('shadow-outside.example.test')),
      'the captured shadowRoot getter must retain links hidden by a patched accessor');
    assert.ok(inspected.contract.forms.some((form) => form.action.includes('outside.example.test')),
      'captured form getters must ignore own-instance action/method/enctype decoys');
    assert.ok(inspected.contract.integrity.cdpStructuralInventory.externalLinkCount >= 2);
    assert.ok(inspected.contract.integrity.cdpStructuralInventory.unsafeFormCount >= 1);
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Document.prototype.querySelectorAll'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Element.prototype.matches'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('globalThis.getComputedStyle'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Element.prototype.getBoundingClientRect'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Performance.prototype.getEntriesByType'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Array.prototype.map'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Array.prototype.filter'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Array.prototype.flatMap'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.includes('Element.prototype.shadowRoot'));
    assert.ok(inspected.contract.integrity.nativeApiTampering.some((entry) => entry.includes('getAttribute')));
    assert.ok(inspected.contract.integrity.nativeApiTampering.some((entry) => entry.includes('action:own-property')));

    const comparison = join(directory, 'comparison');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('compare-pages.mjs'), '--baseline', origin, '--candidate', origin,
        '--out', comparison, '--viewport', 'fixture:800x600', '--wait-ms', '0'
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const comparisonSummary = JSON.parse(await readFile(join(comparison, 'summary.json'), 'utf8'));
    assert.equal(comparisonSummary.results[0].semantic.captureIntegrity.valid, false);
    assert.ok(comparisonSummary.results[0].semantic.captureIntegrity.baseline.includes('Array.prototype.map'));

    const manifest = join(directory, 'replica.manifest.json');
    await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('check-candidate-integrity.mjs'), '--inspection', inspection,
        '--source', 'https://source.example.test/job', '--manifest', manifest
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
        && /CAPTURE_NATIVE_API_TAMPERING/.test(error.stdout || '')
        && /EXTERNAL_LINK_TARGET/.test(error.stdout || '')
    );
  } finally {
    await closeHttpServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test('inspection records failed external scripts and fetches independently of resource timing', { timeout: 90000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-external-read-inventory-'));
  const sensitiveAssetPath = 'applicant-asset-c9e175@example.test';
  const ordinaryJobUuid = 'bdcfb29f-4f27-42de-933f-7f83a359b9f0';
  let server;
  try {
    const unreachablePort = await freePort();
    const externalOrigin = `http://127.0.0.1:${unreachablePort}`;
    server = createHttpServer((request, response) => {
      if (request.url !== '/') {
        response.writeHead(404);
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><meta name="replica-mode" content="authorized-local">
        <link rel="stylesheet" href="${externalOrigin}/avatars/${sensitiveAssetPath}.css">
        <script src="${externalOrigin}/declared-but-failed.js"></script></head><body><h1>External read fixture</h1>
        <img src="${externalOrigin}/avatars/${sensitiveAssetPath}.png" alt="Sensitive external asset fixture">
        <img src="${externalOrigin}/jobs/${ordinaryJobUuid}/badge.png" alt="Ordinary job UUID fixture">
        <script>performance.clearResourceTimings();
        Promise.allSettled([fetch('${externalOrigin}/failed-fetch'), import('${externalOrigin}/failed-import.js')])
          .then(() => document.body.setAttribute('data-ready', ''));</script></body></html>`);
    });
    await new Promise((resolveListen, rejectListen) => {
      server.once('error', rejectListen);
      server.listen(0, '127.0.0.1', resolveListen);
    });
    const origin = `http://127.0.0.1:${server.address().port}`;
    const inspection = join(directory, 'inspection');
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'), '--url', origin, '--out', inspection,
      '--ready-selector', '[data-ready]', '--viewport', 'fixture:800x600', '--wait-ms', '0'
    ], { maxBuffer: 20 * 1024 * 1024 });
    const persistedCapture = await readFile(join(inspection, 'fixture', 'contract.json'), 'utf8');
    assert.equal(persistedCapture.includes(sensitiveAssetPath), false,
      'inspection artifacts must not retain PII-bearing external asset paths');
    const captured = JSON.parse(persistedCapture);
    assert.ok(captured.telemetry.externalReadCount >= 3);
    assert.equal(captured.telemetry.externalReadsTruncated, false);
    assert.ok(captured.telemetry.externalReads.some((entry) => entry.resourceType === 'script'));
    assert.ok(captured.telemetry.externalReads.some((entry) => entry.resourceType === 'fetch'));
    assert.ok(captured.telemetry.privacyRiskExternalAssetCount >= 1);
    assert.equal(captured.telemetry.privacyRiskExternalAssetsTruncated, false);
    assert.ok(captured.telemetry.privacyRiskExternalAssets.some((entry) => /REDACTED/.test(entry.url)));
    assert.equal(captured.telemetry.privacyRiskExternalAssets.some((entry) => entry.url.includes(ordinaryJobUuid)), false,
      'ordinary job UUID paths must not be classified as credential-bearing assets');
    assert.equal(captured.contract.integrity.resourceTimingTamperAttempts, 1);
    assert.ok(captured.contract.integrity.scripts.some((entry) => entry.src === `${externalOrigin}/declared-but-failed.js`));
    const manifest = join(directory, 'replica.manifest.json');
    await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('check-candidate-integrity.mjs'), '--inspection', inspection,
        '--source', 'https://source.example/job', '--manifest', manifest,
        '--allow-external-assets'
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
        && /EXTERNAL_SCRIPT_SOURCE/.test(error.stdout || '')
        && /EXTERNAL_READ_DEPENDENCY/.test(error.stdout || '')
        && /CREDENTIAL_LIKE_EXTERNAL_ASSET_URL/.test(error.stdout || '')
        && !(error.stdout || '').includes(sensitiveAssetPath)
        && /RESOURCE_TIMING_TAMPER_ATTEMPT/.test(error.stdout || '')
    );
  } finally {
    await closeHttpServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test('capture telemetry redacts diagnostics and records blocked runtime side-effect attempts', { timeout: 120000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-runtime-attempts-'));
  const candidate = join(directory, 'candidate');
  const diagnosticSecret = 'LIVE_RUNTIME_DIAGNOSTIC_SECRET_852df4561a';
  const payloadSecret = 'LIVE_BEACON_PAYLOAD_MUST_NOT_BE_RECORDED_7b84d1';
  const prefilledValueSecret = 'PRIVATE_PREFILLED_APPLICANT_6f571fd2';
  const opaqueChoiceSecret = 'OPAQUE_PROVIDER_CHOICE_8541be22';
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'), '--out', candidate, '--name', 'runtime-attempt-fixture'
    ]);
    await writeFile(join(candidate, 'public', 'download.txt'), 'synthetic download fixture');
    await writeFile(join(candidate, 'public', 'runtime-attempts.js'), `
      console.warn('ordinary warning remains; password=${diagnosticSecret}');
      console.error('Authorization: Bearer ${diagnosticSecret}');
      try { new WebSocket('ws://' + location.host + '/socket?access_token=${diagnosticSecret}'); } catch {}
      navigator.sendBeacon('/beacon?api_key=${diagnosticSecret}', '${payloadSecret}');
      window.open('/opened?authToken=${diagnosticSecret}', '_blank');
      document.querySelector('#popup-attempt').click();
      document.querySelector('#download-attempt').click();
      navigator.serviceWorker?.register('/app.js?session_token=${diagnosticSecret}', {
        scope: '/runtime-scope?signature=${diagnosticSecret}'
      }).catch(() => {});
      setTimeout(() => {
        document.body.setAttribute('data-ready', '');
        throw new Error('Set-Cookie: session=${diagnosticSecret}; Path=/; HttpOnly');
      }, 50);
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><meta name="replica-mode" content="authorized-local"></head>
      <body><main><h1>Runtime attempt fixture</h1>
        <label>Applicant <input name="full_name" value="${prefilledValueSecret}"></label>
        <label>Provider choice <select name="provider_choice"><option selected value="${opaqueChoiceSecret}">Visible choice</option></select></label>
        <label><input type="radio" name="provider_radio" value="${opaqueChoiceSecret}" checked> Visible radio</label>
        <a id="popup-attempt" target="_blank" href="/popup?token=${diagnosticSecret}">Popup</a>
        <a id="download-attempt" download href="/download.txt?signature=${diagnosticSecret}">Download</a>
      </main><script src="/runtime-attempts.js" defer></script></body></html>`);

    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const origin = `http://127.0.0.1:${port}`;
    await waitForHealth(`${origin}/healthz`);

    const inspection = join(directory, 'inspection');
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'),
      '--url', origin,
      '--out', inspection,
      '--ready-selector', '[data-ready]',
      '--viewport', 'fixture:800x600',
      '--wait-ms', '100'
    ], { maxBuffer: 20 * 1024 * 1024 });
    const inspectionText = await readFile(join(inspection, 'fixture', 'contract.json'), 'utf8');
    assert.doesNotMatch(inspectionText, new RegExp(diagnosticSecret));
    assert.doesNotMatch(inspectionText, new RegExp(payloadSecret));
    assert.doesNotMatch(inspectionText, new RegExp(prefilledValueSecret));
    assert.doesNotMatch(inspectionText, new RegExp(opaqueChoiceSecret));
    const inspected = JSON.parse(inspectionText);
    assert.match(inspected.telemetry.consoleWarnings.join(' '), /ordinary warning remains/);
    assert.match(inspected.telemetry.consoleWarnings.join(' '), /REDACTED/);
    assert.match(inspected.telemetry.consoleErrors.join(' '), /REDACTED/);
    assert.match(inspected.telemetry.pageErrors.join(' '), /Set-Cookie: \[REDACTED\]/i);
    const attempts = inspected.telemetry.runtimeAttempts;
    for (const field of [
      'webSocketAttempts', 'beaconAttempts', 'windowOpenAttempts', 'popupAttempts',
      'downloadAttempts', 'serviceWorkerRegistrationAttempts'
    ]) assert.ok(attempts[field].length >= 1, `${field} must record the attempted effect`);

    const integrityPath = join(directory, 'integrity.json');
    let integrityError;
    try {
      await execFileAsync(process.execPath, [
        script('check-candidate-integrity.mjs'),
        '--inspection', inspection,
        '--source', 'https://source.example/application',
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', integrityPath
      ], { maxBuffer: 20 * 1024 * 1024 });
    } catch (error) {
      integrityError = error;
    }
    assert.equal(integrityError?.code, 2);
    const integrity = await readFile(integrityPath, 'utf8');
    for (const code of [
      'CANDIDATE_WEBSOCKET_ATTEMPT', 'CANDIDATE_BEACON_ATTEMPT',
      'CANDIDATE_WINDOW_OPEN_ATTEMPT', 'CANDIDATE_POPUP_ATTEMPT',
      'CANDIDATE_DOWNLOAD_ATTEMPT', 'CANDIDATE_SERVICE_WORKER_REGISTRATION_ATTEMPT'
    ]) assert.match(integrity, new RegExp(code));

    const comparison = join(directory, 'comparison');
    const comparisonRun = await execFileAsync(process.execPath, [
      script('compare-pages.mjs'),
      '--baseline', origin,
      '--candidate', origin,
      '--out', comparison,
      '--ready-selector', '[data-ready]',
      '--viewport', 'fixture:800x600',
      '--wait-ms', '100'
    ], { maxBuffer: 20 * 1024 * 1024 });
    const comparisonText = await readFile(join(comparison, 'summary.json'), 'utf8');
    assert.doesNotMatch(`${comparisonText}${comparisonRun.stdout}${comparisonRun.stderr}`, new RegExp(diagnosticSecret));
    assert.doesNotMatch(comparisonText, new RegExp(payloadSecret));
    assert.doesNotMatch(comparisonText, new RegExp(prefilledValueSecret));
    assert.doesNotMatch(comparisonText, new RegExp(opaqueChoiceSecret));
    const compared = JSON.parse(comparisonText);
    assert.match(compared.results[0].baseline.telemetry.consoleWarningSamples.join(' '), /ordinary warning remains/);
    assert.match(compared.results[0].baseline.telemetry.pageErrorSamples.join(' '), /REDACTED/);
    assert.ok(compared.results[0].baseline.telemetry.runtimeAttempts.webSocketAttempts.length >= 1);
    assert.ok(compared.results[0].candidate.telemetry.runtimeAttempts.serviceWorkerRegistrationAttempts.length >= 1);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('inspector and synthetic application-flow gate work against the starter service', { timeout: 90000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-browser-'));
  const candidate = join(directory, 'candidate');
  await execFileAsync(process.execPath, [script('scaffold-replica.mjs'), '--out', candidate, '--name', 'browser-smoke']);
  await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
    <html lang="en"><head><meta charset="utf-8"><script src="/app.js" defer></script></head>
    <body data-replica-ready><main><h1>Application</h1>
      <form><label>Full name <input name="full_name" required></label>
        <label>Email <input name="email" type="email" required></label>
        <fieldset><legend>Authorized?</legend>
          <label><input type="radio" name="authorized" value="yes" required> Yes</label>
          <label><input type="radio" name="authorized" value="no" required> No</label></fieldset>
        <label>Resume <input name="resume" type="file" required></label>
        <button type="submit">Submit</button>
      </form></main></body></html>`);
  const port = await freePort();
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: candidate,
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  try {
    await waitForHealth(`http://127.0.0.1:${port}/healthz`);
    const inspection = join(directory, 'inspection');
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'),
      '--url', `http://127.0.0.1:${port}/`,
      '--ready-selector', '[data-replica-ready]',
      '--viewport', 'desktop:800x600',
      '--out', inspection
    ], { maxBuffer: 20 * 1024 * 1024 });
    const contract = JSON.parse(await readFile(join(inspection, 'desktop', 'contract.json'), 'utf8'));
    assert.equal(contract.contract.controls.length, 6);
    assert.equal(contract.stability.stable, true);

    const interaction = join(directory, 'interaction.json');
    await execFileAsync(process.execPath, [
      script('test-application-flow.mjs'),
      '--candidate', `http://127.0.0.1:${port}/`,
      '--manifest', join(candidate, 'replica.manifest.json'),
      '--out', interaction
    ], { maxBuffer: 20 * 1024 * 1024 });
    const result = JSON.parse(await readFile(interaction, 'utf8'));
    assert.equal(result.pass, true);
    assert.equal(result.sameOriginWrites.length, 2, 'one UI submission plus one idempotent retry');
    assert.equal(result.oneLogicalReceipt, true);
    assert.equal(result.receipt.emailConfirmation, false);
    assert.equal(result.receipt.id, result.retryReceipt.id);
    assert.equal(result.receipt.id, result.receiptLookup.id);
    assert.equal(result.payloadProof.metadataEquivalent, true);
    assert.equal(result.payloadProof.contentEquivalent, true);
    assert.equal(result.payloadProof.ui.canaryPresent, true);
    assert.equal(result.payloadProof.retry.canaryPresent, true);
    assert.equal(result.payloadProof.ui.fileCount, 1);
    assert.equal(result.payloadProof.applicantValuesPersisted, false);
    assert.equal(result.trustedRuntime.spawnedFromVerifiedBackend, true);
    assert.equal(result.trustedRuntime.suppliedCandidateProcessUsed, false);
    assert.equal(result.trustedRuntime.portSelection, 'kernel-assigned-port-zero');
    assert.equal(result.trustedRuntime.readinessChannel, 'ipc');
    assert.notEqual(new URL(result.candidate).origin, `http://127.0.0.1:${port}`);
    assert.ok(result.emptyValidation.invalidCount >= 4);
    assert.equal(result.blockedWrites.length, 0);
    const staleAudit = await (await fetch(`http://127.0.0.1:${port}/api/replica-audit`)).json();
    assert.equal(staleAudit.submissionAttempts, 0, 'the process named by --candidate must never receive synthetic submissions');
    await assert.rejects(fetch(new URL('/healthz', result.candidate)), undefined,
      'the separately spawned audited backend must be terminated after the flow');
    assert.doesNotMatch(
      await readFile(interaction, 'utf8'),
      /Synthetic Applicant|synthetic\.applicant@example\.test|replica-synthetic-canary-v1/
    );
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolveExit) => child.once('exit', resolveExit));
  }
  assert.equal(stderr, '');
});

test('inspector exposes hidden semantics and rejects a CSS full-document raster despite substantial text', { timeout: 90000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-raster-integrity-'));
  const candidate = join(directory, 'candidate');
  await execFileAsync(process.execPath, [script('scaffold-replica.mjs'), '--out', candidate, '--name', 'raster-integrity']);
  const substantialText = 'This is ordinary semantic application content used to prove that text volume cannot excuse a screenshot shortcut. '.repeat(12);
  await writeFile(join(candidate, 'public', 'pixel.svg'), '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><path fill="#abc" d="M0 0h10v10H0z"/></svg>');
  await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
    <html lang="en"><head><meta charset="utf-8"><style>
      html, body { margin: 0; min-height: 100%; }
      body { min-height: 100vh; background-image: url('/pixel.svg'); background-size: cover; }
      #gradient { width: 120px; height: 80px; background-image: linear-gradient(#fff, #000); }
      #complex-generated { position: fixed; inset: 0; pointer-events: none; opacity: .01; filter: blur(.1px);
        background-image: linear-gradient(#000 0%, #111 7%, #222 14%, #333 21%, #444 28%, #555 35%, #666 42%, #777 49%, #888 56%, #999 63%, #aaa 70%, #bbb 77%, #ccc 84%, #ddd 91%, #eee 96%, #fff 100%); }
      #image-set-surface { width: 24px; height: 24px; background-image: image-set('/pixel.svg' 1x, url('/pixel.svg') 2x); }
      #fixed-pseudo::before { content: ""; position: fixed; inset: 0; background-image: url('/pixel.svg'); pointer-events: none; }
      .opacity-hidden { opacity: 0; }
      .visibility-hidden { visibility: hidden; }
      .content-hidden { content-visibility: hidden; }
      .scaled-away { transform: scale(0); }
      .clipped-away { clip-path: inset(50%); }
      .transparent-text { color: transparent; -webkit-text-fill-color: transparent; }
    </style></head><body data-replica-ready>
      <main><h1>Rendered application</h1><p>${substantialText}</p>
        <div id="gradient">CSS gradient, not a raster surface</div>
        <div id="complex-generated"></div>
        <div id="image-set-surface"></div>
        <video id="video-surface" width="24" height="24" poster="/pixel.svg"><source src="/pixel.svg" type="image/svg+xml"></video>
        <svg id="inline-svg-surface" width="24" height="24" viewBox="0 0 24 24"><image href="/pixel.svg" width="24" height="24"/></svg>
        <div id="fixed-pseudo"></div>
        <div hidden><button id="hidden-control">Hidden ancestor</button></div>
        <div class="opacity-hidden"><button id="opacity-control">Opacity hidden</button></div>
        <div class="visibility-hidden"><button id="visibility-control">Visibility hidden</button></div>
        <div class="content-hidden"><button id="content-control">Content hidden</button></div>
        <div class="scaled-away"><button id="scale-control">Scaled away</button></div>
        <div class="clipped-away"><button id="clip-control">Clipped away</button></div>
        <button class="transparent-text" id="transparent-control">Transparent</button>
        <button id="visible-control">Visible</button>
      </main>
    </body></html>`);
  const port = await freePort();
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: candidate,
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  try {
    await waitForHealth(`http://127.0.0.1:${port}/healthz`);
    const inspection = join(directory, 'inspection');
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'),
      '--url', `http://127.0.0.1:${port}/`,
      '--ready-selector', '[data-replica-ready]',
      '--viewport', 'desktop:800x600',
      '--wait-ms', '0',
      '--out', inspection
    ], { maxBuffer: 20 * 1024 * 1024 });
    const result = JSON.parse(await readFile(join(inspection, 'desktop', 'contract.json'), 'utf8'));
    const contract = result.contract;
    assert.ok(contract.page.textLength > 300);
    for (const id of ['hidden-control', 'opacity-control', 'visibility-control', 'content-control', 'scale-control', 'clip-control', 'transparent-control']) {
      assert.equal(contract.controls.find((control) => control.id === id)?.visible, false, `${id} must not be semantically visible`);
    }
    assert.equal(contract.controls.find((control) => control.id === 'visible-control')?.visible, true);
    const bodyBackground = contract.integrity.rasterSurfaces.find((surface) => surface.tag === 'background' && surface.ownerTag === 'body' && !surface.pseudo);
    assert.ok(bodyBackground, 'body background-image URL must be inventoried');
    assert.ok(bodyBackground.documentCoverage >= 0.9, `expected near-full document coverage, got ${bodyBackground.documentCoverage}`);
    const pseudoBackground = contract.integrity.rasterSurfaces.find((surface) => surface.pseudo === '::before');
    assert.ok(pseudoBackground, 'pseudo-element background-image URL must be inventoried');
    assert.equal(pseudoBackground.viewportCoverage, 1);
    const imageSetSurface = contract.integrity.rasterSurfaces.find((surface) => surface.path.includes('#image-set-surface'));
    assert.ok(imageSetSurface?.sources.some((source) => source.endsWith('/pixel.svg')), 'quoted image-set sources must be inventoried');
    const videoSurface = contract.integrity.rasterSurfaces.find((surface) => surface.tag === 'video');
    assert.ok(videoSurface?.sources.some((source) => source.endsWith('/pixel.svg')), 'video src, poster, and child source URLs must be inventoried');
    const svgImageSurface = contract.integrity.rasterSurfaces.find((surface) => surface.tag === 'svg-image');
    assert.ok(svgImageSurface?.sources.some((source) => source.endsWith('/pixel.svg')), 'nested SVG image hrefs must be inventoried');
    assert.ok(contract.integrity.rasterSurfaceCount >= contract.integrity.rasterSurfaces.length);
    assert.equal(contract.integrity.rasterSurfacesTruncated, false);
    assert.ok(contract.integrity.aggregateRasterDocumentCoverage >= 0.9);
    assert.equal(contract.integrity.rasterSurfaces.some((surface) => surface.sources.some((source) => source.includes('linear-gradient'))), false);
    assert.ok(contract.integrity.rasterSurfaces.some((surface) => (
      surface.tag === 'css-generated-image'
      && surface.generatedImageKind === 'complex-gradient'
      && surface.documentCoverage >= 0.8
    )), 'complex full-document URL-free gradients must be inventoried as raster shortcuts');
    assert.ok(contract.integrity.vectorSurfaces.some((surface) => (
      surface.tag === 'filter-surface' && surface.documentCoverage >= 0.8
    )), 'full-document filtered surfaces must be inventoried');

    const integrity = join(directory, 'integrity.json');
    let integrityError = null;
    try {
      await execFileAsync(process.execPath, [
        script('check-candidate-integrity.mjs'),
        '--inspection', inspection,
        '--source', 'https://source.example/job',
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', integrity
      ], { maxBuffer: 20 * 1024 * 1024 });
    } catch (error) {
      integrityError = error;
    }
    assert.equal(integrityError?.code, 2);
    const integrityReport = JSON.parse(await readFile(integrity, 'utf8'));
    assert.equal(integrityReport.pass, false);
    assert.ok(integrityReport.results[0].failures.some((failure) => failure.code === 'FULL_PAGE_RASTER'));
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolveExit) => child.once('exit', resolveExit));
  }
  assert.equal(stderr, '');
});

test('open-shadow contracts are compared and audited while full-document vector surfaces are rejected', { timeout: 120000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-shadow-vector-'));
  const candidate = join(directory, 'candidate');
  await execFileAsync(process.execPath, [script('scaffold-replica.mjs'), '--out', candidate, '--name', 'shadow-vector']);
  await writeFile(join(candidate, 'public', 'pixel.svg'), '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="1200"><rect width="800" height="1200" fill="#abc"/></svg>');
  await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
    <html lang="en"><head><meta charset="utf-8"><meta name="replica-mode" content="authorized-local"><style>
      html, body { margin: 0; min-height: 1200px; }
      #vector { display: block; position: absolute; inset: 0 auto auto 0; width: 800px; height: 1200px; z-index: -1; }
    </style></head><body data-replica-ready>
      <svg id="vector" viewBox="0 0 800 1200" aria-label="Vector backdrop"><rect width="800" height="1200" fill="#eef3f8"/><path d="M0 0L800 1200" stroke="#ccd5e1"/></svg>
      <div id="shadow-host"></div>
      <script src="/shadow-fixture.js" defer></script>
    </body></html>`);
  await writeFile(join(candidate, 'public', 'shadow-fixture.js'), `
    const variant = new URLSearchParams(location.search).get('variant') || 'baseline';
    const vector = document.querySelector('#vector');
    if (variant === 'vector-image') vector.insertAdjacentHTML('beforeend', '<image href="/pixel.svg" width="800" height="1200"/><use href="/pixel.svg#vector" width="10" height="10"/><defs><filter id="external-filter"><feImage href="/pixel.svg"/></filter></defs>');
    const root = document.querySelector('#shadow-host').attachShadow({ mode: variant === 'closed' ? 'closed' : 'open' });
    root.innerHTML = variant === 'closed'
      ? '<img src="/pixel.svg" style="position:fixed;inset:0;width:100vw;height:100vh"><form action="https://source.example/submit"><input name="hidden-in-closed-shadow"></form>'
      : '<h2>Shadow application</h2><form method="post" action="' + (variant === 'unsafe' ? 'https://source.example/submit' : '/api/applications') + '"><label for="shadow-name">Name</label><input id="shadow-name" name="shadow_name" required><input type="hidden" name="provider_token" value="' + (variant === 'candidate' ? 'BBBBBBBB' : 'synthetic-local') + '"><button>Apply</button></form><a href="/details">Details</a>';
    if (variant === 'unsafe') {
      const frame = document.createElement('iframe');
      frame.srcdoc = '<p>embedded source-like content</p>';
      root.append(frame);
    }
    if (variant === 'unsafe-write') {
      fetch('https://source.example/collector', { method: 'POST', body: 'synthetic' }).catch(() => {});
      fetch('http://127.0.0.1:9/private-probe').catch(() => {});
    }
    if (variant === 'unsafe-object') {
      const wrapper = document.createElement('div');
      wrapper.innerHTML = '<object data="/pixel.svg" type="image/svg+xml" style="position:absolute;inset:0 auto auto 0;width:800px;height:1200px"></object><input type="image" src="/pixel.svg" alt="Raster submit" style="position:absolute;inset:0 auto auto 0;width:800px;height:1200px">';
      root.append(...wrapper.childNodes);
    }
  `);
  const port = await freePort();
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: candidate,
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const origin = `http://127.0.0.1:${port}`;
  const inspect = async (variant) => {
    const output = join(directory, `inspect-${variant}`);
    await execFileAsync(process.execPath, [
      script('inspect-page.mjs'),
      '--url', `${origin}/?variant=${variant}`,
      '--ready-selector', '[data-replica-ready]',
      '--viewport', 'desktop:800x600',
      '--wait-ms', '0',
      '--out', output
    ], { maxBuffer: 20 * 1024 * 1024 });
    return output;
  };
  const integrity = async (inspection, name) => {
    try {
      const result = await execFileAsync(process.execPath, [
        script('check-candidate-integrity.mjs'),
        '--inspection', inspection,
        '--source', 'https://source.example/job',
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', join(directory, `integrity-${name}.json`)
      ], { maxBuffer: 20 * 1024 * 1024 });
      return { code: 0, ...result };
    } catch (error) {
      return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
    }
  };
  try {
    await waitForHealth(`${origin}/healthz`);
    const vectorInspection = await inspect('baseline');
    const vectorCapture = JSON.parse(await readFile(join(vectorInspection, 'desktop', 'contract.json'), 'utf8'));
    const vectorContract = vectorCapture.contract;
    assert.equal(vectorContract.integrity.rasterSurfaces.some((surface) => surface.tag === 'svg'), false);
    assert.ok(vectorContract.integrity.vectorSurfaces.some((surface) => (
      surface.tag === 'svg-root' && surface.documentCoverage >= 0.8
    )));
    assert.ok(vectorContract.forms.some((form) => form.action === `${origin}/api/applications`), JSON.stringify(vectorCapture.telemetry));
    assert.ok(vectorContract.controls.some((control) => control.name === 'provider_token'
      && control.hiddenValueLength === 15
      && control.hiddenValueClassification === 'synthetic-local'));
    assert.ok(vectorContract.headings.some((heading) => heading.text === 'Shadow application'));
    const vectorIntegrity = await integrity(vectorInspection, 'vector');
    assert.equal(vectorIntegrity.code, 2);
    assert.match(vectorIntegrity.stdout, /FULL_PAGE_VECTOR_OR_FILTER_SURFACE/);

    const rasterInspection = await inspect('vector-image');
    const rasterContract = JSON.parse(await readFile(join(rasterInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.ok(rasterContract.integrity.rasterSurfaces.some((surface) => surface.tag === 'svg-image' && surface.documentCoverage >= 0.8));
    assert.ok(rasterContract.integrity.vectorSurfaces.some((surface) => surface.tag === 'svg-use-resource'));
    assert.ok(rasterContract.integrity.vectorSurfaces.some((surface) => surface.tag === 'svg-feimage-resource'));
    assert.ok(rasterContract.integrity.cdpStructuralInventory.svgExternalResourceCount >= 2);
    const rasterIntegrity = await integrity(rasterInspection, 'vector-image');
    assert.equal(rasterIntegrity.code, 2);
    assert.match(rasterIntegrity.stdout, /FULL_PAGE_RASTER/);

    const unsafeInspection = await inspect('unsafe');
    const unsafeContract = JSON.parse(await readFile(join(unsafeInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.ok(unsafeContract.integrity.iframeCount >= 1);
    assert.ok(unsafeContract.integrity.browserFrames.length >= 1);
    assert.ok(unsafeContract.forms.some((form) => form.action === 'https://source.example/submit'));
    const unsafeIntegrity = await integrity(unsafeInspection, 'unsafe');
    assert.equal(unsafeIntegrity.code, 2);
    assert.match(unsafeIntegrity.stdout, /IFRAME_PRESENT/);
    assert.match(unsafeIntegrity.stdout, /EXTERNAL_FORM_ACTION/);

    const closedInspection = await inspect('closed');
    const closedContract = JSON.parse(await readFile(join(closedInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.ok(closedContract.integrity.closedShadowRootCount >= 1);
    const closedIntegrity = await integrity(closedInspection, 'closed');
    assert.equal(closedIntegrity.code, 2);
    assert.match(closedIntegrity.stdout, /CLOSED_SHADOW_ROOT_PRESENT/);

    const writeInspection = await inspect('unsafe-write');
    const writeResult = JSON.parse(await readFile(join(writeInspection, 'desktop', 'contract.json'), 'utf8'));
    assert.ok(writeResult.telemetry.runtimeAttempts.externalFetchAttempts.length >= 2);
    const writeIntegrity = await integrity(writeInspection, 'unsafe-write');
    assert.equal(writeIntegrity.code, 2);
    assert.match(writeIntegrity.stdout, /CANDIDATE_EXTERNAL_FETCH_ATTEMPT/);

    const objectInspection = await inspect('unsafe-object');
    const objectCapture = JSON.parse(await readFile(join(objectInspection, 'desktop', 'contract.json'), 'utf8'));
    const objectContract = objectCapture.contract;
    assert.ok(objectContract.integrity.embeddedObjectCount >= 1, JSON.stringify(objectCapture.telemetry));
    assert.ok(objectContract.integrity.rasterSurfaces.some((surface) => surface.tag === 'input-image'
      && surface.documentCoverage >= 0.8), JSON.stringify(objectContract.integrity.rasterSurfaces));
    const objectIntegrity = await integrity(objectInspection, 'unsafe-object');
    assert.equal(objectIntegrity.code, 2);
    assert.match(objectIntegrity.stdout, /EMBEDDED_OBJECT_PRESENT/);
    assert.match(objectIntegrity.stdout, /FULL_PAGE_RASTER/);

    const comparison = join(directory, 'shadow-comparison');
    await execFileAsync(process.execPath, [
      script('compare-pages.mjs'),
      '--baseline', `${origin}/?variant=baseline`,
      '--candidate', `${origin}/?variant=candidate`,
      '--ready-selector', '[data-replica-ready]',
      '--viewport', 'desktop:800x600',
      '--wait-ms', '0',
      '--out', comparison
    ], { maxBuffer: 20 * 1024 * 1024 });
    const comparisonSummary = JSON.parse(await readFile(join(comparison, 'summary.json'), 'utf8'));
    const result = comparisonSummary.results[0];
    assert.equal(result.pixel.tolerantChangedPixels, 0);
    assert.ok(result.semantic.categories.some((category) => category.kind === 'controls'
      && category.changed.some((change) => change.key.includes('provider_token')
        && change.changes.hiddenValueLength)));
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolveExit) => child.once('exit', resolveExit));
    await rm(directory, { recursive: true, force: true });
  }
  assert.equal(stderr, '');
});
