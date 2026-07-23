import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);
const skillRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../skills/pixel-by-pixel');
const script = (name) => join(skillRoot, 'scripts', name);

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const port = server.address().port;
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

async function waitForHealth(url, child) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Candidate exited early with ${child.exitCode}.`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`Timed out waiting for ${url}.`);
}

function syntheticFormData({ includeCanary = true, invalidFile = false } = {}) {
  const form = new FormData();
  form.set('full_name', 'Synthetic Applicant');
  if (includeCanary) form.set('__replica_synthetic_canary', 'replica-synthetic-canary-v1');
  if (invalidFile) {
    form.set('resume', new Blob(['not a pdf'], { type: 'text/plain' }), 'unsafe.txt');
  } else {
    form.set(
      'resume',
      new Blob(['%PDF-1.4\n%%EOF\n'], { type: 'application/pdf' }),
      'synthetic-resume.pdf'
    );
  }
  return form;
}

test('audited backend validates synthetic multipart requests and blocks public symlink traversal', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-backend-adversarial-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'backend-adversarial'
    ]);
    const secret = 'public-symlink-secret-must-not-be-served';
    const external = join(directory, 'outside.txt');
    await writeFile(external, secret);
    await symlink(external, join(candidate, 'public', 'leak.txt'));
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const origin = `http://127.0.0.1:${port}`;
    await waitForHealth(`${origin}/healthz`, child);

    const commonHeaders = {
      'x-idempotency-key': 'synthetic-direct-contract',
      'x-replica-fixture': 'synthetic-browser-run-v1'
    };
    const wrongType = await fetch(`${origin}/api/applications`, {
      method: 'POST',
      headers: { ...commonHeaders, 'content-type': 'text/plain' },
      body: 'arbitrary applicant bytes'
    });
    assert.equal(wrongType.status, 415);

    const noCanary = await fetch(`${origin}/api/applications`, {
      method: 'POST', headers: commonHeaders, body: syntheticFormData({ includeCanary: false })
    });
    assert.equal(noCanary.status, 400);

    const invalidFile = await fetch(`${origin}/api/applications`, {
      method: 'POST', headers: commonHeaders, body: syntheticFormData({ invalidFile: true })
    });
    assert.equal(invalidFile.status, 400);

    const accepted = await fetch(`${origin}/api/applications`, {
      method: 'POST', headers: commonHeaders, body: syntheticFormData()
    });
    assert.equal(accepted.status, 200);
    const receipt = await accepted.json();
    assert.deepEqual(Object.keys(receipt).sort(), ['bodyBytes', 'emailConfirmation', 'id', 'status']);
    assert.equal(receipt.emailConfirmation, false);

    const audit = await (await fetch(`${origin}/api/replica-audit`)).json();
    assert.equal(audit.submissionAttempts, 1, 'invalid requests must not count as accepted attempts');
    assert.equal(audit.storedApplicantBytes, 0);
    assert.equal(audit.storedFileBytes, 0);

    const leaked = await (await fetch(`${origin}/leak.txt`)).text();
    assert.doesNotMatch(leaked, new RegExp(secret));
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction gate blocks and reports uncontrolled local writes and WebSockets', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-adversarial-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-adversarial'
    ]);
    await writeFile(join(candidate, 'public', 'adversarial.js'), `
        addEventListener('DOMContentLoaded', () => {
          fetch('/api/unexpected', { method: 'POST', body: 'synthetic-canary' }).catch(() => {});
          const socket = new WebSocket('ws://' + location.host + '/unexpected-socket');
          socket.addEventListener('error', () => {});
          try { new WebTransport('https://example.test/transport'); } catch {}
          try { new WebSocketStream('wss://example.test/stream'); } catch {}
          try { new RTCPeerConnection().createDataChannel('blocked'); } catch {}
        });
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><script src="/app.js" defer></script>
      <script src="/adversarial.js" defer></script></head><body data-replica-ready><main><h1>Application</h1>
      <form><label>Name <input name="full_name" required></label>
      <label>Email <input name="email" type="email" required></label>
      <button type="submit">Submit</button></form></main></body></html>`);

    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const reportPath = join(directory, 'interaction.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', `http://127.0.0.1:${port}/`,
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.pass, false);
    assert.ok(report.failures.some((failure) => failure.code === 'UNEXPECTED_LOCAL_WRITE'));
    assert.ok(report.failures.some((failure) => failure.code === 'WEBSOCKET_BLOCKED'));
    assert.ok(report.failures.some((failure) => failure.code === 'MODERN_TRANSPORT_BLOCKED'));
    assert.ok(report.blockedModernTransports.some((attempt) => attempt.kind === 'RTCPeerConnection'));
    assert.equal(report.auditAfter.submissionAttempts, 2);
    assert.equal(report.auditAfter.logicalReceipts, 1);
    assert.equal(report.blockedWrites.length, 0);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction gate blocks browser storage retention while the exact backend submission still succeeds', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-storage-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'), '--out', candidate, '--name', 'interaction-storage-adversarial'
    ]);
    await writeFile(join(candidate, 'public', 'storage-adversarial.js'), `
      document.addEventListener('submit', (event) => {
        const form = event.target;
        const fullName = form.elements.full_name?.value || '';
        const email = form.elements.email?.value || '';
        const resumeName = form.elements.resume?.files?.[0]?.name || '';
        const retained = JSON.stringify({ fullName, email, resumeName });
        try { document.cookie = 'applicant=' + encodeURIComponent(retained); } catch {}
        try { localStorage.setItem('applicant', retained); } catch {}
        try { localStorage.applicantEmail = email; } catch {}
        try { sessionStorage.setItem('resumeMetadata', resumeName); } catch {}
        try { indexedDB.open('synthetic-applicant-records', 1); } catch {}
        try { caches.open('synthetic-resume-cache').catch(() => {}); } catch {}
        try { navigator.storage.getDirectory().catch(() => {}); } catch {}
        try {
          const popup = window.open('about:blank');
          popup?.navigator.storage.getDirectory().then(async (root) => {
            await root.getFileHandle('synthetic-applicant-record', { create: true });
          }).catch(() => {});
        } catch {}
      });
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8">
      <script src="/storage-adversarial.js" defer></script><script src="/app.js" defer></script></head>
      <body data-replica-ready><form>
        <label>Name <input name="full_name" required></label>
        <label>Email <input name="email" type="email" required></label>
        <label>Resume <input name="resume" type="file" required></label>
        <button type="submit">Submit</button>
      </form></body></html>`);
    const reportPath = join(directory, 'interaction.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', 'http://127.0.0.1:9/',
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const serialized = await readFile(reportPath, 'utf8');
    const report = JSON.parse(serialized);
    assert.ok(report.failures.some((failure) => failure.code === 'BROWSER_STORAGE_MUTATION_ATTEMPTED'));
    const mutationKinds = new Set(report.storageAudit.mutationAttempts.map((attempt) => attempt.kind));
    for (const kind of [
      'document.cookie', 'Storage.setItem', 'localStorage.propertyWrite',
      'indexedDB.open', 'CacheStorage.open', 'OPFS.getDirectory'
    ]) assert.ok(mutationKinds.has(kind), `missing storage mutation telemetry for ${kind}; saw ${[...mutationKinds].join(', ')}`);
    assert.ok(report.blockedModernTransports.some((attempt) => attempt.kind === 'window.open' || attempt.kind === 'popup'));
    assert.deepEqual(report.storageAudit.after.counts, {
      cookieCount: 0,
      localStorageKeyCount: 0,
      sessionStorageKeyCount: 0,
      indexedDbDatabaseCount: 0,
      cacheCount: 0,
      opfsUsageBytes: 0
    });
    assert.equal(report.storageAudit.opfsCleanupSucceeded, true);
    assert.equal(report.storageAudit.sensitiveValueDetected, false);
    assert.equal(report.auditAfter.submissionAttempts, 2);
    assert.equal(report.auditAfter.logicalReceipts, 1);
    assert.doesNotMatch(serialized, /Synthetic Applicant|synthetic\.applicant@example\.test|synthetic-resume\.pdf|replica-synthetic-canary-v1/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('a missing form fails unless the manifest carries an explicit no-form exemption', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-no-form-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-no-form'
    ]);
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const manifestPath = join(candidate, 'replica.manifest.json');
    const rejectedPath = join(directory, 'rejected.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', `http://127.0.0.1:${port}/`,
        '--manifest', manifestPath,
        '--out', rejectedPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const rejected = JSON.parse(await readFile(rejectedPath, 'utf8'));
    assert.ok(rejected.failures.some((failure) => failure.code === 'APPLICATION_FORM_MISSING_WITHOUT_EXPLICIT_EXEMPTION'));

    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.interaction = {
      notApplicable: true,
      reason: 'This synthetic fixture intentionally contains no application form.'
    };
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const acceptedPath = join(directory, 'accepted.json');
    await execFileAsync(process.execPath, [
      script('test-application-flow.mjs'),
      '--candidate', `http://127.0.0.1:${port}/`,
      '--manifest', manifestPath,
      '--out', acceptedPath
    ], { maxBuffer: 20 * 1024 * 1024 });
    const accepted = JSON.parse(await readFile(acceptedPath, 'utf8'));
    assert.equal(accepted.pass, true);
    assert.equal(accepted.notApplicable, true);
    assert.equal(accepted.auditBefore.submissionAttempts, 0);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction request telemetry is bounded and truncation fails closed', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-request-cap-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-request-cap'
    ]);
    await writeFile(join(candidate, 'public', 'request-spam.js'), `
      const attempts = Array.from({ length: 3200 }, (_, index) =>
        fetch('/request-spam/' + index, { method: 'POST', body: 'synthetic' }).catch(() => null));
      Promise.allSettled(attempts).then(() => document.body.setAttribute('data-spam-complete', ''));
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><script src="/request-spam.js" defer></script></head>
      <body data-replica-ready><main><h1>Informational role</h1></main></body></html>`);
    const manifestPath = join(candidate, 'replica.manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.page.readySelector = '[data-spam-complete]';
    manifest.interaction = {
      notApplicable: true,
      reason: 'This synthetic request-cap fixture intentionally contains no application form.'
    };
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const candidateUrl = `http://127.0.0.1:${await freePort()}/`;
    const reportPath = join(directory, 'interaction.json');
    let exitCode = 0;
    let failureOutput = '';
    try {
      await execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', candidateUrl,
        '--manifest', manifestPath,
        '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 });
    } catch (error) {
      exitCode = error.code;
      failureOutput = `${error.stdout || ''}\n${error.stderr || ''}`;
    }
    const report = JSON.parse(await readFile(reportPath, 'utf8').catch((error) => {
      throw new Error(`interaction report missing after exit ${exitCode}: ${failureOutput}`, { cause: error });
    }));
    assert.equal(exitCode, 2, JSON.stringify(report.eventAudit));
    assert.equal(report.pass, false);
    assert.equal(report.eventAudit.truncated.requests, true);
    assert.ok(report.eventAudit.totals.requests > report.eventAudit.limits.requests);
    assert.equal(report.requests.length, report.eventAudit.limits.requests);
    assert.ok(report.failures.some((failure) => failure.code === 'INTERACTION_EVENT_INVENTORY_TRUNCATED'));
    assert.equal(report.eventAudit.overallLimitExceeded, true);
    assert.ok(report.failures.some((failure) => failure.code === 'INTERACTION_EVENT_TOTAL_LIMIT_EXCEEDED'));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('no-form exemption cannot hide active light-DOM or open-shadow forms with a false selector', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-hidden-form-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-hidden-form'
    ]);
    await writeFile(join(candidate, 'public', 'hidden-form.js'), `
      const root = document.querySelector('#shadow-host').attachShadow({ mode: 'open' });
      root.innerHTML = '<form id="shadow-form"><input required><button>Submit</button></form>';
      if ('__replicaStorageInventory' in globalThis) {
        Document.prototype.querySelectorAll = () => [];
      }
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><script src="/hidden-form.js" defer></script></head>
      <body data-replica-ready>
        <form id="actual-form"><label>Name <input name="full_name" required></label><button>Submit</button></form>
        <div id="shadow-host"></div>
      </body></html>`);
    const manifestPath = join(candidate, 'replica.manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.interaction = {
      notApplicable: true,
      reason: 'Adversarial false exemption.',
      formSelector: '#does-not-exist'
    };
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const reportPath = join(directory, 'interaction.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', `http://127.0.0.1:${port}/`,
        '--manifest', manifestPath,
        '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.notApplicable, false, JSON.stringify(report.formInventory));
    assert.equal(report.formInventory.activeFormCount, 2);
    assert.ok(report.failures.some((failure) => failure.code === 'FORM_SELECTOR_OMITS_ACTIVE_FORM'));
    assert.ok(report.failures.some((failure) => failure.code === 'INTERACTION_NATIVE_API_TAMPERING'));
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('application flow submits and retries the already-resolved open-shadow form', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-shadow-flow-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-shadow-flow'
    ]);
    await writeFile(join(candidate, 'public', 'shadow-flow.js'), `
      const root = document.querySelector('#shadow-host').attachShadow({ mode: 'open' });
      root.innerHTML = '<a role="link" data-replica-source-link>Source posting</a><form><label>Name <input name="full_name" required></label><label>Email <input name="email" type="email" required></label><button type="submit">Submit</button></form>';
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><script src="/app.js" defer></script><script src="/shadow-flow.js" defer></script></head>
      <body data-replica-ready><div id="shadow-host"></div></body></html>`);
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const reportPath = join(directory, 'interaction.json');
    await execFileAsync(process.execPath, [
      script('test-application-flow.mjs'),
      '--candidate', `http://127.0.0.1:${port}/`,
      '--manifest', join(candidate, 'replica.manifest.json'),
      '--out', reportPath
    ], { maxBuffer: 20 * 1024 * 1024 });
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.pass, true);
    assert.equal(report.initialSameOriginWrites.length, 1, 'composed submit must be handled only once');
    assert.equal(report.sameOriginWrites.length, 2);
    assert.equal(report.payloadProof.metadataEquivalent, true);
    assert.equal(report.payloadProof.contentEquivalent, true);
    assert.equal(report.sourceLinkSafety.discoveredCount, 1);
    assert.equal(report.sourceLinkSafety.structurallyInert, true);
    assert.equal(report.sourceLinkSafety.navigationTargetCount, 0);
    assert.equal(report.sourceLinkSafety.activated, true);
    assert.equal(report.sourceLinkSafety.urlUnchanged, true);
    assert.equal(report.sourceLinkSafety.originUnchanged, true);
    assert.equal(report.sourceLinkSafety.requestCount, 0);
    assert.equal(report.auditAfter.submissionAttempts, 2);
    assert.equal(report.auditAfter.logicalReceipts, 1);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction gate rejects href and xlink:href on marked open-shadow source links before activation', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-shadow-source-link-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-shadow-source-link'
    ]);
    await writeFile(join(candidate, 'public', 'shadow-source-links.js'), `
      const root = document.querySelector('#shadow-host').attachShadow({ mode: 'open' });
      root.innerHTML = '<a data-replica-source-link href="https://source.example.test/live">Unsafe href</a><svg><a data-replica-source-link xlink:href="https://source.example.test/alternate"><text>Unsafe xlink</text></a></svg><form><label>Name <input name="full_name" required></label><label>Email <input name="email" type="email" required></label><button type="submit">Submit</button></form>';
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><script src="/app.js" defer></script><script src="/shadow-source-links.js" defer></script></head>
      <body data-replica-ready><div id="shadow-host"></div></body></html>`);
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const reportPath = join(directory, 'interaction.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', `http://127.0.0.1:${port}/`,
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.pass, false);
    assert.equal(report.sourceLinkSafety.discoveredCount, 2);
    assert.equal(report.sourceLinkSafety.structurallyInert, false);
    assert.equal(report.sourceLinkSafety.navigationTargetCount, 2);
    assert.equal(report.sourceLinkSafety.activated, false, 'unsafe marked links must not be activated');
    assert.ok(report.failures.some((failure) => failure.code === 'SOURCE_LINK_NAVIGATION_TARGET'));
    assert.equal(report.auditAfter.submissionAttempts, 2, 'the synthetic application flow should still be fully audited');
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction gate activates every inert source-link marker in isolated state', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-all-source-links-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [script('scaffold-replica.mjs'), '--out', candidate, '--name', 'all-source-links']);
    await writeFile(join(candidate, 'public', 'source-link-probe.js'), `
      document.querySelector('#second-source-link').addEventListener('click', () => { fetch('/source-link-probe').catch(() => {}); });
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><script src="/app.js" defer></script><script src="/source-link-probe.js" defer></script></head>
      <body data-replica-ready>
        <a role="link" tabindex="0" data-replica-source-link>First source link</a>
        <a id="second-source-link" role="link" tabindex="0" data-replica-source-link>Second source link</a>
        <form><label>Name <input name="full_name" required></label><label>Email <input name="email" type="email" required></label><button type="submit">Submit</button></form>
      </body></html>`);
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const reportPath = join(directory, 'interaction.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'), '--candidate', `http://127.0.0.1:${port}/`,
        '--manifest', join(candidate, 'replica.manifest.json'), '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.sourceLinkSafety.discoveredCount, 2);
    assert.ok(report.sourceLinkSafety.activations.some((activation) => (
      activation.ordinal === 1
      && activation.method === 'click'
      && activation.requests.some((request) => new URL(request.url).pathname === '/source-link-probe')
    )), 'the second marker must be activated and independently audited');
    assert.ok(report.failures.some((failure) => failure.code === 'SOURCE_LINK_NOT_INERT'));
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction gate rejects a UI payload that omits fields present in the evaluator retry', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-payload-mismatch-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-payload-mismatch'
    ]);
    await writeFile(join(candidate, 'public', 'payload-mismatch.js'), `
        document.addEventListener('submit', async (event) => {
          event.preventDefault();
          event.stopImmediatePropagation();
          const payload = new FormData();
          payload.set('__replica_synthetic_canary', 'replica-synthetic-canary-v1');
          const response = await fetch('/api/applications', {
            method: 'POST',
            headers: {
              'x-idempotency-key': 'synthetic-browser-run',
              'x-replica-fixture': 'synthetic-browser-run-v1'
            },
            body: payload
          });
          await response.json();
        });
    `);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8">
      <script src="/payload-mismatch.js" defer></script><script src="/app.js" defer></script></head>
      <body data-replica-ready><form>
        <label>Name <input name="full_name" required></label>
        <label>Email <input name="email" type="email" required></label>
        <button type="submit">Submit</button>
      </form></body></html>`);
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const reportPath = join(directory, 'interaction.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', `http://127.0.0.1:${port}/`,
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.payloadProof.metadataEquivalent, false);
    assert.equal(report.payloadProof.contentEquivalent, false);
    assert.ok(report.failures.some((failure) => failure.code === 'UI_RETRY_MULTIPART_MISMATCH'));
    assert.equal(report.auditAfter.submissionAttempts, 2);
    assert.equal(report.auditAfter.logicalReceipts, 1);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction gate revalidates custom aria-required controls after fill actions', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-custom-required-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'interaction-custom-required'
    ]);
    await writeFile(join(candidate, 'public', 'index.html'), `<!doctype html>
      <html lang="en"><head><meta charset="utf-8"><script src="/app.js" defer></script></head>
      <body data-replica-ready><form>
        <label>Name <input name="full_name" required></label>
        <div role="combobox" tabindex="0" aria-required="true" aria-invalid="true"></div>
        <button type="submit">Submit</button>
      </form></body></html>`);
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForHealth(`http://127.0.0.1:${port}/healthz`, child);
    const reportPath = join(directory, 'interaction.json');
    await assert.rejects(
      execFileAsync(process.execPath, [
        script('test-application-flow.mjs'),
        '--candidate', `http://127.0.0.1:${port}/`,
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--out', reportPath
      ], { maxBuffer: 20 * 1024 * 1024 }),
      (error) => error.code === 2
    );
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.customValidationAfterFill.invalidCount, 1);
    assert.ok(report.failures.some((failure) => failure.code === 'CUSTOM_REQUIRED_CONTROLS_UNFILLED'));
    assert.equal(report.auditAfter.submissionAttempts, 0);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});
