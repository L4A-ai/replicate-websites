import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import {
  bootstrapSourceProvenance,
  publicResourceDescriptor
} from '../../skills/pixel-by-pixel/scripts/bootstrap-static-replica.mjs';

const execFileAsync = promisify(execFile);
const skillRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../skills/pixel-by-pixel');
const script = (name) => join(skillRoot, 'scripts', name);
const liveToken = 'LIVE_PROVIDER_TOKEN_DO_NOT_COPY_7f236af6c1164a11a9';
const liveLinkToken = 'LIVE_SIGNED_LINK_DO_NOT_COPY_9405d572692f4f09b0';
const liveNestedLinkToken = 'LIVE_NESTED_LINK_DO_NOT_COPY_8c1a2e4215df4cf995';
const liveDoubleEncodedLinkToken = 'LIVE_DOUBLE_ENCODED_LINK_DO_NOT_COPY_dfb358cb6d';
const liveFragmentToken = 'LIVE_FRAGMENT_DO_NOT_COPY_3530e7946cc44c259e';
const liveTemplateToken = 'LIVE_TEMPLATE_TOKEN_DO_NOT_COPY_eaf77c0fe29a4c0eaa';
const liveShadowToken = 'LIVE_SHADOW_TOKEN_DO_NOT_COPY_b06d38a50e4549e3ad';
const liveActiveShadowToken = 'LIVE_ACTIVE_SHADOW_TOKEN_DO_NOT_COPY_8282e431a7';
const liveDataCarrierToken = 'LIVE_GENERIC_DATA_CARRIER_DO_NOT_COPY_4fbe1c7f26';
const liveMetaCarrierToken = 'LIVE_GENERIC_META_CARRIER_DO_NOT_COPY_c3789d2a61';
const liveSamlCarrierToken = 'LIVE_SAML_CARRIER_DO_NOT_COPY_414c90d339';
const liveSchemeRelativeToken = 'LIVE_SCHEME_RELATIVE_USERINFO_DO_NOT_COPY_8f94c72b0a';
const liveDecodeCapDataToken = 'LIVE_DECODE_CAP_DATA_DO_NOT_COPY_f31b9e35a0';
const liveDecodeCapMetaToken = 'LIVE_DECODE_CAP_META_DO_NOT_COPY_1858d6b68b';
const prefilledName = 'PREFILLED_APPLICANT_NAME_DO_NOT_COPY_1fd954ef';
const prefilledEmail = 'prefilled-applicant-c9e175@example.test';
const prefilledPhone = '+15555550987';
const prefilledTextarea = 'PREFILLED_APPLICANT_TEXTAREA_DO_NOT_COPY_716b8c31';
const prefilledContentEditable = 'PREFILLED_CONTENTEDITABLE_DO_NOT_COPY_842e726a';
const opaqueRadioValue = 'OPAQUE_RADIO_SUBMISSION_DO_NOT_COPY_5ac1ef5c';
const opaqueCheckboxValue = 'OPAQUE_CHECKBOX_SUBMISSION_DO_NOT_COPY_a3bb77b4';
const opaqueOptionValue = 'OPAQUE_OPTION_SUBMISSION_DO_NOT_COPY_2db10c99';
const tamperedSerializationSentinel = 'TAMPERED_SERIALIZATION_DO_NOT_COPY_87ee4f3b';
const tamperedSomeCarrierSentinel = 'TAMPERED_SOME_CARRIER_DO_NOT_COPY_4e654370';
const sensitiveAssetPathSentinel = 'RESET_ASSET_PATH_DO_NOT_COPY_90984b5a17';
const ordinaryAssetJobUuid = 'bdcfb29f-4f27-42de-933f-7f83a359b9f0';
const applicantValueSentinels = [
  prefilledName,
  prefilledEmail,
  prefilledPhone,
  prefilledTextarea,
  prefilledContentEditable,
  opaqueRadioValue,
  opaqueCheckboxValue,
  opaqueOptionValue
];
const encodeLayers = (value, count) => Array.from({ length: count }).reduce((encoded) => encodeURIComponent(encoded), value);
const dataCarrierPayload = JSON.stringify({
  displayMode: 'wide',
  routing: {
    callback: `https://redirect.example.test/continue?next=${encodeURIComponent(`https://vault.example.test/read?api_key=${liveDataCarrierToken}`)}`
  }
});
const metaCarrierPayload = JSON.stringify({
  theme: 'light',
  callback: encodeURIComponent(encodeURIComponent(`https://meta.example.test/read?session_token=${liveMetaCarrierToken}`))
});

const renderedMarkup = `
  <main id="ready" class="card" data-display-mode="wide" data-runtime-config='${dataCarrierPayload}'
    data-federation="samlResponse=${liveSamlCarrierToken}"
    data-endpoint="//fixture-user:${liveSchemeRelativeToken}@collector.example.test/path"
    data-overencoded="${encodeLayers(`next=https://vault.example.test/read?access_token=${liveDecodeCapDataToken}`, 5)}">
    <div class="brand-row">
      <img class="brand" src="/badge.svg" alt="Synthetic badge">
      <div><p class="eyebrow">Authorized local fixture</p><h1>Frontend Engineer</h1></div>
    </div>
    <p class="summary">Build careful interfaces and verify the details.</p>
    <p><a class="no-href">Reference only</a></p>
    <p><a href="/next?view=full&amp;X-Amz-Credential=${liveLinkToken}#access_token=${liveFragmentToken}">Sensitive link</a></p>
    <p><a href="/redirect?next=${encodeURIComponent(`https://cdn.example.test/file?access_token=${liveNestedLinkToken}`)}">Sensitive link</a></p>
    <p><a href="/encoded?%2570assword=${liveDoubleEncodedLinkToken}#%2570assword%253D${liveDoubleEncodedLinkToken}">Sensitive link</a></p>
    <map name="source-map"><area href="https://collector.example.test/map-target" alt="Source map target"></map>
    <form id="light-application-form" action="/live-submit" method="post">
      <input type="hidden" name="provider_token" value="${liveToken}">
      <label>Full name <input name="full_name" value="${prefilledName}" required></label>
      <label>Email <input name="email" type="email" value="${prefilledEmail}" required></label>
      <label>Phone <input name="phone" type="tel" value="${prefilledPhone}"></label>
      <label for="cover-note">Cover note</label><textarea id="cover-note" name="cover_note">${prefilledTextarea}</textarea>
      <button type="submit" formaction="https://collector.example.test/override" formmethod="get" formtarget="_blank">Submit application</button>
    </form>
    <template id="nested-template">
      <script>window.__nestedTemplateScriptMustNotSurvive = '${liveTemplateToken}'</script>
      <form action="https://collector.example.test/template-submit" method="post">
        <input type="hidden" name="csrf_token" value="${liveTemplateToken}">
        <div contenteditable="true">${prefilledContentEditable}</div>
        <label>Template radio <input type="radio" name="template_choice" value="${opaqueRadioValue}" checked></label>
        <label>Template checkbox <input type="checkbox" name="template_check" value="${opaqueCheckboxValue}" checked></label>
        <label>Template select <select name="template_select"><option value="${opaqueOptionValue}" selected>Visible option</option></select></label>
        <a href="https://collector.example.test/next?token=${liveTemplateToken}">Nested template link</a>
      </form>
    </template>
    <div id="shadow-host"></div>
  </main>`;

const shadowMarkup = `
  <style>.shadow-copy { display: block; margin-top: 14px; color: #172033; }</style>
  <span class="shadow-copy">Open shadow fidelity marker</span>
  <form id="shadow-application-form" action="/shadow-live-submit" method="get">
    <input type="hidden" name="provider_token" value="${liveActiveShadowToken}">
    <label>Shadow name <input name="shadow_name" required></label>
    <button type="submit">Shadow apply</button>
  </form>
  <a href="/shadow-next?token=${liveActiveShadowToken}">Sensitive link</a>
  <template>
    <script>window.__shadowTemplateScriptMustNotSurvive = '${liveShadowToken}'</script>
    <form action="https://collector.example.test/shadow-submit" method="post">
      <input type="hidden" name="shadow_secret" value="${liveShadowToken}">
      <a href="https://collector.example.test/shadow?signature=${liveShadowToken}">Nested shadow link</a>
    </form>
  </template>`;

const scriptLiteral = (value) => JSON.stringify(value).replace(/<\/script/gi, '<\\/script');

const sourceHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/">
    <meta name="description" content="Synthetic careers fixture with stable visible metadata.">
    <meta property="og:application-config" content='${metaCarrierPayload}'>
    <meta property="og:overencoded-config" content="${encodeLayers(`next=//fixture-user:${liveDecodeCapMetaToken}@meta.example.test/path`, 5)}">
    <title>Bootstrap fixture</title>
    <link rel="stylesheet" href="/site.css">
  </head>
  <body>
    <div id="mount">Rendering fixture…</div>
    <script>
      fetch('__PRIVATE_PROBE__/should-not-be-read').catch(() => {});
      try { new WebSocket('wss://transport.example.test/socket'); } catch {}
      try { if (globalThis.WebTransport) new WebTransport('https://transport.example.test/session'); } catch {}
      try { if (globalThis.WebSocketStream) new WebSocketStream('wss://transport.example.test/stream'); } catch {}
      try { if (globalThis.RTCPeerConnection) new RTCPeerConnection().createDataChannel('blocked'); } catch {}
      setTimeout(() => {
        document.querySelector('#mount').innerHTML = ${scriptLiteral(renderedMarkup)};
        const shadow = document.querySelector('#shadow-host').attachShadow({ mode: 'open' });
        shadow.innerHTML = ${scriptLiteral(shadowMarkup)};
        for (const control of document.querySelectorAll('[name="full_name"], [name="email"], [name="phone"], [name="cover_note"]')) {
          control.value = '';
        }
        document.body.dataset.rendered = 'true';
      }, 20);
    </script>
  </body>
</html>`;

const sourceCss = `
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  background: #eef3f8;
  color: #172033;
  font-family: Arial, sans-serif;
}
.card {
  width: 560px;
  margin: 44px auto;
  padding: 30px;
  border: 1px solid #cbd5e1;
  border-radius: 14px;
  background: #fff url('/badge.svg') no-repeat right 24px top 24px / 30px 30px;
  box-shadow: 0 12px 32px rgba(23, 32, 51, 0.12);
}
.brand-row { display: flex; align-items: center; gap: 16px; }
.brand { width: 48px; height: 48px; }
.eyebrow { margin: 0 0 3px; color: #3763c8; font-size: 12px; font-weight: 700; text-transform: uppercase; }
h1 { margin: 0; font-size: 29px; line-height: 36px; }
.summary { margin: 22px 0; line-height: 24px; }
form { display: grid; gap: 16px; }
label { display: grid; gap: 7px; font-size: 14px; font-weight: 700; }
input:not([type='hidden']) { height: 42px; border: 1px solid #94a3b8; border-radius: 7px; padding: 0 11px; font: inherit; }
button { width: max-content; border: 0; border-radius: 7px; padding: 12px 18px; color: white; background: #315fc4; font: 700 14px Arial, sans-serif; }
@media (min-width: 5000px) {
  .card {
    border-image-source: image-set('/deferred-image-set.svg' 1x, url('/deferred.svg') 2x);
  }
  .card::before { background-image: url('/password-reset/${sensitiveAssetPathSentinel}'); }
  .card::after { background-image: url('/jobs/${ordinaryAssetJobUuid}/badge.svg'); }
}
`;

const sourceSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">
  <rect width="48" height="48" rx="12" fill="#315fc4"/>
  <path d="M13 25h9V13h5v12h8L24 36z" fill="#fff"/>
</svg>`;

const tamperedSourceHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="99999;url=/leak?secret=${tamperedSerializationSentinel}">
    <title>Adversarial bootstrap fixture</title>
  </head>
  <body>
    <main id="ready">
      <form><input name="applicant" value="${tamperedSerializationSentinel}"></form>
    </main>
    <script>
      const nativeMatches = Element.prototype.matches;
      const nativeGetAttribute = Element.prototype.getAttribute;
      Element.prototype.matches = function (selector) {
        if (String(selector).includes('meta')) return false;
        return nativeMatches.call(this, selector);
      };
      Element.prototype.getAttribute = function (name) {
        if (String(name).toLowerCase() === 'value') return '';
        return nativeGetAttribute.call(this, name);
      };
      Array.prototype.filter = function () { return []; };
      Object.defineProperty(Element.prototype, 'outerHTML', {
        configurable: true,
        get() {
          return '<html><head><meta http-equiv="refresh" content="0;url=/leak?secret=${tamperedSerializationSentinel}"></head><body>${tamperedSerializationSentinel}</body></html>';
        }
      });
    </script>
  </body>
</html>`;

const tamperedSomeCarrierSourceHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta property="og:application-config" content='{"session_token":"${tamperedSomeCarrierSentinel}"}'>
    <title>Adversarial Array.some bootstrap fixture</title>
  </head>
  <body>
    <main id="ready" data-runtime-config='{"api_key":"${tamperedSomeCarrierSentinel}"}'>
      <p>Visible fixture content</p>
    </main>
    <script>Array.prototype.some = function () { return false; };</script>
  </body>
</html>`;

function respond(response, status, type, body) {
  response.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  response.end(body);
}

async function startSourceServer(requests, privateProbeOrigin) {
  const server = createServer((request, response) => {
    requests.push({ method: request.method, url: request.url });
    if (request.url === '/') {
      return respond(response, 200, 'text/html; charset=utf-8', sourceHtml.replace('__PRIVATE_PROBE__', privateProbeOrigin));
    }
    if (request.url === '/site.css') return respond(response, 200, 'text/css; charset=utf-8', sourceCss);
    if (request.url === '/badge.svg'
      || request.url === '/deferred.svg'
      || request.url === '/deferred-image-set.svg'
      || request.url === `/password-reset/${sensitiveAssetPathSentinel}`
      || request.url === `/jobs/${ordinaryAssetJobUuid}/badge.svg`) {
      return respond(response, 200, 'image/svg+xml', sourceSvg);
    }
    if (request.url === '/favicon.ico') return respond(response, 204, 'image/x-icon', '');
    return respond(response, 404, 'text/plain; charset=utf-8', 'not found');
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server;
}

async function startPrivateProbeServer(requests) {
  const server = createServer((request, response) => {
    requests.push({ method: request.method, url: request.url });
    respond(response, 200, 'text/plain; charset=utf-8', 'private fixture');
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server;
}

async function startHtmlServer(html) {
  const server = createServer((_request, response) => respond(response, 200, 'text/html; charset=utf-8', html));
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server;
}

async function closeServer(server) {
  if (!server?.listening) return;
  await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
}

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const { port } = server.address();
  await closeServer(server);
  return port;
}

async function runNode(pathname, args, options = {}) {
  try {
    return await execFileAsync(process.execPath, [pathname, ...args], {
      maxBuffer: 50 * 1024 * 1024,
      timeout: 120000,
      ...options
    });
  } catch (error) {
    const stdout = error.stdout || '';
    const stderr = error.stderr || '';
    throw new Error(`${pathname} failed (${error.code ?? 'unknown'}).\nstdout:\n${stdout}\nstderr:\n${stderr}`, { cause: error });
  }
}

async function waitForHealth(url, child, stderr) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Candidate exited before health check (${child.exitCode}).\n${stderr()}`);
    try {
      const response = await fetch(url);
      if (response.ok) return response;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`Timed out waiting for ${url}.\n${stderr()}`);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  const exited = new Promise((resolveExit) => child.once('exit', resolveExit));
  child.kill('SIGTERM');
  await Promise.race([
    exited,
    new Promise((resolveWait) => setTimeout(resolveWait, 5000))
  ]);
  if (child.exitCode === null) child.kill('SIGKILL');
}

async function filesBelow(root) {
  const files = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const pathname = join(root, entry.name);
    if (entry.isDirectory()) files.push(...await filesBelow(pathname));
    else if (entry.isFile()) files.push(pathname);
  }
  return files;
}

function safetyApproval(rule) {
  if (rule.kind !== 'changed' || !String(rule.rationale || '').trim()) return false;
  const fields = [...(rule.changeFields || [])].sort();
  const fingerprint = `${rule.key || ''} ${rule.keyPattern || ''}`;
  if (rule.category === 'forms') {
    return (JSON.stringify(fields) === JSON.stringify(['action', 'actionAttribute'])
        || JSON.stringify(fields) === JSON.stringify(['action', 'actionAttribute', 'method', 'methodAttribute']))
      && /form/.test(fingerprint);
  }
  if (rule.category === 'controls') {
    return fields.length > 0
      && fields.every((field) => ['hiddenValueLength', 'hiddenValuePresent'].includes(field))
      && /provider_token/.test(fingerprint)
      && /hidden/.test(fingerprint);
  }
  if (rule.category === 'links') {
    return fields.length === 1
      && fields[0] === 'href'
      && /Sensitive link/.test(fingerprint)
      && /structurally inert/.test(rule.rationale);
  }
  return false;
}

test('bootstrap provenance rejects sensitive path tokens while allowing ordinary job UUIDs', () => {
  const ordinaryJob = 'https://jobs.example.test/company/bdcfb29f-4f27-42de-933f-7f83a359b9f0/apply';
  const ordinary = bootstrapSourceProvenance(ordinaryJob);
  assert.equal(ordinary.parsedUrl.href, ordinaryJob);
  assert.equal(ordinary.provenance.source, ordinaryJob);
  const pathSecret = 'RESET_PATH_SECRET_DO_NOT_COPY_527be689';
  let rejection;
  try {
    bootstrapSourceProvenance(`https://jobs.example.test/password-reset/${pathSecret}`);
  } catch (error) {
    rejection = error;
  }
  assert.match(String(rejection?.message || ''), /credential|token|path segment/i);
  assert.doesNotMatch(String(rejection?.message || ''), new RegExp(pathSecret));
});

test('bootstrap snapshot resource descriptors redact sensitive path data without obscuring job UUIDs', () => {
  const ordinaryUuid = 'bdcfb29f-4f27-42de-933f-7f83a359b9f0';
  const ordinary = publicResourceDescriptor(`https://assets.example.test/jobs/${ordinaryUuid}/badge.svg`);
  assert.deepEqual(ordinary, {
    origin: 'https://assets.example.test',
    pathname: `/jobs/${ordinaryUuid}/badge.svg`
  });

  const sentinels = [
    'applicant-asset-c9e175@example.test',
    '+15555550987',
    'RESET_PATH_SECRET_DO_NOT_COPY_527be689',
    'MAGIC_LINK_SECRET_DO_NOT_COPY_c832a19f',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcml2YXRlLWFwcGxpY2FudCJ9.signature123',
    'sk-privateassetsecret1234567890'
  ];
  const urls = [
    `https://assets.example.test/avatars/${sentinels[0]}.png`,
    `https://assets.example.test/phone/${sentinels[1]}/avatar.png`,
    `https://assets.example.test/password-reset/${sentinels[2]}`,
    `https://assets.example.test/magic-link/${sentinels[3]}`,
    `https://assets.example.test/session/${sentinels[4]}`,
    `https://assets.example.test/keys/${sentinels[5]}`
  ];
  for (let index = 0; index < urls.length; index += 1) {
    const serialized = JSON.stringify(publicResourceDescriptor(urls[index]));
    assert.equal(serialized.includes(sentinels[index]), false, `descriptor retained sensitive path case ${index}`);
    assert.match(serialized, /REDACTED/);
  }
});

test('bootstrap fails closed before a source can forge sanitized serialization', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-bootstrap-tamper-'));
  const candidate = join(directory, 'candidate');
  let sourceServer;
  try {
    sourceServer = await startHtmlServer(tamperedSourceHtml);
    const sourceUrl = `http://127.0.0.1:${sourceServer.address().port}/`;
    let failure;
    try {
      await execFileAsync(process.execPath, [script('bootstrap-static-replica.mjs'),
        '--url', sourceUrl,
        '--out', candidate,
        '--mode', 'authorized-local',
        '--ready-selector', '#ready',
        '--wait-ms', '0',
        '--no-auto-scroll'
      ], { maxBuffer: 10 * 1024 * 1024, timeout: 45000 });
    } catch (error) {
      failure = error;
    }
    assert.ok(failure, 'capture-critical intrinsic tampering must reject the bootstrap');
    const diagnostics = `${failure.stdout || ''}${failure.stderr || ''}`;
    assert.match(diagnostics, /source modified capture-critical browser APIs/i);
    assert.equal(diagnostics.includes(tamperedSerializationSentinel), false,
      'failure diagnostics must not disclose the source sentinel');
    let candidateExists = true;
    try {
      await readdir(candidate);
    } catch (error) {
      if (error.code === 'ENOENT') candidateExists = false;
      else throw error;
    }
    assert.equal(candidateExists, false, 'a rejected source must not leave a candidate behind');
    assert.deepEqual(await readdir(directory), [], 'rejected staging output must be removed');
  } finally {
    await closeServer(sourceServer);
    await rm(directory, { recursive: true, force: true });
  }
});

test('bootstrap rejects Array.prototype.some tampering before credential carriers can be serialized', { timeout: 60000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-bootstrap-some-tamper-'));
  const candidate = join(directory, 'candidate');
  let sourceServer;
  try {
    sourceServer = await startHtmlServer(tamperedSomeCarrierSourceHtml);
    const sourceUrl = `http://127.0.0.1:${sourceServer.address().port}/`;
    let failure;
    try {
      await execFileAsync(process.execPath, [script('bootstrap-static-replica.mjs'),
        '--url', sourceUrl,
        '--out', candidate,
        '--mode', 'authorized-local',
        '--ready-selector', '#ready',
        '--wait-ms', '0',
        '--no-auto-scroll'
      ], { maxBuffer: 10 * 1024 * 1024, timeout: 45000 });
    } catch (error) {
      failure = error;
    }
    assert.ok(failure, 'Array.prototype.some tampering must reject the bootstrap');
    const diagnostics = `${failure.stdout || ''}${failure.stderr || ''}`;
    assert.match(diagnostics, /source modified capture-critical browser APIs/i);
    assert.equal(diagnostics.includes(tamperedSomeCarrierSentinel), false,
      'failure diagnostics must not disclose credential-carrier source data');
    let candidateExists = true;
    try {
      await readdir(candidate);
    } catch (error) {
      if (error.code === 'ENOENT') candidateExists = false;
      else throw error;
    }
    assert.equal(candidateExists, false, 'a rejected source must not leave credential carriers behind');
    assert.deepEqual(await readdir(directory), [], 'rejected staging output must be removed');
  } finally {
    await closeServer(sourceServer);
    await rm(directory, { recursive: true, force: true });
  }
});

test('portable bootstrap localizes a rendered form replica and emits passing safety evidence', { timeout: 180000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-bootstrap-'));
  const candidate = join(directory, 'candidate');
  const requests = [];
  const privateProbeRequests = [];
  let sourceServer;
  let privateProbeServer;
  let candidateChild;
  let candidateStderr = '';

  try {
    privateProbeServer = await startPrivateProbeServer(privateProbeRequests);
    const privateProbeOrigin = `http://127.0.0.1:${privateProbeServer.address().port}`;
    sourceServer = await startSourceServer(requests, privateProbeOrigin);
    const sourcePort = sourceServer.address().port;
    const sourceOrigin = `http://127.0.0.1:${sourcePort}`;
    const sourceUrl = `${sourceOrigin}/`;

    const bootstrapRun = await runNode(script('bootstrap-static-replica.mjs'), [
      '--url', sourceUrl,
      '--out', candidate,
      '--mode', 'authorized-local',
      '--ready-selector', '#ready',
      '--viewport', '800x600',
      '--wait-ms', '0'
    ]);
    for (const sentinel of [...applicantValueSentinels, sensitiveAssetPathSentinel]) {
      assert.equal(`${bootstrapRun.stdout || ''}${bootstrapRun.stderr || ''}`.includes(sentinel), false);
    }

    const candidateFiles = await filesBelow(candidate);
    const secretMatches = [];
    for (const pathname of candidateFiles) {
      const body = await readFile(pathname);
      if ([
        liveToken, liveLinkToken, liveNestedLinkToken, liveDoubleEncodedLinkToken, liveFragmentToken,
        liveTemplateToken, liveShadowToken, liveActiveShadowToken, liveDataCarrierToken, liveMetaCarrierToken,
        liveSamlCarrierToken, liveSchemeRelativeToken, liveDecodeCapDataToken, liveDecodeCapMetaToken,
        sensitiveAssetPathSentinel,
        ...applicantValueSentinels
      ]
        .some((token) => body.includes(Buffer.from(token)))) {
        secretMatches.push(pathname);
      }
    }
    assert.deepEqual(secretMatches, [], 'the generated candidate must not retain source form or link secrets');

    const persistedSnapshot = await readFile(join(candidate, 'snapshot.json'), 'utf8');
    assert.equal(persistedSnapshot.includes(sensitiveAssetPathSentinel), false,
      'snapshot evidence must not retain credential-bearing resource path segments');
    const snapshot = JSON.parse(persistedSnapshot);
    assert.equal(snapshot.source, sourceUrl);
    assert.ok(snapshot.resources.some((resource) => resource.origin === sourceOrigin && resource.pathname === '/site.css'));
    assert.ok(snapshot.resources.some((resource) => resource.origin === sourceOrigin && resource.pathname === '/badge.svg'));
    assert.ok(snapshot.resources.some((resource) => resource.origin === sourceOrigin && resource.pathname === '/deferred.svg'), 'CSS dependency closure should localize inactive-breakpoint assets');
    assert.ok(snapshot.resources.some((resource) => resource.origin === sourceOrigin && resource.pathname === '/deferred-image-set.svg'), 'quoted image-set URLs should be localized even at inactive breakpoints');
    assert.ok([...snapshot.resources, ...snapshot.skippedResources].some((resource) => (
      resource.origin === sourceOrigin && resource.pathname === '/password-reset/[REDACTED]'
    )), 'credential-bearing captured or rejected resource paths must be represented only by redacted descriptors');
    assert.ok(snapshot.resources.some((resource) => (
      resource.origin === sourceOrigin && resource.pathname === `/jobs/${ordinaryAssetJobUuid}/badge.svg`
    )), 'ordinary job UUID resource paths must remain useful in snapshot coverage evidence');
    assert.equal(privateProbeRequests.length, 0, 'a captured page must not reach a different private origin');
    assert.ok(snapshot.blockedPrivateReads.some((request) => request.origin === privateProbeOrigin));
    assert.ok(snapshot.runtimeAttemptCounts.webSocketAttempts >= 1,
      'bootstrap must block and count source WebSocket construction before network egress');
    for (const field of [
      'webTransportAttempts', 'webSocketStreamAttempts', 'rtcPeerConnectionAttempts', 'rtcDataChannelAttempts'
    ]) assert.equal(Number.isSafeInteger(snapshot.runtimeAttemptCounts[field]), true, `${field} must be audited`);
    for (const resource of snapshot.resources) {
      assert.match(resource.local, /^\/snapshot-assets\//);
      assert.equal((await stat(join(candidate, 'public', resource.local))).isFile(), true);
    }
    const localizedStylesheet = snapshot.resources.find((resource) => resource.pathname === '/site.css');
    const localizedCss = await readFile(join(candidate, 'public', localizedStylesheet.local), 'utf8');
    assert.match(localizedCss, /image-set\(['"]\/snapshot-assets\//);
    assert.doesNotMatch(localizedCss, /deferred-image-set\.svg/);

    const manifest = JSON.parse(await readFile(join(candidate, 'replica.manifest.json'), 'utf8'));
    assert.equal(manifest.mode, 'authorized-local');
    assert.equal(manifest.backend.emailEnabledByDefault, false);
    assert.equal(manifest.backend.retainsApplicantValues, false);
    assert.equal(manifest.page.readySelector, '[data-replica-ready]');
    assert.equal(manifest.interaction.formSelector, null, 'multiple active forms must require an explicit selector');
    manifest.interaction.formSelector = '#shadow-application-form';
    await writeFile(join(candidate, 'replica.manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    const generatedHtml = await readFile(join(candidate, 'public', 'index.html'), 'utf8');
    assert.match(generatedHtml, /Content-Security-Policy/);
    assert.match(generatedHtml, /<a class="no-href">Reference only<\/a>/, 'anchors without href should survive serialization');
    const markedSourceAnchors = generatedHtml.match(/<a\b(?=[^>]*data-replica-source-link)[^>]*>/gi) || [];
    assert.ok(markedSourceAnchors.length > 0, 'navigable source anchors must become marked inert anchors');
    assert.ok(markedSourceAnchors.every((anchor) => /\brole="link"/i.test(anchor)), 'inert source anchors must retain link accessibility semantics');
    assert.match(generatedHtml, /data-display-mode="wide"/, 'ordinary presentation data attributes must survive');
    assert.match(generatedHtml, /data-runtime-config="synthetic-local"/, 'credential-bearing generic data attributes must be replaced');
    assert.match(generatedHtml, /data-federation="synthetic-local"/, 'SAML response carriers must be replaced');
    assert.match(generatedHtml, /data-endpoint="synthetic-local"/, 'scheme-relative URL credentials must be replaced');
    assert.match(generatedHtml, /data-overencoded="synthetic-local"/, 'values encoded beyond the decode cap must fail closed');
    assert.match(generatedHtml, /<meta name="description" content="Synthetic careers fixture with stable visible metadata\."\s*\/?>/i);
    assert.match(generatedHtml, /<meta property="og:application-config" content="synthetic-local"\s*\/?>/i);
    assert.match(generatedHtml, /<meta property="og:overencoded-config" content="synthetic-local"\s*\/?>/i);
    assert.ok(snapshot.sanitization.sensitiveAttributes >= 1);
    assert.ok(snapshot.sanitization.sensitiveMetadata >= 1);
    assert.ok(snapshot.sanitization.freeformValues >= 4);
    assert.ok(snapshot.sanitization.choiceValues >= 2);
    assert.ok(snapshot.sanitization.optionValues >= 1);
    assert.ok(snapshot.sanitization.contentEditableValues >= 1);
    assert.match(generatedHtml, /value="synthetic-local-choice-\d{4}"/);
    assert.match(generatedHtml, /value="synthetic-local-option-\d{4}"/);
    for (const sentinel of applicantValueSentinels) assert.equal(generatedHtml.includes(sentinel), false);
    assert.doesNotMatch(generatedHtml, /<a\b[^>]*\bhref=/i, 'source anchors must be structurally inert for click, auxclick, and context-menu activation');
    assert.doesNotMatch(generatedHtml, /<area\b[^>]*\bhref=/i, 'image-map areas must also be structurally inert');
    assert.doesNotMatch(generatedHtml, /<base\b/i, 'base URL declarations must not survive serialization');
    assert.doesNotMatch(generatedHtml, /view=full/);
    assert.doesNotMatch(generatedHtml, /X-Amz-Credential|access_token/);
    assert.match(generatedHtml, /<template[^>]+shadowrootmode="open"/i, 'open shadow roots should serialize as declarative shadow DOM');
    assert.doesNotMatch(generatedHtml, /nestedTemplateScriptMustNotSurvive|shadowTemplateScriptMustNotSurvive/);
    assert.doesNotMatch(generatedHtml, /collector\.example\.test\/(?:template|shadow)-submit/);

    const candidatePort = await freePort();
    candidateChild = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(candidatePort) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    candidateChild.stderr.on('data', (chunk) => { candidateStderr += chunk; });
    const candidateOrigin = `http://127.0.0.1:${candidatePort}`;
    const health = await waitForHealth(`${candidateOrigin}${manifest.start.healthPath}`, candidateChild, () => candidateStderr);
    assert.equal(health.headers.get('x-replica-mode'), 'authorized-local');
    const documentResponse = await fetch(candidateOrigin);
    const documentCsp = documentResponse.headers.get('content-security-policy') || '';
    assert.match(documentCsp, /script-src 'self'/);
    assert.match(documentCsp, /connect-src 'self'/);
    assert.match(documentCsp, /form-action 'self'/);
    assert.match(documentCsp, /object-src 'none'/);
    assert.match(documentCsp, /frame-ancestors 'none'/);
    assert.equal(documentResponse.headers.get('x-frame-options'), 'DENY');
    const fallbackResponse = await fetch(`${candidateOrigin}/palantir/synthetic-job/apply`);
    assert.equal(fallbackResponse.status, 200);
    assert.equal(fallbackResponse.headers.get('content-security-policy'), documentCsp,
      'SPA fallback HTML must receive the same document security policy');
    assert.equal(fallbackResponse.headers.get('x-frame-options'), 'DENY');
    const svgResource = snapshot.resources.find((resource) => resource.pathname === '/badge.svg');
    const svgResponse = await fetch(new URL(svgResource.local, candidateOrigin));
    assert.equal(svgResponse.headers.get('x-content-type-options'), 'nosniff');
    assert.match(svgResponse.headers.get('content-security-policy') || '', /script-src 'none'/);

    const inspectionDirectory = join(directory, 'candidate-inspection');
    await runNode(script('inspect-page.mjs'), [
      '--url', candidateOrigin,
      '--out', inspectionDirectory,
      '--ready-selector', manifest.page.readySelector,
      '--viewport', 'desktop:800x600',
      '--wait-ms', '0'
    ]);
    const inspection = JSON.parse(await readFile(join(inspectionDirectory, 'desktop', 'contract.json'), 'utf8'));
    assert.equal(inspection.telemetry.failedGets.length, 0);
    assert.equal(inspection.telemetry.pageErrors.length, 0);
    assert.equal(inspection.contract.forms[0].action, `${candidateOrigin}/api/applications`);
    assert.equal(inspection.contract.forms.length, 2);
    assert.ok(inspection.contract.forms.every((form) => form.action === `${candidateOrigin}/api/applications`));
    assert.ok(inspection.contract.integrity.replicaSourceLinks.length > 0);
    assert.ok(inspection.contract.integrity.replicaSourceLinks.every((link) => (
      link.hrefAttribute === null && link.xlinkHrefAttribute === null && link.role === 'link'
    )), 'marked source links must be structurally inert while preserving their link role');
    const populatedHiddenControls = inspection.contract.controls.filter((control) => (
      control.type === 'hidden' && control.hiddenValuePresent
    ));
    assert.ok(populatedHiddenControls.length > 0);
    assert.ok(populatedHiddenControls.every((control) => (
      control.value === null && control.hiddenValueClassification === 'synthetic-local'
    )), 'hidden input inspection must classify the exact placeholder without retaining its raw value');
    const overrideControl = inspection.contract.controls.find((control) => control.formActionAttribute !== null);
    assert.equal(overrideControl.formAction, `${candidateOrigin}/api/applications`);
    assert.equal(overrideControl.formMethod, 'post');
    assert.equal(overrideControl.formTargetAttribute, null);
    for (const resource of inspection.contract.resources) {
      assert.equal(new URL(resource.name).origin, candidateOrigin, `external candidate resource: ${resource.name}`);
    }
    for (const stylesheet of inspection.contract.stylesheets.filter((entry) => entry.href)) {
      assert.equal(new URL(stylesheet.href).origin, candidateOrigin, `external candidate stylesheet: ${stylesheet.href}`);
    }
    for (const surface of inspection.contract.integrity.rasterSurfaces.filter((entry) => entry.src)) {
      assert.equal(new URL(surface.src).origin, candidateOrigin, `external candidate image: ${surface.src}`);
    }
    const integrityPath = join(directory, 'candidate-integrity.json');
    await runNode(script('check-candidate-integrity.mjs'), [
      '--inspection', inspectionDirectory,
      '--source', sourceUrl,
      '--manifest', join(candidate, 'replica.manifest.json'),
      '--out', integrityPath
    ]);
    assert.equal(JSON.parse(await readFile(integrityPath, 'utf8')).pass, true);

    const comparisonDirectory = join(directory, 'comparison');
    await runNode(script('compare-pages.mjs'), [
      '--baseline', sourceUrl,
      '--candidate', candidateOrigin,
      '--out', comparisonDirectory,
      '--baseline-ready-selector', '#ready',
      '--candidate-ready-selector', '[data-replica-ready]',
      '--viewport', 'desktop:800x600',
      '--wait-ms', '0'
    ]);
    const comparison = JSON.parse(await readFile(join(comparisonDirectory, 'summary.json'), 'utf8'));
    assert.equal(comparison.results.length, 1);
    assert.equal(comparison.results[0].pixel.dimensionsMatch, true);
    assert.equal(comparison.results[0].pixel.strictChangedPixels, 0);
    assert.equal(comparison.results[0].pixel.tolerantChangedPixels, 0);

    const policyPath = join(candidate, 'fidelity-policy.json');
    const policy = JSON.parse(await readFile(policyPath, 'utf8'));
    assert.ok(policy.approvedSemanticMismatches.length > 0);
    assert.ok(policy.approvedSemanticMismatches.every(safetyApproval), 'policy may approve only local form-action, synthetic hidden-value, and credential-link changes');

    const scorePath = join(directory, 'score.json');
    await runNode(script('assert-fidelity.mjs'), [
      '--summary', join(comparisonDirectory, 'summary.json'),
      '--policy', policyPath,
      '--out', scorePath
    ]);
    const score = JSON.parse(await readFile(scorePath, 'utf8'));
    assert.equal(score.pass, true);
    assert.equal(score.results[0].metrics.unapprovedSemanticMismatchCount, 0);
    assert.equal(score.results[0].metrics.approvedSemanticMismatchCount, score.results[0].metrics.rawSemanticMismatchCount);
    assert.ok(score.results[0].metrics.approvedSemanticMismatchCount >= 3);

    const interactionPath = join(directory, 'interaction.json');
    await runNode(script('test-application-flow.mjs'), [
      '--candidate', candidateOrigin,
      '--manifest', join(candidate, 'replica.manifest.json'),
      '--out', interactionPath
    ]);
    const interaction = JSON.parse(await readFile(interactionPath, 'utf8'));
    assert.equal(interaction.pass, true);
    assert.equal(interaction.invalidRequired.length, 0);
    assert.equal(interaction.blockedWrites.length, 0);
    assert.equal(interaction.sameOriginWrites.length, 2);
    assert.equal(new URL(interaction.sameOriginWrites[0].url).pathname, '/api/applications');
    assert.equal(interaction.oneLogicalReceipt, true);

    assert.ok(requests.length > 0);
    assert.ok(requests.every((request) => ['GET', 'HEAD', 'OPTIONS'].includes(request.method)), 'the source fixture must stay read-only');
    assert.equal(candidateStderr, '');
  } finally {
    await stopChild(candidateChild);
    await closeServer(sourceServer);
    await closeServer(privateProbeServer);
    await rm(directory, { recursive: true, force: true });
  }
});
