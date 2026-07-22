import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, request as httpRequest } from 'node:http';
import { connect as connectTcp, createServer as createTcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { createValidatingBrowserProxy } from '../scripts/lib/validating-proxy.mjs';

const execFileAsync = promisify(execFile);
const skillRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function listen(server) {
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  return server.address().port;
}

async function closeServer(server) {
  if (!server.listening) return;
  await new Promise((resolveClose) => server.close(resolveClose));
}

async function proxyGet(proxy, target) {
  const parsed = new URL(target);
  return new Promise((resolveResponse, rejectResponse) => {
    const clientRequest = httpRequest({
      host: proxy.host,
      port: proxy.port,
      method: 'GET',
      path: parsed.href,
      headers: { host: parsed.host },
      agent: false
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolveResponse({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8')
      }));
    });
    clientRequest.setTimeout(5000, () => {
      clientRequest.destroy(new Error('proxy GET timed out'));
    });
    clientRequest.once('error', rejectResponse);
    clientRequest.end();
  });
}

async function waitFor(predicate, message, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(message);
    await delay(10);
  }
}

test('validating proxy resolves every public connection and pins the vetted address', async () => {
  const observations = [];
  const origin = createServer((request, response) => {
    observations.push({ host: request.headers.host, via: request.headers.via });
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('pinned');
  });
  const port = await listen(origin);
  let resolverCalls = 0;
  const proxy = await createValidatingBrowserProxy({
    resolver: async () => {
      resolverCalls += 1;
      return [{ address: '127.0.0.1', family: 4 }];
    },
    // This dependency injection models a vetted public result while keeping the fixture local.
    addressIsBlocked: () => false
  });
  try {
    const target = `http://does-not-resolve.invalid:${port}/proof`;
    assert.deepEqual(await proxyGet(proxy, target), { status: 200, body: 'pinned' });
    assert.deepEqual(await proxyGet(proxy, target), { status: 200, body: 'pinned' });
    assert.equal(resolverCalls, 2, 'a public result must be resolved afresh for each upstream connection');
    assert.equal(proxy.stats.dnsResolutions, 2);
    assert.equal(observations.length, 2);
    assert.ok(observations.every((entry) => entry.host === `does-not-resolve.invalid:${port}`));
    assert.ok(observations.every((entry) => /replicate-validating-proxy/.test(entry.via || '')));
  } finally {
    await proxy.close();
    await closeServer(origin);
  }
});

test('validating proxy rejects any private DNS answer but permits only its exact loopback endpoint', async () => {
  let originHits = 0;
  const origin = createServer((_request, response) => {
    originHits += 1;
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('loopback-ok');
  });
  const port = await listen(origin);
  const mixedAnswerProxy = await createValidatingBrowserProxy({
    resolver: async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '127.0.0.1', family: 4 }
    ]
  });
  const loopbackProxy = await createValidatingBrowserProxy({
    allowedLoopbackUrl: `http://localhost:${port}/candidate`,
    resolver: async () => [
      { address: '::1', family: 6 },
      { address: '127.0.0.1', family: 4 }
    ]
  });
  try {
    const blocked = await proxyGet(mixedAnswerProxy, `http://rebind.invalid:${port}/private`);
    assert.equal(blocked.status, 403);
    assert.equal(originHits, 0);

    const allowed = await proxyGet(loopbackProxy, `http://localhost:${port}/candidate`);
    assert.deepEqual(allowed, { status: 200, body: 'loopback-ok' });
    const wrongPort = port === 65535 ? port - 1 : port + 1;
    const rejected = await proxyGet(loopbackProxy, `http://localhost:${wrongPort}/candidate`);
    assert.equal(rejected.status, 403);
    assert.equal(originHits, 1);
  } finally {
    await mixedAnswerProxy.close();
    await loopbackProxy.close();
    await closeServer(origin);
  }
});

test('validating proxy absorbs client CONNECT resets and closes the paired upstream', { timeout: 10000 }, async () => {
  let tunnelSocket;
  let tunnelClosed = false;
  const tunnelOrigin = createTcpServer((socket) => {
    tunnelSocket = socket;
    socket.on('error', () => {});
    socket.once('close', () => { tunnelClosed = true; });
    const traffic = setInterval(() => {
      if (!socket.destroyed) socket.write(Buffer.alloc(4096, 0x78));
    }, 5);
    traffic.unref();
    socket.once('close', () => clearInterval(traffic));
  });
  const httpOrigin = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('still-healthy');
  });
  const tunnelPort = await listen(tunnelOrigin);
  const httpPort = await listen(httpOrigin);
  const proxy = await createValidatingBrowserProxy({
    resolver: async () => [{ address: '127.0.0.1', family: 4 }],
    addressIsBlocked: () => false
  });
  let client;
  try {
    client = connectTcp({ host: proxy.host, port: proxy.port });
    client.on('error', () => {});
    let response = '';
    let reset = false;
    client.on('data', (chunk) => {
      response += chunk.toString('latin1');
      if (!reset && response.includes('200 Connection Established')) {
        reset = true;
        client.resetAndDestroy();
      }
    });
    client.write(
      `CONNECT tunnel-reset.invalid:${tunnelPort} HTTP/1.1\r\n`
      + `Host: tunnel-reset.invalid:${tunnelPort}\r\n\r\n`
    );

    await waitFor(() => reset, 'the proxy never established the CONNECT tunnel');
    await waitFor(() => tunnelClosed, 'the paired upstream socket remained open');
    await waitFor(
      () => proxy.stats.clientSocketErrors > 0,
      'the accepted CONNECT reset was not recorded as a handled client socket error'
    );
    assert.equal(tunnelSocket.destroyed, true);
    assert.deepEqual(
      await proxyGet(proxy, `http://still-healthy.invalid:${httpPort}/proof`),
      { status: 200, body: 'still-healthy' },
      'one reset tunnel must not poison the proxy for later requests'
    );
  } finally {
    client?.destroy();
    await proxy.close();
    await closeServer(tunnelOrigin);
    await closeServer(httpOrigin);
  }
});

test('inspect-page sends even loopback navigation through the validating proxy', { timeout: 60000 }, async () => {
  let sawProxyHeader = false;
  const origin = createServer((request, response) => {
    sawProxyHeader ||= /replicate-validating-proxy/.test(request.headers.via || '');
    if (!sawProxyHeader) {
      response.writeHead(421, { 'content-type': 'text/plain' });
      response.end('proxy required');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end('<!doctype html><html><head><link rel="icon" href="data:,"></head><body><main><h1>Proxy proof</h1></main></body></html>');
  });
  const port = await listen(origin);
  const output = await mkdtemp(join(tmpdir(), 'replicate-proxy-inspection-'));
  try {
    const script = join(skillRoot, 'scripts', 'inspect-page.mjs');
    const result = await execFileAsync(process.execPath, [
      script,
      '--url', `http://127.0.0.1:${port}/`,
      '--out', output,
      '--viewport', 'proof:320x240',
      '--wait-ms', '0',
      '--no-auto-scroll'
    ], { maxBuffer: 20 * 1024 * 1024 });
    assert.match(result.stdout, /Inspection:/);
    assert.equal(sawProxyHeader, true, 'Chromium must not apply its implicit loopback proxy bypass');
  } finally {
    await rm(output, { recursive: true, force: true });
    await closeServer(origin);
  }
});
