import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, connect as netConnect } from 'node:net';
import {
  isLoopbackHostname,
  isPrivateOrReservedAddress,
  resolvePublicHostAddresses
} from './network-safety.mjs';

const proxyAgent = 'replicate-validating-proxy';

class DestinationRejected extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function normalizedHostname(value) {
  return String(value || '')
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

function effectivePort(protocol, rawPort) {
  if (rawPort) return Number(rawPort);
  return protocol === 'https:' ? 443 : 80;
}

function parseAuthority(value) {
  const raw = String(value || '').trim();
  let hostname = '';
  let rawPort = '';
  if (raw.startsWith('[')) {
    const match = /^\[([^\]]+)]:(\d+)$/.exec(raw);
    if (!match) throw new DestinationRejected('INVALID_CONNECT_AUTHORITY');
    [, hostname, rawPort] = match;
  } else {
    const separator = raw.lastIndexOf(':');
    if (separator <= 0 || raw.indexOf(':') !== separator) {
      throw new DestinationRejected('INVALID_CONNECT_AUTHORITY');
    }
    hostname = raw.slice(0, separator);
    rawPort = raw.slice(separator + 1);
  }
  const port = Number(rawPort);
  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new DestinationRejected('INVALID_CONNECT_AUTHORITY');
  }
  return { hostname: normalizedHostname(hostname), port };
}

function allowedLoopbackEndpoint(rawUrl) {
  if (!rawUrl) return null;
  const parsed = new URL(rawUrl);
  if (!['http:', 'https:'].includes(parsed.protocol) || !isLoopbackHostname(parsed.hostname)) {
    throw new Error('allowedLoopbackUrl must be an exact HTTP(S) loopback URL.');
  }
  return {
    hostname: normalizedHostname(parsed.hostname),
    port: effectivePort(parsed.protocol, parsed.port)
  };
}

async function resolveWithTimeout(resolver, hostname, timeoutMs) {
  let timer;
  try {
    const result = await Promise.race([
      resolver(hostname, { all: true, verbatim: true }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new DestinationRejected('DNS_TIMEOUT')), timeoutMs);
      })
    ]);
    const entries = (Array.isArray(result) ? result : [result])
      .map((entry) => ({
        address: String(entry?.address || entry || ''),
        family: Number(entry?.family || isIP(entry?.address || entry))
      }))
      .filter((entry) => entry.address && [4, 6].includes(entry.family));
    if (!entries.length) throw new DestinationRejected('DNS_NO_ADDRESSES');
    return entries;
  } catch (error) {
    if (error instanceof DestinationRejected) throw error;
    throw new DestinationRejected('DNS_RESOLUTION_FAILED');
  } finally {
    clearTimeout(timer);
  }
}

function sameEndpoint(left, right) {
  return Boolean(left && right)
    && normalizedHostname(left.hostname) === normalizedHostname(right.hostname)
    && Number(left.port) === Number(right.port);
}

function ordinaryForwardHeaders(headers, authority) {
  const output = { ...headers, host: authority };
  delete output['proxy-authorization'];
  delete output['proxy-connection'];
  output.via = output.via ? `${output.via}, 1.1 ${proxyAgent}` : `1.1 ${proxyAgent}`;
  return output;
}

function sendProxyError(response, status, code) {
  if (response.headersSent) return response.destroy();
  const body = `${code}\n`;
  response.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    connection: 'close'
  });
  response.end(body);
}

async function resolveValidatedDestination({
  hostname,
  port,
  allowedLoopback,
  resolver,
  addressIsBlocked,
  resolveTimeoutMs,
  onDnsResolution = () => {}
}) {
  const normalized = normalizedHostname(hostname);
  const endpoint = { hostname: normalized, port: Number(port) };
  const exactAllowedLoopback = sameEndpoint(endpoint, allowedLoopback);
  if (isIP(normalized)) {
    if (addressIsBlocked(normalized) && !exactAllowedLoopback) {
      throw new DestinationRejected('PRIVATE_OR_RESERVED_DESTINATION');
    }
    if (exactAllowedLoopback && !isLoopbackHostname(normalized)) {
      throw new DestinationRejected('INVALID_LOOPBACK_ALLOWANCE');
    }
    return { address: normalized, family: isIP(normalized) };
  }

  onDnsResolution();
  const addresses = await resolveWithTimeout(resolver, normalized, resolveTimeoutMs);
  if (exactAllowedLoopback) {
    if (addresses.some(({ address }) => !isLoopbackHostname(address))) {
      throw new DestinationRejected('LOOPBACK_NAME_RESOLVED_EXTERNALLY');
    }
    // The audited starter binds 127.0.0.1. Node commonly returns ::1 first for
    // localhost, so prefer a vetted IPv4 loopback when both families exist.
    return addresses.find(({ family }) => family === 4) || addresses[0];
  }
  if (addresses.some(({ address }) => addressIsBlocked(address))) {
    throw new DestinationRejected('PRIVATE_OR_RESERVED_DESTINATION');
  }
  return addresses[0];
}

export function playwrightProxyOptions(proxy) {
  return {
    server: proxy.url,
    // Chromium otherwise has an implicit localhost bypass even when a proxy is explicit.
    bypass: '<-loopback>'
  };
}

export async function requestPinnedHttpResource(rawUrl, {
  allowedLoopbackUrl = null,
  resolver = resolvePublicHostAddresses,
  addressIsBlocked = isPrivateOrReservedAddress,
  resolveTimeoutMs = 3000,
  timeoutMs = 10000,
  maximumBytes = 15 * 1024 * 1024,
  headers = {}
} = {}) {
  const parsed = new URL(rawUrl);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new DestinationRejected('INVALID_RESOURCE_URL');
  }
  const port = effectivePort(parsed.protocol, parsed.port);
  const allowedLoopback = allowedLoopbackEndpoint(allowedLoopbackUrl);
  const destination = await resolveValidatedDestination({
    hostname: parsed.hostname,
    port,
    allowedLoopback,
    resolver,
    addressIsBlocked,
    resolveTimeoutMs
  });
  const request = parsed.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolveResponse, rejectResponse) => {
    let settled = false;
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      rejectResponse(error);
    };
    const clientRequest = request({
      hostname: destination.address,
      family: destination.family,
      port,
      method: 'GET',
      path: `${parsed.pathname}${parsed.search}`,
      headers: { ...headers, host: parsed.host },
      agent: false,
      ...(parsed.protocol === 'https:' && !isIP(normalizedHostname(parsed.hostname))
        ? { servername: normalizedHostname(parsed.hostname) }
        : {})
    }, (response) => {
      const declaredLength = Number(response.headers['content-length'] || 0);
      if (declaredLength > maximumBytes) {
        response.destroy();
        const error = new DestinationRejected('RESOURCE_LIMIT');
        return finishReject(error);
      }
      const chunks = [];
      let bytes = 0;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > maximumBytes) {
          response.destroy();
          finishReject(new DestinationRejected('RESOURCE_LIMIT'));
          return;
        }
        chunks.push(chunk);
      });
      response.once('aborted', () => finishReject(new DestinationRejected('UPSTREAM_ABORTED')));
      response.once('error', finishReject);
      response.once('end', () => {
        if (settled) return;
        settled = true;
        resolveResponse({
          status: response.statusCode || 0,
          headers: response.headers,
          body: Buffer.concat(chunks, bytes),
          url: parsed.href
        });
      });
    });
    clientRequest.setTimeout(timeoutMs, () => clientRequest.destroy(new DestinationRejected('UPSTREAM_TIMEOUT')));
    clientRequest.once('error', finishReject);
    clientRequest.end();
  });
}

export async function createValidatingBrowserProxy({
  allowedLoopbackUrl = null,
  resolver = resolvePublicHostAddresses,
  addressIsBlocked = isPrivateOrReservedAddress,
  connect = netConnect,
  request = httpRequest,
  resolveTimeoutMs = 3000,
  connectTimeoutMs = 10000
} = {}) {
  const allowedLoopback = allowedLoopbackEndpoint(allowedLoopbackUrl);
  const sockets = new Set();
  const upstreamSockets = new Set();
  const stats = {
    httpRequests: 0,
    connectTunnels: 0,
    rejectedDestinations: 0,
    dnsResolutions: 0
  };

  const resolveDestination = ({ hostname, port }) => resolveValidatedDestination({
    hostname,
    port,
    allowedLoopback,
    resolver,
    addressIsBlocked,
    resolveTimeoutMs,
    onDnsResolution: () => { stats.dnsResolutions += 1; }
  });

  const server = createServer(async (clientRequest, clientResponse) => {
    stats.httpRequests += 1;
    let parsed;
    try {
      parsed = new URL(clientRequest.url);
      if (parsed.protocol !== 'http:' || parsed.username || parsed.password) {
        throw new DestinationRejected('ABSOLUTE_HTTP_URL_REQUIRED');
      }
      const port = effectivePort(parsed.protocol, parsed.port);
      const destination = await resolveDestination({ hostname: parsed.hostname, port });
      const authority = parsed.host;
      const upstream = request({
        hostname: destination.address,
        family: destination.family,
        port,
        method: clientRequest.method,
        path: `${parsed.pathname}${parsed.search}`,
        headers: ordinaryForwardHeaders(clientRequest.headers, authority),
        agent: false,
        timeout: connectTimeoutMs
      }, (upstreamResponse) => {
        clientResponse.writeHead(
          upstreamResponse.statusCode || 502,
          upstreamResponse.statusMessage || '',
          upstreamResponse.headers
        );
        upstreamResponse.pipe(clientResponse);
      });
      upstream.on('socket', (socket) => {
        upstreamSockets.add(socket);
        socket.once('close', () => upstreamSockets.delete(socket));
      });
      upstream.on('timeout', () => upstream.destroy(new Error('UPSTREAM_TIMEOUT')));
      upstream.on('error', () => sendProxyError(clientResponse, 502, 'UPSTREAM_CONNECTION_FAILED'));
      clientRequest.pipe(upstream);
    } catch (error) {
      stats.rejectedDestinations += 1;
      sendProxyError(
        clientResponse,
        error instanceof DestinationRejected ? 403 : 400,
        error instanceof DestinationRejected ? error.code : 'INVALID_PROXY_REQUEST'
      );
    }
  });

  server.on('connect', async (requestMessage, clientSocket, head) => {
    stats.connectTunnels += 1;
    try {
      const endpoint = parseAuthority(requestMessage.url);
      const destination = await resolveDestination(endpoint);
      const upstream = connect({
        host: destination.address,
        family: destination.family,
        port: endpoint.port
      });
      upstreamSockets.add(upstream);
      upstream.once('close', () => upstreamSockets.delete(upstream));
      upstream.setTimeout(connectTimeoutMs, () => upstream.destroy(new Error('UPSTREAM_TIMEOUT')));
      upstream.once('connect', () => {
        clientSocket.write(`HTTP/1.1 200 Connection Established\r\nProxy-Agent: ${proxyAgent}\r\n\r\n`);
        if (head?.length) upstream.write(head);
        clientSocket.pipe(upstream);
        upstream.pipe(clientSocket);
      });
      upstream.once('error', () => {
        if (!clientSocket.destroyed) clientSocket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
      });
    } catch (error) {
      stats.rejectedDestinations += 1;
      if (!clientSocket.destroyed) clientSocket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    }
  });

  server.on('upgrade', (_request, socket) => {
    stats.rejectedDestinations += 1;
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('clientError', (_error, socket) => {
    if (!socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });

  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  let closed = false;
  const proxy = {
    host: '127.0.0.1',
    port: address.port,
    url: `http://127.0.0.1:${address.port}`,
    stats,
    async close() {
      if (closed) return;
      closed = true;
      for (const socket of [...upstreamSockets, ...sockets]) socket.destroy();
      await new Promise((resolveClose) => server.close(() => resolveClose()));
    }
  };
  proxy.playwright = playwrightProxyOptions(proxy);
  return proxy;
}
