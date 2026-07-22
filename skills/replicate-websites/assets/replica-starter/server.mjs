#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { extname, isAbsolute, join, normalize, relative, resolve, sep } from 'node:path';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('./public/', import.meta.url)));
const rootStat = await fs.lstat(root);
if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
  throw new Error('The public root must be a real, non-symlink directory.');
}
const canonicalRoot = await fs.realpath(root);
const port = Number(process.env.PORT || 4173);
const configuredReplicaMode = '{{REPLICA_MODE}}';
const replicaMode = new Set(['authorized-local', 'owned', 'public-simulation']).has(configuredReplicaMode)
  ? configuredReplicaMode
  : 'authorized-local';
const bindHost = replicaMode === 'authorized-local' ? '127.0.0.1' : '0.0.0.0';
const receipts = new Map();
const syntheticFixtureHeader = 'synthetic-browser-run-v1';
const syntheticCanaryName = '__replica_synthetic_canary';
const syntheticCanaryValue = 'replica-synthetic-canary-v1';
const maxFileBytes = 5 * 1024 * 1024;
const maxMultipartBytes = maxFileBytes + (1024 * 1024);
const documentContentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'none'",
  "script-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "object-src 'none'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "media-src 'self' blob:",
  "worker-src 'none'",
  "manifest-src 'self'"
].join('; ');
let sequence = 0;
const audit = {
  schemaVersion: 1,
  implementation: 'replicate-websites-starter-v1',
  submissionAttempts: 0,
  logicalReceipts: 0,
  storedApplicantBytes: 0,
  storedFileBytes: 0,
  outboxCount: 0,
  emailDispatchCount: 0
};

const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.avif': 'image/avif',
  '.eot': 'application/vnd.ms-fontobject',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.mp4': 'video/mp4',
  '.otf': 'font/otf',
  '.svg': 'image/svg+xml',
  '.ttf': 'font/ttf',
  '.webm': 'video/webm',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

function sendJson(response, status, value) {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-replica-mode': replicaMode
  });
  response.end(body);
}

class RequestValidationError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

async function readBody(request, limit = maxMultipartBytes) {
  let received = 0;
  const chunks = [];
  for await (const chunk of request) {
    received += chunk.length;
    if (received > limit) throw new RequestValidationError(413, 'body_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, received);
}

function multipartBoundary(contentType) {
  const segments = String(contentType || '').split(';');
  if (segments.shift()?.trim().toLowerCase() !== 'multipart/form-data') {
    throw new RequestValidationError(415, 'multipart_form_data_required');
  }
  const raw = segments
    .map((segment) => segment.trim())
    .find((segment) => /^boundary=/i.test(segment))
    ?.replace(/^boundary=/i, '')
    .trim();
  const boundary = raw?.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
  if (!boundary || boundary.length > 70 || /[^\x20-\x7e]|[\r\n]/.test(boundary)) {
    throw new RequestValidationError(400, 'invalid_multipart_boundary');
  }
  return boundary;
}

function dispositionParameters(value) {
  const segments = String(value || '').split(';');
  if (segments.shift()?.trim().toLowerCase() !== 'form-data') {
    throw new RequestValidationError(400, 'invalid_content_disposition');
  }
  const parameters = new Map();
  for (const segment of segments) {
    const match = /^\s*([a-z0-9_-]+)=(?:"([^"\r\n]*)"|([^;\r\n]*))\s*$/i.exec(segment);
    if (!match) throw new RequestValidationError(400, 'invalid_content_disposition');
    const key = match[1].toLowerCase();
    if (parameters.has(key)) throw new RequestValidationError(400, 'duplicate_content_disposition_parameter');
    parameters.set(key, match[2] ?? match[3].trim());
  }
  return parameters;
}

function validateMultipart(body, contentType) {
  const boundary = multipartBoundary(contentType);
  const delimiter = Buffer.from(`--${boundary}`);
  const marker = Buffer.from(`\r\n--${boundary}`);
  const headerSeparator = Buffer.from('\r\n\r\n');
  let cursor = 0;
  let partCount = 0;
  let fieldCount = 0;
  let fileCount = 0;
  let canaryCount = 0;

  if (!body.subarray(0, delimiter.length).equals(delimiter)) {
    throw new RequestValidationError(400, 'invalid_multipart_framing');
  }
  while (cursor < body.length) {
    if (!body.subarray(cursor, cursor + delimiter.length).equals(delimiter)) {
      throw new RequestValidationError(400, 'invalid_multipart_framing');
    }
    cursor += delimiter.length;
    if (body.subarray(cursor, cursor + 2).toString('ascii') === '--') {
      cursor += 2;
      if (body.subarray(cursor).toString('ascii') !== '\r\n' && body.subarray(cursor).length !== 0) {
        throw new RequestValidationError(400, 'invalid_multipart_epilogue');
      }
      break;
    }
    if (body.subarray(cursor, cursor + 2).toString('ascii') !== '\r\n') {
      throw new RequestValidationError(400, 'invalid_multipart_framing');
    }
    cursor += 2;
    const headerEnd = body.indexOf(headerSeparator, cursor);
    if (headerEnd < 0 || headerEnd - cursor > 16 * 1024) {
      throw new RequestValidationError(400, 'invalid_multipart_headers');
    }
    const headers = new Map();
    for (const line of body.subarray(cursor, headerEnd).toString('utf8').split('\r\n')) {
      const separator = line.indexOf(':');
      if (separator <= 0) throw new RequestValidationError(400, 'invalid_multipart_headers');
      const name = line.slice(0, separator).trim().toLowerCase();
      if (headers.has(name)) throw new RequestValidationError(400, 'duplicate_multipart_header');
      headers.set(name, line.slice(separator + 1).trim());
    }
    const parameters = dispositionParameters(headers.get('content-disposition'));
    const name = parameters.get('name');
    if (!name || name.length > 256) throw new RequestValidationError(400, 'invalid_field_name');
    cursor = headerEnd + headerSeparator.length;
    const nextMarker = body.indexOf(marker, cursor);
    if (nextMarker < 0) throw new RequestValidationError(400, 'invalid_multipart_framing');
    const value = body.subarray(cursor, nextMarker);
    cursor = nextMarker + 2;
    partCount += 1;
    if (partCount > 512) throw new RequestValidationError(400, 'too_many_multipart_parts');

    if (parameters.has('filename')) {
      const filename = parameters.get('filename');
      const mimeType = String(headers.get('content-type') || '').toLowerCase();
      const emptySentinel = filename === '' && value.length === 0
        && (!mimeType || mimeType === 'application/octet-stream');
      if (!emptySentinel) {
        if (filename !== 'synthetic-resume.pdf' || mimeType !== 'application/pdf') {
          throw new RequestValidationError(400, 'synthetic_pdf_upload_required');
        }
        if (value.length > maxFileBytes) throw new RequestValidationError(413, 'file_too_large');
        if (!value.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
          throw new RequestValidationError(400, 'invalid_synthetic_pdf');
        }
        fileCount += 1;
      }
    } else {
      if (value.length > 64 * 1024) throw new RequestValidationError(413, 'field_too_large');
      fieldCount += 1;
      if (name === syntheticCanaryName && value.toString('utf8') === syntheticCanaryValue) canaryCount += 1;
    }
  }
  if (partCount === 0 || fieldCount === 0 || canaryCount !== 1) {
    throw new RequestValidationError(400, 'synthetic_canary_required');
  }
  return { bodyBytes: body.length, partCount, fieldCount, fileCount };
}

function isWithin(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (!pathFromParent.startsWith('..') && !isAbsolute(pathFromParent));
}

function safeStaticPath(pathname) {
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { return null; }
  const relative = normalize(decoded).replace(/^[/\\]+/, '');
  const candidate = resolve(join(root, relative || 'index.html'));
  return candidate === root || candidate.startsWith(`${root}${sep}`) ? candidate : null;
}

async function resolveStaticFile(pathname) {
  let pathnameOnDisk = safeStaticPath(pathname);
  if (!pathnameOnDisk) return null;
  try {
    let stat = await fs.lstat(pathnameOnDisk);
    if (stat.isSymbolicLink()) return null;
    if (stat.isDirectory()) {
      pathnameOnDisk = join(pathnameOnDisk, 'index.html');
      stat = await fs.lstat(pathnameOnDisk);
      if (stat.isSymbolicLink()) return null;
    }
    if (!stat.isFile()) return null;
    const components = relative(root, pathnameOnDisk).split(sep).filter(Boolean);
    let current = root;
    for (const component of components) {
      current = join(current, component);
      if ((await fs.lstat(current)).isSymbolicLink()) return null;
    }
    const canonical = await fs.realpath(pathnameOnDisk);
    if (!isWithin(canonicalRoot, canonical)) return null;
    return canonical;
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
    return null;
  }
}

async function serveStatic(pathname, response) {
  const pathnameOnDisk = await resolveStaticFile(pathname);
  if (!pathnameOnDisk) return false;
  try {
    const body = await fs.readFile(pathnameOnDisk);
    const extension = extname(pathnameOnDisk);
    const headers = {
      'content-type': contentTypes[extname(pathnameOnDisk)] || 'application/octet-stream',
      'content-length': body.length,
      'x-content-type-options': 'nosniff',
      'x-replica-mode': replicaMode
    };
    if (extension === '.svg') {
      headers['content-security-policy'] = "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:";
      headers['x-frame-options'] = 'DENY';
    } else if (extension === '.html') {
      headers['content-security-policy'] = documentContentSecurityPolicy;
      headers['x-frame-options'] = 'DENY';
      headers['referrer-policy'] = 'no-referrer';
    }
    response.writeHead(200, headers);
    response.end(body);
    return true;
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
    return false;
  }
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || '127.0.0.1'}`);
    if (request.method === 'GET' && url.pathname === '/healthz') {
      return sendJson(response, 200, { ok: true, service: '{{PROJECT_NAME}}' });
    }
    if (request.method === 'GET' && url.pathname === '/api/replica-audit') {
      return sendJson(response, 200, { ...audit, idempotencyEntries: receipts.size });
    }
    if (request.method === 'POST' && url.pathname === '/api/applications' && !url.search) {
      const rawKey = String(request.headers['x-idempotency-key'] || '');
      if (!/^synthetic-[a-z0-9-]{1,80}$/i.test(rawKey)) {
        return sendJson(response, 400, { error: 'invalid_idempotency_key' });
      }
      if (request.headers['x-replica-fixture'] !== syntheticFixtureHeader) {
        return sendJson(response, 403, { error: 'synthetic_fixture_required' });
      }
      const body = await readBody(request);
      const { bodyBytes } = validateMultipart(body, request.headers['content-type']);
      audit.submissionAttempts += 1;
      const key = createHash('sha256').update(rawKey).digest('hex');
      let receipt = receipts.get(key);
      if (!receipt) {
        if (receipts.size >= 1000) return sendJson(response, 429, { error: 'receipt_limit' });
        sequence += 1;
        receipt = {
          id: `synthetic-${String(sequence).padStart(4, '0')}`,
          status: 'received',
          bodyBytes,
          emailConfirmation: false
        };
        receipts.set(key, receipt);
        audit.logicalReceipts = receipts.size;
      }
      return sendJson(response, 200, receipt);
    }
    if (request.method === 'GET' && url.pathname.startsWith('/api/receipts/')) {
      const id = url.pathname.split('/').pop();
      const receipt = [...receipts.values()].find((candidate) => candidate.id === id);
      return receipt ? sendJson(response, 200, receipt) : sendJson(response, 404, { error: 'not_found' });
    }
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (await serveStatic(url.pathname, response)) return;
      if (await serveStatic('/index.html', response)) return;
    }
    sendJson(response, 404, { error: 'not_found' });
  } catch (error) {
    if (error instanceof RequestValidationError) return sendJson(response, error.status, { error: error.code });
    sendJson(response, 500, { error: 'internal_error' });
  }
});

server.listen(port, bindHost, () => {
  const address = server.address();
  const ready = {
    schemaVersion: 1,
    type: 'replica-backend-ready',
    service: '{{PROJECT_NAME}}',
    mode: replicaMode,
    host: bindHost,
    port: address.port
  };
  if (typeof process.send === 'function') process.send(ready);
  else process.stdout.write(`{{PROJECT_NAME}} listening on http://${bindHost}:${address.port}\n`);
});
