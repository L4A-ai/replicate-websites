#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  assertSafeHttpUrl,
  blocksUnsafeDestinationBeforeProxy,
  isLoopbackHostname,
  redactReportData
} from './lib/network-safety.mjs';
import { verifyTrustedBackend } from './lib/trusted-backend.mjs';
import { startTrustedBackend } from './lib/trusted-backend-process.mjs';
import { createValidatingBrowserProxy } from './lib/validating-proxy.mjs';
import { integrityNativeInitScript } from './lib/integrity-natives.mjs';
import {
  findChromiumExecutable,
  resolveRuntimePackage
} from './lib/runtime-dependencies.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const skillDirectory = resolve(scriptDirectory, '..');
const syntheticCanaryName = '__replica_synthetic_canary';
const syntheticCanaryValue = 'replica-synthetic-canary-v1';
const syntheticFixtureHeader = 'synthetic-browser-run-v1';
const maximumManifestBytes = 256 * 1024;
const maximumManifestPathLength = 2048;
const maximumSelectorLength = 4096;
const maximumInteractionActions = 64;
const maximumUploadContentsBytes = 64 * 1024;

function parseArguments(argv) {
  const options = {
    candidate: null,
    manifest: null,
    out: null,
    source: null,
    allowPublicCandidate: false,
    timeoutMs: 30000,
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
      case '--candidate': options.candidate = take(index, argument); index += 1; break;
      case '--manifest': options.manifest = resolve(take(index, argument)); index += 1; break;
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--source': options.source = take(index, argument); index += 1; break;
      case '--allow-public-candidate': options.allowPublicCandidate = true; break;
      case '--timeout-ms': options.timeoutMs = Number(take(index, argument)); index += 1; break;
      case '--headed': options.headed = true; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && (!options.candidate || !options.manifest)) throw new Error('--candidate and --manifest are required.');
  if (!options.help && (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1000 || options.timeoutMs > 120000)) {
    throw new Error('--timeout-ms must be an integer from 1000 through 120000.');
  }
  return options;
}

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  return value;
}

function boundedString(value, label, maximumLength, { optional = false, allowEmpty = false } = {}) {
  if (value === undefined && optional) return;
  if (typeof value !== 'string' || (!allowEmpty && !value.trim()) || value.length > maximumLength) {
    throw new Error(`${label} must be ${allowEmpty ? '' : 'a non-empty '}string of at most ${maximumLength} characters.`);
  }
}

function boundedManifestPath(value, label) {
  boundedString(value, label, maximumManifestPathLength);
  if (!value.startsWith('/') || value.startsWith('//') || /[?#]/.test(value)) {
    throw new Error(`${label} must be a bounded root-relative path without query or fragment data.`);
  }
}

function validateManifestInteraction(manifest) {
  plainObject(manifest, 'Manifest');
  const start = plainObject(manifest.start, 'manifest.start');
  const page = plainObject(manifest.page, 'manifest.page');
  const backend = plainObject(manifest.backend, 'manifest.backend');
  boundedManifestPath(start.healthPath, 'manifest.start.healthPath');
  boundedManifestPath(page.path, 'manifest.page.path');
  boundedManifestPath(backend.submitPath, 'manifest.backend.submitPath');
  boundedManifestPath(backend.auditPath, 'manifest.backend.auditPath');
  boundedString(page.readySelector, 'manifest.page.readySelector', maximumSelectorLength, { optional: true });

  if (manifest.interaction === undefined) return;
  const interaction = plainObject(manifest.interaction, 'manifest.interaction');
  const allowedInteractionKeys = new Set([
    'notApplicable', 'reason', 'formSelector', 'submitSelector', 'customRequiredSelector',
    'successSelector', 'settleMs', 'actions'
  ]);
  for (const key of Object.keys(interaction)) {
    if (!allowedInteractionKeys.has(key)) throw new Error(`manifest.interaction contains unsupported key "${key}".`);
  }
  if (interaction.notApplicable !== undefined && typeof interaction.notApplicable !== 'boolean') {
    throw new Error('manifest.interaction.notApplicable must be boolean.');
  }
  boundedString(interaction.reason, 'manifest.interaction.reason', 4096, { optional: true });
  for (const key of ['formSelector', 'submitSelector', 'customRequiredSelector', 'successSelector']) {
    boundedString(interaction[key], `manifest.interaction.${key}`, maximumSelectorLength, { optional: true });
  }
  if (interaction.settleMs !== undefined
    && (!Number.isInteger(interaction.settleMs) || interaction.settleMs < 0 || interaction.settleMs > 10000)) {
    throw new Error('manifest.interaction.settleMs must be an integer from 0 through 10000.');
  }
  if (interaction.actions === undefined) return;
  if (!Array.isArray(interaction.actions) || interaction.actions.length > maximumInteractionActions) {
    throw new Error(`manifest.interaction.actions must contain at most ${maximumInteractionActions} actions.`);
  }
  const allowedKeys = {
    fill: new Set(['action', 'selector', 'value']),
    check: new Set(['action', 'selector']),
    uncheck: new Set(['action', 'selector']),
    select: new Set(['action', 'selector', 'value']),
    click: new Set(['action', 'selector']),
    upload: new Set(['action', 'selector', 'name', 'mimeType', 'contents'])
  };
  interaction.actions.forEach((rawAction, index) => {
    const action = plainObject(rawAction, `manifest.interaction.actions[${index}]`);
    if (typeof action.action !== 'string' || !allowedKeys[action.action]) {
      throw new Error(`manifest.interaction.actions[${index}].action is unsupported.`);
    }
    for (const key of Object.keys(action)) {
      if (!allowedKeys[action.action].has(key)) {
        throw new Error(`manifest.interaction.actions[${index}] contains unsupported key "${key}".`);
      }
    }
    boundedString(action.selector, `manifest.interaction.actions[${index}].selector`, maximumSelectorLength);
    if (['fill', 'select'].includes(action.action) && action.value !== undefined) {
      boundedString(action.value, `manifest.interaction.actions[${index}].value`, 8192, { allowEmpty: true });
    }
    if (action.action === 'select' && action.value === undefined) {
      throw new Error(`manifest.interaction.actions[${index}].value is required for select.`);
    }
    if (action.action === 'upload') {
      boundedString(action.name, `manifest.interaction.actions[${index}].name`, 256, { optional: true });
      boundedString(action.mimeType, `manifest.interaction.actions[${index}].mimeType`, 256, { optional: true });
      boundedString(action.contents, `manifest.interaction.actions[${index}].contents`, maximumUploadContentsBytes, {
        optional: true,
        allowEmpty: true
      });
      if (action.contents !== undefined && Buffer.byteLength(action.contents) > maximumUploadContentsBytes) {
        throw new Error(`manifest.interaction.actions[${index}].contents exceeds ${maximumUploadContentsBytes} bytes.`);
      }
    }
  });
}

function validateCandidateBoundary(options, candidate) {
  if (!['http:', 'https:'].includes(candidate.protocol)) {
    throw new Error('--candidate must use http: or https:.');
  }
  if (candidate.username || candidate.password) throw new Error('--candidate may not contain URL credentials.');
  const loopback = isLoopbackHostname(candidate.hostname);
  if (!loopback || options.allowPublicCandidate) {
    throw new Error('Refusing mutation tests against a public candidate. Start the immutable audited backend on loopback; deployed candidates receive read-only fidelity and integrity checks only.');
  }
  if (options.source) {
    const source = assertSafeHttpUrl(options.source, '--source');
    if (source.origin === candidate.origin) throw new Error('Candidate and source origins must differ.');
    return source;
  }
  return null;
}

function isWithin(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (!pathFromParent.startsWith('..') && !isAbsolute(pathFromParent));
}

async function canonicalManifestBoundary(pathname) {
  const requestedManifest = resolve(pathname);
  const requestedRoot = dirname(requestedManifest);
  const rootStat = await fs.lstat(requestedRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error('Manifest parent must be a real, non-symlink candidate directory.');
  }
  const manifestStat = await fs.lstat(requestedManifest);
  if (manifestStat.isSymbolicLink() || !manifestStat.isFile()) {
    throw new Error('Manifest must be a regular, non-symlink file.');
  }
  if (manifestStat.size > maximumManifestBytes) {
    throw new Error(`Manifest exceeds the ${maximumManifestBytes}-byte safety limit.`);
  }
  const candidateRoot = await fs.realpath(requestedRoot);
  const manifestPath = await fs.realpath(requestedManifest);
  if (!isWithin(candidateRoot, manifestPath)) {
    throw new Error('Manifest must remain inside its canonical candidate root.');
  }
  return { candidateRoot, manifestPath };
}

function exactCandidateEndpoint(candidate, rawPath, label) {
  if (typeof rawPath !== 'string' || !rawPath.startsWith('/') || rawPath.startsWith('//')) {
    throw new Error(`${label} must be a root-relative path.`);
  }
  const endpoint = new URL(rawPath, candidate.origin);
  if (endpoint.origin !== candidate.origin || endpoint.search || endpoint.hash) {
    throw new Error(`${label} must resolve to an unqualified path on the candidate origin.`);
  }
  return endpoint;
}

function receiptShape(value) {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && typeof value.id === 'string'
    && value.id.length > 0
    && value.status === 'received'
    && value.emailConfirmation === false;
}

function retainedApplicantData(value) {
  const serialized = JSON.stringify(value || {});
  if (/(?:Synthetic Applicant|synthetic\.applicant@example\.test|\+15555550100|example\.test\/portfolio|synthetic-resume\.pdf)/i.test(serialized)) return true;
  const allowedMetadataKeys = new Set(['bodyBytes', 'emailConfirmation']);
  const visit = (entry) => {
    if (!entry || typeof entry !== 'object') return false;
    if (Array.isArray(entry)) return entry.some(visit);
    return Object.entries(entry).some(([key, child]) => {
      if (!allowedMetadataKeys.has(key) && /(?:applicant|answers?|fields?|values?|payload|resume|phone|full_?name|raw_?body|email)/i.test(key)) return true;
      return visit(child);
    });
  };
  return visit(value);
}

async function fetchCandidateJson(page, pathname) {
  const response = await page.evaluate(async (path) => {
    const result = await fetch(path, { method: 'GET', cache: 'no-store' });
    return {
      status: result.status,
      contentType: result.headers.get('content-type') || '',
      text: await result.text()
    };
  }, pathname);
  let json = null;
  try { json = JSON.parse(response.text); } catch {}
  return { ...response, json };
}

function validAuditShape(value) {
  return Boolean(value)
    && value.schemaVersion === 1
    && value.implementation === 'replicate-websites-starter-v1'
    && Number.isInteger(value.submissionAttempts)
    && Number.isInteger(value.logicalReceipts)
    && Number.isInteger(value.idempotencyEntries)
    && value.storedApplicantBytes === 0
    && value.storedFileBytes === 0
    && value.outboxCount === 0
    && value.emailDispatchCount === 0;
}

async function fillControl(control) {
  const tag = await control.evaluate((element) => element.tagName.toLowerCase());
  const type = await control.getAttribute('type') || tag;
  if (type === 'hidden' || type === 'submit' || type === 'button' || type === 'reset') return 'skipped';
  if (type === 'file') {
    await control.setInputFiles({
      name: 'synthetic-resume.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n')
    });
    return 'upload';
  }
  if (type === 'checkbox') {
    await control.check();
    return 'check';
  }
  if (type === 'radio') {
    await control.check();
    return 'radio';
  }
  if (tag === 'select') {
    const value = await control.evaluate((element) => [...element.options]
      .find((option) => !option.disabled && option.value)?.value || '');
    if (value) await control.selectOption(value);
    return 'select';
  }
  const values = {
    email: 'synthetic.applicant@example.test',
    tel: '+15555550100',
    url: 'https://example.test/portfolio',
    date: '2030-01-01',
    number: '1'
  };
  await control.fill(values[type] || 'Synthetic Applicant');
  return 'fill';
}

async function applyManifestAction(page, action) {
  const locator = page.locator(action.selector).first();
  await locator.waitFor({ state: 'visible' });
  switch (action.action) {
    case 'fill': await locator.fill(String(action.value ?? 'Synthetic Applicant')); break;
    case 'check': await locator.check(); break;
    case 'uncheck': await locator.uncheck(); break;
    case 'select': await locator.selectOption(String(action.value)); break;
    case 'click': await locator.click(); break;
    case 'upload':
      await locator.setInputFiles({
        name: action.name || 'synthetic-resume.pdf',
        mimeType: action.mimeType || 'application/pdf',
        buffer: Buffer.from(action.contents || '%PDF-1.4\n%%EOF\n')
      });
      break;
    default: throw new Error(`Unsupported manifest interaction action: ${action.action}`);
  }
}

function hashPart(hash, label, value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  hash.update(`${label}:${bytes.length}:`);
  hash.update(bytes);
  hash.update('\0');
}

async function inspectSyntheticMultipart(request) {
  const headers = request.headers();
  const contentType = headers['content-type'] || '';
  if (!/^multipart\/form-data\s*;/i.test(contentType)) {
    throw new Error('Controlled submission did not use multipart/form-data.');
  }
  if (headers['x-replica-fixture'] !== syntheticFixtureHeader) {
    throw new Error('Controlled submission omitted the synthetic fixture header.');
  }
  const body = request.postDataBuffer();
  if (!body) throw new Error('Controlled multipart submission had no inspectable body.');
  const parsed = await new Response(body, { headers: { 'content-type': contentType } }).formData();
  const metadataHash = createHash('sha256');
  const contentHash = createHash('sha256');
  let partCount = 0;
  let fieldCount = 0;
  let fileCount = 0;
  let fileBytes = 0;
  let canaryCount = 0;
  for (const [name, value] of parsed.entries()) {
    partCount += 1;
    const isField = typeof value === 'string';
    hashPart(metadataHash, 'name', name);
    hashPart(metadataHash, 'kind', isField ? 'field' : 'file');
    hashPart(contentHash, 'name', name);
    if (isField) {
      fieldCount += 1;
      hashPart(contentHash, 'value', value);
      if (name === syntheticCanaryName && value === syntheticCanaryValue) canaryCount += 1;
    } else {
      const bytes = Buffer.from(await value.arrayBuffer());
      fileCount += 1;
      fileBytes += bytes.length;
      hashPart(metadataHash, 'filename', value.name || '');
      hashPart(metadataHash, 'mime', value.type || '');
      hashPart(metadataHash, 'size', String(bytes.length));
      hashPart(contentHash, 'file', bytes);
    }
  }
  return {
    metadataDigest: metadataHash.digest('hex'),
    contentDigest: contentHash.digest('hex'),
    partCount,
    fieldCount,
    fileCount,
    fileBytes,
    canaryPresent: canaryCount === 1,
    fixtureHeaderPresent: true
  };
}

function publicMultipartMetadata(capture) {
  if (!capture) return null;
  return {
    partCount: capture.partCount,
    fieldCount: capture.fieldCount,
    fileCount: capture.fileCount,
    fileBytes: capture.fileBytes,
    canaryPresent: capture.canaryPresent,
    fixtureHeaderPresent: capture.fixtureHeaderPresent
  };
}

async function inspectCustomRequired(form, selector) {
  return form.evaluate((element, customSelector) => {
    const controls = [...element.querySelectorAll(customSelector)]
      .filter((control) => !(control.willValidate && control.required) && !control.hasAttribute('disabled'));
    const states = controls.map((control, index) => {
      const role = (control.getAttribute('role') || '').toLowerCase();
      const described = (control.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean)
        .map((id) => document.getElementById(id))
        .filter(Boolean);
      const invalidSignal = control.getAttribute('aria-invalid') === 'true'
        || control.getAttribute('data-invalid') === 'true'
        || control.matches('.invalid, .error, [data-error]')
        || described.some((node) => node.getClientRects().length > 0
          && (node.getAttribute('role') === 'alert'
            || node.matches('.invalid, .error, [data-error], [aria-live]'))
          && String(node.textContent || '').trim());
      let hasValue = false;
      if (['checkbox', 'radio', 'switch'].includes(role)) {
        hasValue = control.getAttribute('aria-checked') === 'true';
      } else if (role === 'radiogroup') {
        hasValue = Boolean(control.querySelector('[role="radio"][aria-checked="true"], input[type="radio"]:checked'));
      } else if (role === 'listbox') {
        hasValue = Boolean(control.querySelector('[role="option"][aria-selected="true"], option:checked:not([disabled])'));
      } else if (['textbox', 'searchbox'].includes(role) || control.getAttribute('contenteditable') === 'true') {
        hasValue = Boolean(String(
          control.value
          ?? control.getAttribute('aria-valuetext')
          ?? control.textContent
          ?? ''
        ).trim());
      } else if (role === 'combobox') {
        hasValue = Boolean(String(
          control.value
          ?? control.getAttribute('aria-valuetext')
          ?? control.getAttribute('data-value')
          ?? control.getAttribute('aria-activedescendant')
          ?? ''
        ).trim()) || Boolean(control.querySelector('[aria-selected="true"], option:checked:not([disabled])'));
      } else if (['spinbutton', 'slider'].includes(role)) {
        hasValue = Boolean(String(
          control.value
          ?? control.getAttribute('aria-valuenow')
          ?? control.getAttribute('aria-valuetext')
          ?? ''
        ).trim());
      } else {
        hasValue = Boolean(String(
          control.value
          ?? control.getAttribute('aria-valuetext')
          ?? control.getAttribute('aria-valuenow')
          ?? control.getAttribute('data-value')
          ?? ''
        ).trim()) || Boolean(control.querySelector(
          '[aria-selected="true"], [aria-checked="true"], input:checked, option:checked:not([disabled])'
        ));
      }
      return { index, role: role || null, invalid: invalidSignal || !hasValue, hasValue };
    });
    return {
      count: states.length,
      invalidCount: states.filter((state) => state.invalid).length,
      unresolved: states.filter((state) => state.invalid)
    };
  }, selector);
}

async function countActiveForms(cdp) {
  const { nodes = [] } = await cdp.send('DOM.getFlattenedDocument', { depth: -1, pierce: true });
  const maximumNodes = 100000;
  const inspectedNodes = nodes.length;
  if (inspectedNodes > maximumNodes) return { count: 0, inspectedNodes, truncated: true };
  const byId = new Map(nodes.map((node) => [node.nodeId, node]));
  let count = 0;
  for (const node of nodes) {
    if (String(node?.nodeName || '').toLowerCase() !== 'form') continue;
    let ancestor = byId.get(node.parentId);
    let insideTemplate = false;
    while (ancestor) {
      if (String(ancestor.nodeName || '').toLowerCase() === 'template') {
        insideTemplate = true;
        break;
      }
      ancestor = byId.get(ancestor.parentId);
    }
    if (!insideTemplate) count += 1;
  }
  return { count, inspectedNodes, truncated: false };
}

async function inspectSelectedForms(page, locator) {
  return locator.evaluateAll((elements) => {
    const natives = globalThis.__replicaIntegrityNatives;
    if (!natives) return { onlyForms: false, nativeApiTampering: ['integrity-natives-missing'] };
    const nativeApiTampering = natives.auditElements(elements, 1000);
    let onlyForms = true;
    for (let index = 0; index < elements.length; index += 1) {
      if (!natives.matches(elements[index], 'form')) onlyForms = false;
    }
    return { onlyForms, nativeApiTampering };
  });
}

async function inspectInteractionNatives(page) {
  return page.evaluate(() => {
    const natives = globalThis.__replicaIntegrityNatives;
    if (!natives) return ['integrity-natives-missing'];
    const elements = natives.queryAll(document, '*');
    if (elements.length > 10000) return ['interaction-element-inventory-limit'];
    return natives.auditElements(elements, 1000);
  });
}

function storageGuardInitScript() {
  const report = globalThis.__replicaReportStorageMutation;
  const sensitive = /replica-synthetic-canary|synthetic applicant|synthetic\.applicant@example\.test|\+15555550100|synthetic-resume\.pdf/i;
  const reportAttempt = (kind, scope = '') => {
    try { void report({ kind, scope }); } catch {}
  };
  const replaceMethod = (owner, name, kind, replacement = () => undefined) => {
    if (!owner || typeof owner[name] !== 'function') return null;
    const native = owner[name];
    try {
      Object.defineProperty(owner, name, {
        configurable: false,
        writable: false,
        value(...args) {
          reportAttempt(kind, String(args[0] ?? '').slice(0, 128));
          return replacement(...args);
        }
      });
    } catch {}
    return native;
  };

  const storageKey = globalThis.Storage?.prototype?.key;
  const storageGetItem = globalThis.Storage?.prototype?.getItem;
  const nativeStorages = {};
  for (const scope of ['localStorage', 'sessionStorage']) {
    let descriptorOwner = globalThis;
    let descriptor = null;
    while (descriptorOwner && !descriptor) {
      descriptor = Object.getOwnPropertyDescriptor(descriptorOwner, scope);
      descriptorOwner = Object.getPrototypeOf(descriptorOwner);
    }
    let nativeStorage = null;
    try { nativeStorage = globalThis[scope]; } catch {}
    nativeStorages[scope] = nativeStorage;
    if (!nativeStorage) continue;
    const proxy = new Proxy(nativeStorage, {
      set(_target, property) { reportAttempt(`${scope}.propertyWrite`, String(property)); return true; },
      defineProperty(_target, property) { reportAttempt(`${scope}.defineProperty`, String(property)); return true; },
      deleteProperty(_target, property) { reportAttempt(`${scope}.deleteProperty`, String(property)); return true; }
    });
    for (const owner of [globalThis, globalThis.Window?.prototype]) {
      if (!owner) continue;
      try {
        Object.defineProperty(owner, scope, {
          configurable: false,
          enumerable: descriptor?.enumerable === true,
          get: () => proxy
        });
      } catch {}
    }
  }
  for (const name of ['setItem', 'removeItem', 'clear']) {
    replaceMethod(globalThis.Storage?.prototype, name, `Storage.${name}`);
  }

  const cookieDescriptor = Object.getOwnPropertyDescriptor(globalThis.Document?.prototype || {}, 'cookie');
  if (cookieDescriptor?.set) {
    try {
      Object.defineProperty(globalThis.Document.prototype, 'cookie', {
        configurable: false,
        enumerable: cookieDescriptor.enumerable,
        get: cookieDescriptor.get,
        set() { reportAttempt('document.cookie'); }
      });
    } catch {}
  }

  const indexedDb = globalThis.indexedDB;
  const indexedDbDatabases = indexedDb && typeof indexedDb.databases === 'function'
    ? indexedDb.databases.bind(indexedDb)
    : null;
  replaceMethod(indexedDb, 'open', 'indexedDB.open', () => {
    throw new DOMException('IndexedDB is disabled during replica interaction verification.', 'SecurityError');
  });
  replaceMethod(indexedDb, 'deleteDatabase', 'indexedDB.deleteDatabase', () => {
    throw new DOMException('IndexedDB is disabled during replica interaction verification.', 'SecurityError');
  });
  replaceMethod(globalThis.IDBFactory?.prototype, 'open', 'indexedDB.open', () => {
    throw new DOMException('IndexedDB is disabled during replica interaction verification.', 'SecurityError');
  });
  replaceMethod(globalThis.IDBFactory?.prototype, 'deleteDatabase', 'indexedDB.deleteDatabase', () => {
    throw new DOMException('IndexedDB is disabled during replica interaction verification.', 'SecurityError');
  });

  const cacheStorage = globalThis.caches;
  const cacheKeys = cacheStorage && typeof cacheStorage.keys === 'function'
    ? cacheStorage.keys.bind(cacheStorage)
    : null;
  replaceMethod(cacheStorage, 'open', 'CacheStorage.open', () => Promise.reject(
    new DOMException('Cache Storage is disabled during replica interaction verification.', 'SecurityError')
  ));
  replaceMethod(cacheStorage, 'delete', 'CacheStorage.delete', () => Promise.resolve(false));
  replaceMethod(globalThis.CacheStorage?.prototype, 'open', 'CacheStorage.open', () => Promise.reject(
    new DOMException('Cache Storage is disabled during replica interaction verification.', 'SecurityError')
  ));
  replaceMethod(globalThis.CacheStorage?.prototype, 'delete', 'CacheStorage.delete', () => Promise.resolve(false));
  for (const name of ['add', 'addAll', 'put', 'delete']) {
    replaceMethod(globalThis.Cache?.prototype, name, `Cache.${name}`, () => Promise.resolve(false));
  }

  replaceMethod(globalThis.StorageManager?.prototype, 'getDirectory', 'OPFS.getDirectory', () => Promise.reject(
    new DOMException('OPFS is disabled during replica interaction verification.', 'SecurityError')
  ));
  replaceMethod(globalThis.StorageManager?.prototype, 'persist', 'StorageManager.persist', () => Promise.resolve(false));
  for (const name of ['showOpenFilePicker', 'showSaveFilePicker', 'showDirectoryPicker']) {
    replaceMethod(globalThis, name, `FileSystem.${name}`, () => Promise.reject(
      new DOMException('File-system access is disabled during replica interaction verification.', 'SecurityError')
    ));
    replaceMethod(globalThis.Window?.prototype, name, `FileSystem.${name}`, () => Promise.reject(
      new DOMException('File-system access is disabled during replica interaction verification.', 'SecurityError')
    ));
  }
  replaceMethod(globalThis.FileSystemFileHandle?.prototype, 'createWritable', 'FileSystemFileHandle.createWritable', () => Promise.reject(
    new DOMException('File-system writes are disabled during replica interaction verification.', 'SecurityError')
  ));
  for (const name of ['getFileHandle', 'getDirectoryHandle', 'removeEntry']) {
    replaceMethod(globalThis.FileSystemDirectoryHandle?.prototype, name, `FileSystemDirectoryHandle.${name}`, () => Promise.reject(
      new DOMException('File-system writes are disabled during replica interaction verification.', 'SecurityError')
    ));
  }
  for (const name of ['write', 'truncate']) {
    replaceMethod(globalThis.FileSystemWritableFileStream?.prototype, name, `FileSystemWritableFileStream.${name}`, () => Promise.reject(
      new DOMException('File-system writes are disabled during replica interaction verification.', 'SecurityError')
    ));
  }

  const inventory = async () => {
    const errors = [];
    const maximumKeys = 500;
    let sensitiveValueDetected = false;
    const storageSummary = (scope) => {
      const storage = nativeStorages[scope];
      const names = [];
      let count = 0;
      if (!storage || !storageKey || !storageGetItem) {
        errors.push(`${scope}_inventory_unavailable`);
        return { count, names, truncated: false };
      }
      try {
        count = Number(storage.length || 0);
        for (let index = 0; index < Math.min(count, maximumKeys); index += 1) {
          const key = storageKey.call(storage, index);
          if (typeof key !== 'string') continue;
          names.push(key.slice(0, 256));
          const value = storageGetItem.call(storage, key);
          if (sensitive.test(String(value || ''))) sensitiveValueDetected = true;
        }
      } catch { errors.push(`${scope}_inventory_failed`); }
      return { count, names: [...new Set(names)].sort(), truncated: count > maximumKeys };
    };
    let cookieNames = [];
    try {
      if (!cookieDescriptor?.get) throw new Error('unavailable');
      const rawCookies = cookieDescriptor?.get?.call(document) || '';
      sensitiveValueDetected ||= sensitive.test(rawCookies);
      cookieNames = rawCookies.split(';').map((entry) => entry.split('=', 1)[0].trim()).filter(Boolean)
        .slice(0, maximumKeys).sort();
    } catch { errors.push('cookie_inventory_failed'); }
    let indexedDbNames = [];
    let indexedDbCount = 0;
    if (indexedDbDatabases) {
      try {
        const databases = await indexedDbDatabases();
        indexedDbCount = databases.length;
        indexedDbNames = databases.slice(0, maximumKeys).map((entry) => String(entry.name || '').slice(0, 256)).sort();
      } catch { errors.push('indexeddb_inventory_failed'); }
    } else errors.push('indexeddb_inventory_unavailable');
    let cacheNames = [];
    let cacheCount = 0;
    if (cacheKeys) {
      try {
        const names = await cacheKeys();
        cacheCount = names.length;
        cacheNames = names.slice(0, maximumKeys).map((entry) => String(entry).slice(0, 256)).sort();
      } catch { errors.push('cache_inventory_failed'); }
    } else errors.push('cache_inventory_unavailable');
    const local = storageSummary('localStorage');
    const session = storageSummary('sessionStorage');
    return {
      cookieNames,
      persistentStorageKeys: local.names,
      ephemeralStorageKeys: session.names,
      indexedDbNames,
      cacheNames,
      counts: {
        cookieCount: cookieNames.length,
        localStorageKeyCount: local.count,
        sessionStorageKeyCount: session.count,
        indexedDbDatabaseCount: indexedDbCount,
        cacheCount
      },
      sensitiveValueDetected,
      inventoryTruncated: local.truncated || session.truncated
        || indexedDbCount > maximumKeys || cacheCount > maximumKeys,
      errors
    };
  };
  try {
    Object.defineProperty(globalThis, '__replicaStorageInventory', {
      configurable: false,
      enumerable: false,
      writable: false,
      value: inventory
    });
  } catch {}
}

async function captureBrowserStorageInventory(page, context, origin, cdp) {
  let pageInventory;
  try {
    pageInventory = await page.evaluate(async () => globalThis.__replicaStorageInventory());
  } catch {
    pageInventory = {
      cookieNames: [], persistentStorageKeys: [], ephemeralStorageKeys: [], indexedDbNames: [], cacheNames: [],
      counts: {
        cookieCount: 0,
        localStorageKeyCount: 0,
        sessionStorageKeyCount: 0,
        indexedDbDatabaseCount: 0,
        cacheCount: 0,
        opfsUsageBytes: 0
      },
      sensitiveValueDetected: false,
      inventoryTruncated: false,
      errors: ['page_storage_inventory_failed']
    };
  }
  const cookieRecords = await context.cookies(origin);
  const sensitive = /replica-synthetic-canary|synthetic applicant|synthetic\.applicant@example\.test|\+15555550100|synthetic-resume\.pdf/i;
  const cookieNames = [...new Set(cookieRecords.map((cookie) => cookie.name.slice(0, 256)))].sort();
  let opfsUsageBytes = 0;
  const errors = [...(pageInventory.errors || [])];
  try {
    const usage = await cdp.send('Storage.getUsageAndQuota', { origin });
    const fileSystem = (usage.usageBreakdown || []).find((entry) => entry.storageType === 'file_systems');
    opfsUsageBytes = Math.max(0, Number(fileSystem?.usage || 0));
    if (!Number.isFinite(opfsUsageBytes)) throw new Error('invalid OPFS usage');
  } catch {
    errors.push('opfs_inventory_failed');
  }
  return {
    ...pageInventory,
    cookieNames,
    counts: { ...pageInventory.counts, cookieCount: cookieRecords.length, opfsUsageBytes },
    sensitiveValueDetected: pageInventory.sensitiveValueDetected
      || cookieRecords.some((cookie) => sensitive.test(cookie.value)),
    inventoryTruncated: pageInventory.inventoryTruncated || cookieRecords.length > 500,
    errors
  };
}

function storageInventoryDelta(before, after) {
  const added = {};
  for (const key of ['cookieNames', 'persistentStorageKeys', 'ephemeralStorageKeys', 'indexedDbNames', 'cacheNames']) {
    const initial = new Set(before[key] || []);
    added[key] = (after[key] || []).filter((entry) => !initial.has(entry));
  }
  return {
    added,
    changed: Object.values(added).some((entries) => entries.length > 0)
      || Object.keys(after.counts || {}).some((key) => Number(after.counts[key] || 0) !== Number(before.counts?.[key] || 0))
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node test-application-flow.mjs --candidate LOOPBACK_URL --manifest FILE [--source URL] [--out FILE]\n');
    return;
  }
  const manifestBoundary = await canonicalManifestBoundary(options.manifest);
  options.manifest = manifestBoundary.manifestPath;
  const manifestBytes = await fs.readFile(options.manifest);
  if (manifestBytes.byteLength > maximumManifestBytes) {
    throw new Error(`Manifest exceeds the ${maximumManifestBytes}-byte safety limit.`);
  }
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const requestedCandidate = assertSafeHttpUrl(options.candidate, '--candidate');
  const source = validateCandidateBoundary(options, requestedCandidate);
  exactCandidateEndpoint(requestedCandidate, manifest.backend?.submitPath, 'manifest.backend.submitPath');
  exactCandidateEndpoint(requestedCandidate, manifest.backend?.auditPath, 'manifest.backend.auditPath');
  validateManifestInteraction(manifest);
  const trustedBackend = await verifyTrustedBackend({
    candidateRoot: manifestBoundary.candidateRoot,
    skillRoot: skillDirectory,
    manifest
  });
  const requestedPage = exactCandidateEndpoint(requestedCandidate, manifest.page?.path, 'manifest.page.path');
  const requestedHealth = exactCandidateEndpoint(requestedCandidate, manifest.start?.healthPath, 'manifest.start.healthPath');
  if (requestedCandidate.pathname !== requestedPage.pathname || requestedCandidate.search || requestedCandidate.hash) {
    throw new Error('--candidate path must exactly match manifest.page.path without query or fragment data.');
  }
  const runtime = await startTrustedBackend({
    candidateRoot: manifestBoundary.candidateRoot,
    verifiedServerPath: trustedBackend.serverPath,
    verifiedServerBytes: trustedBackend.verifiedServerBytes,
    expectedServerSha256: trustedBackend.serverSha256,
    projectName: trustedBackend.projectName,
    healthPath: requestedHealth.pathname,
    timeoutMs: options.timeoutMs
  });
  let transport;
  let browser;
  let context;
  let storageCdp;
  try {
  const candidate = exactCandidateEndpoint(new URL(runtime.origin), manifest.page.path, 'manifest.page.path');
  const submitEndpoint = exactCandidateEndpoint(candidate, manifest.backend.submitPath, 'manifest.backend.submitPath');
  const auditEndpoint = exactCandidateEndpoint(candidate, manifest.backend.auditPath, 'manifest.backend.auditPath');
  if (source?.origin === candidate.origin) throw new Error('Candidate and source origins must differ.');
  const trustedRuntime = {
    spawnedFromVerifiedBackend: true,
    suppliedCandidateProcessUsed: false,
    environmentScrubbed: true,
    emailEnabled: false,
    healthPath: requestedHealth.pathname,
    pagePath: candidate.pathname,
    launchedPath: runtime.evidence.launchedPath,
    serverSha256: runtime.evidence.serverSha256,
    publicFileCount: runtime.evidence.publicFileCount,
    publicTotalBytes: runtime.evidence.publicTotalBytes,
    readOnlySnapshot: runtime.evidence.readOnlySnapshot,
    portSelection: runtime.evidence.portSelection,
    readinessChannel: runtime.evidence.readinessChannel
  };
  const playwrightModule = await import(pathToFileURL(resolveRuntimePackage('playwright')).href);
  const chromium = playwrightModule.chromium || playwrightModule.default?.chromium;
  const executablePath = await findChromiumExecutable(chromium);
  transport = await createValidatingBrowserProxy({ allowedLoopbackUrl: candidate.href });
  browser = await chromium.launch({
    headless: !options.headed,
    chromiumSandbox: true,
    args: [
      '--disable-gpu',
      '--force-color-profile=srgb',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--disable-features=WebTransport'
    ],
    ...(executablePath ? { executablePath } : {})
  });
  context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    locale: 'en-US',
    timezoneId: 'UTC',
    serviceWorkers: 'block',
    proxy: transport.playwright
  });
  const requests = [];
  const blockedWrites = [];
  const blockedPrivateReads = [];
  const blockedExternalReads = [];
  const emptyValidationWrites = [];
  const unexpectedLocalWrites = [];
  const blockedWebSockets = [];
  const blockedModernTransports = [];
  const storageMutations = [];
  const multipartCaptures = [];
  const multipartCaptureErrors = [];
  const eventLimits = Object.freeze({
    requests: 2000,
    blockedWrites: 200,
    blockedPrivateReads: 200,
    blockedExternalReads: 200,
    emptyValidationWrites: 100,
    unexpectedLocalWrites: 200,
    blockedWebSockets: 100,
    blockedModernTransports: 100,
    storageMutations: 200,
    multipartCaptures: 10,
    multipartCaptureErrors: 20,
    pageErrors: 100,
    responseTasks: 100,
    writeResponses: 100
  });
  const eventTotals = Object.fromEntries(Object.keys(eventLimits).map((field) => [field, 0]));
  const eventTruncated = Object.fromEntries(Object.keys(eventLimits).map((field) => [field, false]));
  const overallEventLimit = 5000;
  let overallEventTotal = 0;
  const retainEvent = (field, collection, value) => {
    overallEventTotal += 1;
    eventTotals[field] += 1;
    if (collection.length < eventLimits[field]) collection.push(value);
    else eventTruncated[field] = true;
  };
  const eventAudit = () => ({
    limits: eventLimits,
    totals: { ...eventTotals },
    truncated: { ...eventTruncated },
    anyTruncated: Object.values(eventTruncated).some(Boolean),
    overallEventLimit,
    overallEventTotal,
    overallLimitExceeded: overallEventTotal > overallEventLimit
  });
  const appendEventLimitFailure = (failures) => {
    const audit = eventAudit();
    if (audit.anyTruncated) failures.push({ code: 'INTERACTION_EVENT_INVENTORY_TRUNCATED', evidence: audit });
    if (audit.overallLimitExceeded) failures.push({ code: 'INTERACTION_EVENT_TOTAL_LIMIT_EXCEEDED', evidence: audit });
    return audit;
  };
  const requestPhases = new WeakMap();
  let phase = 'navigation';
  await context.routeWebSocket(/.*/, async (webSocket) => {
    retainEvent('blockedWebSockets', blockedWebSockets, { url: webSocket.url().slice(0, 4096), phase });
    await webSocket.close({ code: 1008, reason: 'Replica audit blocks WebSockets' });
  });
  await context.route('**/*', async (route) => {
    const request = route.request();
    const sequence = eventTotals.requests + 1;
    const entry = { sequence, url: request.url().slice(0, 4096), method: request.method(), type: request.resourceType(), phase };
    requestPhases.set(request, phase);
    retainEvent('requests', requests, entry);
    const requestUrl = new URL(request.url());
    const readOnly = ['GET', 'HEAD', 'OPTIONS'].includes(request.method());
    if (eventTruncated.requests
      && !(readOnly && requestUrl.origin === candidate.origin && request.url() === auditEndpoint.href)) {
      return route.abort('blockedbyclient');
    }
    if (requestUrl.origin !== candidate.origin) {
      if (blocksUnsafeDestinationBeforeProxy(request.url(), candidate.origin)) {
        retainEvent('blockedPrivateReads', blockedPrivateReads, entry);
      }
      if (readOnly) retainEvent('blockedExternalReads', blockedExternalReads, entry);
      else retainEvent('blockedWrites', blockedWrites, entry);
      return route.abort('blockedbyclient');
    }
    if (!readOnly) {
      const controlled = request.url() === submitEndpoint.href && ['submission', 'retry'].includes(phase);
      if (!controlled) {
        if (phase === 'empty-validation') retainEvent('emptyValidationWrites', emptyValidationWrites, entry);
        retainEvent('unexpectedLocalWrites', unexpectedLocalWrites, entry);
        return route.abort('blockedbyclient');
      }
      try {
        retainEvent('multipartCaptures', multipartCaptures, { phase, capture: await inspectSyntheticMultipart(request) });
      } catch (error) {
        retainEvent('multipartCaptureErrors', multipartCaptureErrors, { phase, message: error.message });
      }
    }
    return route.continue();
  });
  await context.exposeBinding('__replicaReportBlockedTransport', (_source, attempt) => {
    retainEvent('blockedModernTransports', blockedModernTransports, {
      kind: String(attempt?.kind || ''),
      target: String(attempt?.target || '').slice(0, 4096),
      phase
    });
  });
  await context.exposeBinding('__replicaReportStorageMutation', (_source, attempt) => {
    retainEvent('storageMutations', storageMutations, {
      kind: String(attempt?.kind || '').slice(0, 128),
      scope: String(attempt?.scope || '').slice(0, 128),
      phase
    });
  });
  await context.addInitScript(integrityNativeInitScript);
  await context.addInitScript(storageGuardInitScript);
  await context.addInitScript(() => {
    const report = globalThis.__replicaReportBlockedTransport;
    for (const name of ['WebTransport', 'WebSocketStream', 'RTCPeerConnection', 'webkitRTCPeerConnection']) {
      const BlockedTransport = function(...args) {
        void report({ kind: name, target: typeof args[0] === 'string' ? args[0] : '' });
        throw new DOMException(`${name} is disabled during replica interaction verification.`, 'SecurityError');
      };
      try {
        Object.defineProperty(globalThis, name, {
          configurable: false,
          enumerable: false,
          writable: false,
          value: BlockedTransport
        });
      } catch {}
    }
    const blockPopup = function() {
      void report({ kind: 'window.open', target: '' });
      return null;
    };
    try {
      Object.defineProperty(globalThis, 'open', {
        configurable: false,
        enumerable: false,
        writable: false,
        value: blockPopup
      });
    } catch {}
    try {
      Object.defineProperty(globalThis.Window?.prototype || {}, 'open', {
        configurable: false,
        enumerable: false,
        writable: false,
        value: blockPopup
      });
    } catch {}
  });
  const page = await context.newPage();
  context.on('page', (openedPage) => {
    if (openedPage === page) return;
    retainEvent('blockedModernTransports', blockedModernTransports, {
      kind: 'popup',
      target: '',
      phase
    });
    openedPage.close().catch(() => {});
  });
  storageCdp = await context.newCDPSession(page);
  await storageCdp.send('DOM.enable');
  await storageCdp.send('DOMStorage.enable');
  const storageCleanupTasks = new Set();
  const evaluatorRemovalKeys = new Set();
  const domStorageKind = (storageId) => storageId?.isLocalStorage ? 'localStorage' : 'sessionStorage';
  const domStorageEntryKey = (storageId, key) => `${storageId?.securityOrigin || storageId?.storageKey || ''}|${storageId?.isLocalStorage}|${key}`;
  const retainDomStorageMutation = (event, operation) => {
    retainEvent('storageMutations', storageMutations, {
      kind: `${domStorageKind(event.storageId)}.${operation}`,
      scope: String(event.key || '').slice(0, 128),
      phase
    });
  };
  for (const eventName of ['domStorageItemAdded', 'domStorageItemUpdated']) {
    storageCdp.on(`DOMStorage.${eventName}`, (event) => {
      retainDomStorageMutation(event, 'propertyWrite');
      evaluatorRemovalKeys.add(domStorageEntryKey(event.storageId, event.key));
      const cleanup = storageCdp.send('DOMStorage.removeDOMStorageItem', {
        storageId: event.storageId,
        key: event.key
      }).catch(() => {});
      storageCleanupTasks.add(cleanup);
      cleanup.finally(() => storageCleanupTasks.delete(cleanup));
    });
  }
  storageCdp.on('DOMStorage.domStorageItemRemoved', (event) => {
    if (evaluatorRemovalKeys.delete(domStorageEntryKey(event.storageId, event.key))) return;
    retainDomStorageMutation(event, 'remove');
  });
  storageCdp.on('DOMStorage.domStorageItemsCleared', (event) => retainDomStorageMutation(event, 'clear'));
  const pageErrors = [];
  const responseTasks = [];
  const writeResponses = [];
  page.on('pageerror', (error) => retainEvent('pageErrors', pageErrors, String(error.message || '').slice(0, 4096)));
  page.on('response', (response) => {
    const request = response.request();
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method())) return;
    const responsePhase = requestPhases.get(request) || 'unknown';
    if (eventTotals.responseTasks >= eventLimits.responseTasks) {
      overallEventTotal += 1;
      eventTotals.responseTasks += 1;
      eventTruncated.responseTasks = true;
      return;
    }
    const task = (async () => {
      let text = '';
      try {
        text = await Promise.race([
          response.text(),
          new Promise((_, reject) => setTimeout(() => reject(new Error('response body timeout')), 5000))
        ]);
      } catch {}
      let json = null;
      try { json = JSON.parse(text); } catch {}
      retainEvent('writeResponses', writeResponses, {
        url: response.url().slice(0, 4096),
        method: request.method(),
        phase: responsePhase,
        status: response.status(),
        contentType: response.headers()['content-type'] || '',
        json
      });
    })();
    retainEvent('responseTasks', responseTasks, task);
  });
  phase = 'storage-baseline';
  const baselineResponse = await page.goto(new URL(requestedHealth.pathname, candidate.origin).href, {
    waitUntil: 'domcontentloaded',
    timeout: options.timeoutMs
  });
  if (!baselineResponse?.ok()) throw new Error('Audited storage-baseline navigation failed.');
  const storageBefore = await captureBrowserStorageInventory(page, context, candidate.origin, storageCdp);
  const finalizeStorageAudit = async (failures) => {
    await Promise.allSettled([...storageCleanupTasks]);
    const after = await captureBrowserStorageInventory(page, context, candidate.origin, storageCdp);
    const delta = storageInventoryDelta(storageBefore, after);
    const inventoryErrors = [...new Set([...(storageBefore.errors || []), ...(after.errors || [])])];
    const audit = {
      before: storageBefore,
      after,
      delta,
      mutationAttempts: storageMutations,
      mutationAttemptTotal: eventTotals.storageMutations,
      mutationAttemptsTruncated: eventTruncated.storageMutations,
      sensitiveValueDetected: storageBefore.sensitiveValueDetected || after.sensitiveValueDetected,
      inventoryTruncated: storageBefore.inventoryTruncated || after.inventoryTruncated,
      inventoryErrors
    };
    if (audit.mutationAttemptTotal > 0) {
      failures.push({ code: 'BROWSER_STORAGE_MUTATION_ATTEMPTED', evidence: audit });
    }
    if (delta.changed) failures.push({ code: 'BROWSER_STORAGE_RETAINED', evidence: audit });
    if (audit.sensitiveValueDetected) failures.push({ code: 'BROWSER_STORAGE_SENSITIVE_VALUE_RETAINED', evidence: audit });
    if (audit.inventoryTruncated || inventoryErrors.length) {
      failures.push({ code: 'BROWSER_STORAGE_INVENTORY_INCOMPLETE', evidence: audit });
    }
    try {
      await storageCdp.send('Storage.clearDataForOrigin', {
        origin: candidate.origin,
        storageTypes: 'file_systems'
      });
      audit.opfsCleanupSucceeded = true;
    } catch {
      audit.opfsCleanupSucceeded = false;
      failures.push({ code: 'BROWSER_STORAGE_CLEANUP_FAILED', evidence: { storageType: 'file_systems' } });
    }
    return audit;
  };
  let report;
    phase = 'navigation';
    const response = await page.goto(candidate.href, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs });
    if (!response?.ok()) throw new Error(`Candidate returned HTTP ${response?.status() ?? 'unknown'}.`);
    if (manifest.page?.readySelector) {
      await page.locator(manifest.page.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
    }
    await page.waitForTimeout(100);
    const sourceLinkFailures = [];
    const sourceLinks = page.locator('[data-replica-source-link]');
    const sourceLinkLimit = 100;
    const discoveredSourceLinkCount = await sourceLinks.count();
    const sourceLinkSafety = {
      discoveredCount: discoveredSourceLinkCount,
      inspectedCount: Math.min(discoveredSourceLinkCount, sourceLinkLimit),
      inventoryTruncated: discoveredSourceLinkCount > sourceLinkLimit,
      structurallyInert: true,
      navigationTargetCount: 0,
      navigationTargets: [],
      activated: false,
      activatedCount: 0,
      activations: [],
      urlUnchanged: true,
      originUnchanged: true,
      requestCount: 0,
      activationError: null
    };
    if (sourceLinkSafety.inventoryTruncated) {
      sourceLinkFailures.push({
        code: 'SOURCE_LINK_INVENTORY_TRUNCATED',
        evidence: { discoveredCount: discoveredSourceLinkCount, limit: sourceLinkLimit }
      });
    }
    const inertSourceLinks = [];
    for (let index = 0; index < sourceLinkSafety.inspectedCount; index += 1) {
      const candidateLink = sourceLinks.nth(index);
      const navigationTarget = await candidateLink.evaluate((element, ordinal) => {
        const xlinkNamespace = 'http://www.w3.org/1999/xlink';
        const hrefAttribute = element.getAttribute('href');
        const xlinkHrefAttribute = element.getAttribute('xlink:href')
          ?? element.getAttributeNS(xlinkNamespace, 'href');
        return {
          ordinal,
          tag: element.tagName.toLowerCase(),
          role: element.getAttribute('role') || '',
          tabIndex: element.tabIndex,
          hrefAttribute,
          xlinkHrefAttribute,
          hasHrefAttribute: hrefAttribute !== null,
          hasXlinkHrefAttribute: xlinkHrefAttribute !== null
        };
      }, index);
      if (navigationTarget.hasHrefAttribute || navigationTarget.hasXlinkHrefAttribute) {
        sourceLinkSafety.navigationTargets.push(navigationTarget);
        continue;
      }
      if (await candidateLink.isVisible() && await candidateLink.isEnabled()) {
        inertSourceLinks.push(navigationTarget);
      }
    }
    sourceLinkSafety.navigationTargetCount = sourceLinkSafety.navigationTargets.length;
    sourceLinkSafety.structurallyInert = sourceLinkSafety.navigationTargetCount === 0;
    if (!sourceLinkSafety.structurallyInert) {
      sourceLinkFailures.push({
        code: 'SOURCE_LINK_NAVIGATION_TARGET',
        evidence: {
          discoveredCount: sourceLinkSafety.discoveredCount,
          navigationTargetCount: sourceLinkSafety.navigationTargetCount,
          navigationTargets: sourceLinkSafety.navigationTargets
        }
      });
    }
    for (const descriptor of inertSourceLinks) {
      const activationMethods = ['click'];
      if (descriptor.tag === 'a' || descriptor.tag === 'area'
        || ['link', 'button'].includes(descriptor.role)
        || descriptor.tabIndex >= 0) activationMethods.push('Enter');
      if (descriptor.tag === 'button' || descriptor.role === 'button') activationMethods.push('Space');
      for (const method of [...new Set(activationMethods)]) {
        await page.goto(candidate.href, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs });
        if (manifest.page?.readySelector) {
          await page.locator(manifest.page.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
        }
        await page.waitForTimeout(100);
        const activeLink = page.locator('[data-replica-source-link]').nth(descriptor.ordinal);
        const beforeUrl = page.url();
        const beforeRequestCount = eventTotals.requests;
        phase = 'source-link-check';
        let activationError = null;
        try {
          if (method === 'click') {
            await activeLink.click({ noWaitAfter: true, timeout: Math.min(options.timeoutMs, 5000) });
          } else {
            await activeLink.focus({ timeout: Math.min(options.timeoutMs, 5000) });
            await activeLink.press(method, { noWaitAfter: true, timeout: Math.min(options.timeoutMs, 5000) });
          }
        } catch (error) {
          activationError = error.message;
          if (!sourceLinkSafety.activationError) sourceLinkSafety.activationError = error.message;
        }
        await page.waitForTimeout(150);
        const afterUrl = page.url();
        const linkRequests = requests.filter((request) => request.sequence > beforeRequestCount);
        const activation = {
          ordinal: descriptor.ordinal,
          tag: descriptor.tag,
          role: descriptor.role,
          method,
          activationError,
          urlUnchanged: afterUrl === beforeUrl,
          originUnchanged: new URL(afterUrl).origin === new URL(beforeUrl).origin,
          requestCount: linkRequests.length,
          requests: linkRequests.slice(0, 50),
          requestsTruncated: linkRequests.length > 50
        };
        sourceLinkSafety.activations.push(activation);
        sourceLinkSafety.activatedCount += activationError ? 0 : 1;
        sourceLinkSafety.requestCount += linkRequests.length;
        sourceLinkSafety.urlUnchanged &&= activation.urlUnchanged;
        sourceLinkSafety.originUnchanged &&= activation.originUnchanged;
        if (activationError || !activation.urlUnchanged || !activation.originUnchanged || linkRequests.length > 0) {
          sourceLinkFailures.push({ code: 'SOURCE_LINK_NOT_INERT', evidence: activation });
        }
      }
    }
    sourceLinkSafety.activated = sourceLinkSafety.activatedCount > 0;
    if (inertSourceLinks.length) {
      await page.goto(candidate.href, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs });
      if (manifest.page?.readySelector) {
        await page.locator(manifest.page.readySelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
      }
      await page.waitForTimeout(100);
    }
    phase = 'audit-before';
    const auditBeforeResponse = await fetchCandidateJson(page, auditEndpoint.pathname);
    const auditBefore = auditBeforeResponse.json;
    const auditStartsEmpty = validAuditShape(auditBefore)
      && auditBefore.submissionAttempts === 0
      && auditBefore.logicalReceipts === 0
      && auditBefore.idempotencyEntries === 0;
    const formSelector = manifest.interaction?.formSelector || 'form';
    const forms = page.locator(formSelector);
    const formCount = await forms.count();
    const activeFormInventory = await countActiveForms(storageCdp);
    const activeFormCount = activeFormInventory.count;
    const selectedFormInspection = formCount === 0
      ? { onlyForms: true, nativeApiTampering: [] }
      : await inspectSelectedForms(page, forms);
    const selectorMatchesOnlyForms = selectedFormInspection.onlyForms;
    const nativeApiTampering = [
      ...await inspectInteractionNatives(page),
      ...(selectedFormInspection.nativeApiTampering || []),
      ...(activeFormInventory.truncated ? ['cdp-form-inventory-limit'] : [])
    ];
    if (!formCount) {
      const declaredNotApplicable = manifest.interaction?.notApplicable === true
        && typeof manifest.interaction?.reason === 'string'
        && manifest.interaction.reason.trim().length > 0;
      const failures = [...sourceLinkFailures];
      if (nativeApiTampering.length) failures.push({ code: 'INTERACTION_NATIVE_API_TAMPERING', evidence: nativeApiTampering });
      if (!declaredNotApplicable) failures.push({ code: 'APPLICATION_FORM_MISSING_WITHOUT_EXPLICIT_EXEMPTION' });
      if (activeFormCount > 0) {
        failures.push({
          code: 'FORM_SELECTOR_OMITS_ACTIVE_FORM',
          evidence: { formSelector, selectedFormCount: formCount, activeFormCount, activeFormInventory }
        });
      }
      if (!auditStartsEmpty) failures.push({ code: 'BACKEND_AUDIT_NOT_CLEAN', evidence: auditBeforeResponse });
      if (blockedPrivateReads.length) failures.push({ code: 'PRIVATE_DESTINATION_BLOCKED', evidence: blockedPrivateReads });
      if (blockedExternalReads.length) failures.push({ code: 'EXTERNAL_READ_BLOCKED', evidence: blockedExternalReads });
      if (blockedWrites.length) failures.push({ code: 'EXTERNAL_WRITE_BLOCKED', evidence: blockedWrites });
      if (unexpectedLocalWrites.length) failures.push({ code: 'UNEXPECTED_LOCAL_WRITE', evidence: unexpectedLocalWrites });
      if (blockedWebSockets.length) failures.push({ code: 'WEBSOCKET_BLOCKED', evidence: blockedWebSockets });
      if (blockedModernTransports.length) failures.push({ code: 'MODERN_TRANSPORT_BLOCKED', evidence: blockedModernTransports });
      if (pageErrors.length) failures.push({ code: 'PAGE_ERROR', evidence: pageErrors });
      const storageAudit = await finalizeStorageAudit(failures);
      const interactionEventAudit = appendEventLimitFailure(failures);
      report = {
        schemaVersion: 2,
        generatedAt: new Date().toISOString(),
        candidate: candidate.href,
        pass: failures.length === 0,
        notApplicable: activeFormCount === 0,
        reason: manifest.interaction?.reason || 'No application form was found.',
        formInventory: { formSelector, selectedFormCount: formCount, activeFormCount, activeFormInventory },
        nativeApiTampering,
        trustedBackend,
        trustedRuntime,
        sourceLinkSafety,
        auditBefore,
        requests,
        blockedWrites,
        blockedPrivateReads,
        blockedExternalReads,
        unexpectedLocalWrites,
        blockedWebSockets,
        blockedModernTransports,
        storageAudit,
        pageErrors,
        eventAudit: interactionEventAudit,
        failures
      };
    } else if (formCount !== 1 || !selectorMatchesOnlyForms || manifest.interaction?.notApplicable === true) {
      const failures = [...sourceLinkFailures, {
        code: formCount !== 1 || !selectorMatchesOnlyForms
          ? 'FORM_SELECTOR_MUST_MATCH_EXACTLY_ONE_FORM'
          : 'FORM_PRESENT_BUT_DECLARED_NOT_APPLICABLE',
        evidence: { formSelector, formCount, activeFormCount, selectorMatchesOnlyForms, activeFormInventory }
      }];
      if (nativeApiTampering.length) failures.push({ code: 'INTERACTION_NATIVE_API_TAMPERING', evidence: nativeApiTampering });
      const storageAudit = await finalizeStorageAudit(failures);
      const interactionEventAudit = appendEventLimitFailure(failures);
      report = {
        schemaVersion: 2,
        generatedAt: new Date().toISOString(),
        candidate: candidate.href,
        pass: false,
        notApplicable: false,
        formInventory: { formSelector, selectedFormCount: formCount, activeFormCount, activeFormInventory },
        nativeApiTampering,
        trustedBackend,
        trustedRuntime,
        sourceLinkSafety,
        auditBefore,
        requests,
        blockedWrites,
        blockedPrivateReads,
        blockedExternalReads,
        unexpectedLocalWrites,
        blockedWebSockets,
        blockedModernTransports,
        storageAudit,
        pageErrors,
        eventAudit: interactionEventAudit,
        failures
      };
    } else {
      const form = forms.first();
      const failures = [...sourceLinkFailures];
      if (!auditStartsEmpty) failures.push({ code: 'BACKEND_AUDIT_NOT_CLEAN', evidence: auditBeforeResponse });
      const submitSelector = manifest.interaction?.submitSelector || 'button, input[type="submit"], input[type="button"], [role="button"]';
      const submitCandidates = form.locator(submitSelector);
      const submitCandidateLimit = 500;
      const submitCandidateCount = await submitCandidates.count();
      if (submitCandidateCount > submitCandidateLimit) {
        failures.push({
          code: 'SUBMIT_CONTROL_INVENTORY_TRUNCATED',
          evidence: { count: submitCandidateCount, limit: submitCandidateLimit }
        });
      }
      const visibleSubmitCandidates = [];
      for (let index = 0; index < Math.min(submitCandidateCount, submitCandidateLimit); index += 1) {
        const submitCandidate = submitCandidates.nth(index);
        if (await submitCandidate.isVisible() && await submitCandidate.isEnabled()) {
          const accessibleText = await submitCandidate.evaluate((element) => String(
            element.getAttribute('aria-label') || element.textContent || element.value || ''
          ).replace(/\s+/g, ' ').trim());
          visibleSubmitCandidates.push({
            candidate: submitCandidate,
            score: /submit|apply|send|complete|continue/i.test(accessibleText) ? 1 : 0
          });
        }
      }
      visibleSubmitCandidates.sort((left, right) => right.score - left.score);
      const submit = visibleSubmitCandidates[0]?.candidate || null;

      const customRequiredSelector = manifest.interaction?.customRequiredSelector
        || '[aria-required="true"], [contenteditable="true"][aria-required="true"]';
      const emptyValidation = await form.evaluate((element, selector) => {
        const required = [...element.elements].filter((control) => control.willValidate && control.required && !control.disabled);
        const invalid = required.filter((control) => !control.checkValidity());
        const custom = [...element.querySelectorAll(selector)]
          .filter((control) => !(control.willValidate && control.required) && !control.hasAttribute('disabled'));
        if (required.length) element.reportValidity();
        return {
          applicable: required.length + custom.length > 0,
          requiredCount: required.length,
          invalidCount: invalid.length,
          customRequiredCount: custom.length,
          invalid: invalid.map((control) => ({ name: control.name, type: control.type }))
        };
      }, customRequiredSelector);
      if (emptyValidation.applicable && submit) {
        phase = 'empty-validation';
        try { await submit.click({ timeout: Math.min(options.timeoutMs, 5000) }); }
        catch (error) { failures.push({ code: 'EMPTY_VALIDATION_TRIGGER_FAILED', evidence: error.message }); }
        await page.waitForTimeout(200);
        phase = 'fill';
      }
      const customValidation = await inspectCustomRequired(form, customRequiredSelector);
      emptyValidation.customInvalidCount = customValidation.invalidCount;
      if (!emptyValidation.applicable) failures.push({ code: 'NO_REQUIRED_CONTROLS_DECLARED' });
      if (emptyValidation.applicable && emptyValidation.invalidCount === 0) {
        if (emptyValidation.customRequiredCount === 0) failures.push({ code: 'EMPTY_REQUIRED_VALIDATION_MISSING', evidence: emptyValidation });
      }
      if (customValidation.count > 0 && customValidation.invalidCount !== customValidation.count) {
        failures.push({ code: 'CUSTOM_REQUIRED_VALIDATION_MISSING', evidence: customValidation });
      }
      if (emptyValidationWrites.length) {
        failures.push({ code: 'EMPTY_FORM_WROTE_DATA', evidence: emptyValidationWrites });
      }

      const actions = [];
      const controls = form.locator('input, select, textarea');
      const controlCount = await controls.count();
      const controlLimit = 2000;
      if (controlCount > controlLimit) {
        failures.push({
          code: 'FORM_CONTROL_INVENTORY_TRUNCATED',
          evidence: { count: controlCount, limit: controlLimit }
        });
      }
      const handledRadioNames = new Set();
      for (let index = 0; index < Math.min(controlCount, controlLimit); index += 1) {
        const control = controls.nth(index);
        if (!(await control.isVisible()) || !(await control.isEnabled())) continue;
        const type = await control.getAttribute('type') || await control.evaluate((element) => element.tagName.toLowerCase());
        const name = await control.getAttribute('name') || '';
        if (type === 'radio' && handledRadioNames.has(name)) continue;
        if (type === 'radio') handledRadioNames.add(name);
        try {
          actions.push({ index, name, type, action: await fillControl(control) });
        } catch (error) {
          actions.push({ index, name, type, action: 'error', error: error.message });
        }
      }
      for (const action of manifest.interaction?.actions || []) await applyManifestAction(page, action);
      await form.evaluate((element, { name, value }) => {
        for (const control of [...element.elements]) {
          if (control.name === name) control.remove();
        }
        const canary = document.createElement('input');
        canary.type = 'hidden';
        canary.name = name;
        canary.value = value;
        canary.setAttribute('data-replica-evaluator-canary', 'true');
        element.append(canary);
      }, { name: syntheticCanaryName, value: syntheticCanaryValue });
      const invalidRequired = await form.evaluate((element) => [...element.elements]
        .filter((control) => control.willValidate && !control.checkValidity())
        .map((control) => ({ name: control.name, type: control.type, validationMessage: control.validationMessage })));
      const customValidationAfterFill = await inspectCustomRequired(form, customRequiredSelector);
      if (customValidationAfterFill.invalidCount > 0) {
        failures.push({ code: 'CUSTOM_REQUIRED_CONTROLS_UNFILLED', evidence: customValidationAfterFill });
      }
      const requestCountBeforeSubmit = eventTotals.requests;
      phase = 'submission';
      if (!invalidRequired.length && customValidationAfterFill.invalidCount === 0 && submit) {
        await submit.click({ timeout: options.timeoutMs });
      }
      await page.waitForTimeout(manifest.interaction?.settleMs ?? 1500);
      if (manifest.interaction?.successSelector) {
        await page.locator(manifest.interaction.successSelector).first().waitFor({ state: 'visible', timeout: options.timeoutMs });
      }
      await Promise.all([...responseTasks]);
      const initialSubmitRequests = requests.filter((request) => request.sequence > requestCountBeforeSubmit);
      const initialSameOriginWrites = initialSubmitRequests.filter((request) => {
        try {
          return !['GET', 'HEAD', 'OPTIONS'].includes(request.method)
            && new URL(request.url).origin === candidate.origin;
        } catch { return false; }
      });
      const initialEndpointWrites = initialSameOriginWrites.filter((request) => request.url === submitEndpoint.href);
      const initialReceiptResponse = writeResponses.find((response) => response.phase === 'submission' && response.url === submitEndpoint.href);
      const initialReceipt = initialReceiptResponse?.json || null;

      let retryResponse = null;
      let retryReceipt = null;
      let receiptLookupResponse = null;
      let receiptLookup = null;
      if (receiptShape(initialReceipt)) {
        const idempotencyKey = 'synthetic-browser-run';
        phase = 'retry';
        retryResponse = await form.evaluate(async (activeForm, { endpoint, key, fixture }) => {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'x-idempotency-key': key,
              'x-replica-fixture': fixture
            },
            body: new FormData(activeForm)
          });
          return { status: response.status, contentType: response.headers.get('content-type') || '', text: await response.text() };
        }, { endpoint: submitEndpoint.pathname, key: idempotencyKey, fixture: syntheticFixtureHeader });
        try { retryReceipt = JSON.parse(retryResponse.text); } catch {}

        phase = 'receipt-lookup';
        receiptLookupResponse = await page.evaluate(async (path) => {
          const response = await fetch(path, { method: 'GET' });
          return { status: response.status, contentType: response.headers.get('content-type') || '', text: await response.text() };
        }, `/api/receipts/${encodeURIComponent(initialReceipt.id)}`);
        try { receiptLookup = JSON.parse(receiptLookupResponse.text); } catch {}
        await page.waitForTimeout(100);
        await Promise.all([...responseTasks]);
      }
      phase = 'audit-after';
      const auditAfterResponse = await fetchCandidateJson(page, auditEndpoint.pathname);
      const auditAfter = auditAfterResponse.json;
      const postSubmitRequests = requests.filter((request) => request.sequence > requestCountBeforeSubmit);
      const sameOriginWrites = postSubmitRequests.filter((request) => {
        try {
          return !['GET', 'HEAD', 'OPTIONS'].includes(request.method)
            && new URL(request.url).origin === candidate.origin
            && request.url === submitEndpoint.href
            && ['submission', 'retry'].includes(request.phase);
        } catch { return false; }
      });
      const endpointWrites = sameOriginWrites.filter((request) => request.url === submitEndpoint.href);
      const unexpectedSameOriginWrites = sameOriginWrites.filter((request) => request.url !== submitEndpoint.href);
      const initialPayloadCaptures = multipartCaptures.filter((entry) => entry.phase === 'submission');
      const retryPayloadCaptures = multipartCaptures.filter((entry) => entry.phase === 'retry');
      const initialPayload = initialPayloadCaptures[0]?.capture || null;
      const retryPayload = retryPayloadCaptures[0]?.capture || null;
      const payloadProof = {
        ui: publicMultipartMetadata(initialPayload),
        retry: publicMultipartMetadata(retryPayload),
        metadataEquivalent: Boolean(initialPayload && retryPayload
          && initialPayload.metadataDigest === retryPayload.metadataDigest),
        contentEquivalent: Boolean(initialPayload && retryPayload
          && initialPayload.contentDigest === retryPayload.contentDigest),
        transientComparison: true,
        applicantValuesPersisted: false
      };

      if (invalidRequired.length) failures.push({ code: 'REQUIRED_CONTROLS_UNFILLED', evidence: invalidRequired });
      if (!submit) failures.push({ code: 'NO_VISIBLE_SUBMIT', evidence: { submitSelector } });
      if (initialEndpointWrites.length !== 1) failures.push({ code: 'EXACTLY_ONE_UI_SUBMISSION_REQUIRED', evidence: initialSameOriginWrites });
      if (unexpectedSameOriginWrites.length) failures.push({ code: 'UNEXPECTED_LOCAL_WRITE_ENDPOINT', evidence: unexpectedSameOriginWrites });
      if (endpointWrites.length !== 2) failures.push({ code: 'IDEMPOTENT_RETRY_MISSING_OR_DUPLICATED', evidence: endpointWrites });
      if (multipartCaptureErrors.length
        || initialPayloadCaptures.length !== 1
        || retryPayloadCaptures.length !== 1) {
        failures.push({
          code: 'MULTIPART_PAYLOAD_PROOF_MISSING',
          evidence: {
            errors: multipartCaptureErrors,
            uiCaptureCount: initialPayloadCaptures.length,
            retryCaptureCount: retryPayloadCaptures.length
          }
        });
      }
      if (!initialPayload?.canaryPresent || !retryPayload?.canaryPresent
        || !initialPayload?.fixtureHeaderPresent || !retryPayload?.fixtureHeaderPresent) {
        failures.push({ code: 'SYNTHETIC_PAYLOAD_CANARY_MISSING', evidence: payloadProof });
      }
      if (!payloadProof.metadataEquivalent || !payloadProof.contentEquivalent) {
        failures.push({ code: 'UI_RETRY_MULTIPART_MISMATCH', evidence: payloadProof });
      }
      if (!initialReceiptResponse || initialReceiptResponse.status < 200 || initialReceiptResponse.status >= 300
        || !/application\/json/i.test(initialReceiptResponse.contentType) || !receiptShape(initialReceipt)) {
        failures.push({ code: 'INVALID_SUBMISSION_RECEIPT', evidence: initialReceiptResponse || null });
      }
      if (!retryResponse || retryResponse.status < 200 || retryResponse.status >= 300
        || !/application\/json/i.test(retryResponse.contentType) || !receiptShape(retryReceipt)) {
        failures.push({ code: 'INVALID_RETRY_RECEIPT', evidence: retryResponse });
      }
      if (!initialReceipt || !retryReceipt || initialReceipt.id !== retryReceipt.id) {
        failures.push({ code: 'IDEMPOTENCY_RECEIPT_MISMATCH', evidence: { initialId: initialReceipt?.id, retryId: retryReceipt?.id } });
      }
      if (!receiptLookupResponse || receiptLookupResponse.status < 200 || receiptLookupResponse.status >= 300
        || !/application\/json/i.test(receiptLookupResponse.contentType) || !receiptShape(receiptLookup)
        || receiptLookup?.id !== initialReceipt?.id) {
        failures.push({ code: 'RECEIPT_LOOKUP_FAILED', evidence: receiptLookupResponse });
      }
      if ([initialReceipt, retryReceipt, receiptLookup].some(retainedApplicantData)) {
        failures.push({ code: 'APPLICANT_VALUES_RETAINED', evidence: { receiptKeys: Object.keys(receiptLookup || {}) } });
      }
      if (!validAuditShape(auditAfter)
        || auditAfter.submissionAttempts !== 2
        || auditAfter.logicalReceipts !== 1
        || auditAfter.idempotencyEntries !== 1) {
        failures.push({ code: 'BACKEND_AUDIT_CONTRACT_FAILED', evidence: auditAfterResponse });
      }
      if (blockedWrites.length) failures.push({ code: 'EXTERNAL_WRITE_BLOCKED', evidence: blockedWrites });
      if (blockedPrivateReads.length) failures.push({ code: 'PRIVATE_DESTINATION_BLOCKED', evidence: blockedPrivateReads });
      if (blockedExternalReads.length) failures.push({ code: 'EXTERNAL_READ_BLOCKED', evidence: blockedExternalReads });
      if (unexpectedLocalWrites.length) failures.push({ code: 'UNEXPECTED_LOCAL_WRITE', evidence: unexpectedLocalWrites });
      if (blockedWebSockets.length) failures.push({ code: 'WEBSOCKET_BLOCKED', evidence: blockedWebSockets });
      if (blockedModernTransports.length) failures.push({ code: 'MODERN_TRANSPORT_BLOCKED', evidence: blockedModernTransports });
      if (manifest.backend?.emailEnabledByDefault !== false) failures.push({ code: 'EMAIL_DEFAULT_NOT_DISABLED' });
      if (manifest.backend?.retainsApplicantValues !== false) failures.push({ code: 'MANIFEST_NON_RETENTION_NOT_DECLARED' });
      if (pageErrors.length) failures.push({ code: 'PAGE_ERROR', evidence: pageErrors });
      if (nativeApiTampering.length) failures.push({ code: 'INTERACTION_NATIVE_API_TAMPERING', evidence: nativeApiTampering });
      const storageAudit = await finalizeStorageAudit(failures);
      const interactionEventAudit = appendEventLimitFailure(failures);
      report = {
        schemaVersion: 2,
        generatedAt: new Date().toISOString(),
        candidate: candidate.href,
        source: source?.href || null,
        submitEndpoint: submitEndpoint.href,
        trustedBackend,
        trustedRuntime,
        sourceLinkSafety,
        pass: failures.length === 0,
        notApplicable: false,
        formInventory: { formSelector, selectedFormCount: formCount, activeFormCount, activeFormInventory },
        nativeApiTampering,
        emptyValidation,
        customValidationAfterFill,
        actions,
        invalidRequired,
        requests,
        sameOriginWrites,
        initialSameOriginWrites,
        receipt: initialReceipt,
        retryReceipt,
        receiptLookup,
        auditBefore,
        auditAfter,
        payloadProof,
        oneLogicalReceipt: Boolean(initialReceipt && retryReceipt && receiptLookup
          && initialReceipt.id === retryReceipt.id && initialReceipt.id === receiptLookup.id),
        blockedWrites,
        blockedPrivateReads,
        blockedExternalReads,
        unexpectedLocalWrites,
        blockedWebSockets,
        blockedModernTransports,
        storageAudit,
        pageErrors,
        eventAudit: interactionEventAudit,
        failures
      };
    }
  report = redactReportData(report);
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) await fs.writeFile(options.out, serialized);
  process.stdout.write(serialized);
  if (!report.pass) process.exitCode = 2;
  } finally {
    await storageCdp?.detach().catch(() => {});
    await context?.close().catch(() => {});
    await browser?.close().catch(() => {});
    await transport?.close().catch(() => {});
    await runtime.close().catch(() => {});
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
