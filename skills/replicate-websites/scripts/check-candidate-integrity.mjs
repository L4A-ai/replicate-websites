#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { isAbsolute, dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertSafeHttpUrl,
  credentialLikeUrlIssue,
  isLoopbackHostname,
  redactSensitiveUrl
} from './lib/network-safety.mjs';

const inspectionSchemaVersion = 1;
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const bundledStarterAppPath = resolve(scriptDirectory, '../assets/replica-starter/public/app.js');
const auditedBackend = Object.freeze({
  implementation: 'replicate-websites-starter-v1',
  submitPath: '/api/applications',
  auditPath: '/api/replica-audit'
});
const safeFormEnctypes = new Set(['application/x-www-form-urlencoded', 'multipart/form-data']);
const viewportNamePattern = /^[a-z0-9](?:[a-z0-9_-]{0,63})$/;
const requiredPublicDisclosureMediaVariants = Object.freeze([
  ['light-reduce-dpr1', 'light', 'reduce', 1],
  ['dark-reduce-dpr1', 'dark', 'reduce', 1],
  ['light-no-preference-dpr1', 'light', 'no-preference', 1],
  ['dark-no-preference-dpr1', 'dark', 'no-preference', 1],
  ['light-reduce-dpr2', 'light', 'reduce', 2],
  ['dark-reduce-dpr2', 'dark', 'reduce', 2],
  ['light-no-preference-dpr2', 'light', 'no-preference', 2],
  ['dark-no-preference-dpr2', 'dark', 'no-preference', 2]
]);
const runtimeAttemptFields = [
  'webSocketAttempts',
  'beaconAttempts',
  'windowOpenAttempts',
  'popupAttempts',
  'downloadAttempts',
  'serviceWorkerRegistrationAttempts',
  'externalFetchAttempts',
  'externalXhrAttempts',
  'webTransportAttempts',
  'webSocketStreamAttempts',
  'rtcPeerConnectionAttempts',
  'rtcDataChannelAttempts'
];

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object.`);
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  return value;
}

function requireBoolean(value, label) {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean.`);
  return value;
}

function requireFinitePositive(value, label) {
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${label} must be finite and positive.`);
  return value;
}

function requireNonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative safe integer.`);
  return value;
}

function pathIsWithin(root, pathname) {
  const pathFromRoot = relative(root, pathname);
  return pathFromRoot === '' || (!isAbsolute(pathFromRoot) && pathFromRoot !== '..' && !pathFromRoot.startsWith(`..${sep}`));
}

function normalizedRootPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/')) return null;
  try {
    const parsed = new URL(value, 'https://replica.invalid/');
    if (parsed.origin !== 'https://replica.invalid' || parsed.username || parsed.password || parsed.search || parsed.hash) return null;
    return parsed.pathname.startsWith('//') ? null : parsed.pathname;
  } catch {
    return null;
  }
}

function backendDeclarationIssues(manifest) {
  const backend = isPlainObject(manifest.backend) ? manifest.backend : {};
  const issues = [];
  if (backend.implementation !== auditedBackend.implementation) issues.push('implementation');
  if (normalizedRootPath(backend.submitPath) !== auditedBackend.submitPath) issues.push('submitPath');
  if (normalizedRootPath(backend.auditPath) !== auditedBackend.auditPath) issues.push('auditPath');
  if (backend.emailEnabledByDefault !== false) issues.push('emailEnabledByDefault');
  if (backend.retainsApplicantValues !== false) issues.push('retainsApplicantValues');
  return issues;
}

async function requireCanonicalFile(root, pathname, label) {
  const stat = await fs.lstat(pathname);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${label} must be a regular file, not a symlink.`);
  const canonicalPath = await fs.realpath(pathname);
  if (!pathIsWithin(root, canonicalPath)) throw new Error(`${label} must remain within the inspection root.`);
  return canonicalPath;
}

async function requireCanonicalDirectory(root, pathname, label) {
  const stat = await fs.lstat(pathname);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`${label} must be a directory, not a symlink.`);
  const canonicalPath = await fs.realpath(pathname);
  if (!pathIsWithin(root, canonicalPath)) throw new Error(`${label} must remain within the inspection root.`);
  return canonicalPath;
}

function validateRequiredCaptureEvidence(inspection, viewportResult, label) {
  if (inspection.schemaVersion !== inspectionSchemaVersion) {
    throw new Error(`${label}.schemaVersion must be ${inspectionSchemaVersion}.`);
  }
  const viewport = requireObject(inspection.viewport, `${label}.viewport`);
  if (viewport.name !== viewportResult.viewport.name
    || viewport.width !== viewportResult.viewport.width
    || viewport.height !== viewportResult.viewport.height) {
    throw new Error(`${label}.viewport must exactly match its summary entry.`);
  }
  const telemetry = requireObject(inspection.telemetry, `${label}.telemetry`);
  for (const field of [
    'blockedWrites', 'blockedPrivateReads', 'failedGets', 'externalReads', 'privacyRiskExternalAssets'
  ]) {
    requireArray(telemetry[field], `${label}.telemetry.${field}`);
  }
  requireNonNegativeInteger(telemetry.externalReadCount, `${label}.telemetry.externalReadCount`);
  requireFinitePositive(telemetry.externalReadLimit, `${label}.telemetry.externalReadLimit`);
  requireObject(telemetry.externalReadTypeCounts, `${label}.telemetry.externalReadTypeCounts`);
  requireBoolean(telemetry.externalReadsTruncated, `${label}.telemetry.externalReadsTruncated`);
  if (telemetry.externalReadCount < telemetry.externalReads.length) {
    throw new Error(`${label}.telemetry.externalReadCount cannot be smaller than the retained inventory.`);
  }
  if (!telemetry.externalReadsTruncated && telemetry.externalReadCount !== telemetry.externalReads.length) {
    throw new Error(`${label}.telemetry.externalReadCount must equal the retained inventory when it is not truncated.`);
  }
  requireNonNegativeInteger(
    telemetry.privacyRiskExternalAssetCount,
    `${label}.telemetry.privacyRiskExternalAssetCount`
  );
  requireFinitePositive(
    telemetry.privacyRiskExternalAssetLimit,
    `${label}.telemetry.privacyRiskExternalAssetLimit`
  );
  requireBoolean(
    telemetry.privacyRiskExternalAssetsTruncated,
    `${label}.telemetry.privacyRiskExternalAssetsTruncated`
  );
  if (telemetry.privacyRiskExternalAssetCount < telemetry.privacyRiskExternalAssets.length) {
    throw new Error(`${label}.telemetry.privacyRiskExternalAssetCount cannot be smaller than the retained inventory.`);
  }
  if (telemetry.privacyRiskExternalAssets.length > telemetry.privacyRiskExternalAssetLimit) {
    throw new Error(`${label}.telemetry.privacyRiskExternalAssets exceeds its retained-inventory limit.`);
  }
  if (!telemetry.privacyRiskExternalAssetsTruncated
    && telemetry.privacyRiskExternalAssetCount !== telemetry.privacyRiskExternalAssets.length) {
    throw new Error(`${label}.telemetry.privacyRiskExternalAssetCount must equal the retained inventory when it is not truncated.`);
  }
  const runtimeAttempts = requireObject(telemetry.runtimeAttempts, `${label}.telemetry.runtimeAttempts`);
  for (const field of runtimeAttemptFields) requireArray(runtimeAttempts[field], `${label}.telemetry.runtimeAttempts.${field}`);

  const contract = requireObject(inspection.contract, `${label}.contract`);
  const page = requireObject(contract.page, `${label}.contract.page`);
  if (typeof page.url !== 'string' || !page.url) throw new Error(`${label}.contract.page.url must be a non-empty string.`);
  const geometry = requireObject(page.geometry, `${label}.contract.page.geometry`);
  requireFinitePositive(geometry.width, `${label}.contract.page.geometry.width`);
  requireFinitePositive(geometry.height, `${label}.contract.page.geometry.height`);
  for (const field of ['resources', 'forms', 'links', 'controls', 'stylesheets', 'elements']) {
    requireArray(contract[field], `${label}.contract.${field}`);
  }
  const integrity = requireObject(contract.integrity, `${label}.contract.integrity`);
  for (const field of [
    'nativeApiTampering', 'embeddedFrames', 'browserFrames', 'embeddedObjects', 'scripts',
    'stylesheetLinks', 'baseElements', 'replicaSourceLinks', 'rasterSurfaces', 'vectorSurfaces',
    'metaRefreshElements'
  ]) requireArray(integrity[field], `${label}.contract.integrity.${field}`);
  const cdpStructuralInventory = requireObject(
    integrity.cdpStructuralInventory,
    `${label}.contract.integrity.cdpStructuralInventory`
  );
  for (const field of [
    'formCount', 'unsafeFormCount', 'navigableLinkCount', 'externalLinkCount', 'unsafeLinkCount',
    'scriptCount', 'externalScriptCount', 'stylesheetLinkCount', 'externalStylesheetCount',
    'baseElementCount', 'iframeCount', 'embeddedObjectCount', 'disclosureCount',
    'metaRefreshCount', 'inlineScriptCount', 'svgElementCount', 'svgExternalResourceCount'
  ]) requireNonNegativeInteger(cdpStructuralInventory[field], `${label}.contract.integrity.cdpStructuralInventory.${field}`);
  for (const field of [
    'iframeCount', 'embeddedObjectCount', 'closedShadowRootCount', 'resourceTimingBufferSize',
    'resourceTimingBufferFullEvents', 'resourceTimingTamperAttempts', 'rasterSurfaceCount',
    'vectorSurfaceCount', 'svgElementCount', 'svgExternalResourceCount'
  ]) requireNonNegativeInteger(integrity[field], `${label}.contract.integrity.${field}`);
  requireBoolean(integrity.resourceTimingOverflow, `${label}.contract.integrity.resourceTimingOverflow`);
  requireBoolean(integrity.rasterSurfacesTruncated, `${label}.contract.integrity.rasterSurfacesTruncated`);
  requireBoolean(integrity.vectorSurfacesTruncated, `${label}.contract.integrity.vectorSurfacesTruncated`);
  requireBoolean(integrity.elementLimitReached, `${label}.contract.integrity.elementLimitReached`);
  if (!Number.isFinite(integrity.aggregateRasterDocumentCoverage)
    || integrity.aggregateRasterDocumentCoverage < 0
    || integrity.aggregateRasterDocumentCoverage > 1) {
    throw new Error(`${label}.contract.integrity.aggregateRasterDocumentCoverage must be finite from 0 to 1.`);
  }
  if (!Number.isFinite(integrity.aggregateVectorDocumentCoverage)
    || integrity.aggregateVectorDocumentCoverage < 0
    || integrity.aggregateVectorDocumentCoverage > 1) {
    throw new Error(`${label}.contract.integrity.aggregateVectorDocumentCoverage must be finite from 0 to 1.`);
  }
  if (integrity.rasterSurfaceCount < integrity.rasterSurfaces.length) {
    throw new Error(`${label}.contract.integrity.rasterSurfaceCount cannot be smaller than the retained inventory.`);
  }
  if (!integrity.rasterSurfacesTruncated && integrity.rasterSurfaceCount !== integrity.rasterSurfaces.length) {
    throw new Error(`${label}.contract.integrity.rasterSurfaceCount must equal the retained inventory when it is not truncated.`);
  }
  if (integrity.vectorSurfaceCount < integrity.vectorSurfaces.length) {
    throw new Error(`${label}.contract.integrity.vectorSurfaceCount cannot be smaller than the retained inventory.`);
  }
  if (!integrity.vectorSurfacesTruncated && integrity.vectorSurfaceCount !== integrity.vectorSurfaces.length) {
    throw new Error(`${label}.contract.integrity.vectorSurfaceCount must equal the retained inventory when it is not truncated.`);
  }
  const securityHeaders = requireObject(integrity.mainResponseSecurityHeaders, `${label}.contract.integrity.mainResponseSecurityHeaders`);
  const refreshHeader = requireObject(securityHeaders.refresh, `${label}.contract.integrity.mainResponseSecurityHeaders.refresh`);
  requireBoolean(refreshHeader.present, `${label}.contract.integrity.mainResponseSecurityHeaders.refresh.present`);
  requireNonNegativeInteger(refreshHeader.length, `${label}.contract.integrity.mainResponseSecurityHeaders.refresh.length`);
  requireBoolean(refreshHeader.hasUrlDirective, `${label}.contract.integrity.mainResponseSecurityHeaders.refresh.hasUrlDirective`);
  const preFreeze = requireObject(integrity.preFreezeDisclosureState, `${label}.contract.integrity.preFreezeDisclosureState`);
  requireArray(preFreeze.entries, `${label}.contract.integrity.preFreezeDisclosureState.entries`);
  for (const field of ['disclosureCount', 'animationRiskCount', 'transitionRiskCount', 'pseudoElementOpaqueOverlayRiskCount']) {
    requireNonNegativeInteger(preFreeze[field], `${label}.contract.integrity.preFreezeDisclosureState.${field}`);
  }
  const delayedPersistence = requireObject(integrity.delayedPersistenceNavigation, `${label}.contract.integrity.delayedPersistenceNavigation`);
  requireFinitePositive(delayedPersistence.sampleDelayMs, `${label}.contract.integrity.delayedPersistenceNavigation.sampleDelayMs`);
  requireBoolean(delayedPersistence.completed, `${label}.contract.integrity.delayedPersistenceNavigation.completed`);
  requireNonNegativeInteger(delayedPersistence.navigationCount, `${label}.contract.integrity.delayedPersistenceNavigation.navigationCount`);
  requireBoolean(delayedPersistence.urlChanged, `${label}.contract.integrity.delayedPersistenceNavigation.urlChanged`);
  const scriptInventory = requireObject(integrity.scriptResponseInventory, `${label}.contract.integrity.scriptResponseInventory`);
  requireArray(scriptInventory.responses, `${label}.contract.integrity.scriptResponseInventory.responses`);
  for (const field of ['responseCount', 'retainedCount', 'responseLimit', 'singleBodyByteLimit', 'totalBodyByteLimit', 'declaredBodyBytesRead']) {
    requireNonNegativeInteger(scriptInventory[field], `${label}.contract.integrity.scriptResponseInventory.${field}`);
  }
  requireBoolean(scriptInventory.responsesTruncated, `${label}.contract.integrity.scriptResponseInventory.responsesTruncated`);
  requireBoolean(scriptInventory.bodyReadLimitReached, `${label}.contract.integrity.scriptResponseInventory.bodyReadLimitReached`);
  if (scriptInventory.retainedCount !== scriptInventory.responses.length) {
    throw new Error(`${label}.contract.integrity.scriptResponseInventory.retainedCount must equal the retained responses.`);
  }
  if (!scriptInventory.responsesTruncated && scriptInventory.responseCount !== scriptInventory.responses.length) {
    throw new Error(`${label}.contract.integrity.scriptResponseInventory.responseCount must equal retained responses when it is not truncated.`);
  }
  if (typeof scriptInventory.expectedBundledStarterAppSha256 !== 'string'
    || !/^[0-9a-f]{64}$/.test(scriptInventory.expectedBundledStarterAppSha256)) {
    throw new Error(`${label}.contract.integrity.scriptResponseInventory.expectedBundledStarterAppSha256 must be SHA-256 hex.`);
  }
  const stylesheetInventory = requireObject(
    integrity.stylesheetResponseInventory,
    `${label}.contract.integrity.stylesheetResponseInventory`
  );
  requireArray(stylesheetInventory.responses, `${label}.contract.integrity.stylesheetResponseInventory.responses`);
  for (const field of ['responseCount', 'retainedCount', 'responseLimit', 'singleBodyByteLimit', 'totalBodyByteLimit', 'declaredBodyBytesRead']) {
    requireNonNegativeInteger(stylesheetInventory[field], `${label}.contract.integrity.stylesheetResponseInventory.${field}`);
  }
  requireBoolean(stylesheetInventory.responsesTruncated, `${label}.contract.integrity.stylesheetResponseInventory.responsesTruncated`);
  requireBoolean(stylesheetInventory.bodyReadLimitReached, `${label}.contract.integrity.stylesheetResponseInventory.bodyReadLimitReached`);
  if (stylesheetInventory.retainedCount !== stylesheetInventory.responses.length) {
    throw new Error(`${label}.contract.integrity.stylesheetResponseInventory.retainedCount must equal the retained responses.`);
  }
  if (!stylesheetInventory.responsesTruncated
    && stylesheetInventory.responseCount !== stylesheetInventory.responses.length) {
    throw new Error(`${label}.contract.integrity.stylesheetResponseInventory.responseCount must equal retained responses when it is not truncated.`);
  }
  const validateExecutableStyleSnapshot = (value, snapshotLabel, waitResult) => {
    const snapshot = requireObject(value, snapshotLabel);
    if (waitResult) {
      requireBoolean(snapshot.completed, `${snapshotLabel}.completed`);
      requireNonNegativeInteger(snapshot.waitedMs, `${snapshotLabel}.waitedMs`);
    }
    requireNonNegativeInteger(snapshot.quietWindowMs, `${snapshotLabel}.quietWindowMs`);
    requireNonNegativeInteger(snapshot.pendingCount, `${snapshotLabel}.pendingCount`);
    requireNonNegativeInteger(snapshot.quietForMs, `${snapshotLabel}.quietForMs`);
    requireBoolean(snapshot.recordsTruncated, `${snapshotLabel}.recordsTruncated`);
    requireArray(snapshot.pending, `${snapshotLabel}.pending`);
    requireArray(snapshot.failures, `${snapshotLabel}.failures`);
    for (const counterName of ['started', 'finished', 'failed']) {
      const counter = requireObject(snapshot[counterName], `${snapshotLabel}.${counterName}`);
      requireNonNegativeInteger(counter.script, `${snapshotLabel}.${counterName}.script`);
      requireNonNegativeInteger(counter.stylesheet, `${snapshotLabel}.${counterName}.stylesheet`);
    }
    return snapshot;
  };
  for (const field of [
    'executableStyleInitialQuiescence', 'executableStylePostSettleQuiescence',
    'executableStyleFinalQuiescence'
  ]) validateExecutableStyleSnapshot(integrity[field], `${label}.contract.integrity.${field}`, true);
  validateExecutableStyleSnapshot(
    integrity.executableStyleTerminalSnapshot,
    `${label}.contract.integrity.executableStyleTerminalSnapshot`,
    false
  );
  const mediaMatrix = requireObject(integrity.publicDisclosureMediaMatrix, `${label}.contract.integrity.publicDisclosureMediaMatrix`);
  requireNonNegativeInteger(mediaMatrix.requiredVariantCount, `${label}.contract.integrity.publicDisclosureMediaMatrix.requiredVariantCount`);
  requireNonNegativeInteger(mediaMatrix.sampleDelayMs, `${label}.contract.integrity.publicDisclosureMediaMatrix.sampleDelayMs`);
  requireBoolean(mediaMatrix.completed, `${label}.contract.integrity.publicDisclosureMediaMatrix.completed`);
  requireNonNegativeInteger(mediaMatrix.navigationCount, `${label}.contract.integrity.publicDisclosureMediaMatrix.navigationCount`);
  requireBoolean(mediaMatrix.urlChanged, `${label}.contract.integrity.publicDisclosureMediaMatrix.urlChanged`);
  requireArray(mediaMatrix.entries, `${label}.contract.integrity.publicDisclosureMediaMatrix.entries`);
  const stylesheetGraph = requireObject(integrity.stylesheetGraph, `${label}.contract.integrity.stylesheetGraph`);
  for (const field of ['sheetLimit', 'ruleLimit', 'totalSheetCount', 'retainedSheetCount', 'totalRuleCount', 'ruleAccessFailureCount']) {
    requireNonNegativeInteger(stylesheetGraph[field], `${label}.contract.integrity.stylesheetGraph.${field}`);
  }
  for (const field of ['sheetsTruncated', 'rulesTruncated']) {
    requireBoolean(stylesheetGraph[field], `${label}.contract.integrity.stylesheetGraph.${field}`);
  }
  requireArray(stylesheetGraph.unresolvedOwners, `${label}.contract.integrity.stylesheetGraph.unresolvedOwners`);
  requireArray(stylesheetGraph.sheets, `${label}.contract.integrity.stylesheetGraph.sheets`);
  if (stylesheetGraph.retainedSheetCount !== stylesheetGraph.sheets.length) {
    throw new Error(`${label}.contract.integrity.stylesheetGraph.retainedSheetCount must equal the retained sheets.`);
  }
  requireObject(integrity.documentPointInTime, `${label}.contract.integrity.documentPointInTime`);
  return contract;
}

function parseArguments(argv) {
  const options = { inspection: null, source: null, manifest: null, out: null, allowExternalAssets: false, help: false };
  const take = (index, option) => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${option} requires a value.`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--inspection': options.inspection = resolve(take(index, argument)); index += 1; break;
      case '--source': options.source = take(index, argument); index += 1; break;
      case '--manifest': options.manifest = resolve(take(index, argument)); index += 1; break;
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--allow-source-assets': case '--allow-external-assets': options.allowExternalAssets = true; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && (!options.inspection || !options.source || !options.manifest)) {
    throw new Error('--inspection, --source, and --manifest are required.');
  }
  return options;
}

function clippedRect(surface, documentWidth, documentHeight) {
  const rect = surface.rect || {};
  const left = Math.max(0, Number(rect.x || 0));
  const top = Math.max(0, Number(rect.y || 0));
  const right = Math.min(documentWidth, Number(rect.x || 0) + Math.max(0, Number(rect.width || 0)));
  const bottom = Math.min(documentHeight, Number(rect.y || 0) + Math.max(0, Number(rect.height || 0)));
  return right > left && bottom > top ? { left, top, right, bottom } : null;
}

function rectangleUnionArea(rectangles) {
  const xCoordinates = [...new Set(rectangles.flatMap((rect) => [rect.left, rect.right]))].sort((a, b) => a - b);
  let area = 0;
  for (let index = 0; index < xCoordinates.length - 1; index += 1) {
    const left = xCoordinates[index];
    const right = xCoordinates[index + 1];
    if (right <= left) continue;
    const intervals = rectangles
      .filter((rect) => rect.left < right && rect.right > left)
      .map((rect) => [rect.top, rect.bottom])
      .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    let coveredHeight = 0;
    let start = null;
    let end = null;
    for (const [intervalStart, intervalEnd] of intervals) {
      if (start === null || intervalStart > end) {
        if (start !== null) coveredHeight += end - start;
        start = intervalStart;
        end = intervalEnd;
      } else {
        end = Math.max(end, intervalEnd);
      }
    }
    if (start !== null) coveredHeight += end - start;
    area += (right - left) * coveredHeight;
  }
  return area;
}

function disclosureEvidence(contract) {
  if (Array.isArray(contract.integrity?.disclosures)) return contract.integrity.disclosures;
  return (contract.elements || [])
    .filter((element) => (element.classes || []).includes('replica-disclosure'))
    .map((element) => ({
      path: element.path,
      text: element.text,
      visible: true,
      position: element.style?.position || '',
      rect: element.rect
    }));
}

function hasStrictPublicSimulationCsp(policy) {
  const selfOrNone = (entry) => entry?.present === true
    && entry.duplicate !== true
    && ['self', 'none'].includes(entry.mode);
  const optionalSelfOrNone = (entry) => !entry?.present || selfOrNone(entry);
  return selfOrNone(policy?.scriptSrc)
    && optionalSelfOrNone(policy?.scriptSrcElem)
    && optionalSelfOrNone(policy?.scriptSrcAttr)
    && selfOrNone(policy?.connectSrc)
    && selfOrNone(policy?.formAction)
    && policy?.objectSrc?.present === true
    && policy.objectSrc.duplicate !== true
    && policy.objectSrc.mode === 'none'
    && policy?.frameAncestors?.present === true
    && policy.frameAncestors.duplicate !== true
    && policy.frameAncestors.mode === 'none';
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node check-candidate-integrity.mjs --inspection DIR --source URL --manifest FILE [--out FILE]\n');
    return;
  }
  const source = assertSafeHttpUrl(options.source, '--source');
  options.source = source.href;
  const manifest = JSON.parse(await fs.readFile(options.manifest, 'utf8'));
  const allowedModes = new Set(['authorized-local', 'owned', 'public-simulation']);
  if (!allowedModes.has(manifest.mode)) {
    throw new Error('Manifest mode must be authorized-local, owned, or public-simulation.');
  }
  const declaredBackendIssues = backendDeclarationIssues(manifest);
  const expectedBundledStarterAppSha256 = createHash('sha256')
    .update(await fs.readFile(bundledStarterAppPath))
    .digest('hex');
  const inspectionStat = await fs.lstat(options.inspection);
  if (inspectionStat.isSymbolicLink() || !inspectionStat.isDirectory()) {
    throw new Error('--inspection must be a real directory, not a symlink.');
  }
  const inspectionRoot = await fs.realpath(options.inspection);
  const summaryPath = await requireCanonicalFile(inspectionRoot, join(inspectionRoot, 'summary.json'), 'inspection summary');
  const summary = JSON.parse(await fs.readFile(summaryPath, 'utf8'));
  if (summary.schemaVersion !== inspectionSchemaVersion) {
    throw new Error(`inspection summary.schemaVersion must be ${inspectionSchemaVersion}.`);
  }
  requireArray(summary.results, 'inspection summary.results');
  if (!summary.results.length) throw new Error('inspection summary.results must contain at least one viewport.');
  const requestedCandidate = assertSafeHttpUrl(summary.url, 'inspection summary.url');
  const requestedCandidateOrigin = requestedCandidate.origin;
  const captures = new Map();
  const viewportNames = new Set();
  for (const [index, viewportResult] of summary.results.entries()) {
    const viewport = requireObject(viewportResult?.viewport, `inspection summary.results[${index}].viewport`);
    if (!viewportNamePattern.test(viewport.name || '')) {
      throw new Error(`inspection summary.results[${index}].viewport.name must be a lowercase filesystem-safe slug.`);
    }
    if (viewportNames.has(viewport.name)) throw new Error(`inspection viewport name "${viewport.name}" is duplicated.`);
    viewportNames.add(viewport.name);
    requireFinitePositive(viewport.width, `inspection summary.results[${index}].viewport.width`);
    requireFinitePositive(viewport.height, `inspection summary.results[${index}].viewport.height`);
    const viewportDirectory = await requireCanonicalDirectory(
      inspectionRoot,
      join(inspectionRoot, viewport.name),
      `inspection viewport ${viewport.name}`
    );
    const pathname = await requireCanonicalFile(
      inspectionRoot,
      join(viewportDirectory, 'contract.json'),
      `inspection viewport ${viewport.name} contract`
    );
    const inspection = JSON.parse(await fs.readFile(pathname, 'utf8'));
    validateRequiredCaptureEvidence(inspection, viewportResult, `inspection viewport ${viewport.name}`);
    captures.set(viewport.name, inspection);
  }
  const results = [];
  for (const viewportResult of summary.results) {
    const inspection = captures.get(viewportResult.viewport.name);
    const contract = inspection.contract;
    const failures = [];
    const fail = (code, evidence) => failures.push({ code, evidence });
    if (declaredBackendIssues.length) {
      fail('MANIFEST_BACKEND_DECLARATION_INVALID', { fields: declaredBackendIssues });
    }
    let candidate = requestedCandidate;
    try {
      const finalCandidate = new URL(contract.page.url);
      if (!['http:', 'https:'].includes(finalCandidate.protocol) || finalCandidate.username || finalCandidate.password) {
        fail('CANDIDATE_FINAL_URL_UNSAFE', { requested: requestedCandidate.href, final: '[unsafe final URL omitted]' });
      } else {
        candidate = finalCandidate;
        if (candidate.origin !== requestedCandidateOrigin) {
          fail('CANDIDATE_CROSS_ORIGIN_REDIRECT', {
            requested: requestedCandidate.href,
            final: redactSensitiveUrl(candidate.href),
            requestedOrigin: requestedCandidateOrigin,
            finalOrigin: candidate.origin
          });
        }
      }
    } catch {
      fail('CANDIDATE_FINAL_URL_UNSAFE', { requested: requestedCandidate.href, final: '[unsafe final URL omitted]' });
    }
    const blockedWrites = inspection.telemetry?.blockedWrites || [];
    const blockedPrivateReads = inspection.telemetry?.blockedPrivateReads || [];
    const failedGets = inspection.telemetry?.failedGets || [];
    const externalReads = inspection.telemetry?.externalReads || [];
    const externalReadCount = Number(inspection.telemetry?.externalReadCount || externalReads.length);
    const externalReadsTruncated = inspection.telemetry?.externalReadsTruncated === true
      || externalReadCount > externalReads.length;
    const reportedCredentialLikeExternalAssets = inspection.telemetry?.privacyRiskExternalAssets || [];
    const credentialLikeExternalAssetCount = Number(
      inspection.telemetry?.privacyRiskExternalAssetCount || reportedCredentialLikeExternalAssets.length
    );
    const credentialLikeExternalAssetsTruncated = inspection.telemetry?.privacyRiskExternalAssetsTruncated === true
      || credentialLikeExternalAssetCount > reportedCredentialLikeExternalAssets.length;
    if (blockedWrites.length) fail('CANDIDATE_BLOCKED_WRITE_ATTEMPT', blockedWrites);
    if (blockedPrivateReads.length) fail('CANDIDATE_BLOCKED_PRIVATE_READ_ATTEMPT', blockedPrivateReads);
    const nativeApiTampering = Array.isArray(contract.integrity.nativeApiTampering)
      ? contract.integrity.nativeApiTampering
      : [];
    if (nativeApiTampering.length) fail('CAPTURE_NATIVE_API_TAMPERING', nativeApiTampering);
    const cdpStructure = contract.integrity.cdpStructuralInventory || {};
    const pageStructure = {
      formCount: contract.forms.length,
      navigableLinkCount: contract.links.filter((link) => (
        link.hrefAttribute !== null && link.hrefAttribute !== undefined
      ) || (link.xlinkHrefAttribute !== null && link.xlinkHrefAttribute !== undefined)).length,
      scriptCount: contract.integrity.scripts.length,
      inlineScriptCount: contract.integrity.scripts.filter((script) => script.inline === true).length,
      stylesheetLinkCount: contract.integrity.stylesheetLinks.length,
      baseElementCount: contract.integrity.baseElements.length,
      iframeCount: Number(contract.integrity.iframeCount || 0),
      embeddedObjectCount: Number(contract.integrity.embeddedObjectCount || 0),
      disclosureCount: Array.isArray(contract.integrity.disclosures) ? contract.integrity.disclosures.length : 0,
      metaRefreshCount: contract.integrity.metaRefreshElements.length,
      svgElementCount: Number(contract.integrity.svgElementCount || 0),
      svgExternalResourceCount: Number(contract.integrity.svgExternalResourceCount || 0)
    };
    const cdpStructureMismatches = Object.entries(pageStructure)
      .filter(([field, count]) => Number(cdpStructure[field]) !== Number(count))
      .map(([field, count]) => ({ field, pageCount: count, cdpCount: Number(cdpStructure[field]) }));
    if (cdpStructureMismatches.length) fail('CDP_STRUCTURAL_INVENTORY_MISMATCH', cdpStructureMismatches);
    if (Number(cdpStructure.unsafeFormCount || 0) > 0) fail('CDP_UNSAFE_FORM_CONFIGURATION', { count: cdpStructure.unsafeFormCount });
    if (Number(cdpStructure.externalLinkCount || 0) > 0) fail('CDP_EXTERNAL_LINK_TARGET', { count: cdpStructure.externalLinkCount });
    if (Number(cdpStructure.unsafeLinkCount || 0) > 0) fail('CDP_UNSAFE_LINK_TARGET', { count: cdpStructure.unsafeLinkCount });
    if (Number(cdpStructure.externalScriptCount || 0) > 0) fail('CDP_EXTERNAL_SCRIPT_SOURCE', { count: cdpStructure.externalScriptCount });
    if (!options.allowExternalAssets && Number(cdpStructure.externalStylesheetCount || 0) > 0) {
      fail('CDP_EXTERNAL_STYLESHEET_SOURCE', { count: cdpStructure.externalStylesheetCount });
    }
    const refreshHeader = contract.integrity.mainResponseSecurityHeaders.refresh;
    if (refreshHeader.present === true) {
      fail('MAIN_RESPONSE_REFRESH_PRESENT', {
        length: refreshHeader.length,
        hasUrlDirective: refreshHeader.hasUrlDirective === true
      });
    }
    if (contract.integrity.metaRefreshElements.length || Number(cdpStructure.metaRefreshCount || 0) > 0) {
      fail('META_REFRESH_PRESENT', {
        pageCount: contract.integrity.metaRefreshElements.length,
        cdpCount: Number(cdpStructure.metaRefreshCount || 0),
        elements: contract.integrity.metaRefreshElements
      });
    }
    const externalFailedGets = [];
    const unsafeFailedGets = [];
    for (const entry of failedGets) {
      let target;
      try { target = new URL(String(entry.url || ''), requestedCandidate); }
      catch { unsafeFailedGets.push({ type: entry.type || '', reason: 'malformed-url' }); continue; }
      if (target.username || target.password) unsafeFailedGets.push({ type: entry.type || '', reason: 'url-credentials' });
      else if (!['http:', 'https:'].includes(target.protocol)) unsafeFailedGets.push({ type: entry.type || '', protocol: target.protocol, reason: 'unsafe-protocol' });
      else if (target.origin !== requestedCandidateOrigin) externalFailedGets.push({
        type: entry.type || '',
        url: redactSensitiveUrl(target.href),
        error: entry.error || ''
      });
    }
    if (failedGets.length) fail('FAILED_GET_DEPENDENCY', { count: failedGets.length });
    if (externalFailedGets.length) fail('EXTERNAL_FAILED_GET_DEPENDENCY', externalFailedGets);
    if (unsafeFailedGets.length) fail('UNSAFE_FAILED_GET_DEPENDENCY', unsafeFailedGets);
    if (externalReadsTruncated) {
      fail('EXTERNAL_READ_INVENTORY_TRUNCATED', {
        count: externalReadCount,
        retained: externalReads.length,
        limit: Number(inspection.telemetry?.externalReadLimit || 0),
        typeCounts: inspection.telemetry?.externalReadTypeCounts || {}
      });
    }
    const allowedExternalAssetTypes = new Set(['font', 'image', 'media', 'stylesheet']);
    const classifyExternalAssetUrl = (rawUrl, rawResourceType) => {
      const resourceType = String(rawResourceType || '').toLowerCase();
      if (!allowedExternalAssetTypes.has(resourceType)) return [];
      let target;
      try { target = new URL(String(rawUrl || ''), candidate); } catch { return []; }
      if (!['http:', 'https:'].includes(target.protocol) || target.origin === requestedCandidateOrigin) return [];
      return credentialLikeUrlIssue(target.href)
        ? [{ resourceType, url: redactSensitiveUrl(target.href) }]
        : [];
    };
    const resourceInitiatorAssetType = (initiatorType) => {
      const normalized = String(initiatorType || '').toLowerCase();
      if (['css', 'link', 'stylesheet'].includes(normalized)) return 'stylesheet';
      if (['img', 'image'].includes(normalized)) return 'image';
      if (['audio', 'video', 'media'].includes(normalized)) return 'media';
      return normalized === 'font' ? 'font' : '';
    };
    const independentlyClassifiedExternalAssets = [
      ...externalReads.flatMap((entry) => classifyExternalAssetUrl(entry.url, entry.resourceType)),
      ...(contract.resources || []).flatMap((resource) => classifyExternalAssetUrl(
        resource.name,
        resourceInitiatorAssetType(resource.initiatorType)
      )),
      ...[
        ...(contract.stylesheets || []),
        ...(contract.integrity.stylesheetLinks || [])
      ].flatMap((stylesheet) => classifyExternalAssetUrl(
        stylesheet.href || stylesheet.hrefAttribute,
        'stylesheet'
      )),
      ...[
        ...(contract.integrity.rasterSurfaces || []),
        ...(contract.integrity.vectorSurfaces || [])
      ].flatMap((surface) => (surface.sources || (surface.src ? [surface.src] : []))
        .flatMap((sourceUrl) => classifyExternalAssetUrl(sourceUrl, 'image')))
    ];
    if (credentialLikeExternalAssetCount > 0 || independentlyClassifiedExternalAssets.length > 0) {
      fail('CREDENTIAL_LIKE_EXTERNAL_ASSET_URL', {
        count: Math.max(credentialLikeExternalAssetCount, independentlyClassifiedExternalAssets.length),
        retained: reportedCredentialLikeExternalAssets.length,
        truncated: credentialLikeExternalAssetsTruncated,
        assets: [
          ...reportedCredentialLikeExternalAssets.map((entry) => ({
            resourceType: String(entry.resourceType || '').toLowerCase(),
            url: redactSensitiveUrl(String(entry.url || ''))
          })),
          ...independentlyClassifiedExternalAssets
        ].slice(0, 100)
      });
    }
    const prohibitedExternalReads = options.allowExternalAssets
      ? externalReads.filter((entry) => !allowedExternalAssetTypes.has(String(entry.resourceType || '').toLowerCase()))
      : externalReads;
    if (prohibitedExternalReads.length) {
      fail('EXTERNAL_READ_DEPENDENCY', prohibitedExternalReads.slice(0, 100));
    }
    if (contract.integrity.resourceTimingOverflow === true
      || Number(contract.integrity.resourceTimingBufferFullEvents || 0) > 0) {
      fail('RESOURCE_TIMING_BUFFER_OVERFLOW', {
        bufferSize: Number(contract.integrity.resourceTimingBufferSize || 0),
        bufferFullEvents: Number(contract.integrity.resourceTimingBufferFullEvents || 0)
      });
    }
    if (Number(contract.integrity.resourceTimingTamperAttempts || 0) > 0) {
      fail('RESOURCE_TIMING_TAMPER_ATTEMPT', {
        count: Number(contract.integrity.resourceTimingTamperAttempts || 0)
      });
    }
    const runtimeAttempts = inspection.telemetry?.runtimeAttempts || {};
    const runtimeAttemptGates = [
      ['webSocketAttempts', 'CANDIDATE_WEBSOCKET_ATTEMPT'],
      ['beaconAttempts', 'CANDIDATE_BEACON_ATTEMPT'],
      ['windowOpenAttempts', 'CANDIDATE_WINDOW_OPEN_ATTEMPT'],
      ['popupAttempts', 'CANDIDATE_POPUP_ATTEMPT'],
      ['downloadAttempts', 'CANDIDATE_DOWNLOAD_ATTEMPT'],
      ['serviceWorkerRegistrationAttempts', 'CANDIDATE_SERVICE_WORKER_REGISTRATION_ATTEMPT'],
      ['externalFetchAttempts', 'CANDIDATE_EXTERNAL_FETCH_ATTEMPT'],
      ['externalXhrAttempts', 'CANDIDATE_EXTERNAL_XHR_ATTEMPT'],
      ['webTransportAttempts', 'CANDIDATE_WEBTRANSPORT_ATTEMPT'],
      ['webSocketStreamAttempts', 'CANDIDATE_WEBSOCKET_STREAM_ATTEMPT'],
      ['rtcPeerConnectionAttempts', 'CANDIDATE_RTC_PEER_CONNECTION_ATTEMPT'],
      ['rtcDataChannelAttempts', 'CANDIDATE_RTC_DATA_CHANNEL_ATTEMPT']
    ];
    for (const [field, code] of runtimeAttemptGates) {
      const attempts = Array.isArray(runtimeAttempts[field]) ? runtimeAttempts[field] : [];
      if (attempts.length) fail(code, attempts);
    }
    const frames = [
      ...(contract.integrity.embeddedFrames || []),
      ...(contract.integrity.browserFrames || []).map((frame) => ({ ...frame, src: frame.src || frame.url || '' }))
    ];
    if (Number(contract.integrity.iframeCount || 0) > 0 || frames.length > 0) {
      fail('IFRAME_PRESENT', { count: contract.integrity.iframeCount, frames });
    }
    const sourceFrames = frames.filter((frame) => {
      try {
        const frameUrl = new URL(frame.src);
        return frameUrl.origin !== requestedCandidateOrigin && frameUrl.hostname === source.hostname;
      } catch { return false; }
    });
    if (sourceFrames.length) fail('SOURCE_IFRAME', sourceFrames);
    const embeddedObjects = contract.integrity.embeddedObjects || [];
    if (Number(contract.integrity.embeddedObjectCount || 0) > 0 || embeddedObjects.length) {
      fail('EMBEDDED_OBJECT_PRESENT', embeddedObjects);
    }
    if (Number(contract.integrity.closedShadowRootCount || 0) > 0) {
      fail('CLOSED_SHADOW_ROOT_PRESENT', contract.integrity.closedShadowRoots || {
        count: contract.integrity.closedShadowRootCount
      });
    }
    const documentWidth = Math.max(1, Number(contract.page.geometry?.width || 0));
    const documentHeight = Math.max(1, Number(contract.page.geometry?.height || 0));
    const documentCoverage = (surface) => {
      const declared = Number(surface.documentCoverage);
      const rect = clippedRect(surface, documentWidth, documentHeight);
      const recomputed = rect
        ? (rect.right - rect.left) * (rect.bottom - rect.top) / (documentWidth * documentHeight)
        : 0;
      return Number.isFinite(declared) ? Math.max(declared, recomputed) : recomputed;
    };
    const rasterSurfaces = contract.integrity.rasterSurfaces || [];
    const suspiciousRaster = rasterSurfaces
      .map((surface) => ({ ...surface, documentCoverage: documentCoverage(surface) }))
      .filter((surface) => surface.documentCoverage >= 0.8);
    if (suspiciousRaster.length) fail('FULL_PAGE_RASTER', suspiciousRaster);
    const rasterRectangles = rasterSurfaces
      .map((surface) => clippedRect(surface, documentWidth, documentHeight))
      .filter(Boolean);
    const retainedAggregateRasterCoverage = rectangleUnionArea(rasterRectangles) / (documentWidth * documentHeight);
    const declaredAggregateRasterCoverage = Number(contract.integrity.aggregateRasterDocumentCoverage);
    const aggregateRasterCoverage = Number.isFinite(declaredAggregateRasterCoverage)
      ? Math.max(retainedAggregateRasterCoverage, declaredAggregateRasterCoverage)
      : retainedAggregateRasterCoverage;
    const rasterSurfaceCount = Number.isSafeInteger(Number(contract.integrity.rasterSurfaceCount))
      ? Number(contract.integrity.rasterSurfaceCount)
      : rasterSurfaces.length;
    if (aggregateRasterCoverage >= 0.8) {
      fail('FULL_PAGE_RASTER_AGGREGATE', {
        surfaceCount: rasterSurfaceCount,
        retainedSurfaceCount: rasterSurfaces.length,
        truncated: Boolean(contract.integrity.rasterSurfacesTruncated),
        coverageMethod: contract.integrity.aggregateRasterCoverageMethod || 'exact-retained-rectangle-union',
        documentCoverage: aggregateRasterCoverage,
        surfaces: rasterSurfaces.slice(0, 100)
      });
    }
    if (contract.integrity.rasterSurfacesTruncated) {
      fail('RASTER_INVENTORY_TRUNCATED', {
        surfaceCount: rasterSurfaceCount,
        retainedSurfaceCount: rasterSurfaces.length,
        declaredAggregateCoveragePresent: Number.isFinite(declaredAggregateRasterCoverage),
        reason: 'A truncated raster inventory cannot prove dependency or surface safety.'
      });
    }
    const vectorSurfaces = contract.integrity.vectorSurfaces || [];
    const suspiciousVector = vectorSurfaces
      .map((surface) => ({ ...surface, documentCoverage: documentCoverage(surface) }))
      .filter((surface) => surface.documentCoverage >= 0.8);
    if (suspiciousVector.length) fail('FULL_PAGE_VECTOR_OR_FILTER_SURFACE', suspiciousVector);
    const vectorRectangles = vectorSurfaces
      .map((surface) => clippedRect(surface, documentWidth, documentHeight))
      .filter(Boolean);
    const retainedAggregateVectorCoverage = rectangleUnionArea(vectorRectangles) / (documentWidth * documentHeight);
    const declaredAggregateVectorCoverage = Number(contract.integrity.aggregateVectorDocumentCoverage);
    const aggregateVectorCoverage = Number.isFinite(declaredAggregateVectorCoverage)
      ? Math.max(retainedAggregateVectorCoverage, declaredAggregateVectorCoverage)
      : retainedAggregateVectorCoverage;
    const vectorSurfaceCount = Number(contract.integrity.vectorSurfaceCount);
    if (aggregateVectorCoverage >= 0.8) {
      fail('FULL_PAGE_VECTOR_AGGREGATE', {
        surfaceCount: vectorSurfaceCount,
        retainedSurfaceCount: vectorSurfaces.length,
        truncated: Boolean(contract.integrity.vectorSurfacesTruncated),
        coverageMethod: contract.integrity.aggregateVectorCoverageMethod || 'exact-retained-rectangle-union',
        documentCoverage: aggregateVectorCoverage,
        surfaces: vectorSurfaces.slice(0, 100)
      });
    }
    if (contract.integrity.vectorSurfacesTruncated) {
      fail('VECTOR_INVENTORY_TRUNCATED', {
        surfaceCount: vectorSurfaceCount,
        retainedSurfaceCount: vectorSurfaces.length,
        declaredAggregateCoveragePresent: Number.isFinite(declaredAggregateVectorCoverage)
      });
    }
    if (contract.integrity.elementLimitReached) {
      fail('ELEMENT_INVENTORY_TRUNCATED', { reason: 'The visible-element safety inventory reached its configured limit.' });
    }
    const externalRasterSources = rasterSurfaces.flatMap((surface) => (surface.sources || (surface.src ? [surface.src] : []))
      .map((resource) => ({ resource, surface })))
      .filter(({ resource }) => {
        try {
          const resourceUrl = new URL(resource, candidate);
          return ['http:', 'https:'].includes(resourceUrl.protocol) && resourceUrl.origin !== requestedCandidateOrigin;
        } catch { return false; }
      });
    if (externalRasterSources.length && !options.allowExternalAssets) {
      fail('EXTERNAL_RASTER_DEPENDENCY', externalRasterSources.slice(0, 30));
    }
    const externalVectorSources = vectorSurfaces.flatMap((surface) => (surface.sources || (surface.src ? [surface.src] : []))
      .map((resource) => ({ resource, surface })))
      .filter(({ resource }) => {
        try {
          const resourceUrl = new URL(resource, candidate);
          return ['http:', 'https:'].includes(resourceUrl.protocol) && resourceUrl.origin !== requestedCandidateOrigin;
        } catch { return false; }
      });
    if (externalVectorSources.length && !options.allowExternalAssets) {
      fail('EXTERNAL_VECTOR_DEPENDENCY', externalVectorSources.slice(0, 30));
    }
    const renderedMode = contract.page.replicaMode || null;
    if (renderedMode !== manifest.mode) {
      fail('REPLICA_MODE_MISMATCH', { manifest: manifest.mode, rendered: renderedMode });
    }
    if (!isLoopbackHostname(requestedCandidate.hostname)
      && (manifest.mode === 'authorized-local' || renderedMode === 'authorized-local')) {
      fail('AUTHORIZED_LOCAL_PUBLIC_ORIGIN', {
        hostname: requestedCandidate.hostname,
        manifestMode: manifest.mode,
        renderedMode
      });
    }
    const baseElements = contract.integrity.baseElements || [];
    const externalBaseElements = [];
    const unsafeBaseElements = [];
    for (const base of baseElements) {
      if (String(base.target || '').trim() && String(base.target).toLowerCase() !== '_self') {
        unsafeBaseElements.push({ target: String(base.target), reason: 'browsing-context-target' });
      }
      if (base.hrefAttribute === null || base.hrefAttribute === undefined) continue;
      let target;
      try { target = new URL(String(base.href || base.hrefAttribute), candidate); }
      catch { unsafeBaseElements.push({ hrefAttributePresent: true, reason: 'malformed-url' }); continue; }
      const evidence = { href: ['http:', 'https:'].includes(target.protocol) ? redactSensitiveUrl(target.href) : undefined };
      if (target.username || target.password) unsafeBaseElements.push({ ...evidence, reason: 'url-credentials' });
      else if (!['http:', 'https:'].includes(target.protocol)) unsafeBaseElements.push({ protocol: target.protocol, reason: 'unsafe-protocol' });
      else if (target.origin !== requestedCandidateOrigin) externalBaseElements.push(evidence);
    }
    if (externalBaseElements.length) fail('EXTERNAL_BASE_HREF', externalBaseElements);
    if (unsafeBaseElements.length) fail('UNSAFE_BASE_HREF', unsafeBaseElements);
    const disclosures = disclosureEvidence(contract);
    if (manifest.mode === 'public-simulation') {
      const securityHeaders = contract.integrity.mainResponseSecurityHeaders || {};
      const inlineScripts = (contract.integrity.scripts || []).filter((script) => script.inline === true);
      if (inlineScripts.length || Number(cdpStructure.inlineScriptCount || 0) > 0) {
        fail('PUBLIC_INLINE_SCRIPT_PRESENT', {
          pageCount: inlineScripts.length,
          cdpCount: Number(cdpStructure.inlineScriptCount || 0),
          scripts: inlineScripts.map((script) => ({ type: script.type || '', textLength: Number(script.textLength || 0) }))
        });
      }
      const scriptInventory = contract.integrity.scriptResponseInventory;
      const sameOriginScriptResponses = scriptInventory.responses.filter((entry) => entry.sameOrigin === true);
      const unverifiedScriptResponses = sameOriginScriptResponses.filter((entry) => (
        entry.status < 200
        || entry.status >= 300
        || entry.bodyRead !== true
        || entry.bodyWithinLimit !== true
        || entry.sha256 !== expectedBundledStarterAppSha256
        || entry.matchesBundledStarterApp !== true
      ));
      if (scriptInventory.expectedBundledStarterAppSha256 !== expectedBundledStarterAppSha256) {
        fail('PUBLIC_SCRIPT_EXPECTED_HASH_MISMATCH', { expectedHashMatchesEvaluator: false });
      }
      if (scriptInventory.responsesTruncated || scriptInventory.bodyReadLimitReached) {
        fail('PUBLIC_SCRIPT_RESPONSE_INVENTORY_INCOMPLETE', {
          responseCount: scriptInventory.responseCount,
          retainedCount: scriptInventory.retainedCount,
          responseLimit: scriptInventory.responseLimit,
          responsesTruncated: scriptInventory.responsesTruncated,
          bodyReadLimitReached: scriptInventory.bodyReadLimitReached
        });
      }
      if (!sameOriginScriptResponses.length) {
        fail('PUBLIC_STARTER_SCRIPT_RESPONSE_MISSING', { expectedSha256: expectedBundledStarterAppSha256 });
      }
      if (unverifiedScriptResponses.length) {
        fail('PUBLIC_SCRIPT_RESPONSE_NOT_EXACT_STARTER', unverifiedScriptResponses.map((entry) => ({
          url: entry.url,
          status: entry.status,
          bodyRead: entry.bodyRead,
          bodyWithinLimit: entry.bodyWithinLimit,
          sha256Matches: entry.sha256 === expectedBundledStarterAppSha256
        })));
      }
      const externalDomScripts = (contract.integrity.scripts || []).filter((script) => script.inline !== true);
      const exactStarterDomScripts = externalDomScripts.filter((script) => {
        try {
          const target = new URL(script.src || script.srcAttribute || '', candidate);
          return target.origin === requestedCandidateOrigin
            && target.pathname === '/app.js'
            && !target.search
            && !target.hash;
        } catch {
          return false;
        }
      });
      const exactStarterResponses = sameOriginScriptResponses.filter((entry) => (
        entry.pathname === '/app.js'
        && entry.searchPresent !== true
        && entry.hashPresent !== true
        && entry.matchesBundledStarterApp === true
      ));
      if (externalDomScripts.length !== 1
        || exactStarterDomScripts.length !== 1
        || scriptInventory.responseCount !== 1
        || scriptInventory.responses.length !== 1
        || exactStarterResponses.length !== 1) {
        fail('PUBLIC_SCRIPT_DOM_RESPONSE_RECONCILIATION_FAILED', {
          domScriptCount: externalDomScripts.length,
          exactStarterDomScriptCount: exactStarterDomScripts.length,
          responseCount: scriptInventory.responseCount,
          retainedResponseCount: scriptInventory.responses.length,
          exactStarterResponseCount: exactStarterResponses.length
        });
      }
      const quiescenceStages = [
        ['initial', contract.integrity.executableStyleInitialQuiescence],
        ['post-settle', contract.integrity.executableStylePostSettleQuiescence],
        ['final', contract.integrity.executableStyleFinalQuiescence]
      ];
      const incompleteQuiescence = quiescenceStages.filter(([, evidence]) => (
        evidence.completed !== true
        || evidence.pendingCount !== 0
        || evidence.recordsTruncated === true
        || evidence.failures.length > 0
        || evidence.failed.script > 0
        || evidence.failed.stylesheet > 0
      ));
      const terminalNetwork = contract.integrity.executableStyleTerminalSnapshot;
      const finalNetwork = contract.integrity.executableStyleFinalQuiescence;
      const terminalChangedAfterFinal = ['script', 'stylesheet'].some((kind) => (
        terminalNetwork.started[kind] !== finalNetwork.started[kind]
        || terminalNetwork.finished[kind] !== finalNetwork.finished[kind]
        || terminalNetwork.failed[kind] !== finalNetwork.failed[kind]
      ));
      if (incompleteQuiescence.length
        || terminalNetwork.pendingCount !== 0
        || terminalNetwork.recordsTruncated === true
        || terminalNetwork.failures.length > 0
        || terminalNetwork.quietForMs < terminalNetwork.quietWindowMs
        || terminalChangedAfterFinal) {
        fail('PUBLIC_EXECUTABLE_STYLE_RESOURCES_NOT_QUIESCENT', {
          incompleteStages: incompleteQuiescence.map(([stage, evidence]) => ({ stage, evidence })),
          terminal: terminalNetwork,
          changedAfterFinalQuiescence: terminalChangedAfterFinal
        });
      }
      if (terminalNetwork.started.script !== 1
        || terminalNetwork.finished.script !== 1
        || terminalNetwork.failed.script !== 0
        || terminalNetwork.started.script !== scriptInventory.responseCount) {
        fail('PUBLIC_SCRIPT_REQUEST_LIFECYCLE_MISMATCH', {
          lifecycle: {
            started: terminalNetwork.started.script,
            finished: terminalNetwork.finished.script,
            failed: terminalNetwork.failed.script
          },
          responseCount: scriptInventory.responseCount
        });
      }
      const stylesheetInventory = contract.integrity.stylesheetResponseInventory;
      const unverifiedStylesheetResponses = stylesheetInventory.responses.filter((entry) => (
        entry.sameOrigin !== true
        || entry.searchPresent === true
        || entry.hashPresent === true
        || entry.status < 200
        || entry.status >= 300
        || entry.contentType !== 'text/css'
        || entry.bodyRead !== true
        || entry.bodyWithinLimit !== true
        || !/^[0-9a-f]{64}$/.test(String(entry.sha256 || ''))
      ));
      if (stylesheetInventory.responsesTruncated || stylesheetInventory.bodyReadLimitReached) {
        fail('PUBLIC_STYLESHEET_RESPONSE_INVENTORY_INCOMPLETE', {
          responseCount: stylesheetInventory.responseCount,
          retainedCount: stylesheetInventory.retainedCount,
          responseLimit: stylesheetInventory.responseLimit,
          responsesTruncated: stylesheetInventory.responsesTruncated,
          bodyReadLimitReached: stylesheetInventory.bodyReadLimitReached
        });
      }
      if (unverifiedStylesheetResponses.length) {
        fail('PUBLIC_STYLESHEET_RESPONSE_UNVERIFIED', unverifiedStylesheetResponses.map((entry) => ({
          url: entry.url,
          sameOrigin: entry.sameOrigin,
          status: entry.status,
          contentType: entry.contentType,
          searchPresent: entry.searchPresent,
          hashPresent: entry.hashPresent,
          bodyRead: entry.bodyRead,
          bodyWithinLimit: entry.bodyWithinLimit,
          sha256Present: /^[0-9a-f]{64}$/.test(String(entry.sha256 || ''))
        })));
      }
      if (terminalNetwork.started.stylesheet !== stylesheetInventory.responseCount
        || terminalNetwork.finished.stylesheet !== stylesheetInventory.responseCount
        || terminalNetwork.failed.stylesheet !== 0) {
        fail('PUBLIC_STYLESHEET_REQUEST_LIFECYCLE_MISMATCH', {
          lifecycle: {
            started: terminalNetwork.started.stylesheet,
            finished: terminalNetwork.finished.stylesheet,
            failed: terminalNetwork.failed.stylesheet
          },
          responseCount: stylesheetInventory.responseCount
        });
      }
      const stylesheetGraph = contract.integrity.stylesheetGraph;
      if (stylesheetGraph.sheetsTruncated
        || stylesheetGraph.rulesTruncated
        || stylesheetGraph.ruleAccessFailureCount > 0
        || stylesheetGraph.unresolvedOwners.length > 0) {
        fail('PUBLIC_STYLESHEET_GRAPH_INCOMPLETE', {
          sheetsTruncated: stylesheetGraph.sheetsTruncated,
          rulesTruncated: stylesheetGraph.rulesTruncated,
          ruleAccessFailureCount: stylesheetGraph.ruleAccessFailureCount,
          unresolvedOwners: stylesheetGraph.unresolvedOwners
        });
      }
      const canonicalStyleKey = (entry) => entry.sameOrigin === true
        && typeof entry.pathname === 'string'
        && entry.pathname.startsWith('/')
        && entry.searchPresent !== true
        && entry.hashPresent !== true
        ? entry.pathname
        : null;
      const responseStyleKeys = new Set(stylesheetInventory.responses.map(canonicalStyleKey).filter(Boolean));
      const graphStyleKeys = new Set(stylesheetGraph.sheets
        .filter((entry) => entry.url)
        .map(canonicalStyleKey)
        .filter(Boolean));
      const invalidGraphSheets = stylesheetGraph.sheets.filter((entry) => entry.url && !canonicalStyleKey(entry));
      const graphMissingResponses = [...graphStyleKeys].filter((key) => !responseStyleKeys.has(key));
      const responsesMissingGraph = [...responseStyleKeys].filter((key) => !graphStyleKeys.has(key));
      const domStyleKeys = [];
      const invalidDomStyleLinks = [];
      for (const link of contract.integrity.stylesheetLinks || []) {
        try {
          const target = new URL(link.href || link.hrefAttribute || '', candidate);
          if (target.origin !== requestedCandidateOrigin || target.search || target.hash) {
            invalidDomStyleLinks.push({ href: redactSensitiveUrl(target.href) });
          } else {
            domStyleKeys.push(target.pathname);
          }
        } catch {
          invalidDomStyleLinks.push({ reason: 'malformed-url' });
        }
      }
      const domLinksMissingGraph = [...new Set(domStyleKeys)].filter((key) => !graphStyleKeys.has(key));
      if (invalidGraphSheets.length
        || invalidDomStyleLinks.length
        || graphMissingResponses.length
        || responsesMissingGraph.length
        || domLinksMissingGraph.length) {
        fail('PUBLIC_STYLESHEET_DOM_RESPONSE_RECONCILIATION_FAILED', {
          invalidGraphSheets,
          invalidDomStyleLinks,
          graphMissingResponses,
          responsesMissingGraph,
          domLinksMissingGraph
        });
      }
      const preFreeze = contract.integrity.preFreezeDisclosureState;
      if (preFreeze.disclosureCount !== disclosures.length) {
        fail('PUBLIC_DISCLOSURE_PRE_FREEZE_COUNT_MISMATCH', {
          preFreezeCount: preFreeze.disclosureCount,
          retainedCount: disclosures.length
        });
      }
      if (preFreeze.animationRiskCount > 0 || preFreeze.transitionRiskCount > 0) {
        fail('PUBLIC_DISCLOSURE_DYNAMIC_VISIBILITY_RISK', {
          animationRiskCount: preFreeze.animationRiskCount,
          transitionRiskCount: preFreeze.transitionRiskCount,
          entries: preFreeze.entries
        });
      }
      if (preFreeze.pseudoElementOpaqueOverlayRiskCount > 0) {
        fail('PUBLIC_DISCLOSURE_PSEUDO_OVERLAY_RISK', {
          count: preFreeze.pseudoElementOpaqueOverlayRiskCount,
          entries: preFreeze.entries
        });
      }
      const delayedPersistence = contract.integrity.delayedPersistenceNavigation;
      if (delayedPersistence.completed !== true
        || delayedPersistence.navigationCount > 0
        || delayedPersistence.urlChanged === true) {
        fail('PUBLIC_DELAYED_PERSISTENCE_NAVIGATION_RISK', delayedPersistence);
      }
      const csp = securityHeaders.contentSecurityPolicy || {};
      const cspPolicies = Array.isArray(csp.policies) ? csp.policies : [];
      const strictCsp = csp.present === true
        && csp.overLimit !== true
        && csp.policyLimitReached !== true
        && cspPolicies.some(hasStrictPublicSimulationCsp);
      if (!strictCsp) {
        fail('PUBLIC_RESPONSE_CSP_MISSING_OR_UNSAFE', {
          present: csp.present === true,
          overLimit: csp.overLimit === true,
          policyLimitReached: csp.policyLimitReached === true,
          policyCount: cspPolicies.length,
          policies: cspPolicies
        });
      }
      const xFrameOptions = securityHeaders.xFrameOptions || {};
      if (xFrameOptions.disposition !== 'deny') {
        fail('PUBLIC_X_FRAME_OPTIONS_MISSING_OR_UNSAFE', {
          present: xFrameOptions.present === true,
          disposition: xFrameOptions.disposition || 'missing'
        });
      }
      const authenticityContradiction = (value) => {
        const text = String(value || '');
        const withoutAllowedNegation = text.replace(/\bnot\s+the\s+original(?:\s+(?:website|site))?\b/gi, ' ');
        return /\b(?:official|authentic|genuine|original|real\s+(?:website|site))\b/i.test(withoutAllowedNegation);
      };
      const hasRequiredDisclosureCopy = (value) => {
        const text = String(value || '');
        const explicitNegation = /\bnot\s+the\s+original(?:\s+(?:website|site))?\b/i;
        const withoutNegation = text.replace(explicitNegation, ' ');
        return /\bsimulation\b/i.test(text)
          && explicitNegation.test(text)
          && !authenticityContradiction(withoutNegation);
      };
      const mediaMatrix = contract.integrity.publicDisclosureMediaMatrix;
      const expectedMediaVariants = new Map(requiredPublicDisclosureMediaVariants.map((entry) => [entry[0], entry]));
      const retainedMediaVariantNames = mediaMatrix.entries.map((entry) => entry.variant?.name || '');
      const duplicateMediaVariantNames = retainedMediaVariantNames.filter((name, index) => (
        retainedMediaVariantNames.indexOf(name) !== index
      ));
      const invalidMediaEntries = [];
      for (const entry of mediaMatrix.entries) {
        const expected = expectedMediaVariants.get(entry.variant?.name);
        const environmentMatches = expected
          && entry.variant.colorScheme === expected[1]
          && entry.variant.reducedMotion === expected[2]
          && entry.variant.deviceScaleFactor === expected[3]
          && entry.environment?.colorScheme === expected[1]
          && entry.environment?.reducedMotion === expected[2]
          && Math.abs(Number(entry.environment?.deviceScaleFactor) - expected[3]) < 0.01;
        const preFreezeVariant = entry.preFreeze || {};
        const quiescence = entry.quiescence || {};
        const persistentDisclosures = (entry.disclosures || []).filter((disclosure) => (
          disclosure.persistent === true
          && ['fixed', 'sticky'].includes(String(disclosure.position || '').toLowerCase())
          && disclosure.visibleAtStart === true
          && disclosure.visibleAtDocumentEnd === true
          && disclosure.visibleAfterDelay === true
          && disclosure.unoccludedAtStart === true
          && disclosure.unoccludedAtDocumentEnd === true
          && disclosure.unoccludedAfterDelay === true
          && hasRequiredDisclosureCopy(disclosure.innerTextAtStart)
          && hasRequiredDisclosureCopy(disclosure.geometricVisibleTextAtStart)
          && hasRequiredDisclosureCopy(disclosure.visibleTextAtStart)
          && hasRequiredDisclosureCopy(disclosure.innerTextAtDocumentEnd)
          && hasRequiredDisclosureCopy(disclosure.geometricVisibleTextAtDocumentEnd)
          && hasRequiredDisclosureCopy(disclosure.visibleTextAtDocumentEnd)
          && hasRequiredDisclosureCopy(disclosure.innerTextAfterDelay)
          && hasRequiredDisclosureCopy(disclosure.geometricVisibleTextAfterDelay)
          && hasRequiredDisclosureCopy(disclosure.visibleTextAfterDelay)
        ));
        if (entry.completed !== true
          || !environmentMatches
          || quiescence.completed !== true
          || quiescence.pendingCount !== 0
          || quiescence.recordsTruncated === true
          || (quiescence.failures || []).length > 0
          || preFreezeVariant.disclosureCount !== disclosures.length
          || preFreezeVariant.animationRiskCount !== 0
          || preFreezeVariant.transitionRiskCount !== 0
          || preFreezeVariant.pseudoElementOpaqueOverlayRiskCount !== 0
          || persistentDisclosures.length === 0) {
          invalidMediaEntries.push({
            variant: entry.variant || null,
            completed: entry.completed === true,
            environment: entry.environment || null,
            quiescence: entry.quiescence || null,
            preFreeze: entry.preFreeze || null,
            disclosureCount: (entry.disclosures || []).length,
            persistentRequiredDisclosureCount: persistentDisclosures.length
          });
        }
      }
      const missingMediaVariants = [...expectedMediaVariants.keys()].filter((name) => !retainedMediaVariantNames.includes(name));
      if (mediaMatrix.completed !== true
        || mediaMatrix.requiredVariantCount !== requiredPublicDisclosureMediaVariants.length
        || mediaMatrix.entries.length !== requiredPublicDisclosureMediaVariants.length
        || mediaMatrix.navigationCount !== 0
        || mediaMatrix.urlChanged === true
        || duplicateMediaVariantNames.length
        || missingMediaVariants.length
        || invalidMediaEntries.length) {
        fail('PUBLIC_DISCLOSURE_MEDIA_MATRIX_FAILED', {
          completed: mediaMatrix.completed,
          requiredVariantCount: mediaMatrix.requiredVariantCount,
          retainedVariantCount: mediaMatrix.entries.length,
          navigationCount: mediaMatrix.navigationCount,
          urlChanged: mediaMatrix.urlChanged,
          duplicateMediaVariantNames,
          missingMediaVariants,
          invalidEntries: invalidMediaEntries
        });
      }
      const contradictoryDisclosures = disclosures.filter((entry) => [
        entry.text,
        entry.innerTextAtStart,
        entry.innerTextAtDocumentEnd,
        entry.innerTextAfterDelay
      ].some(authenticityContradiction));
      if (contradictoryDisclosures.length) {
        fail('PUBLIC_DISCLOSURE_CONTRADICTORY_AUTHENTICITY', contradictoryDisclosures);
      }
      const intendedDisclosure = disclosures.filter((entry) => hasRequiredDisclosureCopy(entry.text));
      const geometricallyRenderedAtStart = intendedDisclosure.filter((entry) => (
        hasRequiredDisclosureCopy(entry.innerTextAtStart)
        && hasRequiredDisclosureCopy(entry.geometricVisibleTextAtStart)
      ));
      const genuinelyVisibleAtStart = geometricallyRenderedAtStart.filter((entry) => (
        entry.visible === true
        && entry.visibleAtStart === true
        && entry.unoccludedAtStart === true
        && hasRequiredDisclosureCopy(entry.visibleTextAtStart)
      ));
      if (!geometricallyRenderedAtStart.length) {
        fail('PUBLIC_DISCLOSURE_MISSING', disclosures);
      } else if (!genuinelyVisibleAtStart.length) {
        fail('PUBLIC_DISCLOSURE_OCCLUDED', geometricallyRenderedAtStart);
      } else {
        const persistentDisclosure = genuinelyVisibleAtStart.filter((entry) => entry.persistent === true
          && ['fixed', 'sticky'].includes(String(entry.position || '').toLowerCase())
          && entry.visibleAtStart === true
          && entry.visibleAtDocumentEnd === true
          && entry.unoccludedAtStart === true
          && entry.unoccludedAtDocumentEnd === true
          && entry.visibleAfterDelay === true
          && entry.unoccludedAfterDelay === true
          && hasRequiredDisclosureCopy(entry.innerTextAtDocumentEnd)
          && hasRequiredDisclosureCopy(entry.geometricVisibleTextAtDocumentEnd)
          && hasRequiredDisclosureCopy(entry.visibleTextAtDocumentEnd)
          && hasRequiredDisclosureCopy(entry.innerTextAfterDelay)
          && hasRequiredDisclosureCopy(entry.geometricVisibleTextAfterDelay)
          && hasRequiredDisclosureCopy(entry.visibleTextAfterDelay));
        if (!persistentDisclosure.length) {
          fail('PUBLIC_DISCLOSURE_NOT_PERSISTENT', genuinelyVisibleAtStart);
        }
      }
    }
    const sourceResources = (contract.resources || []).filter((resource) => {
      try {
        const resourceUrl = new URL(resource.name);
        return resourceUrl.origin !== requestedCandidateOrigin && resourceUrl.hostname === source.hostname;
      } catch { return false; }
    });
    const externalResources = (contract.resources || []).filter((resource) => {
      try {
        const resourceUrl = new URL(resource.name);
        return ['http:', 'https:'].includes(resourceUrl.protocol) && resourceUrl.origin !== requestedCandidateOrigin;
      } catch { return false; }
    });
    const prohibitedResources = externalResources.filter((resource) => {
      if (!options.allowExternalAssets) return true;
      return ['fetch', 'xmlhttprequest', 'script', 'iframe', 'document'].includes(String(resource.initiatorType).toLowerCase());
    });
    if (prohibitedResources.length) fail('EXTERNAL_RESOURCE_DEPENDENCY', prohibitedResources.slice(0, 30));
    const externalForms = [];
    const unsafeForms = [];
    for (const form of contract.forms || []) {
      let target;
      try { target = new URL(String(form.action || form.actionAttribute || ''), candidate); }
      catch {
        unsafeForms.push({ path: form.path, reason: 'malformed-action' });
        continue;
      }
      if (target.origin !== requestedCandidateOrigin) externalForms.push({ path: form.path, reason: 'external-action' });
      if (target.username || target.password || !['http:', 'https:'].includes(target.protocol)) {
        unsafeForms.push({ path: form.path, reason: 'unsafe-action' });
      } else if (target.origin !== requestedCandidateOrigin
        || target.pathname !== auditedBackend.submitPath
        || target.search
        || target.hash) {
        unsafeForms.push({ path: form.path, reason: 'non-audited-submit-path' });
      }
      if (String(form.method || 'get').toLowerCase() !== 'post') {
        unsafeForms.push({ path: form.path, reason: 'non-post-method' });
      }
      if (!safeFormEnctypes.has(String(form.enctype || '').toLowerCase())) {
        unsafeForms.push({ path: form.path, reason: 'unsafe-enctype' });
      }
      const targetAttribute = String(form.targetAttribute || '').trim().toLowerCase();
      if (targetAttribute && targetAttribute !== '_self') {
        unsafeForms.push({ path: form.path, reason: 'browsing-context-target' });
      }
    }
    if (externalForms.length) fail('EXTERNAL_FORM_ACTION', externalForms);
    if (unsafeForms.length) fail('UNSAFE_FORM_CONFIGURATION', unsafeForms);
    const replicaSourceLinks = Array.isArray(contract.integrity.replicaSourceLinks)
      ? contract.integrity.replicaSourceLinks
      : (contract.links || []).filter((link) => link.replicaSourceLink === true);
    const navigableReplicaSourceLinks = replicaSourceLinks.filter((link) => (
      (link.hrefAttribute !== null && link.hrefAttribute !== undefined)
      || (link.xlinkHrefAttribute !== null && link.xlinkHrefAttribute !== undefined)
    ));
    if (navigableReplicaSourceLinks.length) {
      fail('SOURCE_LINK_NAVIGATION_TARGET', navigableReplicaSourceLinks.map((link) => ({
        path: link.path,
        tag: link.tag,
        hasHrefAttribute: link.hrefAttribute !== null && link.hrefAttribute !== undefined,
        hasXlinkHrefAttribute: link.xlinkHrefAttribute !== null && link.xlinkHrefAttribute !== undefined
      })));
    }
    const externalLinkTargets = [];
    const unsafeLinkTargets = [];
    for (const link of contract.links || []) {
      const declaredTargets = [
        ['href', link.hrefAttribute],
        ['xlink:href', link.xlinkHrefAttribute],
        ['resolved-href', link.href || null]
      ].filter(([, value]) => value !== null && value !== undefined);
      for (const [attribute, value] of declaredTargets) {
        let target;
        try {
          target = new URL(String(value), candidate);
        } catch {
          unsafeLinkTargets.push({ path: link.path, attribute, reason: 'malformed-url' });
          continue;
        }
        const evidence = {
          path: link.path,
          attribute,
          resolved: ['http:', 'https:'].includes(target.protocol) ? redactSensitiveUrl(target.href) : undefined
        };
        if (target.username || target.password) {
          unsafeLinkTargets.push({ ...evidence, reason: 'url-credentials' });
        } else if (!['http:', 'https:'].includes(target.protocol)) {
          unsafeLinkTargets.push({ path: link.path, attribute, protocol: target.protocol, reason: 'unsafe-protocol' });
        } else if (target.origin !== requestedCandidateOrigin) {
          externalLinkTargets.push(evidence);
        }
      }
    }
    if (externalLinkTargets.length) fail('EXTERNAL_LINK_TARGET', externalLinkTargets);
    if (unsafeLinkTargets.length) fail('UNSAFE_LINK_TARGET', unsafeLinkTargets);
    const unsafeFormOverrides = [];
    for (const control of contract.controls || []) {
      if (control.formActionAttribute !== null && control.formActionAttribute !== undefined) {
        let target;
        try { target = new URL(String(control.formAction || control.formActionAttribute), candidate); }
        catch {
          unsafeFormOverrides.push({ path: control.path, attribute: 'formaction', reason: 'malformed-url' });
          continue;
        }
        if (target.username || target.password) {
          unsafeFormOverrides.push({ path: control.path, attribute: 'formaction', reason: 'url-credentials' });
        } else if (!['http:', 'https:'].includes(target.protocol)) {
          unsafeFormOverrides.push({ path: control.path, attribute: 'formaction', protocol: target.protocol, reason: 'unsafe-protocol' });
        } else if (target.origin !== requestedCandidateOrigin) {
          unsafeFormOverrides.push({
            path: control.path,
            attribute: 'formaction',
            resolved: redactSensitiveUrl(target.href),
            reason: 'external-origin'
          });
        } else if (target.pathname !== auditedBackend.submitPath || target.search || target.hash) {
          unsafeFormOverrides.push({ path: control.path, attribute: 'formaction', reason: 'non-audited-submit-path' });
        }
      }
      if (control.formMethodAttribute !== null && control.formMethodAttribute !== undefined
        && String(control.formMethod || '').toLowerCase() !== 'post') {
        unsafeFormOverrides.push({ path: control.path, attribute: 'formmethod', reason: 'non-post-method' });
      }
      if (control.formTargetAttribute !== null && control.formTargetAttribute !== undefined
        && !['', '_self'].includes(String(control.formTarget || '').trim().toLowerCase())) {
        unsafeFormOverrides.push({ path: control.path, attribute: 'formtarget', reason: 'browsing-context-target' });
      }
      if (control.formEnctypeAttribute !== null && control.formEnctypeAttribute !== undefined
        && !safeFormEnctypes.has(String(control.formEnctype || '').toLowerCase())) {
        unsafeFormOverrides.push({ path: control.path, attribute: 'formenctype', reason: 'unsafe-enctype' });
      }
    }
    if (unsafeFormOverrides.length) fail('UNSAFE_FORM_SUBMISSION_OVERRIDE', unsafeFormOverrides);
    const unsafeHiddenControls = (contract.controls || [])
      .filter((control) => String(control.type || '').toLowerCase() === 'hidden')
      .filter((control) => control.hiddenValuePresent === true || Number(control.hiddenValueLength || 0) > 0)
      .filter((control) => control.hiddenValueClassification !== 'synthetic-local')
      .map((control) => ({
        path: control.path,
        name: control.name || '',
        hiddenValueLength: Number(control.hiddenValueLength || 0),
        hiddenValueClassification: control.hiddenValueClassification || 'unclassified-nonempty'
      }));
    if (unsafeHiddenControls.length) fail('UNSAFE_HIDDEN_INPUT_VALUE', unsafeHiddenControls);
    const inventoriedScripts = [
      ...(contract.integrity.scripts || []).map((script) => ({ source: script.src || '', inventory: script })),
      ...(contract.elements || [])
        .filter((element) => element.tag === 'script')
        .map((element) => ({ source: element.source || '', inventory: element }))
    ];
    const externalScripts = [];
    const unsafeScripts = [];
    for (const script of inventoriedScripts.filter((entry) => entry.source)) {
      let scriptUrl;
      try { scriptUrl = new URL(script.source, candidate); }
      catch { unsafeScripts.push({ reason: 'malformed-url' }); continue; }
      if (scriptUrl.username || scriptUrl.password) unsafeScripts.push({ reason: 'url-credentials' });
      else if (!['http:', 'https:'].includes(scriptUrl.protocol)) unsafeScripts.push({ protocol: scriptUrl.protocol, reason: 'unsafe-protocol' });
      else if (scriptUrl.origin !== requestedCandidateOrigin) externalScripts.push({ src: redactSensitiveUrl(scriptUrl.href) });
    }
    if (externalScripts.length) fail('EXTERNAL_SCRIPT_SOURCE', externalScripts);
    if (unsafeScripts.length) fail('UNSAFE_SCRIPT_SOURCE', unsafeScripts);
    const inventoriedStylesheets = [
      ...(contract.stylesheets || []).map((stylesheet) => stylesheet.href || ''),
      ...(contract.integrity.stylesheetLinks || []).map((stylesheet) => stylesheet.href || stylesheet.hrefAttribute || '')
    ].filter(Boolean);
    const externalStylesheets = [];
    const unsafeStylesheets = [];
    for (const sourceHref of new Set(inventoriedStylesheets)) {
      let stylesheetUrl;
      try { stylesheetUrl = new URL(sourceHref, candidate); }
      catch { unsafeStylesheets.push({ reason: 'malformed-url' }); continue; }
      if (stylesheetUrl.username || stylesheetUrl.password) unsafeStylesheets.push({ reason: 'url-credentials' });
      else if (!['http:', 'https:'].includes(stylesheetUrl.protocol)) unsafeStylesheets.push({ protocol: stylesheetUrl.protocol, reason: 'unsafe-protocol' });
      else if (stylesheetUrl.origin !== requestedCandidateOrigin) externalStylesheets.push({ href: redactSensitiveUrl(stylesheetUrl.href) });
    }
    if (externalStylesheets.length && !options.allowExternalAssets) fail('EXTERNAL_STYLESHEET_SOURCE', externalStylesheets);
    if (unsafeStylesheets.length) fail('UNSAFE_STYLESHEET_SOURCE', unsafeStylesheets);
    const sourceScripts = inventoriedScripts.filter((element) => {
      if (!element.source) return false;
      try {
        const scriptUrl = new URL(element.source);
        return scriptUrl.origin !== requestedCandidateOrigin && scriptUrl.hostname === source.hostname;
      } catch { return false; }
    });
    if (sourceScripts.length) fail('SOURCE_SCRIPT', sourceScripts.slice(0, 20));
    results.push({
      viewport: viewportResult.viewport,
      pass: failures.length === 0,
      evidence: {
        textLength: contract.page.textLength,
        iframeCount: contract.integrity.iframeCount,
        embeddedObjectCount: Number(contract.integrity.embeddedObjectCount || 0),
        largestRasterCoverage: Math.max(0, ...(contract.integrity.rasterSurfaces || []).map((surface) => Number(surface.viewportCoverage) || 0)),
        largestRasterDocumentCoverage: Math.max(0, ...(contract.integrity.rasterSurfaces || []).map(documentCoverage)),
        aggregateRasterDocumentCoverage: aggregateRasterCoverage,
        rasterSurfaceCount,
        rasterSurfacesTruncated: Boolean(contract.integrity.rasterSurfacesTruncated),
        rasterSurfaceTags: [...new Set(rasterSurfaces.map((surface) => surface.tag))].sort(),
        aggregateVectorDocumentCoverage: aggregateVectorCoverage,
        vectorSurfaceCount,
        vectorSurfacesTruncated: Boolean(contract.integrity.vectorSurfacesTruncated),
        vectorSurfaceTags: [...new Set(vectorSurfaces.map((surface) => surface.tag))].sort(),
        replicaMode: renderedMode,
        disclosureCount: disclosures.length,
        persistentDisclosureCount: disclosures.filter((entry) => entry.persistent === true).length,
        blockedWriteAttempts: blockedWrites.length,
        blockedPrivateReadAttempts: blockedPrivateReads.length,
        failedGetDependencyCount: failedGets.length,
        externalFailedGetDependencyCount: externalFailedGets.length,
        unsafeFailedGetDependencyCount: unsafeFailedGets.length,
        externalReadCount,
        externalReadsRetained: externalReads.length,
        externalReadsTruncated,
        credentialLikeExternalAssetCount,
        credentialLikeExternalAssetsRetained: reportedCredentialLikeExternalAssets.length,
        credentialLikeExternalAssetsTruncated,
        prohibitedExternalReadCount: prohibitedExternalReads.length,
        nativeApiTamperingCount: nativeApiTampering.length,
        runtimeAttemptCounts: Object.fromEntries(runtimeAttemptGates.map(([field]) => [
          field,
          Array.isArray(runtimeAttempts[field]) ? runtimeAttempts[field].length : 0
        ])),
        sourceResourceCount: sourceResources.length,
        externalResourceCount: externalResources.length,
        externalFormCount: externalForms.length,
        navigableReplicaSourceLinkCount: navigableReplicaSourceLinks.length,
        externalLinkTargetCount: externalLinkTargets.length,
        unsafeLinkTargetCount: unsafeLinkTargets.length,
        unsafeHiddenInputValueCount: unsafeHiddenControls.length,
        externalBaseHrefCount: externalBaseElements.length,
        unsafeBaseHrefCount: unsafeBaseElements.length,
        unsafeFormSubmissionOverrideCount: unsafeFormOverrides.length,
        externalScriptSourceCount: externalScripts.length,
        unsafeScriptSourceCount: unsafeScripts.length,
        externalStylesheetSourceCount: externalStylesheets.length,
        unsafeStylesheetSourceCount: unsafeStylesheets.length,
        resourceTimingBufferFullEvents: Number(contract.integrity.resourceTimingBufferFullEvents || 0)
      },
      failures
    });
  }
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    source: options.source,
    inspection: options.inspection,
    manifest: options.manifest,
    declaredMode: manifest.mode,
    pass: results.every((result) => result.pass),
    results
  };
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) await fs.writeFile(options.out, serialized);
  process.stdout.write(serialized);
  if (!report.pass) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
