import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, cp, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { PNG } from 'pngjs';
import {
  cssDependencyReferer,
  fetchCssDependency
} from '../../skills/replicate-websites/scripts/bootstrap-static-replica.mjs';
import {
  assertSafeHttpUrl,
  blocksPrivateDestination,
  blocksUnsafeDestinationBeforeProxy,
  createPrivateHostChecker,
  createPublicHostResolver,
  isLoopbackHostname,
  isPrivateOrReservedAddress,
  redactReportData,
  redactSensitiveUrl
} from '../../skills/replicate-websites/scripts/lib/network-safety.mjs';

const execFileAsync = promisify(execFile);
const skillRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../skills/replicate-websites');
const repositoryRoot = resolve(skillRoot, '../..');
const script = (name) => join(skillRoot, 'scripts', name);
const bundledStarterAppSha256 = createHash('sha256')
  .update(await readFile(join(skillRoot, 'assets', 'replica-starter', 'public', 'app.js')))
  .digest('hex');
const auditedBackend = {
  implementation: 'replicate-websites-starter-v1',
  submitPath: '/api/applications',
  auditPath: '/api/replica-audit',
  emailEnabledByDefault: false,
  retainsApplicantValues: false
};
const integrityManifest = (mode) => ({ schemaVersion: 1, mode, backend: auditedBackend });

async function run(pathname, args, options = {}) {
  try {
    const result = await execFileAsync(process.execPath, [pathname, ...args], { maxBuffer: 20 * 1024 * 1024, ...options });
    return { code: 0, ...result };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

async function chmodTree(root, directoryMode, fileMode) {
  await chmod(root, directoryMode);
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const pathname = join(root, entry.name);
    if (entry.isDirectory()) await chmodTree(pathname, directoryMode, fileMode);
    else if (entry.isFile()) await chmod(pathname, fileMode);
  }
}

function comparisonResult() {
  return {
    viewport: { name: 'desktop', width: 1440, height: 1000 },
    pixel: {
      dimensionsMatch: true,
      strictChangedPixels: 10,
      strictDiffPercent: 0.01,
      tolerantChangedPixels: 2,
      tolerantDiffPercent: 0.001,
      maskedOnEitherPixels: 0
    },
    candidate: {
      stability: { stable: true },
      telemetry: { failedGetResourcesByType: {}, pageErrors: 0, consoleErrors: 0 }
    },
    semantic: {
      mismatchCount: 1,
      captureIntegrity: { baseline: [], candidate: [], valid: true },
      categories: [
        {
          kind: 'controls',
          missing: [],
          extra: [],
          changed: [
            {
              key: 'name:provider_token|input:hidden|#0',
              changes: { hiddenValueLength: { baseline: 100, candidate: 20 } }
            }
          ]
        }
      ]
    }
  };
}

function requiredRuntimeAttempts(overrides = {}) {
  return {
    webSocketAttempts: [],
    beaconAttempts: [],
    windowOpenAttempts: [],
    popupAttempts: [],
    downloadAttempts: [],
    serviceWorkerRegistrationAttempts: [],
    externalFetchAttempts: [],
    externalXhrAttempts: [],
    webTransportAttempts: [],
    webSocketStreamAttempts: [],
    rtcPeerConnectionAttempts: [],
    rtcDataChannelAttempts: [],
    ...overrides
  };
}

function requiredTelemetry(overrides = {}) {
  return {
    blockedWrites: [],
    blockedPrivateReads: [],
    failedGets: [],
    externalReads: [],
    externalReadCount: 0,
    externalReadLimit: 2000,
    externalReadTypeCounts: {},
    externalReadsTruncated: false,
    privacyRiskExternalAssets: [],
    privacyRiskExternalAssetCount: 0,
    privacyRiskExternalAssetLimit: 200,
    privacyRiskExternalAssetsTruncated: false,
    runtimeAttempts: requiredRuntimeAttempts(),
    ...overrides
  };
}

function requiredCdpStructuralInventory(overrides = {}) {
  return {
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
    svgExternalResourceCount: 0,
    ...overrides
  };
}

function requiredScriptResponseInventory(overrides = {}) {
  return {
    responseCount: 0,
    retainedCount: 0,
    responseLimit: 100,
    responsesTruncated: false,
    singleBodyByteLimit: 262144,
    totalBodyByteLimit: 2097152,
    declaredBodyBytesRead: 0,
    bodyReadLimitReached: false,
    expectedBundledStarterAppSha256: bundledStarterAppSha256,
    responses: [],
    ...overrides
  };
}

function requiredStylesheetResponseInventory(overrides = {}) {
  return {
    responseCount: 0,
    retainedCount: 0,
    responseLimit: 300,
    responsesTruncated: false,
    singleBodyByteLimit: 1048576,
    totalBodyByteLimit: 8388608,
    declaredBodyBytesRead: 0,
    bodyReadLimitReached: false,
    responses: [],
    ...overrides
  };
}

function requiredExecutableStyleSnapshot(overrides = {}) {
  return {
    quietWindowMs: 150,
    started: { script: 0, stylesheet: 0 },
    finished: { script: 0, stylesheet: 0 },
    failed: { script: 0, stylesheet: 0 },
    pendingCount: 0,
    pending: [],
    failures: [],
    recordsTruncated: false,
    quietForMs: 150,
    ...overrides
  };
}

function requiredExecutableStyleQuiescence(overrides = {}) {
  return requiredExecutableStyleSnapshot({ completed: true, waitedMs: 150, ...overrides });
}

function requiredIntegrity(overrides = {}) {
  return {
    nativeApiTampering: [],
    cdpStructuralInventory: requiredCdpStructuralInventory(),
    iframeCount: 0,
    embeddedFrames: [],
    browserFrames: [],
    embeddedObjects: [],
    embeddedObjectCount: 0,
    closedShadowRootCount: 0,
    scripts: [],
    metaRefreshElements: [],
    stylesheetLinks: [],
    baseElements: [],
    replicaSourceLinks: [],
    resourceTimingBufferSize: 2048,
    resourceTimingBufferFullEvents: 0,
    resourceTimingOverflow: false,
    resourceTimingTamperAttempts: 0,
    elementLimitReached: false,
    rasterSurfaceCount: 0,
    rasterSurfacesTruncated: false,
    aggregateRasterDocumentCoverage: 0,
    aggregateRasterCoverageMethod: 'conservative-256x256-document-grid',
    rasterSurfaces: [],
    vectorSurfaceCount: 0,
    vectorSurfacesTruncated: false,
    aggregateVectorDocumentCoverage: 0,
    aggregateVectorCoverageMethod: 'conservative-256x256-document-grid',
    vectorSurfaces: [],
    svgElementCount: 0,
    svgExternalResourceCount: 0,
    mainResponseSecurityHeaders: {
      refresh: { present: false, length: 0, hasUrlDirective: false }
    },
    preFreezeDisclosureState: {
      phase: 'after-domcontentloaded-before-freeze-css',
      disclosureCount: 0,
      entries: [],
      animationRiskCount: 0,
      transitionRiskCount: 0,
      pseudoElementOpaqueOverlayRiskCount: 0
    },
    delayedPersistenceNavigation: {
      sampleDelayMs: 500,
      completed: true,
      navigationCount: 0,
      urlChanged: false
    },
    scriptResponseInventory: requiredScriptResponseInventory(),
    stylesheetResponseInventory: requiredStylesheetResponseInventory(),
    executableStyleInitialQuiescence: requiredExecutableStyleQuiescence(),
    executableStylePostSettleQuiescence: requiredExecutableStyleQuiescence(),
    executableStyleFinalQuiescence: requiredExecutableStyleQuiescence(),
    executableStyleTerminalSnapshot: requiredExecutableStyleSnapshot(),
    publicDisclosureMediaMatrix: {
      requiredVariantCount: 8,
      sampleDelayMs: 40,
      completed: false,
      navigationCount: 0,
      urlChanged: false,
      entries: []
    },
    stylesheetGraph: {
      sheetLimit: 600,
      ruleLimit: 20000,
      totalSheetCount: 0,
      retainedSheetCount: 0,
      totalRuleCount: 0,
      sheetsTruncated: false,
      rulesTruncated: false,
      ruleAccessFailureCount: 0,
      unresolvedOwners: [],
      sheets: []
    },
    documentPointInTime: {
      phase: 'after-explicit-settle-scroll-and-delayed-persistence-sample',
      delayedSampleMs: 500
    },
    ...overrides
  };
}

test('assert-fidelity distinguishes approved backend mismatches from unexplained mismatches', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-assert-'));
  const summaryPath = join(directory, 'summary.json');
  const policyPath = join(directory, 'policy.json');
  await writeFile(summaryPath, JSON.stringify({ schemaVersion: 1, results: [comparisonResult()] }));

  const unapproved = await run(script('assert-fidelity.mjs'), ['--summary', summaryPath]);
  assert.equal(unapproved.code, 2);
  assert.match(unapproved.stdout, /SEMANTIC_UNAPPROVED/);

  const blockedAttempt = comparisonResult();
  blockedAttempt.semantic = { mismatchCount: 0, categories: [] };
  blockedAttempt.candidate.telemetry.blockedWrites = [{ method: 'POST', url: 'https://source.example/collector' }];
  blockedAttempt.candidate.telemetry.blockedPrivateReads = [{ method: 'GET', url: 'http://127.0.0.1/private' }];
  await writeFile(summaryPath, JSON.stringify({ schemaVersion: 1, results: [blockedAttempt] }));
  const blocked = await run(script('assert-fidelity.mjs'), ['--summary', summaryPath]);
  assert.equal(blocked.code, 2);
  assert.match(blocked.stdout, /CANDIDATE_BLOCKED_WRITE_ATTEMPT/);
  assert.match(blocked.stdout, /CANDIDATE_BLOCKED_PRIVATE_READ_ATTEMPT/);

  const tamperedCapture = comparisonResult();
  tamperedCapture.semantic = {
    mismatchCount: 0,
    categories: [],
    captureIntegrity: {
      baseline: ['Array.prototype.map'],
      candidate: ['element[0]:getAttribute'],
      valid: false
    }
  };
  await writeFile(summaryPath, JSON.stringify({ schemaVersion: 1, results: [tamperedCapture] }));
  const tampered = await run(script('assert-fidelity.mjs'), ['--summary', summaryPath]);
  assert.equal(tampered.code, 2);
  assert.match(tampered.stdout, /BASELINE_CAPTURE_API_TAMPERING/);
  assert.match(tampered.stdout, /CANDIDATE_CAPTURE_API_TAMPERING/);
  await writeFile(summaryPath, JSON.stringify({ schemaVersion: 1, results: [comparisonResult()] }));

  await writeFile(policyPath, JSON.stringify({
    schemaVersion: 1,
    approvedSemanticMismatches: [
      {
        viewport: 'desktop',
        category: 'controls',
        kind: 'changed',
        key: 'name:provider_token|input:hidden|#0',
        changeFields: ['hiddenValueLength'],
        rationale: 'The candidate uses a synthetic local token.'
      }
    ]
  }));
  const approved = await run(script('assert-fidelity.mjs'), ['--summary', summaryPath, '--policy', policyPath]);
  assert.equal(approved.code, 0, approved.stderr);
  const score = JSON.parse(approved.stdout);
  assert.equal(score.pass, true);
  assert.equal(score.results[0].metrics.approvedSemanticMismatchCount, 1);
  assert.equal(score.results[0].metrics.unapprovedSemanticMismatchCount, 0);

  await writeFile(policyPath, JSON.stringify({
    schemaVersion: 1,
    approvedSemanticMismatches: [{ rationale: 'safe' }]
  }));
  const permissive = await run(script('assert-fidelity.mjs'), ['--summary', summaryPath, '--policy', policyPath]);
  assert.equal(permissive.code, 1);
  assert.match(permissive.stderr, /viewport.*non-empty|string|exact viewport/i);

  await writeFile(policyPath, JSON.stringify({
    schemaVersion: 1,
    approvedSemanticMismatches: [{
      viewport: '*',
      category: 'controls',
      kind: 'changed',
      keyPattern: '.*',
      changeFields: ['hiddenValueLength'],
      rationale: 'broad regex'
    }]
  }));
  const wildcard = await run(script('assert-fidelity.mjs'), ['--summary', summaryPath, '--policy', policyPath]);
  assert.equal(wildcard.code, 1);
  assert.match(wildcard.stderr, /unknown field "keyPattern"|exact viewport/i);
});

test('diagnose-diff ranks changed rows and maps candidate elements', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-diagnose-'));
  const report = join(directory, 'report');
  const contract = join(directory, 'contract');
  await mkdir(join(report, 'tiny'), { recursive: true });
  await mkdir(join(contract, 'tiny'), { recursive: true });
  const image = new PNG({ width: 8, height: 8 });
  for (const [x, y] of [[2, 3], [3, 3], [3, 4]]) {
    const offset = (y * image.width + x) * 4;
    image.data[offset] = 255;
    image.data[offset + 3] = 255;
  }
  await writeFile(join(report, 'tiny', 'diff.png'), PNG.sync.write(image));
  await writeFile(join(report, 'summary.json'), JSON.stringify({
    results: [{ viewport: { name: 'tiny', width: 8, height: 8 }, pixel: { tolerantChangedPixels: 3 } }]
  }));
  await writeFile(join(contract, 'tiny', 'contract.json'), JSON.stringify({
    contract: { elements: [{ path: 'main > p', tag: 'p', text: 'Mismatch', rect: { x: 0, y: 3, width: 8, height: 2 } }] }
  }));
  const out = join(directory, 'diagnosis.json');
  const result = await run(script('diagnose-diff.mjs'), [
    '--report', report,
    '--candidate-contract', contract,
    '--out', out
  ]);
  assert.equal(result.code, 0, result.stderr);
  const diagnosis = JSON.parse(await readFile(out, 'utf8'));
  assert.equal(diagnosis.results[0].rowBands[0].start, 3);
  assert.equal(diagnosis.results[0].rowBands[0].end, 4);
  assert.equal(diagnosis.results[0].rowBands[0].candidateElements[0].path, 'main > p');
});

test('fidelity loop rejects duplicate iteration IDs before touching artifacts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-iteration-ledger-'));
  const iteration = join(directory, 'iterations', 'geometry-01');
  const marker = join(iteration, 'comparison', 'marker.txt');
  await mkdir(dirname(marker), { recursive: true });
  await writeFile(marker, 'immutable-prior-artifact');
  await writeFile(join(directory, 'series.json'), JSON.stringify({
    schemaVersion: 1,
    iterations: [{ id: 'geometry-01', vector: [0, 0, 0, 0, 0] }],
    bestIteration: 'geometry-01'
  }));
  const result = await run(script('run-fidelity-loop.mjs'), [
    '--baseline', 'https://baseline.invalid/',
    '--candidate', 'https://candidate.invalid/',
    '--out', directory,
    '--iteration', 'geometry-01'
  ]);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Iteration already exists/);
  assert.equal(await readFile(marker, 'utf8'), 'immutable-prior-artifact');
  assert.deepEqual((await readdir(join(directory, 'iterations'))).sort(), ['geometry-01']);
});

test('scaffold-replica renders safe bind modes, public disclosure, and refuses overwrites', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-scaffold-'));
  const output = join(directory, 'authorized');
  const first = await run(script('scaffold-replica.mjs'), [
    '--out', output,
    '--name', 'synthetic-job-site',
    '--mode', 'authorized-local'
  ]);
  assert.equal(first.code, 0, first.stderr);
  const packageJson = JSON.parse(await readFile(join(output, 'package.json'), 'utf8'));
  assert.equal(packageJson.name, 'synthetic-job-site');
  const authorizedServer = await readFile(join(output, 'server.mjs'), 'utf8');
  const authorizedHtml = await readFile(join(output, 'public', 'index.html'), 'utf8');
  const authorizedManifest = JSON.parse(await readFile(join(output, 'replica.manifest.json'), 'utf8'));
  assert.doesNotMatch(authorizedServer, /\{\{(?:PROJECT_NAME|REPLICA_MODE)\}\}/);
  assert.match(authorizedServer, /const configuredReplicaMode = 'authorized-local';/);
  assert.match(authorizedServer, /replicaMode === 'authorized-local' \? '127\.0\.0\.1' : '0\.0\.0\.0'/);
  assert.match(authorizedHtml, /name="replica-mode" content="authorized-local"/);
  assert.equal(authorizedManifest.mode, 'authorized-local');
  assert.doesNotMatch(authorizedHtml, /replica-disclosure/);

  const owned = join(directory, 'owned');
  const ownedResult = await run(script('scaffold-replica.mjs'), ['--out', owned, '--mode', 'owned']);
  assert.equal(ownedResult.code, 0, ownedResult.stderr);
  assert.match(await readFile(join(owned, 'server.mjs'), 'utf8'), /const configuredReplicaMode = 'owned';/);
  assert.match(await readFile(join(owned, 'public', 'index.html'), 'utf8'), /name="replica-mode" content="owned"/);
  assert.equal(JSON.parse(await readFile(join(owned, 'replica.manifest.json'), 'utf8')).mode, 'owned');

  const publicSimulation = join(directory, 'public-simulation');
  const publicResult = await run(script('scaffold-replica.mjs'), [
    '--out', publicSimulation,
    '--mode', 'public-simulation'
  ]);
  assert.equal(publicResult.code, 0, publicResult.stderr);
  const publicServer = await readFile(join(publicSimulation, 'server.mjs'), 'utf8');
  const publicHtml = await readFile(join(publicSimulation, 'public', 'index.html'), 'utf8');
  assert.match(publicServer, /const configuredReplicaMode = 'public-simulation';/);
  assert.match(publicHtml, /name="replica-mode" content="public-simulation"/);
  assert.match(publicHtml, /class="replica-disclosure" data-replica-disclosure/);
  assert.match(publicHtml, /not the original website/i);
  assert.doesNotMatch(publicHtml, /\{\{DISCLOSURE_HTML\}\}/);
  assert.equal(JSON.parse(await readFile(join(publicSimulation, 'replica.manifest.json'), 'utf8')).mode, 'public-simulation');

  const second = await run(script('scaffold-replica.mjs'), ['--out', output]);
  assert.equal(second.code, 1);
  assert.match(second.stderr, /Refusing to overwrite/);

  const invalid = await run(script('scaffold-replica.mjs'), [
    '--out', join(directory, 'invalid'),
    '--mode', 'unknown'
  ]);
  assert.equal(invalid.code, 1);
  assert.match(invalid.stderr, /authorized-local, owned, or public-simulation/);
});

test('unrendered starter template fails closed to loopback mode', async () => {
  const template = await readFile(join(skillRoot, 'assets', 'replica-starter', 'server.mjs'), 'utf8');
  assert.match(template, /const configuredReplicaMode = '\{\{REPLICA_MODE\}\}';/);
  assert.match(template, /new Set\(\['authorized-local', 'owned', 'public-simulation'\]\)\.has\(configuredReplicaMode\)/);
  assert.match(template, /: 'authorized-local';/);
  assert.match(template, /replicaMode === 'authorized-local' \? '127\.0\.0\.1' : '0\.0\.0\.0'/);
});

test('scaffold-replica produces writable output from an immutable skill snapshot', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-readonly-skill-'));
  const frozenSkill = join(directory, 'skill');
  const output = join(directory, 'candidate');
  await cp(skillRoot, frozenSkill, { recursive: true });
  await chmodTree(frozenSkill, 0o555, 0o444);
  try {
    const result = await run(join(frozenSkill, 'scripts', 'scaffold-replica.mjs'), [
      '--out', output,
      '--name', 'immutable-skill-fixture'
    ]);
    assert.equal(result.code, 0, result.stderr);
    await writeFile(join(output, 'public', 'index.html'), '<!doctype html><title>writable</title>');
    assert.equal(JSON.parse(await readFile(join(output, 'package.json'), 'utf8')).name, 'immutable-skill-fixture');
  } finally {
    await chmodTree(frozenSkill, 0o755, 0o644);
    await rm(directory, { recursive: true, force: true });
  }
});

test('candidate integrity rejects every iframe, tiled raster shortcuts, and external form actions', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-integrity-'));
  const viewportDirectory = join(directory, 'desktop');
  const manifest = join(directory, 'replica.manifest.json');
  await mkdir(viewportDirectory, { recursive: true });
  await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
  await writeFile(join(directory, 'summary.json'), JSON.stringify({
    schemaVersion: 1,
    url: 'http://127.0.0.1:4173/',
    results: [{ viewport: { name: 'desktop', width: 1440, height: 1000 } }]
  }));
  await writeFile(join(viewportDirectory, 'contract.json'), JSON.stringify({
    schemaVersion: 1,
    viewport: { name: 'desktop', width: 1440, height: 1000 },
    contract: {
      page: {
        url: 'http://127.0.0.1:4173/',
        textLength: 500,
        replicaMode: 'authorized-local',
        geometry: { width: 1000, height: 1000 }
      },
      integrity: requiredIntegrity({
        iframeCount: 2,
        embeddedFrames: [
          { src: 'https://source.example/embed' },
          { src: 'https://unrelated.example/embed' }
        ],
        replicaSourceLinks: [
          { path: 'body > a', tag: 'a', hrefAttribute: 'https://source.example/job', xlinkHrefAttribute: null },
          { path: 'body > svg > a', tag: 'a', hrefAttribute: null, xlinkHrefAttribute: 'https://source.example/alternate' }
        ],
        baseElements: [
          { href: 'https://external-base.example/root/', hrefAttribute: 'https://external-base.example/root/', target: '' },
          { href: '', hrefAttribute: null, target: '_blank' }
        ],
        scripts: [{ src: 'https://failed-script.invalid/not-loaded.js', srcAttribute: 'https://failed-script.invalid/not-loaded.js', inline: false }],
        stylesheetLinks: [{ href: 'https://external-style.example/site.css', hrefAttribute: 'https://external-style.example/site.css' }],
        resourceTimingBufferSize: 2048,
        resourceTimingBufferFullEvents: 1,
        resourceTimingOverflow: true,
        rasterSurfaceCount: 120,
        rasterSurfacesTruncated: true,
        aggregateRasterDocumentCoverage: 0.9,
        aggregateRasterCoverageMethod: 'conservative-256x256-document-grid',
        rasterSurfaces: [
          { tag: 'svg-image', rect: { x: 0, y: 0, width: 100, height: 100 }, sources: ['/tile-1.png'] },
          { tag: 'video', rect: { x: 100, y: 0, width: 100, height: 100 }, sources: ['/tile-2.webm'] },
          { tag: 'background-image-set', rect: { x: 200, y: 0, width: 100, height: 100 }, sources: ['/tile-3.webp'] },
          { tag: 'img', rect: { x: 300, y: 0, width: 100, height: 100 }, sources: ['/tile-4.png'] }
        ]
      }),
      resources: [],
      forms: [{ action: 'https://source.example/submit' }],
      links: [
        { path: 'body > a.external', hrefAttribute: 'https://source.example/job', xlinkHrefAttribute: null },
        { path: 'body > a.script', hrefAttribute: 'javascript:alert(1)', xlinkHrefAttribute: null },
        { path: 'body > a.internal', href: 'http://127.0.0.1:4173/safe-details', hrefAttribute: '/safe-details', xlinkHrefAttribute: null },
        { path: 'body > a.base-resolved', href: 'https://external-base.example/safe-details', hrefAttribute: '/safe-details', xlinkHrefAttribute: null },
        { path: 'body > map > area', tag: 'area', href: 'https://external-map.example/target', hrefAttribute: 'https://external-map.example/target', xlinkHrefAttribute: null }
      ],
      controls: [
        {
          path: 'body > input.live-token',
          type: 'hidden',
          name: 'provider_token',
          hiddenValuePresent: true,
          hiddenValueLength: 24,
          hiddenValueClassification: 'unexpected-nonempty'
        },
        {
          path: 'body > input.synthetic-token',
          type: 'hidden',
          name: 'synthetic_provider_token',
          hiddenValuePresent: true,
          hiddenValueLength: 15,
          hiddenValueClassification: 'synthetic-local'
        },
        {
          path: 'body > form > button',
          type: 'submit',
          name: '',
          formActionAttribute: '/looks-local-under-external-base',
          formAction: 'https://external-base.example/looks-local-under-external-base',
          formMethodAttribute: 'get',
          formMethod: 'get',
          formEnctypeAttribute: null,
          formEnctype: '',
          formTargetAttribute: '_blank',
          formTarget: '_blank'
        }
      ],
      stylesheets: [],
      elements: []
    },
    telemetry: requiredTelemetry({
      failedGets: [{
        url: 'https://failed-dynamic-import.invalid/module.js',
        type: 'script',
        error: 'net::ERR_NAME_NOT_RESOLVED'
      }],
      externalReads: [{ method: 'GET', resourceType: 'script', url: 'https://failed-dynamic-import.invalid/module.js' }],
      externalReadCount: 2001,
      externalReadLimit: 2000,
      externalReadTypeCounts: { script: 2001 },
      externalReadsTruncated: true
    })
  }));
  const result = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory,
    '--source', 'https://source.example/job',
    '--manifest', manifest
  ]);
  assert.equal(result.code, 2);
  assert.match(result.stdout, /IFRAME_PRESENT/);
  assert.match(result.stdout, /SOURCE_IFRAME/);
  assert.match(result.stdout, /FULL_PAGE_RASTER_AGGREGATE/);
  assert.match(result.stdout, /"surfaceCount": 120/);
  assert.match(result.stdout, /EXTERNAL_FORM_ACTION/);
  assert.match(result.stdout, /SOURCE_LINK_NAVIGATION_TARGET/);
  assert.match(result.stdout, /EXTERNAL_LINK_TARGET/);
  assert.match(result.stdout, /UNSAFE_LINK_TARGET/);
  assert.match(result.stdout, /UNSAFE_HIDDEN_INPUT_VALUE/);
  assert.match(result.stdout, /EXTERNAL_BASE_HREF/);
  assert.match(result.stdout, /UNSAFE_FORM_SUBMISSION_OVERRIDE/);
  assert.match(result.stdout, /EXTERNAL_SCRIPT_SOURCE/);
  assert.match(result.stdout, /EXTERNAL_STYLESHEET_SOURCE/);
  assert.match(result.stdout, /RESOURCE_TIMING_BUFFER_OVERFLOW/);
  assert.match(result.stdout, /FAILED_GET_DEPENDENCY/);
  assert.match(result.stdout, /EXTERNAL_FAILED_GET_DEPENDENCY/);
  assert.match(result.stdout, /EXTERNAL_READ_DEPENDENCY/);
  assert.match(result.stdout, /EXTERNAL_READ_INVENTORY_TRUNCATED/);
});

test('candidate integrity fails closed on forged inspection artifacts and recomputes single-surface coverage', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-integrity-preflight-'));
  const viewportDirectory = join(directory, 'desktop');
  const manifest = join(directory, 'replica.manifest.json');
  const summaryPath = join(directory, 'summary.json');
  const contractPath = join(viewportDirectory, 'contract.json');
  const viewport = { name: 'desktop', width: 1440, height: 1000 };
  const summary = { schemaVersion: 1, url: 'http://127.0.0.1:4173/', results: [{ viewport }] };
  const validCapture = {
    schemaVersion: 1,
    viewport,
    telemetry: requiredTelemetry(),
    contract: {
      page: {
        url: 'http://127.0.0.1:4173/',
        replicaMode: 'authorized-local',
        textLength: 100,
        geometry: { width: 1000, height: 1000 }
      },
      integrity: requiredIntegrity({
        rasterSurfaceCount: 1,
        aggregateRasterDocumentCoverage: 0,
        rasterSurfaces: [{
          tag: 'img',
          documentCoverage: 0,
          viewportCoverage: 0,
          rect: { x: 0, y: 0, width: 1000, height: 1000 },
          sources: ['/forged-full-page.png']
        }]
      }),
      resources: [], forms: [], links: [], controls: [], stylesheets: [], elements: []
    }
  };
  await mkdir(viewportDirectory, { recursive: true });
  await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
  const common = ['--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest];

  await writeFile(summaryPath, JSON.stringify({ ...summary, results: [] }));
  const empty = await run(script('check-candidate-integrity.mjs'), common);
  assert.equal(empty.code, 1);
  assert.match(empty.stderr, /at least one viewport/);

  await writeFile(summaryPath, JSON.stringify(summary));
  await writeFile(contractPath, JSON.stringify({ schemaVersion: 1, viewport, contract: validCapture.contract }));
  const partial = await run(script('check-candidate-integrity.mjs'), common);
  assert.equal(partial.code, 1);
  assert.match(partial.stderr, /telemetry/);

  const outsideContract = join(directory, 'outside-contract.json');
  await writeFile(outsideContract, JSON.stringify(validCapture));
  await rm(contractPath, { force: true });
  await symlink(outsideContract, contractPath);
  const linked = await run(script('check-candidate-integrity.mjs'), common);
  assert.equal(linked.code, 1);
  assert.match(linked.stderr, /regular file, not a symlink/);

  await rm(contractPath, { force: true });
  await writeFile(contractPath, JSON.stringify(validCapture));
  validCapture.contract.integrity.rasterSurfaceCount = 2;
  await writeFile(contractPath, JSON.stringify(validCapture));
  const forgedRasterCount = await run(script('check-candidate-integrity.mjs'), common);
  assert.equal(forgedRasterCount.code, 1);
  assert.match(forgedRasterCount.stderr, /rasterSurfaceCount must equal the retained inventory/);

  validCapture.contract.integrity.rasterSurfaceCount = 1;
  validCapture.telemetry.externalReadCount = 1;
  await writeFile(contractPath, JSON.stringify(validCapture));
  const forgedExternalReadCount = await run(script('check-candidate-integrity.mjs'), common);
  assert.equal(forgedExternalReadCount.code, 1);
  assert.match(forgedExternalReadCount.stderr, /externalReadCount must equal the retained inventory/);

  validCapture.telemetry.externalReadCount = 0;
  await writeFile(contractPath, JSON.stringify(validCapture));
  const forgedRaster = await run(script('check-candidate-integrity.mjs'), common);
  assert.equal(forgedRaster.code, 2);
  assert.match(forgedRaster.stdout, /FULL_PAGE_RASTER/);
  assert.match(forgedRaster.stdout, /FULL_PAGE_RASTER_AGGREGATE/);
});

test('candidate integrity rejects cross-origin redirects and keeps the requested origin as its trust boundary', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-integrity-origin-'));
  const viewportDirectory = join(directory, 'desktop');
  const manifest = join(directory, 'replica.manifest.json');
  const requestedUrl = 'http://127.0.0.1:4173/requested';
  await mkdir(viewportDirectory, { recursive: true });
  await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
  await writeFile(join(directory, 'summary.json'), JSON.stringify({
    schemaVersion: 1,
    url: requestedUrl,
    results: [{ viewport: { name: 'desktop', width: 1440, height: 1000 } }]
  }));
  await writeFile(join(viewportDirectory, 'contract.json'), JSON.stringify({
    schemaVersion: 1,
    viewport: { name: 'desktop', width: 1440, height: 1000 },
    contract: {
      page: {
        url: 'https://redirected.example.test/final',
        replicaMode: 'authorized-local',
        geometry: { width: 1000, height: 1000 }
      },
      integrity: requiredIntegrity({
        cdpStructuralInventory: requiredCdpStructuralInventory({ formCount: 1, navigableLinkCount: 1 })
      }),
      resources: [{ name: 'http://127.0.0.1:4173/site.css', initiatorType: 'link' }],
      forms: [{
        action: 'http://127.0.0.1:4173/api/applications',
        method: 'post',
        enctype: 'multipart/form-data',
        targetAttribute: null
      }],
      links: [{ path: 'body > a', hrefAttribute: 'http://127.0.0.1:4173/details', xlinkHrefAttribute: null }],
      controls: [],
      stylesheets: [],
      elements: []
    },
    telemetry: requiredTelemetry()
  }));
  const result = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory,
    '--source', 'https://source.example/job',
    '--manifest', manifest
  ]);
  assert.equal(result.code, 2);
  const report = JSON.parse(result.stdout);
  const codes = report.results[0].failures.map((failure) => failure.code);
  assert.deepEqual(codes, ['CANDIDATE_CROSS_ORIGIN_REDIRECT']);
  assert.equal(report.results[0].evidence.externalResourceCount, 0);
  assert.equal(report.results[0].evidence.externalFormCount, 0);
  assert.equal(report.results[0].evidence.externalLinkTargetCount, 0);
});

test('candidate integrity allows a declared external stylesheet only with the explicit asset option', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-integrity-stylesheet-'));
  const viewportDirectory = join(directory, 'desktop');
  const manifest = join(directory, 'replica.manifest.json');
  await mkdir(viewportDirectory, { recursive: true });
  await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
  await writeFile(join(directory, 'summary.json'), JSON.stringify({
    schemaVersion: 1,
    url: 'http://127.0.0.1:4173/',
    results: [{ viewport: { name: 'desktop', width: 1440, height: 1000 } }]
  }));
  const inspectionCapture = {
    schemaVersion: 1,
    viewport: { name: 'desktop', width: 1440, height: 1000 },
    contract: {
      page: { url: 'http://127.0.0.1:4173/', replicaMode: 'authorized-local', geometry: { width: 100, height: 100 } },
      integrity: requiredIntegrity({
        stylesheetLinks: [{ href: 'https://assets.example.test/site.css', hrefAttribute: 'https://assets.example.test/site.css' }],
        cdpStructuralInventory: requiredCdpStructuralInventory({
          stylesheetLinkCount: 1,
          externalStylesheetCount: 1
        })
      }),
      resources: [{
        name: 'https://assets.example.test/jobs/bdcfb29f-4f27-42de-933f-7f83a359b9f0/badge.png',
        initiatorType: 'img'
      }],
      forms: [], links: [], controls: [], stylesheets: [], elements: []
    },
    telemetry: requiredTelemetry()
  };
  await writeFile(join(viewportDirectory, 'contract.json'), JSON.stringify(inspectionCapture));
  const common = ['--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest];
  const rejected = await run(script('check-candidate-integrity.mjs'), common);
  assert.equal(rejected.code, 2);
  assert.match(rejected.stdout, /EXTERNAL_STYLESHEET_SOURCE/);
  const accepted = await run(script('check-candidate-integrity.mjs'), [...common, '--allow-external-assets']);
  assert.equal(accepted.code, 0, accepted.stderr || accepted.stdout);

  const pathSecret = 'RESET_ASSET_PATH_DO_NOT_COPY_48be3caa7e';
  const emailPathSecret = 'applicant-integrity-48be3caa7e@example.test';
  inspectionCapture.contract.resources.push({
    name: `https://assets.example.test/avatars/${emailPathSecret}.png`,
    initiatorType: 'img'
  });
  inspectionCapture.telemetry = requiredTelemetry({
    externalReads: [{
      method: 'GET',
      resourceType: 'stylesheet',
      url: `https://assets.example.test/password-reset/${pathSecret}/theme.css`
    }],
    externalReadCount: 1,
    externalReadTypeCounts: { stylesheet: 1 }
  });
  await writeFile(join(viewportDirectory, 'contract.json'), JSON.stringify(inspectionCapture));
  const credentialBearing = await run(
    script('check-candidate-integrity.mjs'),
    [...common, '--allow-external-assets']
  );
  assert.equal(credentialBearing.code, 2);
  assert.match(credentialBearing.stdout, /CREDENTIAL_LIKE_EXTERNAL_ASSET_URL/);
  assert.equal(credentialBearing.stdout.includes(pathSecret), false,
    'integrity diagnostics must not retain a credential-bearing asset path');
  assert.equal(credentialBearing.stdout.includes(emailPathSecret), false,
    'integrity diagnostics must not retain a PII-bearing asset path');
});

test('authorized-local mode is rejected on a non-loopback requested candidate origin', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-integrity-public-authorized-local-'));
  const viewportDirectory = join(directory, 'desktop');
  const manifest = join(directory, 'replica.manifest.json');
  await mkdir(viewportDirectory, { recursive: true });
  await writeFile(manifest, JSON.stringify(integrityManifest('authorized-local')));
  await writeFile(join(directory, 'summary.json'), JSON.stringify({
    schemaVersion: 1,
    url: 'https://candidate.example.test/',
    results: [{ viewport: { name: 'desktop', width: 1440, height: 1000 } }]
  }));
  await writeFile(join(viewportDirectory, 'contract.json'), JSON.stringify({
    schemaVersion: 1,
    viewport: { name: 'desktop', width: 1440, height: 1000 },
    contract: {
      page: { url: 'https://candidate.example.test/', replicaMode: 'authorized-local', geometry: { width: 100, height: 100 } },
      integrity: requiredIntegrity(),
      resources: [], forms: [], links: [], controls: [], stylesheets: [], elements: []
    },
    telemetry: requiredTelemetry()
  }));
  const result = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest
  ]);
  assert.equal(result.code, 2);
  assert.match(result.stdout, /AUTHORIZED_LOCAL_PUBLIC_ORIGIN/);
});

test('public-simulation integrity requires matching metadata and a visible disclosure', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-public-integrity-'));
  const viewportDirectory = join(directory, 'desktop');
  const manifest = join(directory, 'replica.manifest.json');
  await mkdir(viewportDirectory, { recursive: true });
  await writeFile(manifest, JSON.stringify(integrityManifest('public-simulation')));
  await writeFile(join(directory, 'summary.json'), JSON.stringify({
    schemaVersion: 1,
    url: 'http://127.0.0.1:4173/',
    results: [{ viewport: { name: 'desktop', width: 1440, height: 1000 } }]
  }));
  const contractPath = join(viewportDirectory, 'contract.json');
  const contract = {
    schemaVersion: 1,
    viewport: { name: 'desktop', width: 1440, height: 1000 },
    contract: {
      page: {
        url: 'http://127.0.0.1:4173/',
        replicaMode: 'public-simulation',
        geometry: { width: 1000, height: 1000 }
      },
      integrity: requiredIntegrity({
        disclosures: [],
        scripts: [{
          src: 'http://127.0.0.1:4173/app.js',
          srcAttribute: '/app.js',
          type: '',
          inline: false,
          textLength: 0
        }],
        cdpStructuralInventory: requiredCdpStructuralInventory({ navigableLinkCount: 1, scriptCount: 1 }),
        scriptResponseInventory: requiredScriptResponseInventory({
          responseCount: 1,
          retainedCount: 1,
          declaredBodyBytesRead: 100,
          responses: [{
            url: 'http://127.0.0.1:4173/app.js',
            sameOrigin: true,
            pathname: '/app.js',
            searchPresent: false,
            hashPresent: false,
            status: 200,
            contentType: 'text/javascript',
            contentLengthPresent: true,
            declaredBodyBytes: 100,
            contentEncodingPresent: false,
            bodyRead: true,
            bodyWithinLimit: true,
            sha256: bundledStarterAppSha256,
            matchesBundledStarterApp: true
          }]
        }),
        executableStyleInitialQuiescence: requiredExecutableStyleQuiescence({
          started: { script: 1, stylesheet: 0 },
          finished: { script: 1, stylesheet: 0 }
        }),
        executableStylePostSettleQuiescence: requiredExecutableStyleQuiescence({
          started: { script: 1, stylesheet: 0 },
          finished: { script: 1, stylesheet: 0 }
        }),
        executableStyleFinalQuiescence: requiredExecutableStyleQuiescence({
          started: { script: 1, stylesheet: 0 },
          finished: { script: 1, stylesheet: 0 }
        }),
        executableStyleTerminalSnapshot: requiredExecutableStyleSnapshot({
          started: { script: 1, stylesheet: 0 },
          finished: { script: 1, stylesheet: 0 }
        })
      }),
      resources: [],
      forms: [],
      links: [{ path: 'body > a', hrefAttribute: '/safe-details', xlinkHrefAttribute: null }],
      controls: [
        {
          path: 'body > input.synthetic-token',
          type: 'hidden',
          name: 'provider_token',
          hiddenValuePresent: true,
          hiddenValueLength: 15,
          hiddenValueClassification: 'synthetic-local'
        },
        {
          path: 'body > input.empty-token',
          type: 'hidden',
          name: 'empty_token',
          hiddenValuePresent: false,
          hiddenValueLength: 0,
          hiddenValueClassification: 'empty'
        }
      ],
      stylesheets: [],
      elements: []
    },
    telemetry: requiredTelemetry()
  };
  await writeFile(contractPath, JSON.stringify(contract));
  const sourceSecret = 'INTEGRITY_SOURCE_SECRET_13b74402';
  const unsafeSource = `https://source.example/job?redirect=${encodeURIComponent(`https://cdn.example/a?access_token=${sourceSecret}`)}`;
  const unsafeOutput = join(directory, 'unsafe-source-report.json');
  const unsafe = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory, '--source', unsafeSource, '--manifest', manifest, '--out', unsafeOutput
  ]);
  assert.equal(unsafe.code, 1);
  assert.doesNotMatch(`${unsafe.stdout}${unsafe.stderr}`, new RegExp(sourceSecret));
  await assert.rejects(readFile(unsafeOutput));

  const missing = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest
  ]);
  assert.equal(missing.code, 2);
  assert.match(missing.stdout, /PUBLIC_DISCLOSURE_MISSING/);

  const disclosureEvidence = (text) => ({
    path: 'body > aside', text, visible: true, position: 'sticky',
    visibleAtStart: true, visibleAtDocumentEnd: true,
    unoccludedAtStart: true, unoccludedAtDocumentEnd: true,
    innerTextAtStart: text, innerTextAtDocumentEnd: text,
    geometricVisibleTextAtStart: text, geometricVisibleTextAtDocumentEnd: text,
    visibleTextAtStart: text, visibleTextAtDocumentEnd: text,
    visibleAfterDelay: true, unoccludedAfterDelay: true,
    innerTextAfterDelay: text, geometricVisibleTextAfterDelay: text, visibleTextAfterDelay: text,
    persistent: true
  });
  for (const misleadingCopy of [
    'Simulation replica for recruiting.',
    'Official simulation — independent replica of the original website.'
  ]) {
    contract.contract.integrity.disclosures = [disclosureEvidence(misleadingCopy)];
    await writeFile(contractPath, JSON.stringify(contract));
    const misleading = await run(script('check-candidate-integrity.mjs'), [
      '--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest
    ]);
    assert.equal(misleading.code, 2);
    assert.match(misleading.stdout, /PUBLIC_DISCLOSURE_MISSING/);
  }

  contract.contract.integrity.disclosures = [disclosureEvidence('Simulation — this is not the original website.')];
  contract.contract.integrity.cdpStructuralInventory.disclosureCount = 1;
  contract.contract.integrity.preFreezeDisclosureState.disclosureCount = 1;
  contract.contract.integrity.preFreezeDisclosureState.entries = [{
    ordinal: 0,
    inspectedAncestorCount: 3,
    animationRisk: false,
    transitionRisk: false,
    pseudoElementOpaqueOverlayRisk: false
  }];
  const mediaVariants = [
    ['light-reduce-dpr1', 'light', 'reduce', 1],
    ['dark-reduce-dpr1', 'dark', 'reduce', 1],
    ['light-no-preference-dpr1', 'light', 'no-preference', 1],
    ['dark-no-preference-dpr1', 'dark', 'no-preference', 1],
    ['light-reduce-dpr2', 'light', 'reduce', 2],
    ['dark-reduce-dpr2', 'dark', 'reduce', 2],
    ['light-no-preference-dpr2', 'light', 'no-preference', 2],
    ['dark-no-preference-dpr2', 'dark', 'no-preference', 2]
  ];
  contract.contract.integrity.publicDisclosureMediaMatrix = {
    requiredVariantCount: 8,
    sampleDelayMs: 40,
    completed: true,
    navigationCount: 0,
    urlChanged: false,
    entries: mediaVariants.map(([name, colorScheme, reducedMotion, deviceScaleFactor]) => ({
      variant: { name, colorScheme, reducedMotion, deviceScaleFactor },
      environment: { colorScheme, reducedMotion, deviceScaleFactor },
      quiescence: requiredExecutableStyleQuiescence({
        started: { script: 1, stylesheet: 0 },
        finished: { script: 1, stylesheet: 0 }
      }),
      preFreeze: {
        disclosureCount: 1,
        entries: [],
        animationRiskCount: 0,
        transitionRiskCount: 0,
        pseudoElementOpaqueOverlayRiskCount: 0
      },
      disclosures: [disclosureEvidence('Simulation — this is not the original website.')],
      completed: true
    }))
  };
  await writeFile(contractPath, JSON.stringify(contract));
  const unprotected = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest
  ]);
  assert.equal(unprotected.code, 2);
  assert.match(unprotected.stdout, /PUBLIC_RESPONSE_CSP_MISSING_OR_UNSAFE/);
  assert.match(unprotected.stdout, /PUBLIC_X_FRAME_OPTIONS_MISSING_OR_UNSAFE/);

  contract.contract.integrity.mainResponseSecurityHeaders = {
    contentSecurityPolicy: {
      present: true,
      length: 160,
      overLimit: false,
      policyLimitReached: false,
      policies: [{
        scriptSrc: { present: true, duplicate: false, mode: 'other' },
        scriptSrcElem: { present: false, duplicate: false, mode: 'missing' },
        scriptSrcAttr: { present: false, duplicate: false, mode: 'missing' },
        connectSrc: { present: true, duplicate: false, mode: 'self' },
        formAction: { present: true, duplicate: false, mode: 'self' },
        objectSrc: { present: true, duplicate: false, mode: 'none' },
        frameAncestors: { present: true, duplicate: false, mode: 'none' }
      }]
    },
    xFrameOptions: { present: true, disposition: 'deny' },
    refresh: { present: false, length: 0, hasUrlDirective: false }
  };
  await writeFile(contractPath, JSON.stringify(contract));
  const unsafeCsp = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest
  ]);
  assert.equal(unsafeCsp.code, 2);
  assert.match(unsafeCsp.stdout, /PUBLIC_RESPONSE_CSP_MISSING_OR_UNSAFE/);

  contract.contract.integrity.mainResponseSecurityHeaders.contentSecurityPolicy.policies[0].scriptSrc.mode = 'self';
  await writeFile(contractPath, JSON.stringify(contract));
  const passing = await run(script('check-candidate-integrity.mjs'), [
    '--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest
  ]);
  assert.equal(passing.code, 0, passing.stderr || passing.stdout);

  const expectPublicFailure = async (code) => {
    await writeFile(contractPath, JSON.stringify(contract));
    const result = await run(script('check-candidate-integrity.mjs'), [
      '--inspection', directory, '--source', 'https://source.example/job', '--manifest', manifest
    ]);
    assert.equal(result.code, 2);
    assert.match(result.stdout, new RegExp(code));
  };
  contract.contract.integrity.mainResponseSecurityHeaders.refresh = { present: true, length: 22, hasUrlDirective: true };
  await expectPublicFailure('MAIN_RESPONSE_REFRESH_PRESENT');
  contract.contract.integrity.mainResponseSecurityHeaders.refresh = { present: false, length: 0, hasUrlDirective: false };

  contract.contract.integrity.metaRefreshElements = [{ contentPresent: true, contentLength: 18, hasUrlDirective: true }];
  contract.contract.integrity.cdpStructuralInventory.metaRefreshCount = 1;
  await expectPublicFailure('META_REFRESH_PRESENT');
  contract.contract.integrity.metaRefreshElements = [];
  contract.contract.integrity.cdpStructuralInventory.metaRefreshCount = 0;

  contract.contract.integrity.scripts = [{ src: '', srcAttribute: null, type: '', inline: true, textLength: 20 }];
  contract.contract.integrity.cdpStructuralInventory.scriptCount = 1;
  contract.contract.integrity.cdpStructuralInventory.inlineScriptCount = 1;
  await expectPublicFailure('PUBLIC_INLINE_SCRIPT_PRESENT');
  contract.contract.integrity.scripts = [];
  contract.contract.integrity.cdpStructuralInventory.scriptCount = 0;
  contract.contract.integrity.cdpStructuralInventory.inlineScriptCount = 0;

  const exactScript = contract.contract.integrity.scriptResponseInventory.responses[0];
  exactScript.sha256 = '0'.repeat(64);
  exactScript.matchesBundledStarterApp = false;
  await expectPublicFailure('PUBLIC_SCRIPT_RESPONSE_NOT_EXACT_STARTER');
  exactScript.sha256 = bundledStarterAppSha256;
  exactScript.matchesBundledStarterApp = true;

  contract.contract.integrity.preFreezeDisclosureState.animationRiskCount = 1;
  contract.contract.integrity.preFreezeDisclosureState.entries[0].animationRisk = true;
  await expectPublicFailure('PUBLIC_DISCLOSURE_DYNAMIC_VISIBILITY_RISK');
  contract.contract.integrity.preFreezeDisclosureState.animationRiskCount = 0;
  contract.contract.integrity.preFreezeDisclosureState.entries[0].animationRisk = false;

  contract.contract.integrity.preFreezeDisclosureState.pseudoElementOpaqueOverlayRiskCount = 1;
  contract.contract.integrity.preFreezeDisclosureState.entries[0].pseudoElementOpaqueOverlayRisk = true;
  await expectPublicFailure('PUBLIC_DISCLOSURE_PSEUDO_OVERLAY_RISK');
  contract.contract.integrity.preFreezeDisclosureState.pseudoElementOpaqueOverlayRiskCount = 0;
  contract.contract.integrity.preFreezeDisclosureState.entries[0].pseudoElementOpaqueOverlayRisk = false;

  contract.contract.integrity.delayedPersistenceNavigation.navigationCount = 1;
  await expectPublicFailure('PUBLIC_DELAYED_PERSISTENCE_NAVIGATION_RISK');
  contract.contract.integrity.delayedPersistenceNavigation.navigationCount = 0;

  const safeDisclosure = contract.contract.integrity.disclosures[0];
  for (const field of ['text', 'innerTextAtStart', 'innerTextAtDocumentEnd', 'innerTextAfterDelay']) {
    safeDisclosure[field] = 'Simulation — this is not the original website. This is the official authentic careers site.';
  }
  await expectPublicFailure('PUBLIC_DISCLOSURE_CONTRADICTORY_AUTHENTICITY');
});

test('network safety allows only the declared private origin and rejects mapped loopback forms', async () => {
  const hostIsPrivate = createPrivateHostChecker();
  assert.equal(await hostIsPrivate('127.0.0.1'), true);
  assert.equal(await hostIsPrivate('::ffff:7f00:1'), true);
  assert.equal(await hostIsPrivate('::ffff:127.0.0.1'), true);
  assert.equal(await hostIsPrivate('::7f00:1'), true);
  assert.equal(await hostIsPrivate('::127.0.0.1'), true);
  assert.equal(await hostIsPrivate('fec0::1'), true, 'deprecated IPv6 site-local space must stay private');
  assert.equal(await hostIsPrivate('feff::1'), true, 'the full fec0::/10 site-local range must stay private');
  assert.equal(await hostIsPrivate('2001:4860:4860::8888'), false);
  assert.equal(await hostIsPrivate('93.184.216.34'), false);
  assert.equal(isLoopbackHostname('127.99.2.3'), true);
  assert.equal(isLoopbackHostname('::ffff:7f00:1'), true);
  assert.equal(isLoopbackHostname('localhost'), true);
  assert.equal(isLoopbackHostname('93.184.216.34'), false);
  assert.equal(isLoopbackHostname('fec0::1'), false);
  assert.equal(await blocksPrivateDestination('http://127.0.0.1:4100/a', 'http://127.0.0.1:4100', hostIsPrivate), false);
  assert.equal(await blocksPrivateDestination('http://127.0.0.1:4200/a', 'http://127.0.0.1:4100', hostIsPrivate), true);
  assert.equal(await blocksPrivateDestination('http://user:password@127.0.0.1:4100/a', 'http://127.0.0.1:4100', hostIsPrivate), true);
  assert.equal(await blocksPrivateDestination('file:///tmp/private', 'http://127.0.0.1:4100', hostIsPrivate), true);
  assert.equal(blocksUnsafeDestinationBeforeProxy('http://127.0.0.1:4100/a', 'http://127.0.0.1:4100'), false);
  assert.equal(blocksUnsafeDestinationBeforeProxy('http://127.0.0.1:4200/a', 'http://127.0.0.1:4100'), true);
  assert.equal(blocksUnsafeDestinationBeforeProxy('https://public.example/a', 'https://source.example'), false);
  assert.equal(blocksUnsafeDestinationBeforeProxy('https://metadata.internal/a', 'https://source.example'), true);
  assert.equal(blocksUnsafeDestinationBeforeProxy('https://user:password@public.example/a', 'https://source.example'), true);
});

test('network safety does not trust a public declared origin or cache public DNS answers', async () => {
  let sameOriginChecks = 0;
  const publicOriginReboundPrivate = await blocksPrivateDestination(
    'https://public.example/job',
    'https://public.example',
    async () => {
      sameOriginChecks += 1;
      return true;
    }
  );
  assert.equal(publicOriginReboundPrivate, true);
  assert.equal(sameOriginChecks, 1, 'a public same-origin URL must still pass through DNS safety checks');

  let resolverCalls = 0;
  const hostIsPrivate = createPrivateHostChecker({
    resolver: async () => {
      resolverCalls += 1;
      return resolverCalls === 1
        ? [{ address: '93.184.216.34', family: 4 }]
        : [{ address: '127.0.0.1', family: 4 }];
    }
  });
  assert.equal(await hostIsPrivate('rebind.example'), false);
  assert.equal(await hostIsPrivate('rebind.example'), true);
  assert.equal(resolverCalls, 2, 'public DNS results must never be cached across requests');
  assert.equal(isPrivateOrReservedAddress('192.0.2.1'), true);
  assert.equal(isPrivateOrReservedAddress('2001:db8::1'), true);
});

test('public resolver bypasses only exclusive 198.18/15 fake-IP DNS answers', async () => {
  let fallbackCalls = 0;
  const fakeIpResolver = createPublicHostResolver({
    systemResolver: async () => [
      { address: '198.18.3.79', family: 4 },
      { address: '198.19.255.254', family: 4 }
    ],
    dohResolver: async () => {
      fallbackCalls += 1;
      return [
        { address: '93.184.216.34', family: 4 },
        { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 }
      ];
    }
  });
  assert.deepEqual(await fakeIpResolver('public.example', { all: true }), [
    { address: '93.184.216.34', family: 4 },
    { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 }
  ]);
  assert.equal(fallbackCalls, 1);

  const mixedAnswers = [
    { address: '198.18.3.79', family: 4 },
    { address: '127.0.0.1', family: 4 }
  ];
  const mixedResolver = createPublicHostResolver({
    systemResolver: async () => mixedAnswers,
    dohResolver: async () => {
      fallbackCalls += 1;
      return [{ address: '93.184.216.34', family: 4 }];
    }
  });
  assert.deepEqual(await mixedResolver('rebind.example', { all: true }), mixedAnswers);
  assert.equal(fallbackCalls, 1, 'mixed or genuinely private system answers must never invoke the fallback');

  const ordinaryAnswers = [{ address: '93.184.216.34', family: 4 }];
  const ordinaryResolver = createPublicHostResolver({
    systemResolver: async () => ordinaryAnswers,
    dohResolver: async () => {
      fallbackCalls += 1;
      return [{ address: '203.0.113.1', family: 4 }];
    }
  });
  assert.deepEqual(await ordinaryResolver('ordinary.example', { all: true }), ordinaryAnswers);
  assert.equal(fallbackCalls, 1, 'ordinary public system DNS answers must be used directly');

  let fakeCalls = 0;
  const noCaching = createPublicHostResolver({
    systemResolver: async () => {
      fakeCalls += 1;
      return [{ address: '198.18.0.1', family: 4 }];
    },
    dohResolver: async () => [{ address: '93.184.216.34', family: 4 }]
  });
  await noCaching('fresh.example', { all: true });
  await noCaching('fresh.example', { all: true });
  assert.equal(fakeCalls, 2, 'the fallback resolver must not cache answers across connections');

  let nonPublicResolutionCalls = 0;
  const nonPublicResolver = createPublicHostResolver({
    systemResolver: async () => {
      nonPublicResolutionCalls += 1;
      return [{ address: '198.18.0.1', family: 4 }];
    },
    dohResolver: async () => {
      nonPublicResolutionCalls += 1;
      return [{ address: '93.184.216.34', family: 4 }];
    }
  });
  for (const hostname of ['payroll', 'payroll.corp', 'files.lan', 'router.home', 'service.home.arpa']) {
    await assert.rejects(nonPublicResolver(hostname, { all: true }), /Non-public hostnames/);
  }
  assert.equal(nonPublicResolutionCalls, 0, 'split-DNS hostnames must never be disclosed to system or public resolvers');
});

test('capture URL validation rejects credentials while reports redact nested signed resource URLs', () => {
  for (const url of [
    'https://user:password@example.test/job',
    'https://example.test/job?X-Amz-Credential=live-secret',
    'https://example.test/job#access_token=live-secret'
  ]) {
    assert.throws(() => assertSafeHttpUrl(url, 'fixture'), /credentials|sensitive query|credential-like fragment/i);
  }
  assert.doesNotThrow(() => assertSafeHttpUrl('https://example.test/job?gh_jid=123#job-description', 'fixture'));
  assert.doesNotThrow(() => assertSafeHttpUrl(
    'https://jobs.example.test/palantir/bdcfb29f-4f27-42de-933f-7f83a359b9f0/apply',
    'fixture'
  ));

  const pathSecrets = [
    'RESET_PATH_SECRET_1234567890',
    'INVITE_PATH_SECRET_0987654321',
    'sk-livepathsecret1234567890',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl'
  ];
  const sensitivePathUrls = [
    `https://example.test/password-reset/${pathSecrets[0]}`,
    `https://example.test/invite/${pathSecrets[1]}`,
    `https://example.test/assets/${pathSecrets[2]}`,
    `https://example.test/callback/${pathSecrets[3]}`
  ];
  for (let index = 0; index < sensitivePathUrls.length; index += 1) {
    assert.throws(() => assertSafeHttpUrl(sensitivePathUrls[index], 'fixture'), /path|token|credential/i);
    assert.doesNotMatch(redactSensitiveUrl(sensitivePathUrls[index]), new RegExp(pathSecrets[index].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  const piiSecrets = {
    email: 'applicant.private+fixture@example.test',
    phone: '+14155552671',
    formattedPhone: '(415) 555-2671',
    firstName: 'PII_FIRSTNAME_7e51',
    address: 'PII_ADDRESS_29b4'
  };
  for (const piiUrl of [
    `https://example.test/apply/${encodeURIComponent(piiSecrets.email)}`,
    `https://example.test/apply?q=${encodeURIComponent(piiSecrets.email)}`,
    `https://example.test/apply?q=${encodeURIComponent(piiSecrets.phone)}`
  ]) {
    assert.throws(() => assertSafeHttpUrl(piiUrl, 'fixture'), /email|phone|personal data/i);
    const redactedPiiUrl = redactSensitiveUrl(piiUrl);
    assert.doesNotMatch(redactedPiiUrl, /applicant\.private|14155552671/i);
  }
  const piiReport = JSON.stringify(redactReportData({
    warning: `Applicant ${piiSecrets.email}, ${piiSecrets.formattedPhone}`,
    applicant: {
      email: piiSecrets.email,
      phoneNumber: piiSecrets.phone,
      firstName: piiSecrets.firstName,
      address: piiSecrets.address
    }
  }));
  for (const pii of Object.values(piiSecrets)) {
    assert.doesNotMatch(piiReport, new RegExp(pii.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  const nestedSecret = 'NESTEDSECRET123';
  const nestedUrl = `https://example.test/job?redirect=${encodeURIComponent(`https://cdn.test/a?access_token=${nestedSecret}`)}`;
  assert.throws(() => assertSafeHttpUrl(nestedUrl, 'fixture'), /nested|credential|sensitive query/i);
  assert.doesNotMatch(JSON.stringify(redactReportData({ url: nestedUrl })), new RegExp(nestedSecret));

  const embeddedSecret = 'EMBEDDED_USERINFO_SECRET_456';
  for (const embeddedValue of [
    `go to https://user:${embeddedSecret}@cdn.test/path`,
    `prefix //user:${embeddedSecret}@cdn.test/path`,
    `inspect https://cdn.test/path?access_token=${embeddedSecret}`
  ]) {
    const embeddedUrl = `https://example.test/job?note=${encodeURIComponent(embeddedValue)}`;
    assert.throws(() => assertSafeHttpUrl(embeddedUrl, 'fixture'), /embedded|credential|sensitive query|email address/i);
    assert.doesNotMatch(redactSensitiveUrl(embeddedUrl), new RegExp(embeddedSecret));
  }
  const embeddedUrlOverflow = `https://example.test/job?note=${encodeURIComponent(
    Array.from({ length: 51 }, (_, index) => `https://safe${index}.example.test/path`).join(' ')
  )}`;
  assert.throws(() => assertSafeHttpUrl(embeddedUrlOverflow, 'fixture'), /too many embedded URLs/i);
  assert.match(redactSensitiveUrl(embeddedUrlOverflow), /REDACTED/);

  const overlongPlainSecret = 'OVERLONG_PLAINTEXT_SECRET_123';
  const overlongPlainUrl = `https://example.test/job?config=${'x'.repeat(17000)} password=${overlongPlainSecret}`;
  assert.throws(() => assertSafeHttpUrl(overlongPlainUrl, 'fixture'), /overlong value/i);
  assert.doesNotMatch(redactSensitiveUrl(overlongPlainUrl), new RegExp(overlongPlainSecret));

  const doubleEncodedSecret = 'DOUBLESECRET123';
  for (const encodedUrl of [
    `https://example.test/job?%2570assword=${doubleEncodedSecret}`,
    `https://example.test/job?%2561pi_key=${doubleEncodedSecret}`,
    `https://example.test/job#%2570assword%253D${doubleEncodedSecret}`
  ]) {
    assert.throws(() => assertSafeHttpUrl(encodedUrl, 'fixture'), /sensitive query|credential-like fragment/i);
    assert.doesNotMatch(JSON.stringify(redactReportData({ url: encodedUrl })), new RegExp(doubleEncodedSecret));
  }

  const carrierSecret = 'opaque123XYZ';
  let overEncodedName = '%70assword';
  for (let index = 0; index < 6; index += 1) overEncodedName = encodeURIComponent(overEncodedName);
  let overEncodedFragment = `password=${carrierSecret}`;
  for (let index = 0; index < 6; index += 1) overEncodedFragment = encodeURIComponent(overEncodedFragment);
  let overEncodedNested = `https://cdn.test/a?token=${carrierSecret}`;
  for (let index = 0; index < 6; index += 1) overEncodedNested = encodeURIComponent(overEncodedNested);
  const credentialCarriers = [
    `https://example.test/job?password[]=${carrierSecret}`,
    `https://example.test/job?user[password]=${carrierSecret}`,
    `https://example.test/job?auth[token]=${carrierSecret}`,
    `https://example.test/job?password:raw=${carrierSecret}`,
    `https://example.test/job?password/raw=${carrierSecret}`,
    `https://example.test/job?password%00=${carrierSecret}`,
    `https://example.test/job?clientSecret=${carrierSecret}`,
    `https://example.test/job?refreshToken=${carrierSecret}`,
    `https://example.test/job?idToken=${carrierSecret}`,
    `https://example.test/job?csrfToken=${carrierSecret}`,
    `https://example.test/job?passwordResetToken=${carrierSecret}`,
    `https://example.test/job?sessionId=${carrierSecret}`,
    `https://example.test/job?samlResponse=${carrierSecret}`,
    `https://example.test/job?config=${encodeURIComponent(JSON.stringify({ token: carrierSecret }))}`,
    `https://example.test/job#clientSecret=${carrierSecret}`,
    `https://example.test/job#${encodeURIComponent(JSON.stringify({ password: carrierSecret }))}`,
    `https://example.test/job?redirect=${encodeURIComponent(`//user:${carrierSecret}@cdn.test/path`)}`,
    `https://example.test/job?${overEncodedName}=${carrierSecret}`,
    `https://example.test/job#${overEncodedFragment}`,
    `https://example.test/job?redirect=${overEncodedNested}`
  ];
  for (const encodedUrl of credentialCarriers) {
    assert.throws(() => assertSafeHttpUrl(encodedUrl, 'fixture'), /credential|sensitive|encoding|nested|email address/i);
    assert.doesNotMatch(redactSensitiveUrl(encodedUrl), new RegExp(carrierSecret));
  }

  const signed = 'https://user:password@cdn.example.test/asset.svg?view=full&X-Amz-Credential=live-secret#access_token=fragment-secret';
  const redacted = redactSensitiveUrl(signed);
  assert.match(redacted, /view=full/);
  assert.doesNotMatch(redacted, /user|password|live-secret|fragment-secret|access_token/);
  const report = redactReportData({
    resource: signed,
    warning: `Resource failed: ${signed}`,
    nested: [{ ordinary: 'https://example.test/job?gh_jid=123' }]
  });
  assert.doesNotMatch(JSON.stringify(report), /password|live-secret|fragment-secret|access_token/);
  assert.match(report.nested[0].ordinary, /gh_jid=123/);

  const diagnosticSecrets = {
    password: 'DIAGNOSTIC_PASSWORD_2197d30d',
    passwordWords: 'correct horse battery staple',
    apiKeyWords: 'opaque secret words',
    bearer: 'DIAGNOSTIC_BEARER_36f165e8',
    basic: 'DIAGNOSTIC_BASIC_8c63e8dc',
    cookie: 'DIAGNOSTIC_COOKIE_028c93ac',
    object: 'DIAGNOSTIC_OBJECT_SECRET_fad66f92'
  };
  const diagnostics = redactReportData({
    warning: `ordinary warning remains; password=${diagnosticSecrets.password}`,
    multilineDiagnostic: `password = ${diagnosticSecrets.passwordWords}\nordinary second line remains`,
    assignmentDiagnostic: `api_key = ${diagnosticSecrets.apiKeyWords}; ordinary tail remains`,
    authDiagnostic: `Authorization: Bearer ${diagnosticSecrets.bearer}`,
    basicAuthDiagnostic: `Authorization Basic ${diagnosticSecrets.basic}`,
    requestDiagnostic: `Cookie: session=${diagnosticSecrets.cookie}; theme=light`,
    responseDiagnostic: `Set-Cookie: session=${diagnosticSecrets.cookie}; Path=/; HttpOnly`,
    nested: { accessToken: diagnosticSecrets.object },
    ordinary: 'Cookie policy warning and tokenization diagnostic remain readable.'
  });
  const diagnosticsText = JSON.stringify(diagnostics);
  for (const secret of Object.values(diagnosticSecrets)) assert.doesNotMatch(diagnosticsText, new RegExp(secret));
  assert.match(diagnostics.warning, /ordinary warning remains/);
  assert.match(diagnostics.multilineDiagnostic, /ordinary second line remains/);
  assert.match(diagnostics.assignmentDiagnostic, /ordinary tail remains/);
  assert.equal(diagnostics.ordinary, 'Cookie policy warning and tokenization diagnostic remain readable.');
  assert.match(diagnosticsText, /REDACTED/);
  const machineCodes = redactReportData({
    failure: { code: 'SOURCE_LINK_NOT_INERT' },
    category: { code: 'SAFETY' },
    process: { code: 2 },
    oauth: { code: 'liveAuthCodeSecret' }
  });
  assert.equal(machineCodes.failure.code, 'SOURCE_LINK_NOT_INERT');
  assert.equal(machineCodes.category.code, 'SAFETY');
  assert.equal(machineCodes.process.code, 2);
  assert.equal(machineCodes.oauth.code, '[REDACTED]');
});

test('cross-origin CSS dependencies receive only an origin referrer', async () => {
  const requests = [];
  const server = createHttpServer((request, response) => {
    requests.push({ url: request.url, referer: request.headers.referer || '' });
    response.writeHead(200, { 'content-type': 'image/svg+xml' });
    response.end('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>');
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const destination = `http://127.0.0.1:${server.address().port}/asset.svg`;
  const signedStylesheet = 'https://source.example/styles/site.css?signature=CSS_REFERER_SECRET';
  try {
    assert.equal(cssDependencyReferer(signedStylesheet, destination), 'https://source.example/');
    await fetchCssDependency(destination, signedStylesheet, {
      allowedOrigin: 'https://source.example',
      hostIsPrivate: async () => false,
      addressIsBlocked: () => false,
      maximumBytes: 1024 * 1024,
      timeoutMs: 5000,
      userAgent: 'replica-test'
    });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].referer, 'https://source.example/');
    assert.doesNotMatch(JSON.stringify(requests), /CSS_REFERER_SECRET/);
  } finally {
    await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
  }
});

test('CSS dependency fetch pins and revalidates the resolver answer used for the socket', async () => {
  const server = createHttpServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/css' });
    response.end('body { color: green; }');
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const destination = `http://rebind.invalid:${server.address().port}/nested.css`;
  try {
    await assert.rejects(fetchCssDependency(destination, 'https://source.example/site.css', {
      allowedOrigin: 'https://source.example',
      hostIsPrivate: async () => false,
      resolver: async () => [{ address: '127.0.0.1', family: 4 }],
      maximumBytes: 1024 * 1024,
      timeoutMs: 5000,
      userAgent: 'replica-test'
    }), /PRIVATE_DESTINATION/);

    const fetched = await fetchCssDependency(destination, 'https://source.example/site.css', {
      allowedOrigin: 'https://source.example',
      hostIsPrivate: async () => false,
      resolver: async () => [{ address: '127.0.0.1', family: 4 }],
      addressIsBlocked: () => false,
      maximumBytes: 1024 * 1024,
      timeoutMs: 5000,
      userAgent: 'replica-test'
    });
    assert.equal(fetched.body.toString('utf8'), 'body { color: green; }');
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test('capture CLIs reject credential-like top-level URLs before launching a browser', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-capture-url-'));
  const cases = [
    [script('compare-pages.mjs'), ['--baseline', 'https://example.test/job?token=live', '--candidate', 'https://candidate.example.test']],
    [script('compare-pages.mjs'), ['--baseline', 'https://example.test/job', '--candidate', 'https://user:password@candidate.example.test']],
    [script('inspect-page.mjs'), ['--url', 'https://example.test/job#access_token=live', '--out', join(directory, 'inspection')]]
  ];
  for (const [pathname, args] of cases) {
    const result = await run(pathname, args);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /credentials|sensitive query|credential-like fragment/i);
  }
  const publicWrite = await run(script('compare-pages.mjs'), [
    '--baseline', 'https://example.test/job',
    '--candidate', 'https://candidate.example.test',
    '--allow-non-get'
  ]);
  assert.equal(publicWrite.code, 1);
  assert.match(publicWrite.stderr, /loopback candidate/i);
});

test('bootstrap rejects credential-like source query values and fragments before scaffolding', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-sensitive-url-'));
  const signedOutput = join(directory, 'signed');
  const signed = await run(script('bootstrap-static-replica.mjs'), [
    '--url', 'https://example.test/page?X-Amz-Credential=synthetic-secret',
    '--out', signedOutput,
    '--mode', 'authorized-local'
  ]);
  assert.equal(signed.code, 1);
  assert.match(signed.stderr, /sensitive query parameter/i);
  await assert.rejects(readFile(join(signedOutput, 'snapshot.json')));

  const fragmentOutput = join(directory, 'fragment');
  const fragment = await run(script('bootstrap-static-replica.mjs'), [
    '--url', 'https://example.test/page#access_token=synthetic-secret',
    '--out', fragmentOutput,
    '--mode', 'authorized-local'
  ]);
  assert.equal(fragment.code, 1);
  assert.match(fragment.stderr, /credential-like fragment/i);
  await assert.rejects(readFile(join(fragmentOutput, 'snapshot.json')));
});

test('repository skill validator accepts the distributable skill structure', async () => {
  const result = await run(join(repositoryRoot, 'evals', 'scripts', 'validate-skill.mjs'), [
    '--skill', skillRoot
  ]);
  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stdout).pass, true);
});

test('contamination scanner checks paths and rejects disguised binary or raster artifacts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-contamination-'));
  const syntheticSkill = join(directory, 'skill');
  const targets = join(directory, 'targets.json');
  await mkdir(join(syntheticSkill, 'nested'), { recursive: true });
  const expandedBenchmarkName = ['Synthetic', 'Benchmark', 'Capital'].join(' ');
  await writeFile(targets, JSON.stringify({
    targets: [{ contaminationTokens: ['forbidden-marker', expandedBenchmarkName] }]
  }));
  await writeFile(join(syntheticSkill, 'nested', 'forbidden-marker.txt'), 'otherwise clean');
  await writeFile(
    join(syntheticSkill, 'disguised.dat'),
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00])
  );
  await writeFile(join(syntheticSkill, 'captured-page.png'), 'not actually an image');
  await writeFile(join(syntheticSkill, 'embedded.txt'), ['data', 'image/png;base64,c3ludGhldGlj'].join(':'));
  await writeFile(join(syntheticSkill, 'encoded.txt'), [['iV', 'BORw0KGgo'].join(''), 'c3ludGhldGlj'].join(''));
  await writeFile(join(syntheticSkill, 'benchmark.txt'), expandedBenchmarkName);
  await writeFile(join(syntheticSkill, expandedBenchmarkName.toLowerCase().replaceAll(' ', '-')), 'normalized path token');
  await mkdir(join(syntheticSkill, 'candidate-inspection'));
  await writeFile(join(syntheticSkill, 'candidate-inspection', 'report.json'), '{}');

  const result = await run(join(repositoryRoot, 'evals', 'scripts', 'check-contamination.mjs'), [
    '--root', syntheticSkill,
    '--targets', targets
  ]);
  assert.equal(result.code, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.pass, false);
  assert.ok(report.findings.some((finding) => finding.kind === 'benchmark-token' && finding.location === 'path'));
  assert.ok(report.findings.some((finding) => finding.kind === 'prohibited-binary-magic' && finding.file === 'disguised.dat'));
  assert.ok(report.findings.some((finding) => finding.kind === 'prohibited-asset-extension' && finding.file === 'captured-page.png'));
  assert.ok(report.findings.some((finding) => finding.kind === 'embedded-image-data-uri' && finding.file === 'embedded.txt'));
  assert.ok(report.findings.some((finding) => finding.kind === 'base64-image-signature' && finding.file === 'encoded.txt'));
  assert.ok(report.findings.some((finding) => finding.kind === 'benchmark-token' && finding.file === 'benchmark.txt'));
  assert.ok(report.findings.some((finding) => finding.kind === 'benchmark-token' && finding.location === 'path' && finding.file.includes('synthetic-benchmark-capital')));
  assert.ok(report.findings.some((finding) => finding.kind === 'prohibited-generated-directory'));
});
