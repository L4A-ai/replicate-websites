import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { createAttestation, parseArguments as parseInitArguments } from '../scripts/init-case.mjs';
import {
  buildEffectiveFidelityPolicy,
  captureCandidateEmptyBaseEvidence,
  createCandidateEnvironment,
  launchEvaluatorOwnedBackend,
  readJsonLimited,
  resolveEvaluatorCase,
  resolveCandidatePolicyPath,
  resolveLoopbackManifestPath,
  validateAuthorizedLocalManifest,
  validateIsolationAttestation,
  validateStartCommand
} from '../scripts/run-case.mjs';
import { startTrustedBackend } from '../../skills/replicate-websites/scripts/lib/trusted-backend-process.mjs';
import { verifyTrustedBackend } from '../../skills/replicate-websites/scripts/lib/trusted-backend.mjs';

const execFileAsync = promisify(execFile);
const syntheticGitSha = '1'.repeat(40);

async function fixture() {
  const root = await fs.mkdtemp(join(tmpdir(), 'replicate-evaluator-test-'));
  const skill = join(root, 'skill');
  const workspace = join(root, 'workspace');
  const attestation = join(root, 'evaluator-artifacts', 'isolation.json');
  const prompt = join(root, 'builder-prompt.txt');
  await fs.mkdir(skill);
  await fs.writeFile(join(skill, 'SKILL.md'), '# Synthetic skill\n');
  await fs.writeFile(prompt, 'Build the synthetic candidate in the supplied empty workspace.\n');
  await fs.chmod(join(skill, 'SKILL.md'), 0o444);
  await fs.chmod(skill, 0o555);
  await fs.chmod(prompt, 0o444);
  return { root, skill, workspace, attestation, prompt };
}

async function createTestAttestation(paths, options) {
  return createAttestation({
    ...options,
    workspace: paths.workspace,
    attestation: paths.attestation,
    skill: paths.skill,
    prompt: paths.prompt,
    gitSha: syntheticGitSha,
    builderId: `builder-${options.caseId}`,
    builderWritableRoots: [paths.workspace],
    filesystemSandboxEnforced: true,
    revisionVerifier: async ({ gitSha, skill, evaluator }) => ({
      repositoryRoot: evaluator.root,
      gitSha,
      repositoryClean: true,
      headMatchedRequestedSha: true,
      trackedSkillPath: 'skills/replicate-websites',
      trackedSkillMatched: true,
      trackedSkillFileCount: skill.fileCount,
      trackedSkillSha256: skill.sha256
    })
  });
}

async function cleanup(paths) {
  try { await fs.chmod(paths.skill, 0o755); } catch {}
  await fs.rm(paths.root, { recursive: true, force: true });
}

test('init-case records a pre-dispatch empty workspace and immutable skill hash', async () => {
  const paths = await fixture();
  try {
    const { attestation, attestationPath } = await createTestAttestation(paths, {
      runId: 'round-1',
      caseId: 'synthetic-a'
    });
    assert.equal(attestation.schemaVersion, 2);
    assert.equal(attestation.phase, 'pre-dispatch');
    assert.equal(attestation.isolation.workspaceWasEmpty, true);
    assert.equal(attestation.isolation.skillWasReadOnly, true);
    assert.equal(attestation.isolation.priorArtifactsVisible, false);
    assert.equal(attestation.isolation.filesystemSandboxEnforced, true);
    assert.equal(attestation.builder.id, 'builder-synthetic-a');
    assert.deepEqual(attestation.builder.writableRoots, [await fs.realpath(paths.workspace)]);
    assert.equal(attestation.skill.gitSha, syntheticGitSha);
    assert.equal(attestation.revision.trackedSkillMatched, true);
    assert.equal(attestation.evaluator.outsideBuilderWritableRoots, true);
    assert.match(attestation.prompt.sha256, /^[a-f0-9]{64}$/);
    assert.equal(await fs.readFile(attestation.prompt.copy, 'utf8'), await fs.readFile(paths.prompt, 'utf8'));
    assert.match(attestation.skill.sha256, /^[a-f0-9]{64}$/);
    assert.equal(attestationPath, join(await fs.realpath(join(paths.root, 'evaluator-artifacts')), 'isolation.json'));
    assert.deepEqual(await fs.readdir(paths.workspace), []);
  } finally {
    await cleanup(paths);
  }
});

test('init-case CLI requires a full revision, builder identity, and enforced writable-root sandbox', () => {
  const base = [
    '--run-id', 'round-1',
    '--case-id', 'case-a',
    '--workspace', '/tmp/builder-workspace',
    '--attestation', '/tmp/evaluator/isolation.json'
  ];
  assert.throws(() => parseInitArguments(base), /--git-sha.*--builder-id.*--builder-writable-root.*--filesystem-sandbox-enforced/);
  const parsed = parseInitArguments([
    ...base,
    '--git-sha', syntheticGitSha,
    '--builder-id', 'fresh-agent-1',
    '--builder-writable-root', '/tmp/builder-workspace',
    '--filesystem-sandbox-enforced'
  ]);
  assert.equal(parsed.gitSha, syntheticGitSha);
  assert.equal(parsed.builderId, 'fresh-agent-1');
  assert.equal(parsed.filesystemSandboxEnforced, true);
});

test('init-case refuses a writable skill snapshot', async () => {
  const paths = await fixture();
  try {
    await fs.chmod(paths.skill, 0o755);
    await assert.rejects(
      createTestAttestation(paths, {
        runId: 'round-1',
        caseId: 'synthetic-b'
      }),
      /Skill snapshot root is writable/
    );
  } finally {
    await cleanup(paths);
  }
});

test('init-case refuses a nonempty workspace and keeps attestations outside it', async () => {
  const paths = await fixture();
  try {
    await fs.mkdir(paths.workspace);
    await fs.writeFile(join(paths.workspace, 'prior.txt'), 'prior artifact\n');
    await assert.rejects(
      createTestAttestation(paths, {
        runId: 'round-1',
        caseId: 'synthetic-nonempty'
      }),
      /Workspace is not empty/
    );
    await fs.rm(join(paths.workspace, 'prior.txt'));
    await assert.rejects(
      createTestAttestation({ ...paths, attestation: join(paths.workspace, 'isolation.json') }, {
        runId: 'round-1',
        caseId: 'synthetic-attestation-location'
      }),
      /attestation must be stored outside/
    );
    assert.deepEqual(await fs.readdir(paths.workspace), []);
  } finally {
    await cleanup(paths);
  }
});

test('manifest paths cannot escape the allocated loopback origin', () => {
  const origin = 'http://127.0.0.1:43123';
  assert.equal(resolveLoopbackManifestPath('/apply?step=1', '/', origin, 'page.path'), `${origin}/apply?step=1`);
  assert.equal(resolveLoopbackManifestPath('healthz', '/', origin, 'healthPath'), `${origin}/healthz`);
  assert.throws(() => resolveLoopbackManifestPath('https://example.test/apply', '/', origin, 'page.path'), /origin-relative/);
  assert.throws(() => resolveLoopbackManifestPath('//example.test/apply', '/', origin, 'page.path'), /origin-relative/);
  assert.throws(() => resolveLoopbackManifestPath('\\\\example.test/apply', '/', origin, 'page.path'), /allocated loopback/);
});

test('evaluator binds each case id to its target, selector, and four canonical viewports', async () => {
  const registry = JSON.parse(await fs.readFile(new URL('../targets.json', import.meta.url), 'utf8'));
  const firstTarget = registry.targets[0];
  const canonicalViewports = [
    'desktop:1440x1000', 'tablet:768x1024', 'mobile:390x844', 'compact:360x800'
  ];
  const request = {
    caseId: firstTarget.id,
    targetUrl: firstTarget.url,
    readySelector: firstTarget.readySelector,
    viewports: canonicalViewports
  };
  const resolved = await resolveEvaluatorCase(request);
  assert.equal(resolved.id, firstTarget.id);
  assert.deepEqual(resolved.viewports, canonicalViewports);
  await assert.rejects(resolveEvaluatorCase({ ...request, caseId: registry.targets[1].id }), /target URL does not match/);
  await assert.rejects(resolveEvaluatorCase({ ...request, readySelector: '#forged' }), /ready selector does not match/);
  await assert.rejects(resolveEvaluatorCase({ ...request, viewports: canonicalViewports.slice(0, 3) }), /Every case must use/);
});

test('evaluator refuses non-authorized-local manifests before candidate launch', () => {
  assert.equal(validateAuthorizedLocalManifest({ mode: 'authorized-local' }).mode, 'authorized-local');
  assert.throws(() => validateAuthorizedLocalManifest({ mode: 'owned' }), /authorized-local.*before the candidate is launched/);
  assert.throws(() => validateAuthorizedLocalManifest({ mode: 'public-simulation' }), /authorized-local.*before the candidate is launched/);
  assert.throws(() => validateAuthorizedLocalManifest({}), /authorized-local.*before the candidate is launched/);
});

test('evaluator owns fidelity gates and imports only exact safe semantic approvals', async () => {
  const evaluatorPolicy = JSON.parse(await fs.readFile(new URL('../policies/exact.json', import.meta.url), 'utf8'));
  const malicious = {
    schemaVersion: 1,
    gates: { ...evaluatorPolicy.gates, maxTolerantDiffPercent: 100 },
    approvedSemanticMismatches: []
  };
  assert.throws(
    () => buildEffectiveFidelityPolicy(malicious, evaluatorPolicy, ['desktop']),
    /may not weaken evaluator-owned gate/
  );
  assert.throws(
    () => buildEffectiveFidelityPolicy({
      schemaVersion: 1,
      approvedSemanticMismatches: [{ rationale: 'safe enough' }]
    }, evaluatorPolicy, ['desktop']),
    /must name one evaluator viewport|exact changed fingerprint/
  );
  const provenanceSentinel = 'POLICY_PROVENANCE_SECRET_7a6ce25e';
  const safe = buildEffectiveFidelityPolicy({
    schemaVersion: 1,
    provenance: { arbitrary: provenanceSentinel },
    gates: { ...evaluatorPolicy.gates },
    approvedSemanticMismatches: [{
      viewport: 'desktop',
      category: 'forms',
      kind: 'changed',
      key: 'form:#0',
      changeFields: ['action'],
      rationale: 'Submission is routed to the local synthetic backend.'
    }]
  }, evaluatorPolicy, ['desktop']);
  assert.deepEqual(safe.gates, evaluatorPolicy.gates);
  assert.equal(safe.approvedSemanticMismatches.length, 1);
  assert.equal(safe.provenance.candidatePolicyProvenanceDeclared, true);
  assert.doesNotMatch(JSON.stringify(safe), new RegExp(provenanceSentinel));
});

test('candidate fidelity policy is confined to the candidate except for evaluator exact policy', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'replicate-policy-path-test-'));
  const candidate = join(root, 'candidate');
  const outside = join(root, 'outside.json');
  const evaluator = join(root, 'repository', 'evals', 'policies', 'exact.json');
  try {
    await fs.mkdir(candidate);
    await fs.mkdir(join(root, 'repository', 'evals', 'policies'), { recursive: true });
    await fs.writeFile(join(candidate, 'fidelity-policy.json'), '{}\n');
    await fs.writeFile(outside, '{}\n');
    await fs.writeFile(evaluator, '{}\n');
    assert.equal(
      await resolveCandidatePolicyPath(candidate, join(candidate, 'fidelity-policy.json'), evaluator),
      await fs.realpath(join(candidate, 'fidelity-policy.json'))
    );
    await assert.rejects(
      resolveCandidatePolicyPath(candidate, outside, evaluator),
      /escapes its canonical root/
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('run-case validates the attested IDs, workspace, manifest, skill path, and hash', async () => {
  const paths = await fixture();
  try {
    await createTestAttestation(paths, {
      runId: 'round-2',
      caseId: 'synthetic-c'
    });
    const candidateDir = join(paths.workspace, 'candidate');
    const manifest = join(candidateDir, 'replica.manifest.json');
    await fs.mkdir(candidateDir);
    await fs.writeFile(manifest, '{}\n');
    const options = {
      runId: 'round-2',
      caseId: 'synthetic-c',
      isolationAttestation: paths.attestation,
      candidateDir,
      manifest,
      skill: paths.skill,
      out: join(paths.root, 'evaluator-artifacts', 'score')
    };
    await fs.mkdir(options.out);
    const validation = await validateIsolationAttestation(options);
    assert.equal(validation.attestation.skill.sha256, validation.skill.sha256);
    await assert.rejects(
      validateIsolationAttestation({ ...options, caseId: 'wrong-case' }),
      /runId\/caseId do not match/
    );
  } finally {
    await cleanup(paths);
  }
});

test('run-case rejects candidate and manifest symlink traversal inside the attested workspace', async () => {
  const paths = await fixture();
  try {
    await createTestAttestation(paths, {
      runId: 'round-symlink',
      caseId: 'synthetic-symlink'
    });
    const realCandidate = join(paths.workspace, 'real-candidate');
    await fs.mkdir(realCandidate);
    await fs.writeFile(join(realCandidate, 'replica.manifest.json'), '{}\n');
    const linkedCandidate = join(paths.workspace, 'candidate');
    await fs.symlink(realCandidate, linkedCandidate);
    const out = join(paths.root, 'evaluator-artifacts', 'symlink-score');
    await fs.mkdir(out);
    await assert.rejects(
      validateIsolationAttestation({
        runId: 'round-symlink',
        caseId: 'synthetic-symlink',
        isolationAttestation: paths.attestation,
        candidateDir: linkedCandidate,
        manifest: join(linkedCandidate, 'replica.manifest.json'),
        skill: paths.skill,
        out
      }),
      /symbolic link below its canonical root/
    );

    await fs.unlink(linkedCandidate);
    const candidate = join(paths.workspace, 'candidate');
    await fs.mkdir(candidate);
    const externalManifest = join(paths.root, 'external-manifest.json');
    await fs.writeFile(externalManifest, '{}\n');
    await fs.symlink(externalManifest, join(candidate, 'replica.manifest.json'));
    await assert.rejects(
      validateIsolationAttestation({
        runId: 'round-symlink',
        caseId: 'synthetic-symlink',
        isolationAttestation: paths.attestation,
        candidateDir: candidate,
        manifest: join(candidate, 'replica.manifest.json'),
        skill: paths.skill,
        out
      }),
      /symbolic link below its canonical root/
    );
  } finally {
    await cleanup(paths);
  }
});

test('candidate server environment does not inherit arbitrary evaluator variables', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'replicate-evaluator-env-test-'));
  process.env.REPLICATE_SYNTHETIC_SECRET = 'must-not-cross-boundary';
  try {
    const { environment } = await createCandidateEnvironment(root, 43123);
    assert.equal(environment.REPLICATE_SYNTHETIC_SECRET, undefined);
    assert.equal(environment.PORT, '43123');
    assert.equal(environment.EMAIL_CONFIRMATION_ENABLED, 'false');
    assert.ok(environment.HOME.startsWith(root));
    assert.ok(environment.TMPDIR.startsWith(root));
  } finally {
    delete process.env.REPLICATE_SYNTHETIC_SECRET;
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('candidate start command is a direct local node or npm invocation', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'replicate-evaluator-command-test-'));
  try {
    await fs.writeFile(join(root, 'server.mjs'), 'export {};\n');
    await fs.writeFile(join(root, 'malicious.mjs'), 'throw new Error("must never run");\n');
    await fs.writeFile(join(root, 'package.json'), '{"scripts":{"start":"node server.mjs"}}\n');
    assert.deepEqual(await validateStartCommand(['node', 'server.mjs'], root), [process.execPath, 'server.mjs']);
    assert.deepEqual(await validateStartCommand(['npm', 'start'], root), [process.execPath, 'server.mjs']);
    await assert.rejects(
      validateStartCommand(['node', 'malicious.mjs'], root),
      /exact audited candidate server\.mjs/
    );
    let stagingCalled = false;
    await assert.rejects(
      launchEvaluatorOwnedBackend({
        candidateDir: root,
        manifest: { start: { command: ['node', 'malicious.mjs'], healthPath: '/healthz' } },
        trustedBackend: { serverPath: await fs.realpath(join(root, 'server.mjs')) },
        startRuntime: async () => { stagingCalled = true; }
      }),
      /exact audited candidate server\.mjs/
    );
    assert.equal(stagingCalled, false, 'a builder-selected background process must be rejected before staging or spawn');
    await assert.rejects(validateStartCommand(['bash', '-lc', 'node server.mjs'], root), /directly invoke node or npm/);
    await assert.rejects(validateStartCommand(['node', '-e'], root), /one relative local script/);
    await assert.rejects(validateStartCommand(['node', '../server.mjs'], root));
    const external = join(root, 'real-server.mjs');
    await fs.writeFile(external, 'export {};\n');
    await fs.unlink(join(root, 'server.mjs'));
    await fs.symlink(external, join(root, 'server.mjs'));
    await assert.rejects(
      validateStartCommand(['node', 'server.mjs'], root),
      /symbolic link below its canonical root/
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('evaluator launches verified staged bytes after candidate replacement and removes staging', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'replicate-evaluator-staged-runtime-'));
  const candidate = join(root, 'candidate');
  const sentinel = join(root, 'candidate-process-ran.txt');
  const skillRoot = new URL('../../skills/replicate-websites/', import.meta.url).pathname;
  const stagingEntries = async () => new Set((await fs.readdir(tmpdir()))
    .filter((name) => name.startsWith('replicate-audited-backend-')));
  let launched;
  try {
    await execFileAsync(process.execPath, [
      new URL('../../skills/replicate-websites/scripts/scaffold-replica.mjs', import.meta.url).pathname,
      '--out', candidate,
      '--name', 'evaluator-staged-runtime'
    ]);
    const manifest = JSON.parse(await fs.readFile(join(candidate, 'replica.manifest.json'), 'utf8'));
    const verified = await verifyTrustedBackend({ candidateRoot: candidate, skillRoot, manifest });
    await fs.writeFile(join(candidate, 'server.mjs'), `
      import { writeFile } from 'node:fs/promises';
      await writeFile(${JSON.stringify(sentinel)}, 'candidate process ran');
      setInterval(() => {}, 1000);
    `);
    const stagingBefore = await stagingEntries();
    launched = await launchEvaluatorOwnedBackend({
      candidateDir: candidate,
      manifest,
      trustedBackend: verified,
      startRuntime: startTrustedBackend,
      timeoutMs: 10000
    });
    assert.equal(launched.evidence.suppliedCandidateProcessUsed, false);
    assert.equal(launched.evidence.environmentScrubbed, true);
    assert.equal(launched.evidence.launchedPath, '[evaluator-temp]/server.mjs');
    assert.equal(launched.evidence.serverSha256, verified.serverSha256);
    assert.ok(launched.evidence.publicFileCount > 0);
    assert.ok(launched.evidence.publicTotalBytes > 0);
    assert.equal(launched.evidence.readOnlySnapshot, true);
    const health = await fetch(`${launched.runtime.origin}${manifest.start.healthPath}`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).service, verified.projectName);
    await launched.runtime.close();
    launched = null;
    await assert.rejects(fs.readFile(sentinel), { code: 'ENOENT' });
    const stagingAfter = await stagingEntries();
    assert.deepEqual(
      [...stagingAfter].filter((name) => !stagingBefore.has(name)),
      [],
      'evaluator-owned staging must be removed after process-group cleanup'
    );
  } finally {
    await launched?.runtime.close().catch(() => {});
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('evaluator JSON reads fail closed before oversized candidate data is parsed', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'replicate-evaluator-json-limit-'));
  try {
    const small = join(root, 'small.json');
    const oversized = join(root, 'oversized.json');
    await fs.writeFile(small, '{"schemaVersion":1}\n');
    await fs.writeFile(oversized, JSON.stringify({ payload: 'x'.repeat(2048) }));
    assert.deepEqual(await readJsonLimited(small, 128, 'Synthetic manifest'), { schemaVersion: 1 });
    await assert.rejects(
      readJsonLimited(oversized, 1024, 'Synthetic manifest'),
      /Synthetic manifest exceeds the 1024-byte size limit/
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('evaluator emits a bounded complete empty-base candidate inventory and content-addressed patch', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'replicate-evaluator-evidence-'));
  const candidate = join(root, 'candidate');
  const evidence = join(root, 'evidence');
  try {
    await fs.mkdir(candidate);
    await fs.mkdir(evidence);
    await fs.writeFile(join(candidate, 'index.html'), '<!doctype html><title>Evidence</title>\n');
    await fs.writeFile(join(candidate, 'asset.bin'), Buffer.from([0, 1, 2, 3]));
    const captured = await captureCandidateEmptyBaseEvidence(candidate, evidence);
    assert.equal(captured.inventory.completeFileHashInventory, true);
    assert.equal(captured.inventory.fileCount, 2);
    assert.equal(captured.inventory.files.every((entry) => /^[a-f0-9]{64}$/.test(entry.sha256)), true);
    assert.match(await fs.readFile(captured.patchPath, 'utf8'), /diff --replicate-empty-base/);
    assert.match(captured.patchSha256, /^[a-f0-9]{64}$/);
    assert.match(captured.inventorySha256, /^[a-f0-9]{64}$/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('run-case emits a schema-shaped failed run record for an unsafe manifest URL', async () => {
  const paths = await fixture();
  try {
    const registry = JSON.parse(await fs.readFile(new URL('../targets.json', import.meta.url), 'utf8'));
    const firstTarget = registry.targets[0];
    await createTestAttestation(paths, {
      runId: 'round-3',
      caseId: firstTarget.id
    });
    const candidateDir = join(paths.workspace, 'candidate');
    await fs.mkdir(candidateDir);
    await fs.writeFile(join(candidateDir, 'server.mjs'), 'export {};\n');
    await fs.writeFile(join(candidateDir, 'replica.manifest.json'), `${JSON.stringify({
      mode: 'authorized-local',
      start: { command: ['node', 'server.mjs'], healthPath: '/healthz' },
      page: { path: 'https://example.test/live' }
    })}\n`);
    const out = join(paths.root, 'evaluator-artifacts', 'unsafe-score');
    await assert.rejects(execFileAsync(process.execPath, [
      new URL('../scripts/run-case.mjs', import.meta.url).pathname,
      '--run-id', 'round-3',
      '--case-id', firstTarget.id,
      '--isolation-attestation', paths.attestation,
      '--skill', paths.skill,
      '--target-url', firstTarget.url,
      '--candidate-dir', candidateDir,
      '--out', out
    ]));
    const record = JSON.parse(await fs.readFile(join(out, 'run-record.json'), 'utf8'));
    const detail = JSON.parse(await fs.readFile(join(out, 'result.json'), 'utf8'));
    assert.deepEqual(Object.keys(record).sort(), ['builder', 'caseId', 'evaluator', 'evidence', 'isolation', 'result', 'revision', 'runId', 'schemaVersion', 'skill']);
    assert.equal(record.schemaVersion, 2);
    assert.deepEqual(Object.keys(record.skill).sort(), ['gitSha', 'sha256']);
    assert.deepEqual(Object.keys(record.isolation).sort(), ['filesystemSandboxEnforced', 'priorArtifactsVisible', 'protectedEvidenceOutsideBuilderWritableRoots', 'skillWasReadOnly', 'workspaceWasEmpty']);
    assert.deepEqual(Object.keys(record.result).sort(), ['artifactPath', 'failureCodes', 'pass']);
    assert.match(record.skill.sha256, /^[a-f0-9]{64}$/);
    assert.equal(record.result.pass, false);
    assert.deepEqual(record.result.failureCodes, ['SAFETY'], detail.error?.message);
    assert.equal(record.isolation.workspaceWasEmpty, true);
    assert.equal(record.isolation.skillWasReadOnly, true);
    assert.equal(record.isolation.priorArtifactsVisible, false);
    assert.equal(record.isolation.filesystemSandboxEnforced, true);
    assert.match(record.evidence.sha256, /^[a-f0-9]{64}$/);
    const evidence = JSON.parse(await fs.readFile(record.evidence.indexPath, 'utf8'));
    assert.equal(evidence.evaluatorOwned, true);
    assert.match(evidence.prompt.sha256, /^[a-f0-9]{64}$/);
    assert.match(evidence.manifest.sha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(evidence.targetAndViewports.path.endsWith('target-and-viewports.json'), true);
    assert.equal(evidence.candidateInventory.fileCount, 2);
    assert.match(evidence.diagnosis.sha256, /^[a-f0-9]{64}$/);
  } finally {
    await cleanup(paths);
  }
});

test('run-case rejects and redacts nested target URL credentials in evaluator artifacts', async () => {
  const paths = await fixture();
  const secret = 'must-not-appear-evaluator-secret';
  try {
    await createTestAttestation(paths, {
      runId: 'round-credential',
      caseId: 'case-a'
    });
    const candidateDir = join(paths.workspace, 'candidate');
    await fs.mkdir(candidateDir);
    await fs.writeFile(join(candidateDir, 'server.mjs'), 'export {};\n');
    await fs.writeFile(join(candidateDir, 'replica.manifest.json'), `${JSON.stringify({
      mode: 'authorized-local',
      start: { command: ['node', 'server.mjs'], healthPath: '/healthz' },
      page: { path: '/' }
    })}\n`);
    const out = join(paths.root, 'evaluator-artifacts', 'credential-score');
    const target = `https://source.example.test/?next=${encodeURIComponent(`https://assets.example.test/file?signature=${secret}`)}`;
    await assert.rejects(execFileAsync(process.execPath, [
      new URL('../scripts/run-case.mjs', import.meta.url).pathname,
      '--run-id', 'round-credential',
      '--case-id', 'case-a',
      '--isolation-attestation', paths.attestation,
      '--skill', paths.skill,
      '--target-url', target,
      '--candidate-dir', candidateDir,
      '--out', out
    ]));
    const resultText = await fs.readFile(join(out, 'result.json'), 'utf8');
    const record = JSON.parse(await fs.readFile(join(out, 'run-record.json'), 'utf8'));
    assert.doesNotMatch(resultText, new RegExp(secret));
    assert.match(resultText, /REDACTED/);
    assert.deepEqual(record.result.failureCodes, ['SAFETY']);
  } finally {
    await cleanup(paths);
  }
});
