#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants, promises as fs } from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { hashEvaluatorHarness, hashReadOnlySkill } from './init-case.mjs';
import {
  assertSafeHttpUrl,
  redactReportData
} from '../../skills/replicate-websites/scripts/lib/network-safety.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const defaultSkill = join(repositoryRoot, 'skills/replicate-websites');
const defaultViewports = ['desktop:1440x1000', 'tablet:768x1024', 'mobile:390x844', 'compact:360x800'];
const targetsPath = join(repositoryRoot, 'evals/targets.json');
const candidateJsonLimit = 1024 * 1024;
const evaluatorArtifactJsonLimit = 50 * 1024 * 1024;
const promptByteLimit = 64 * 1024;
const candidateEvidenceLimits = Object.freeze({
  maxFiles: 4096,
  maxFileBytes: 16 * 1024 * 1024,
  maxTotalBytes: 100 * 1024 * 1024,
  maxEmbeddedTextBytes: 256 * 1024,
  maxPatchBytes: 8 * 1024 * 1024
});

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function parseArguments(argv) {
  const options = {
    targetUrl: null,
    candidateDir: null,
    manifest: null,
    out: null,
    skill: defaultSkill,
    policy: join(repositoryRoot, 'evals/policies/exact.json'),
    readySelector: 'body',
    viewports: [],
    runId: null,
    caseId: null,
    isolationAttestation: null,
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
      case '--target-url': options.targetUrl = take(index, argument); index += 1; break;
      case '--candidate-dir': options.candidateDir = resolve(take(index, argument)); index += 1; break;
      case '--manifest': options.manifest = resolve(take(index, argument)); index += 1; break;
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--skill': options.skill = resolve(take(index, argument)); index += 1; break;
      case '--policy': options.policy = resolve(take(index, argument)); index += 1; break;
      case '--ready-selector': options.readySelector = take(index, argument); index += 1; break;
      case '--viewport': options.viewports.push(take(index, argument)); index += 1; break;
      case '--run-id': options.runId = take(index, argument); index += 1; break;
      case '--case-id': options.caseId = take(index, argument); index += 1; break;
      case '--isolation-attestation': options.isolationAttestation = resolve(take(index, argument)); index += 1; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && (!options.targetUrl || !options.candidateDir || !options.out
    || !options.runId || !options.caseId || !options.isolationAttestation)) {
    throw new Error('--target-url, --candidate-dir, --out, --run-id, --case-id, and --isolation-attestation are required.');
  }
  options.manifest ||= options.candidateDir ? join(options.candidateDir, 'replica.manifest.json') : null;
  options.viewports = options.viewports.length ? options.viewports : defaultViewports;
  return options;
}

function isWithin(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (!pathFromParent.startsWith('..') && !isAbsolute(pathFromParent));
}

export function resolveLoopbackManifestPath(value, fallback, origin, label) {
  const raw = value ?? fallback;
  if (typeof raw !== 'string' || !raw.trim()) throw new Error(`${label} must be a non-empty origin-relative path.`);
  const trimmed = raw.trim();
  if (trimmed.startsWith('//') || /^[a-z][a-z\d+.-]*:/i.test(trimmed)) {
    throw new Error(`${label} must be origin-relative, not an absolute or scheme-relative URL.`);
  }
  const resolvedUrl = new URL(trimmed, origin);
  if (resolvedUrl.origin !== origin || resolvedUrl.username || resolvedUrl.password) {
    throw new Error(`${label} must resolve to the allocated loopback candidate origin.`);
  }
  return resolvedUrl.href;
}

function validateTargetUrl(value) {
  return assertSafeHttpUrl(value, '--target-url').href;
}

function viewportString(viewport) {
  if (!viewport || typeof viewport !== 'object' || Array.isArray(viewport)
    || typeof viewport.name !== 'string' || !/^[a-z0-9_-]+$/i.test(viewport.name)
    || !Number.isInteger(viewport.width) || viewport.width < 1 || viewport.width > 10000
    || !Number.isInteger(viewport.height) || viewport.height < 1 || viewport.height > 10000) {
    throw new Error('Evaluator target registry contains an invalid viewport.');
  }
  return `${viewport.name}:${viewport.width}x${viewport.height}`;
}

export async function resolveEvaluatorCase({ caseId, targetUrl, readySelector, viewports }) {
  const registry = await readJsonLimited(targetsPath, candidateJsonLimit, 'Evaluator target registry');
  if (registry?.schemaVersion !== 1 || !Array.isArray(registry.targets) || !Array.isArray(registry.viewports)) {
    throw new Error('Evaluator target registry is malformed.');
  }
  const duplicateIds = registry.targets.filter((target) => target?.id === caseId);
  if (duplicateIds.length !== 1) throw new Error(`caseId "${caseId}" is not exactly one evaluator-owned target.`);
  const target = duplicateIds[0];
  const expectedTargetUrl = validateTargetUrl(target.url);
  if (targetUrl !== expectedTargetUrl) throw new Error('Requested target URL does not match the evaluator-owned caseId.');
  if (readySelector !== target.readySelector) throw new Error('Requested ready selector does not match the evaluator-owned caseId.');
  const expectedViewports = registry.viewports.map(viewportString);
  if (JSON.stringify(viewports) !== JSON.stringify(expectedViewports)
    || JSON.stringify(expectedViewports) !== JSON.stringify(defaultViewports)) {
    throw new Error('Every case must use the evaluator-owned desktop, tablet, mobile, and compact viewports in canonical order.');
  }
  return {
    id: target.id,
    label: String(target.label || ''),
    url: expectedTargetUrl,
    readySelector: target.readySelector,
    viewports: expectedViewports
  };
}

const exactGateNames = [
  'maxTolerantDiffPercent',
  'maxStrictDiffPercent',
  'maxUnapprovedSemanticMismatches',
  'requireDimensionsMatch',
  'requireCandidateStable',
  'maxMaskedPixels',
  'maxCandidateCriticalFailures',
  'maxCandidatePageErrors',
  'maxCandidateConsoleErrors',
  'maxCandidateBlockedWrites',
  'maxCandidateBlockedPrivateReads'
];

function sameStringSet(left, right) {
  return JSON.stringify([...(left || [])].sort()) === JSON.stringify([...(right || [])].sort());
}

export function buildEffectiveFidelityPolicy(candidatePolicy, evaluatorPolicy, viewportNames) {
  if (!candidatePolicy || candidatePolicy.schemaVersion !== 1) throw new Error('Candidate fidelity policy schemaVersion must be 1.');
  if (!evaluatorPolicy || evaluatorPolicy.schemaVersion !== 1) throw new Error('Evaluator fidelity policy schemaVersion must be 1.');
  const allowedTopLevel = new Set(['schemaVersion', 'provenance', 'gates', 'approvedSemanticMismatches']);
  for (const name of Object.keys(candidatePolicy)) {
    if (!allowedTopLevel.has(name)) throw new Error(`Candidate fidelity policy contains forbidden field "${name}".`);
  }
  if (candidatePolicy.gates !== undefined) {
    const candidateGateNames = Object.keys(candidatePolicy.gates || {}).sort();
    if (!sameStringSet(candidateGateNames, exactGateNames)) {
      throw new Error('Candidate fidelity policy gates must exactly match every evaluator-owned gate or be omitted.');
    }
    for (const name of exactGateNames) {
      if (candidatePolicy.gates[name] !== evaluatorPolicy.gates?.[name]) {
        throw new Error(`Candidate fidelity policy may not weaken evaluator-owned gate "${name}".`);
      }
    }
  }
  const approvals = candidatePolicy.approvedSemanticMismatches || [];
  if (!Array.isArray(approvals) || approvals.length > 1000) {
    throw new Error('Candidate semantic approvals must be an array with at most 1000 entries.');
  }
  const allowedViewports = new Set(viewportNames);
  for (const [index, rule] of approvals.entries()) {
    const label = `Candidate semantic approval ${index}`;
    const allowedFields = new Set(['viewport', 'category', 'kind', 'key', 'changeFields', 'rationale']);
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) throw new Error(`${label} must be an object.`);
    for (const name of Object.keys(rule)) {
      if (!allowedFields.has(name)) throw new Error(`${label} contains forbidden field "${name}".`);
    }
    if (!allowedViewports.has(rule.viewport)) throw new Error(`${label} must name one evaluator viewport.`);
    if (rule.kind !== 'changed' || typeof rule.key !== 'string' || !rule.key
      || typeof rule.rationale !== 'string' || rule.rationale.trim().length < 12
      || !Array.isArray(rule.changeFields) || !rule.changeFields.length) {
      throw new Error(`${label} must be an exact changed fingerprint with fields and a safety rationale.`);
    }
    const fields = [...rule.changeFields].sort();
    const formApproval = rule.category === 'forms'
      && /^form:#\d+$/.test(rule.key)
      && (sameStringSet(fields, ['action']) || sameStringSet(fields, ['action', 'method']))
      && /local|synthetic|submission/i.test(rule.rationale);
    const hiddenApproval = rule.category === 'controls'
      && /\|input:hidden\|#\d+$/.test(rule.key)
      && fields.every((field) => ['hiddenValueLength', 'hiddenValuePresent'].includes(field))
      && /hidden|opaque|placeholder|non-secret|synthetic/i.test(rule.rationale);
    const inertLinkApproval = rule.category === 'links'
      && /^link:name:.*\|#\d+$/.test(rule.key)
      && sameStringSet(fields, ['href'])
      && /inert|navigation|credential|query/i.test(rule.rationale);
    if (!formApproval && !hiddenApproval && !inertLinkApproval) {
      throw new Error(`${label} is not one of the evaluator-approved safe backend substitutions.`);
    }
  }
  return {
    schemaVersion: 1,
    provenance: {
      evaluatorOwnedGates: true,
      candidatePolicyProvenanceDeclared: candidatePolicy.provenance !== undefined
    },
    gates: { ...evaluatorPolicy.gates },
    approvedSemanticMismatches: approvals
  };
}

export async function resolveCandidatePolicyPath(candidateDir, policyPath, evaluatorPolicyPath) {
  const requested = resolve(policyPath);
  const evaluatorExact = resolve(evaluatorPolicyPath);
  if (requested === evaluatorExact) {
    return canonicalFileWithin(repositoryRoot, requested, 'Evaluator exact policy');
  }
  return canonicalFileWithin(candidateDir, requested, 'Candidate fidelity policy');
}

export function validateAuthorizedLocalManifest(manifest) {
  if (manifest?.mode !== 'authorized-local') {
    throw new Error('Evaluator mutation checks require manifest.mode to be authorized-local before the candidate is launched. Owned and public-simulation candidates must be evaluated read-only.');
  }
  return manifest;
}

async function canonicalDirectory(pathname, label) {
  const requested = resolve(pathname);
  const stat = await fs.lstat(requested);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${label} must be a real, non-symlink directory.`);
  }
  return fs.realpath(requested);
}

async function canonicalRegularFile(pathname, label, { readOnly = false } = {}) {
  const requested = resolve(pathname);
  const stat = await fs.lstat(requested);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`${label} must be a regular, non-symlink file.`);
  }
  if (readOnly && (stat.mode & 0o222) !== 0) {
    throw new Error(`${label} must be read-only.`);
  }
  return fs.realpath(requested);
}

async function assertNoSymlinkBelow(canonicalRoot, pathname, label) {
  const requested = resolve(pathname);
  const parsed = parse(requested);
  const components = requested.slice(parsed.root.length).split(/[\\/]+/).filter(Boolean);
  let current = parsed.root;
  for (const component of components) {
    const parentCanonical = await fs.realpath(current);
    const next = join(current, component);
    const stat = await fs.lstat(next);
    if (stat.isSymbolicLink() && isWithin(canonicalRoot, parentCanonical)) {
      throw new Error(`${label} may not traverse a symbolic link below its canonical root.`);
    }
    current = next;
  }
}

async function canonicalFileWithin(root, pathname, label) {
  const canonicalRoot = await canonicalDirectory(root, `${label} root`);
  const requested = resolve(pathname);
  await assertNoSymlinkBelow(canonicalRoot, requested, label);
  const stat = await fs.lstat(requested);
  if (!stat.isFile()) throw new Error(`${label} must be a regular file.`);
  const canonical = await fs.realpath(requested);
  if (!isWithin(canonicalRoot, canonical)) throw new Error(`${label} escapes its canonical root.`);
  return canonical;
}

async function canonicalDirectoryWithin(root, pathname, label) {
  const canonicalRoot = await canonicalDirectory(root, `${label} root`);
  const requested = resolve(pathname);
  await assertNoSymlinkBelow(canonicalRoot, requested, label);
  const stat = await fs.lstat(requested);
  if (!stat.isDirectory()) throw new Error(`${label} must be a directory.`);
  const canonical = await fs.realpath(requested);
  if (!isWithin(canonicalRoot, canonical)) throw new Error(`${label} escapes its canonical root.`);
  return canonical;
}

export async function validateStartCommand(command, candidateDir) {
  if (!Array.isArray(command) || !command.length
    || command.some((part) => typeof part !== 'string' || !part || part.includes('\0'))) {
    throw new Error('Manifest start.command must be a non-empty string array.');
  }
  const executable = command[0].toLowerCase();
  if (['npm', 'npm.cmd'].includes(executable)) {
    const npmStart = command.length === 2 && command[1] === 'start';
    const npmRunStart = command.length === 3 && command[1] === 'run' && command[2] === 'start';
    if (!npmStart && !npmRunStart) {
      throw new Error('Manifest npm command must be exactly ["npm", "start"] or ["npm", "run", "start"].');
    }
    const canonicalCandidate = await canonicalDirectory(candidateDir, 'Candidate directory');
    const packagePath = await canonicalFileWithin(
      canonicalCandidate,
      join(canonicalCandidate, 'package.json'),
      'Candidate package.json'
    );
    const packageJson = await readJsonLimited(packagePath, candidateJsonLimit, 'Candidate package.json');
    const startMatch = /^node(?:\.exe)?\s+([^\s]+)$/i.exec(packageJson.scripts?.start || '');
    if (!startMatch) {
      throw new Error('Candidate npm start script must be exactly a direct node invocation of one local script.');
    }
    return validateStartCommand(['node', startMatch[1]], canonicalCandidate);
  }
  if (!['node', 'node.exe'].includes(executable)) {
    throw new Error('Manifest start.command must directly invoke node or npm; shells and absolute executables are refused.');
  }
  if (command.length !== 2 || command[1].startsWith('-') || isAbsolute(command[1])) {
    throw new Error('Manifest node command must contain exactly one relative local script path and no flags.');
  }
  const canonicalCandidate = await canonicalDirectory(candidateDir, 'Candidate directory');
  const scriptPath = await canonicalFileWithin(
    canonicalCandidate,
    resolve(canonicalCandidate, command[1]),
    'Candidate node script'
  );
  if (!/\.(?:cjs|mjs|js)$/i.test(scriptPath)) {
    throw new Error('Manifest node script must be a JavaScript file inside the candidate directory.');
  }
  if (scriptPath !== join(canonicalCandidate, 'server.mjs')) {
    throw new Error('Manifest start.command must canonically target the exact audited candidate server.mjs.');
  }
  return [process.execPath, 'server.mjs'];
}

export async function validateIsolationAttestation(options) {
  const attestationStat = await fs.lstat(options.isolationAttestation);
  if (attestationStat.isSymbolicLink() || !attestationStat.isFile() || (attestationStat.mode & 0o222) !== 0) {
    throw new Error('Isolation attestation must be a read-only regular, non-symlink file.');
  }
  const attestationPath = await fs.realpath(options.isolationAttestation);
  const attestation = await readJsonLimited(attestationPath, candidateJsonLimit, 'Isolation attestation');
  const fail = (message) => { throw new Error(`Invalid isolation attestation: ${message}`); };
  if (attestation.schemaVersion !== 2 || attestation.phase !== 'pre-dispatch') fail('expected schemaVersion 2 and pre-dispatch phase.');
  if (attestation.runId !== options.runId || attestation.caseId !== options.caseId) fail('runId/caseId do not match the requested case.');
  if (!attestation.recordedAt || !Number.isFinite(Date.parse(attestation.recordedAt))) fail('recordedAt is missing or invalid.');
  if (typeof attestation.builder?.id !== 'string'
    || !/^[a-z0-9][a-z0-9._:@/-]{0,127}$/i.test(attestation.builder.id)
    || !Array.isArray(attestation.builder?.writableRoots)
    || !attestation.builder.writableRoots.length) {
    fail('builder identity or writable-root inventory is absent.');
  }
  if (attestation.isolation?.workspaceWasEmpty !== true
    || attestation.isolation?.skillWasReadOnly !== true
    || attestation.isolation?.priorArtifactsVisible !== false
    || attestation.isolation?.filesystemSandboxEnforced !== true
    || attestation.isolation?.workspaceIsExactWritableRoot !== true
    || attestation.isolation?.skillOutsideBuilderWritableRoots !== true
    || attestation.isolation?.evaluatorOutsideBuilderWritableRoots !== true
    || attestation.isolation?.promptOutsideBuilderWritableRoots !== true
    || attestation.isolation?.attestationOutsideBuilderWritableRoots !== true) {
    fail('required clean-slate isolation claims are absent.');
  }
  const workspace = await canonicalDirectory(attestation.workspace, 'Attested workspace');
  const writableRoots = [...new Set(await Promise.all(attestation.builder.writableRoots.map(
    (pathname) => canonicalDirectory(pathname, 'Attested builder writable root')
  )))].sort();
  if (writableRoots.length !== attestation.builder.writableRoots.length
    || !writableRoots.includes(workspace)) {
    fail('workspace is not one exact unique builder writable root.');
  }
  for (const [index, root] of writableRoots.entries()) {
    for (const other of writableRoots.slice(index + 1)) {
      if (isWithin(root, other) || isWithin(other, root)) fail('builder writable roots overlap.');
    }
  }
  const candidateDir = await canonicalDirectoryWithin(
    workspace,
    options.candidateDir,
    'Candidate directory'
  );
  const skill = await hashReadOnlySkill(options.skill);
  const attestedSkillRoot = await canonicalDirectory(attestation.skill?.root || '', 'Attested skill root');
  if (skill.skillRoot !== attestedSkillRoot) fail('skill root does not match.');
  if (skill.sha256 !== attestation.skill?.sha256 || skill.fileCount !== attestation.skill?.fileCount) {
    fail('skill contents changed after the pre-dispatch hash was recorded.');
  }
  if (!/^[a-f0-9]{40}$/.test(attestation.skill?.gitSha || '')
    || attestation.revision?.gitSha !== attestation.skill.gitSha
    || attestation.revision?.repositoryClean !== true
    || attestation.revision?.headMatchedRequestedSha !== true
    || attestation.revision?.trackedSkillPath !== 'skills/replicate-websites'
    || attestation.revision?.trackedSkillMatched !== true
    || attestation.revision?.trackedSkillFileCount !== skill.fileCount
    || attestation.revision?.trackedSkillSha256 !== skill.sha256) {
    fail('clean Git revision or exact tracked skill proof is absent.');
  }
  const evaluator = await hashEvaluatorHarness(repositoryRoot);
  const attestedEvaluatorRoot = await canonicalDirectory(attestation.evaluator?.root || '', 'Attested evaluator root');
  const attestedRevisionRoot = await canonicalDirectory(attestation.revision?.repositoryRoot || '', 'Attested revision repository');
  if (attestedEvaluatorRoot !== evaluator.root || attestedRevisionRoot !== evaluator.root
    || attestation.evaluator?.gitSha !== attestation.skill.gitSha
    || attestation.evaluator?.sha256 !== evaluator.sha256
    || attestation.evaluator?.fileCount !== evaluator.fileCount
    || attestation.evaluator?.totalBytes !== evaluator.totalBytes
    || attestation.evaluator?.outsideBuilderWritableRoots !== true) {
    fail('evaluator harness or revision metadata changed after dispatch.');
  }
  const promptSource = await canonicalRegularFile(attestation.prompt?.source || '', 'Attested prompt source');
  const promptCopy = await canonicalRegularFile(
    attestation.prompt?.copy || '',
    'Attested prompt copy',
    { readOnly: true }
  );
  const [promptSourceBytes, promptCopyBytes] = await Promise.all([
    readFileLimited(promptSource, promptByteLimit, 'Attested prompt source'),
    readFileLimited(promptCopy, promptByteLimit, 'Attested prompt copy')
  ]);
  const promptHash = sha256(promptCopyBytes);
  if (!promptCopyBytes.length || !promptSourceBytes.equals(promptCopyBytes)
    || attestation.prompt?.sha256 !== promptHash
    || attestation.prompt?.bytes !== promptCopyBytes.length) {
    fail('prompt source/copy/hash evidence does not match.');
  }
  for (const root of writableRoots) {
    for (const pathname of [skill.skillRoot, evaluator.root, attestationPath, promptSource, promptCopy]) {
      if (isWithin(root, pathname)) fail('protected evaluator evidence is inside a builder writable root.');
    }
  }
  if (isWithin(skill.skillRoot, attestationPath) || isWithin(evaluator.root, attestationPath)
    || isWithin(skill.skillRoot, promptCopy) || isWithin(evaluator.root, promptCopy)) {
    fail('attestation or prompt copy is inside an immutable code snapshot.');
  }
  const manifestPath = await canonicalFileWithin(candidateDir, options.manifest, 'Candidate manifest');
  const outputParent = await canonicalDirectory(dirname(options.out), 'Evaluator output parent');
  const canonicalOutput = await canonicalDirectoryWithin(
    outputParent,
    join(outputParent, basename(options.out)),
    'Evaluator output directory'
  );
  if (writableRoots.some((root) => isWithin(root, canonicalOutput))
    || isWithin(skill.skillRoot, canonicalOutput)
    || isWithin(evaluator.root, canonicalOutput)) {
    fail('evaluator output must be outside every builder writable root and immutable code snapshot.');
  }
  return {
    attestation,
    attestationPath,
    workspace,
    writableRoots,
    candidateDir,
    manifestPath,
    skill,
    evaluator,
    prompt: { source: promptSource, copy: promptCopy, bytes: promptCopyBytes, sha256: promptHash }
  };
}

export async function createCandidateEnvironment(outputDirectory, port) {
  const runtimeRoot = join(outputDirectory, 'candidate-runtime');
  const runtimeHome = join(runtimeRoot, 'home');
  const runtimeTemp = join(runtimeRoot, 'tmp');
  await fs.mkdir(runtimeHome, { recursive: true });
  await fs.mkdir(runtimeTemp, { recursive: true });
  const environment = {};
  for (const name of ['PATH', 'LANG', 'LC_ALL', 'SystemRoot', 'SYSTEMROOT', 'ComSpec', 'COMSPEC', 'PATHEXT', 'WINDIR']) {
    if (typeof process.env[name] === 'string') environment[name] = process.env[name];
  }
  Object.assign(environment, {
    HOME: runtimeHome,
    USERPROFILE: runtimeHome,
    TMPDIR: runtimeTemp,
    TMP: runtimeTemp,
    TEMP: runtimeTemp,
    PORT: String(port),
    NODE_ENV: 'test',
    CI: 'true',
    NO_COLOR: '1',
    EMAIL_CONFIRMATION_ENABLED: 'false'
  });
  return { environment, runtimeRoot };
}

function normalizedTrustedRuntimeEvidence(runtime, trustedBackend) {
  const evidence = runtime?.evidence;
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    throw new Error('Evaluator-owned backend returned no staging evidence.');
  }
  if (runtime.origin !== `http://127.0.0.1:${runtime.port}`
    || !Number.isSafeInteger(runtime.port) || runtime.port < 1 || runtime.port > 65535) {
    throw new Error('Evaluator-owned backend did not allocate an exact fresh loopback origin.');
  }
  if (typeof runtime.close !== 'function') throw new Error('Evaluator-owned backend returned no cleanup function.');
  if (evidence.launchedPath !== '[evaluator-temp]/server.mjs'
    || evidence.serverSha256 !== trustedBackend.serverSha256
    || !/^[a-f0-9]{64}$/.test(evidence.serverSha256 || '')
    || !Number.isSafeInteger(evidence.publicFileCount) || evidence.publicFileCount < 0
    || !Number.isSafeInteger(evidence.publicTotalBytes) || evidence.publicTotalBytes < 0
    || evidence.readOnlySnapshot !== true) {
    throw new Error('Evaluator-owned backend returned invalid normalized staging evidence.');
  }
  return {
    spawnedFromVerifiedBackend: true,
    suppliedCandidateProcessUsed: false,
    environmentScrubbed: true,
    freshLoopbackPort: true,
    processGroupOwned: true,
    launchedPath: evidence.launchedPath,
    serverSha256: evidence.serverSha256,
    publicFileCount: evidence.publicFileCount,
    publicTotalBytes: evidence.publicTotalBytes,
    readOnlySnapshot: true,
    stagingCleaned: false
  };
}

export async function launchEvaluatorOwnedBackend({
  candidateDir,
  manifest,
  trustedBackend,
  startRuntime,
  timeoutMs = 45000
}) {
  await validateStartCommand(manifest.start?.command, candidateDir);
  const canonicalCandidate = await canonicalDirectory(candidateDir, 'Candidate directory');
  const auditedServer = await canonicalFileWithin(
    canonicalCandidate,
    join(canonicalCandidate, 'server.mjs'),
    'Audited candidate server.mjs'
  );
  if (trustedBackend?.serverPath !== auditedServer) {
    throw new Error('Verified backend path is not the exact audited candidate server.mjs.');
  }
  if (typeof startRuntime !== 'function') throw new Error('Evaluator-owned backend staging primitive is unavailable.');
  const runtime = await startRuntime({
    candidateRoot: canonicalCandidate,
    verifiedServerPath: trustedBackend.serverPath,
    verifiedServerBytes: trustedBackend.verifiedServerBytes,
    expectedServerSha256: trustedBackend.serverSha256,
    projectName: trustedBackend.projectName,
    healthPath: manifest.start?.healthPath,
    timeoutMs
  });
  try {
    return { runtime, evidence: normalizedTrustedRuntimeEvidence(runtime, trustedBackend) };
  } catch (error) {
    await runtime?.close?.().catch(() => {});
    throw error;
  }
}

function failureCodesFor({ sourceStability, candidateDeterminism, fidelity, integrity, interaction, commandFailure }) {
  const codes = new Set();
  if (!sourceStability.pass) codes.add('SOURCE_UNSTABLE');
  if (!candidateDeterminism.pass) codes.add('CAPTURE');
  for (const viewport of fidelity.results || []) {
    for (const failure of viewport.failures || []) {
      if (failure.code === 'DIMENSIONS') codes.add('GEOMETRY');
      else if (failure.code.startsWith('PIXEL_')) codes.add('CONTENT');
      else if (failure.code.startsWith('SEMANTIC_')) codes.add('SEMANTICS');
      else if (failure.code === 'CANDIDATE_CRITICAL_RESOURCE') codes.add('ASSETS');
      else if (failure.code === 'CANDIDATE_UNSTABLE') codes.add('CAPTURE');
      else codes.add('TOOLING');
    }
  }
  if (!integrity.pass) codes.add('SAFETY');
  if (!interaction.pass) {
    codes.add('INTERACTION');
    if ((interaction.failures || []).some((failure) => /SUBMISSION|RECEIPT|EMAIL|BACKEND|LOCAL/i.test(failure.code || ''))) {
      codes.add('BACKEND');
    }
  }
  if (commandFailure.length) codes.add('TOOLING');
  return [...codes].sort();
}

function buildRunRecord(options, isolation, pass, artifactPath, failureCodes, evidence = null) {
  return {
    schemaVersion: 2,
    runId: options.runId,
    caseId: options.caseId,
    builder: { id: isolation.attestation.builder.id },
    skill: {
      gitSha: isolation.attestation.skill.gitSha,
      sha256: isolation.skill.sha256
    },
    revision: {
      gitSha: isolation.attestation.revision.gitSha,
      repositoryClean: true,
      trackedSkillMatched: true
    },
    evaluator: {
      gitSha: isolation.attestation.evaluator.gitSha,
      sha256: isolation.evaluator.sha256
    },
    isolation: {
      workspaceWasEmpty: true,
      skillWasReadOnly: true,
      priorArtifactsVisible: false,
      filesystemSandboxEnforced: true,
      protectedEvidenceOutsideBuilderWritableRoots: true
    },
    evidence: evidence ? {
      indexPath: evidence.path,
      sha256: evidence.sha256
    } : null,
    result: { pass, artifactPath, failureCodes: [...new Set(failureCodes)].sort() }
  };
}

async function ensureEmpty(pathname) {
  try {
    const stat = await fs.lstat(pathname);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(`Output path must be a real, non-symlink directory: ${pathname}`);
    }
    if ((await fs.readdir(pathname)).length) throw new Error(`Output directory is not empty: ${pathname}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fs.mkdir(pathname, { recursive: true });
}

async function runNode(script, args, options = {}) {
  try {
    const result = await execFileAsync(process.execPath, [script, ...args], {
      maxBuffer: 50 * 1024 * 1024,
      timeout: 10 * 60 * 1000,
      ...options
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return {
      code: typeof error.code === 'number' ? error.code : 1,
      stdout: error.stdout || '',
      stderr: error.stderr || error.message
    };
  }
}

function compareArguments(baseline, candidate, out, viewports, baselineReadySelector, candidateReadySelector = baselineReadySelector) {
  const args = ['--baseline', baseline, '--candidate', candidate, '--out', out, '--wait-ms', '1500'];
  if (baselineReadySelector && baselineReadySelector === candidateReadySelector) {
    args.push('--ready-selector', baselineReadySelector);
  } else {
    if (baselineReadySelector) args.push('--baseline-ready-selector', baselineReadySelector);
    if (candidateReadySelector) args.push('--candidate-ready-selector', candidateReadySelector);
  }
  for (const viewport of viewports) args.push('--viewport', viewport);
  return args;
}

async function writeCommandLog(directory, name, result) {
  await fs.writeFile(
    join(directory, `${name}.json`),
    `${JSON.stringify(redactReportData(result), null, 2)}\n`
  );
}

export async function readFileLimited(pathname, maximumBytes, label = 'File') {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new Error(`${label} size limit must be a positive safe integer.`);
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0);
  let handle;
  try {
    handle = await fs.open(pathname, flags);
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(`${label} must be a regular file.`);
    if (stat.size > maximumBytes) throw new Error(`${label} exceeds the ${maximumBytes}-byte size limit.`);
    return await handle.readFile();
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function writeReadOnly(pathname, bytes) {
  await fs.writeFile(pathname, bytes, { flag: 'wx', mode: 0o444 });
  await fs.chmod(pathname, 0o444);
}

function appendBoundedPatch(chunks, state, value) {
  const bytes = Buffer.from(value);
  if (state.bytes + bytes.length > candidateEvidenceLimits.maxPatchBytes) return false;
  chunks.push(bytes);
  state.bytes += bytes.length;
  return true;
}

export async function captureCandidateEmptyBaseEvidence(candidateDir, evidenceDirectory) {
  const canonicalCandidate = await canonicalDirectory(candidateDir, 'Candidate evidence directory');
  const discovered = [];
  async function visit(directory) {
    const entries = (await fs.readdir(directory, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const pathname = join(directory, entry.name);
      const stat = await fs.lstat(pathname);
      if (stat.isSymbolicLink()) throw new Error(`Candidate evidence refuses symbolic links: ${pathname}`);
      if (stat.isDirectory()) await visit(pathname);
      else if (stat.isFile()) discovered.push(pathname);
      else throw new Error(`Candidate evidence refuses unsupported filesystem entries: ${pathname}`);
      if (discovered.length > candidateEvidenceLimits.maxFiles) {
        throw new Error(`Candidate evidence exceeds the ${candidateEvidenceLimits.maxFiles}-file limit.`);
      }
    }
  }
  await visit(canonicalCandidate);
  if (!discovered.length) throw new Error('Candidate evidence cannot attest an empty candidate directory.');

  const files = [];
  const patchChunks = [];
  const patchState = { bytes: 0 };
  let totalBytes = 0;
  let embeddedTextFiles = 0;
  let omittedContentFiles = 0;
  for (const pathname of discovered.sort()) {
    const relativePath = relative(canonicalCandidate, pathname);
    const bytes = await readFileLimited(pathname, candidateEvidenceLimits.maxFileBytes, `Candidate file ${relativePath}`);
    totalBytes += bytes.length;
    if (totalBytes > candidateEvidenceLimits.maxTotalBytes) {
      throw new Error(`Candidate evidence exceeds the ${candidateEvidenceLimits.maxTotalBytes}-byte aggregate limit.`);
    }
    const stat = await fs.lstat(pathname);
    const fileHash = sha256(bytes);
    let text = null;
    if (bytes.length <= candidateEvidenceLimits.maxEmbeddedTextBytes && !bytes.includes(0)) {
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        text = null;
      }
    }
    const mode = (stat.mode & 0o111) !== 0 ? '100755' : '100644';
    const header = [
      `diff --replicate-empty-base ${JSON.stringify(relativePath)}\n`,
      `new file mode ${mode}\n`,
      `sha256 ${fileHash}\n`,
      `size ${bytes.length}\n`
    ].join('');
    let contentIncluded = false;
    if (appendBoundedPatch(patchChunks, patchState, header)) {
      if (text !== null) {
        const body = `content utf8\n${text}${text.endsWith('\n') ? '' : '\n'}end content\n\n`;
        contentIncluded = appendBoundedPatch(patchChunks, patchState, body);
      }
      if (!contentIncluded) {
        appendBoundedPatch(
          patchChunks,
          patchState,
          `content omitted; verify with sha256 (${text === null ? 'binary-or-large' : 'patch-bound'})\n\n`
        );
      }
    }
    if (contentIncluded) embeddedTextFiles += 1;
    else omittedContentFiles += 1;
    files.push({ path: relativePath, bytes: bytes.length, sha256: fileHash, mode, contentIncluded });
  }
  const patchBytes = Buffer.concat(patchChunks, patchState.bytes);
  const aggregate = createHash('sha256');
  for (const file of files) {
    aggregate.update(file.path);
    aggregate.update('\0');
    aggregate.update(file.sha256);
    aggregate.update('\0');
    aggregate.update(file.mode);
    aggregate.update('\0');
  }
  const patchPath = join(evidenceDirectory, 'candidate-empty-base.patch');
  const inventoryPath = join(evidenceDirectory, 'candidate-files.json');
  const inventory = {
    schemaVersion: 1,
    base: 'empty-directory',
    bounds: candidateEvidenceLimits,
    completeFileHashInventory: true,
    fileCount: files.length,
    totalBytes,
    aggregateSha256: aggregate.digest('hex'),
    patch: {
      format: 'replicate-empty-base-v1',
      bytes: patchBytes.length,
      sha256: sha256(patchBytes),
      embeddedTextFiles,
      omittedContentFiles
    },
    files
  };
  const inventoryBytes = Buffer.from(`${JSON.stringify(inventory, null, 2)}\n`);
  await writeReadOnly(patchPath, patchBytes);
  await writeReadOnly(inventoryPath, inventoryBytes);
  return {
    inventory,
    inventoryPath,
    inventorySha256: sha256(inventoryBytes),
    patchPath,
    patchSha256: inventory.patch.sha256
  };
}

export async function emitEvaluatorOwnedEvidence({
  outputDirectory,
  isolation,
  evaluatorCase,
  manifestBytes
}) {
  const evidenceDirectory = join(outputDirectory, 'evidence');
  await fs.mkdir(evidenceDirectory, { recursive: false });
  const promptPath = join(evidenceDirectory, 'prompt.txt');
  const manifestPath = join(evidenceDirectory, 'manifest.json');
  const targetPath = join(evidenceDirectory, 'target-and-viewports.json');
  const evaluatorPath = join(evidenceDirectory, 'evaluator-revision.json');
  const targetBytes = Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    caseId: evaluatorCase.id,
    label: evaluatorCase.label,
    targetUrl: evaluatorCase.url,
    readySelector: evaluatorCase.readySelector,
    viewports: evaluatorCase.viewports
  }, null, 2)}\n`);
  const evaluatorBytes = Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    recordedRevision: isolation.attestation.revision,
    evaluator: isolation.attestation.evaluator,
    revalidatedEvaluator: isolation.evaluator,
    skill: {
      gitSha: isolation.attestation.skill.gitSha,
      sha256: isolation.skill.sha256,
      fileCount: isolation.skill.fileCount
    },
    builder: isolation.attestation.builder,
    isolation: isolation.attestation.isolation
  }, null, 2)}\n`);
  await Promise.all([
    writeReadOnly(promptPath, isolation.prompt.bytes),
    writeReadOnly(manifestPath, manifestBytes),
    writeReadOnly(targetPath, targetBytes),
    writeReadOnly(evaluatorPath, evaluatorBytes)
  ]);
  const candidate = await captureCandidateEmptyBaseEvidence(isolation.candidateDir, evidenceDirectory);
  const indexPath = join(evidenceDirectory, 'index.json');
  const index = {
    schemaVersion: 1,
    evaluatorOwned: true,
    prompt: { path: promptPath, bytes: isolation.prompt.bytes.length, sha256: isolation.prompt.sha256 },
    targetAndViewports: { path: targetPath, bytes: targetBytes.length, sha256: sha256(targetBytes) },
    manifest: { path: manifestPath, bytes: manifestBytes.length, sha256: sha256(manifestBytes) },
    candidateInventory: {
      path: candidate.inventoryPath,
      sha256: candidate.inventorySha256,
      fileCount: candidate.inventory.fileCount,
      totalBytes: candidate.inventory.totalBytes,
      aggregateSha256: candidate.inventory.aggregateSha256
    },
    candidateEmptyBasePatch: {
      path: candidate.patchPath,
      sha256: candidate.patchSha256,
      bytes: candidate.inventory.patch.bytes,
      omittedContentFiles: candidate.inventory.patch.omittedContentFiles
    },
    evaluatorRevision: { path: evaluatorPath, bytes: evaluatorBytes.length, sha256: sha256(evaluatorBytes) },
    diagnosis: { path: join(outputDirectory, 'diagnosis.json'), required: true }
  };
  const indexBytes = Buffer.from(`${JSON.stringify(index, null, 2)}\n`);
  await writeReadOnly(indexPath, indexBytes);
  return { directory: evidenceDirectory, path: indexPath, sha256: sha256(indexBytes), index };
}

export async function finalizeEvaluatorOwnedEvidence(evidence, diagnosisPath) {
  if (!evidence) return null;
  if (evidence.completed === true) return evidence;
  const diagnosisBytes = await readFileLimited(
    diagnosisPath,
    evaluatorArtifactJsonLimit,
    'Evaluator diagnosis evidence'
  );
  const completedIndex = {
    ...evidence.index,
    diagnosis: {
      path: diagnosisPath,
      required: true,
      bytes: diagnosisBytes.length,
      sha256: sha256(diagnosisBytes)
    },
    initialIndex: { path: evidence.path, sha256: evidence.sha256 }
  };
  const completedBytes = Buffer.from(`${JSON.stringify(completedIndex, null, 2)}\n`);
  const completedPath = join(evidence.directory, 'complete-index.json');
  await writeReadOnly(completedPath, completedBytes);
  await fs.chmod(diagnosisPath, 0o444);
  return {
    ...evidence,
    initialPath: evidence.path,
    initialSha256: evidence.sha256,
    path: completedPath,
    sha256: sha256(completedBytes),
    index: completedIndex,
    completed: true
  };
}

export async function readJsonLimited(pathname, maximumBytes = candidateJsonLimit, label = 'JSON file') {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new Error(`${label} size limit must be a positive safe integer.`);
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0);
  let handle;
  try {
    handle = await fs.open(pathname, flags);
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(`${label} must be a regular file.`);
    if (stat.size > maximumBytes) {
      throw new Error(`${label} exceeds the ${maximumBytes}-byte size limit.`);
    }
    const chunks = [];
    let total = 0;
    while (total <= maximumBytes) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (!bytesRead) break;
      total += bytesRead;
      if (total > maximumBytes) {
        throw new Error(`${label} exceeds the ${maximumBytes}-byte size limit.`);
      }
      chunks.push(chunk.subarray(0, bytesRead));
    }
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node run-case.mjs --run-id ID --case-id ID --isolation-attestation FILE --target-url URL --candidate-dir DIR --out DIR [options]\n');
    return;
  }
  await ensureEmpty(options.out);
  let isolation = null;
  let evaluatorEvidence = null;
  try {
  isolation = await validateIsolationAttestation(options);
  options.targetUrl = validateTargetUrl(options.targetUrl);
  const evaluatorCase = await resolveEvaluatorCase(options);
  options.targetUrl = evaluatorCase.url;
  options.readySelector = evaluatorCase.readySelector;
  options.viewports = evaluatorCase.viewports;
  options.candidateDir = isolation.candidateDir;
  options.manifest = isolation.manifestPath;
  const manifestBytes = await readFileLimited(isolation.manifestPath, candidateJsonLimit, 'Candidate manifest');
  const manifest = validateAuthorizedLocalManifest(JSON.parse(manifestBytes.toString('utf8')));
  evaluatorEvidence = await emitEvaluatorOwnedEvidence({
    outputDirectory: options.out,
    isolation,
    evaluatorCase,
    manifestBytes
  });
  const validationOrigin = 'http://127.0.0.1:1';
  resolveLoopbackManifestPath(manifest.page?.path, '/', validationOrigin, 'Manifest page.path');
  resolveLoopbackManifestPath(manifest.start.healthPath, '/healthz', validationOrigin, 'Manifest start.healthPath');
  const backendModule = await import(pathToFileURL(join(
    options.skill,
    'scripts',
    'lib',
    'trusted-backend.mjs'
  )).href);
  const trustedBackend = await backendModule.verifyTrustedBackend({
    candidateRoot: options.candidateDir,
    skillRoot: options.skill,
    manifest
  });
  const backendProcessModule = await import(pathToFileURL(join(
    options.skill,
    'scripts',
    'lib',
    'trusted-backend-process.mjs'
  )).href);
  const evaluatorPolicyPath = join(repositoryRoot, 'evals/policies/exact.json');
  options.policy = await resolveCandidatePolicyPath(
    options.candidateDir,
    options.policy,
    evaluatorPolicyPath
  );
  const evaluatorPolicy = await readJsonLimited(evaluatorPolicyPath, candidateJsonLimit, 'Evaluator fidelity policy');
  const candidatePolicy = await readJsonLimited(options.policy, candidateJsonLimit, 'Candidate fidelity policy');
  const effectivePolicy = buildEffectiveFidelityPolicy(
    candidatePolicy,
    evaluatorPolicy,
    options.viewports.map((viewport) => String(viewport).split(':', 1)[0])
  );
  const effectivePolicyPath = join(options.out, 'effective-fidelity-policy.json');
  await fs.writeFile(effectivePolicyPath, `${JSON.stringify(effectivePolicy, null, 2)}\n`);
  const launchedBackend = await launchEvaluatorOwnedBackend({
    candidateDir: options.candidateDir,
    manifest,
    trustedBackend,
    startRuntime: backendProcessModule.startTrustedBackend
  });
  const runtime = launchedBackend.runtime;
  const trustedRuntime = launchedBackend.evidence;
  const candidateRuntimeEvidencePath = join(options.out, 'candidate-runtime.json');
  let result;
  try {
    const origin = runtime.origin;
    const candidateUrl = resolveLoopbackManifestPath(manifest.page?.path, '/', origin, 'Manifest page.path');
    if (new URL(options.targetUrl).origin === origin) throw new Error('Source and candidate origins must be distinct.');
    const tools = {
      compare: join(options.skill, 'scripts/compare-pages.mjs'),
      assert: join(options.skill, 'scripts/assert-fidelity.mjs'),
      inspect: join(options.skill, 'scripts/inspect-page.mjs'),
      integrity: join(options.skill, 'scripts/check-candidate-integrity.mjs'),
      interaction: join(options.skill, 'scripts/test-application-flow.mjs'),
      diagnose: join(options.skill, 'scripts/diagnose-diff.mjs')
    };
    const sourceSelf = join(options.out, 'source-self');
    const candidateSelf = join(options.out, 'candidate-self');
    const sourceCandidate = join(options.out, 'source-candidate');
    const candidateInspection = join(options.out, 'candidate-inspection');
    const commands = {};
    commands.sourceSelf = await runNode(tools.compare,
      compareArguments(options.targetUrl, options.targetUrl, sourceSelf, options.viewports, options.readySelector));
    await writeCommandLog(options.out, 'source-self-command', commands.sourceSelf);
    commands.candidateSelf = await runNode(tools.compare,
      compareArguments(candidateUrl, candidateUrl, candidateSelf, options.viewports, manifest.page?.readySelector || 'body'));
    await writeCommandLog(options.out, 'candidate-self-command', commands.candidateSelf);
    commands.sourceCandidate = await runNode(tools.compare,
      compareArguments(
        options.targetUrl,
        candidateUrl,
        sourceCandidate,
        options.viewports,
        options.readySelector,
        manifest.page?.readySelector || 'body'
      ));
    await writeCommandLog(options.out, 'source-candidate-command', commands.sourceCandidate);
    if (Object.values(commands).some((commandResult) => commandResult.code !== 0)) {
      throw new Error('At least one comparison command failed; inspect command logs.');
    }

    const inspectArguments = [
      '--url', candidateUrl,
      '--out', candidateInspection,
      '--ready-selector', manifest.page?.readySelector || 'body',
      '--wait-ms', '750'
    ];
    for (const viewport of options.viewports) inspectArguments.push('--viewport', viewport);
    commands.inspect = await runNode(tools.inspect, inspectArguments);
    await writeCommandLog(options.out, 'inspect-command', commands.inspect);

    const diagnosisPath = join(options.out, 'diagnosis.json');
    commands.diagnosis = await runNode(tools.diagnose, [
      '--report', sourceCandidate,
      '--candidate-contract', candidateInspection,
      '--out', diagnosisPath
    ]);
    await writeCommandLog(options.out, 'diagnosis-command', commands.diagnosis);

    const sourceStabilityScore = join(options.out, 'source-stability-score.json');
    commands.sourceStabilityAssert = await runNode(tools.assert, [
      '--summary', join(sourceSelf, 'summary.json'),
      '--policy', join(repositoryRoot, 'evals/policies/source-stability.json'),
      '--out', sourceStabilityScore
    ]);
    await writeCommandLog(options.out, 'source-stability-assert-command', commands.sourceStabilityAssert);

    const candidateSelfScore = join(options.out, 'candidate-self-score.json');
    commands.candidateSelfAssert = await runNode(tools.assert, [
      '--summary', join(candidateSelf, 'summary.json'),
      '--out', candidateSelfScore,
      '--max-tolerant', '0',
      '--max-strict', '0',
      '--max-semantic', '0'
    ]);
    await writeCommandLog(options.out, 'candidate-self-assert-command', commands.candidateSelfAssert);

    const fidelityScore = join(options.out, 'fidelity-score.json');
    commands.fidelityAssert = await runNode(tools.assert, [
      '--summary', join(sourceCandidate, 'summary.json'),
      '--policy', effectivePolicyPath,
      '--out', fidelityScore
    ]);
    await writeCommandLog(options.out, 'fidelity-assert-command', commands.fidelityAssert);

    const integrityPath = join(options.out, 'integrity.json');
    commands.integrity = await runNode(tools.integrity, [
      '--inspection', candidateInspection,
      '--source', options.targetUrl,
      '--manifest', options.manifest,
      '--out', integrityPath
    ]);
    await writeCommandLog(options.out, 'integrity-command', commands.integrity);

    const interactionPath = join(options.out, 'interaction.json');
    commands.interaction = await runNode(tools.interaction, [
      '--candidate', candidateUrl,
      '--manifest', options.manifest,
      '--out', interactionPath
    ]);
    await writeCommandLog(options.out, 'interaction-command', commands.interaction);

    const [sourceSummary, sourceStability, deterministicScore, score, integrity, interaction, diagnosis] = await Promise.all([
      readJsonLimited(join(sourceSelf, 'summary.json'), evaluatorArtifactJsonLimit, 'Source stability summary'),
      readJsonLimited(sourceStabilityScore, evaluatorArtifactJsonLimit, 'Source stability score'),
      readJsonLimited(candidateSelfScore, evaluatorArtifactJsonLimit, 'Candidate determinism score'),
      readJsonLimited(fidelityScore, evaluatorArtifactJsonLimit, 'Fidelity score'),
      readJsonLimited(integrityPath, evaluatorArtifactJsonLimit, 'Integrity report'),
      readJsonLimited(interactionPath, evaluatorArtifactJsonLimit, 'Interaction report'),
      readJsonLimited(diagnosisPath, evaluatorArtifactJsonLimit, 'Diagnosis report')
    ]);
    const commandFailure = Object.entries(commands)
      .filter(([, commandResult]) => ![0, 2].includes(commandResult.code))
      .map(([name, commandResult]) => ({ name, code: commandResult.code }));
    evaluatorEvidence = await finalizeEvaluatorOwnedEvidence(evaluatorEvidence, diagnosisPath);
    const pass = sourceStability.pass && deterministicScore.pass && score.pass
      && integrity.pass && interaction.pass && commandFailure.length === 0;
    const failureCodes = failureCodesFor({
      sourceStability,
      candidateDeterminism: deterministicScore,
      fidelity: score,
      integrity,
      interaction,
      commandFailure
    });
    await runtime.close();
    trustedRuntime.stagingCleaned = true;
    await fs.writeFile(
      candidateRuntimeEvidencePath,
      `${JSON.stringify(trustedRuntime, null, 2)}\n`
    );
    const resultPath = join(options.out, 'result.json');
    const runRecordPath = join(options.out, 'run-record.json');
    result = redactReportData({
      schemaVersion: 2,
      generatedAt: new Date().toISOString(),
      runId: options.runId,
      caseId: options.caseId,
      targetUrl: options.targetUrl,
      evaluatorCase,
      candidateUrl,
      candidateDir: options.candidateDir,
      skill: {
        root: isolation.skill.skillRoot,
        gitSha: isolation.attestation.skill.gitSha,
        sha256: isolation.skill.sha256
      },
      revision: isolation.attestation.revision,
      evaluator: isolation.attestation.evaluator,
      builder: isolation.attestation.builder,
      policy: {
        candidate: options.policy,
        effective: effectivePolicyPath,
        evaluatorGates: evaluatorPolicyPath
      },
      viewports: options.viewports,
      isolationAttestation: isolation.attestationPath,
      trustedBackend,
      trustedRuntime,
      pass,
      sourceStability,
      sourceRepeatMetrics: sourceSummary.results.map((entry) => ({
        viewport: entry.viewport,
        strictDiffPercent: entry.pixel.strictDiffPercent,
        tolerantDiffPercent: entry.pixel.tolerantDiffPercent,
        dimensionsMatch: entry.pixel.dimensionsMatch
      })),
      candidateDeterminism: deterministicScore,
      fidelity: score,
      integrity,
      interaction,
      diagnosis,
      commandFailure,
      evidence: evaluatorEvidence,
      artifactPaths: {
        sourceSelf,
        candidateSelf,
        sourceCandidate,
        candidateInspection,
        candidateRuntime: candidateRuntimeEvidencePath,
        diagnosis: diagnosisPath,
        evidenceIndex: evaluatorEvidence.path
      }
    });
    const runRecord = buildRunRecord(options, isolation, pass, resultPath, failureCodes, evaluatorEvidence);
    await fs.writeFile(resultPath, `${JSON.stringify(result, null, 2)}\n`);
    await fs.writeFile(runRecordPath, `${JSON.stringify(runRecord, null, 2)}\n`);
    process.stdout.write(`${JSON.stringify({ pass, result: resultPath, runRecord: runRecordPath }, null, 2)}\n`);
    if (!pass) process.exitCode = 2;
  } finally {
    await runtime.close();
    trustedRuntime.stagingCleaned = true;
    await fs.writeFile(
      candidateRuntimeEvidencePath,
      `${JSON.stringify(trustedRuntime, null, 2)}\n`
    );
    await fs.writeFile(
      join(options.out, 'candidate-server.log'),
      'Evaluator launched only the staged audited backend; candidate-selected process output is unavailable by design.\n'
    );
  }
  } catch (error) {
    if (isolation) {
      if (evaluatorEvidence && evaluatorEvidence.completed !== true) {
        let failureDiagnosisPath = join(options.out, 'diagnosis.json');
        try {
          await fs.lstat(failureDiagnosisPath);
          failureDiagnosisPath = join(options.out, 'diagnosis-failure.json');
        } catch (statError) {
          if (statError.code !== 'ENOENT') throw statError;
        }
        const failureDiagnosis = redactReportData({
          schemaVersion: 1,
          generatedAt: new Date().toISOString(),
          available: false,
          reason: 'evaluation stopped before a complete visual diagnosis could be produced',
          error: { name: error.name || 'Error', message: error.message || String(error) }
        });
        await writeReadOnly(
          failureDiagnosisPath,
          Buffer.from(`${JSON.stringify(failureDiagnosis, null, 2)}\n`)
        );
        evaluatorEvidence = await finalizeEvaluatorOwnedEvidence(evaluatorEvidence, failureDiagnosisPath);
      }
      const resultPath = join(options.out, 'result.json');
      const runRecordPath = join(options.out, 'run-record.json');
      const failureCodes = /manifest|loopback|candidate origins|start\.command|trusted backend|server\.mjs|package\.json|size limit|credential|sensitive query|nested URL|symbolic link|fidelity policy|semantic approval|evaluator-owned gate|evaluator-owned case|isolation attestation|writable root|revision|prompt evidence/i.test(error.message)
        ? ['SAFETY']
        : ['TOOLING'];
      const failureResult = redactReportData({
        schemaVersion: 2,
        generatedAt: new Date().toISOString(),
        runId: options.runId,
        caseId: options.caseId,
        targetUrl: options.targetUrl,
        candidateDir: options.candidateDir,
        isolationAttestation: isolation.attestationPath,
        revision: isolation.attestation.revision,
        evaluator: isolation.attestation.evaluator,
        builder: isolation.attestation.builder,
        evidence: evaluatorEvidence,
        pass: false,
        error: { name: error.name || 'Error', message: error.message || String(error) }
      });
      await fs.writeFile(resultPath, `${JSON.stringify(failureResult, null, 2)}\n`);
      await fs.writeFile(
        runRecordPath,
        `${JSON.stringify(buildRunRecord(options, isolation, false, resultPath, failureCodes, evaluatorEvidence), null, 2)}\n`
      );
    }
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}
