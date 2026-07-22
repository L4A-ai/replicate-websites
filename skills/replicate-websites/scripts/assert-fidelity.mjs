#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import { resolve } from 'node:path';

function usage() {
  return `Assert a compare-pages summary against explicit fidelity gates.

Usage:
  node assert-fidelity.mjs --summary REPORT/summary.json [options]

Options:
  --policy FILE              JSON policy with gates and approved semantic fingerprints
  --out FILE                 Write the machine-readable score
  --max-tolerant N           Override tolerant diff percentage
  --max-strict N             Override strict diff percentage
  --max-semantic N           Override unapproved semantic mismatch count
  --help                     Show this message

Defaults without a policy: tolerant <= 0.15%, strict <= 2%, zero unapproved
semantic mismatches, exact dimensions, stable candidate layout, zero masks,
zero candidate critical-resource failures, and zero candidate page errors.
`;
}

function parseNumber(value, option) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${option} expects a non-negative number.`);
  return parsed;
}

function parseArguments(argv) {
  const options = {
    summary: null,
    policy: null,
    out: null,
    maxTolerant: null,
    maxStrict: null,
    maxSemantic: null,
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
      case '--summary': options.summary = resolve(take(index, argument)); index += 1; break;
      case '--policy': options.policy = resolve(take(index, argument)); index += 1; break;
      case '--out': options.out = resolve(take(index, argument)); index += 1; break;
      case '--max-tolerant': options.maxTolerant = parseNumber(take(index, argument), argument); index += 1; break;
      case '--max-strict': options.maxStrict = parseNumber(take(index, argument), argument); index += 1; break;
      case '--max-semantic': options.maxSemantic = parseNumber(take(index, argument), argument); index += 1; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && !options.summary) throw new Error('--summary is required.');
  return options;
}

async function readJson(pathname) {
  return JSON.parse(await fs.readFile(pathname, 'utf8'));
}

const gateFields = new Set([
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
]);

function validateGateObject(gates, label) {
  if (gates === undefined) return;
  if (!gates || typeof gates !== 'object' || Array.isArray(gates)) throw new Error(`${label} must be an object.`);
  for (const [name, value] of Object.entries(gates)) {
    if (!gateFields.has(name)) throw new Error(`${label} contains unknown gate "${name}".`);
    if (name.startsWith('require')) {
      if (typeof value !== 'boolean') throw new Error(`${label}.${name} must be boolean.`);
    } else if (!Number.isFinite(value) || value < 0) {
      throw new Error(`${label}.${name} must be a non-negative number.`);
    }
  }
}

function validateApprovalRule(rule, index) {
  const label = `approvedSemanticMismatches[${index}]`;
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) throw new Error(`${label} must be an object.`);
  const allowed = new Set(['viewport', 'category', 'kind', 'key', 'changeFields', 'rationale']);
  for (const name of Object.keys(rule)) {
    if (!allowed.has(name)) throw new Error(`${label} contains unknown field "${name}".`);
  }
  for (const name of ['viewport', 'category', 'kind', 'key', 'rationale']) {
    if (typeof rule[name] !== 'string' || !rule[name].trim()) throw new Error(`${label}.${name} must be a non-empty string.`);
  }
  if (rule.viewport === '*') throw new Error(`${label}.viewport must name one exact viewport, not "*".`);
  if (!['missing', 'extra', 'changed'].includes(rule.kind)) throw new Error(`${label}.kind must be missing, extra, or changed.`);
  if (rule.kind === 'changed') {
    if (!Array.isArray(rule.changeFields) || !rule.changeFields.length
      || rule.changeFields.some((field) => typeof field !== 'string' || !field.trim())
      || new Set(rule.changeFields).size !== rule.changeFields.length) {
      throw new Error(`${label}.changeFields must be a nonempty array of unique field names for a changed mismatch.`);
    }
  } else if (rule.changeFields !== undefined) {
    throw new Error(`${label}.changeFields is allowed only for changed mismatches.`);
  }
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('Policy must be an object.');
  if (policy.schemaVersion !== 1) throw new Error('Policy schemaVersion must be 1.');
  const allowed = new Set(['schemaVersion', 'provenance', 'gates', 'viewportGates', 'approvedSemanticMismatches']);
  for (const name of Object.keys(policy)) {
    if (!allowed.has(name)) throw new Error(`Policy contains unknown field "${name}".`);
  }
  validateGateObject(policy.gates, 'policy.gates');
  if (policy.viewportGates !== undefined) {
    if (!policy.viewportGates || typeof policy.viewportGates !== 'object' || Array.isArray(policy.viewportGates)) {
      throw new Error('policy.viewportGates must be an object.');
    }
    for (const [viewport, gates] of Object.entries(policy.viewportGates)) {
      if (!viewport.trim()) throw new Error('policy.viewportGates may not contain an empty viewport name.');
      validateGateObject(gates, `policy.viewportGates.${viewport}`);
    }
  }
  if (policy.approvedSemanticMismatches !== undefined && !Array.isArray(policy.approvedSemanticMismatches)) {
    throw new Error('policy.approvedSemanticMismatches must be an array.');
  }
  if ((policy.approvedSemanticMismatches || []).length > 1000) throw new Error('Policy contains too many semantic approvals.');
  (policy.approvedSemanticMismatches || []).forEach(validateApprovalRule);
}

function flattenSemantic(semantic) {
  const mismatches = [];
  for (const category of semantic.categories || []) {
    for (const entry of category.missing || []) {
      mismatches.push({ category: category.kind, kind: 'missing', key: typeof entry === 'string' ? entry : entry.key, changes: {} });
    }
    for (const entry of category.extra || []) {
      mismatches.push({ category: category.kind, kind: 'extra', key: typeof entry === 'string' ? entry : entry.key, changes: {} });
    }
    for (const entry of category.changed || []) {
      mismatches.push({ category: category.kind, kind: 'changed', key: entry.key, changes: entry.changes || {} });
    }
  }
  return mismatches;
}

function matchRule(mismatch, rule, viewportName) {
  if (rule.viewport !== viewportName
    || rule.category !== mismatch.category
    || rule.kind !== mismatch.kind
    || rule.key !== mismatch.key) return false;
  if (rule.kind === 'changed') {
    const expected = [...rule.changeFields].sort();
    const actual = Object.keys(mismatch.changes || {}).sort();
    if (JSON.stringify(expected) !== JSON.stringify(actual)) return false;
  }
  return true;
}

function candidateCriticalFailures(result) {
  const byType = result.candidate?.telemetry?.failedGetResourcesByType || {};
  return ['document', 'stylesheet', 'font'].reduce((total, type) => total + Number(byType[type] || 0), 0);
}

function mergedGates(policy, viewportName, options) {
  const defaults = {
    maxTolerantDiffPercent: 0.15,
    maxStrictDiffPercent: 2,
    maxUnapprovedSemanticMismatches: 0,
    requireDimensionsMatch: true,
    requireCandidateStable: true,
    maxMaskedPixels: 0,
    maxCandidateCriticalFailures: 0,
    maxCandidatePageErrors: 0,
    maxCandidateConsoleErrors: 0,
    maxCandidateBlockedWrites: 0,
    maxCandidateBlockedPrivateReads: 0
  };
  const gates = {
    ...defaults,
    ...(policy.gates || {}),
    ...(policy.viewportGates?.[viewportName] || {})
  };
  if (options.maxTolerant !== null) gates.maxTolerantDiffPercent = options.maxTolerant;
  if (options.maxStrict !== null) gates.maxStrictDiffPercent = options.maxStrict;
  if (options.maxSemantic !== null) gates.maxUnapprovedSemanticMismatches = options.maxSemantic;
  return gates;
}

function evaluateResult(result, policy, options) {
  const viewportName = result.viewport?.name || 'unknown';
  const gates = mergedGates(policy, viewportName, options);
  const rawMismatches = flattenSemantic(result.semantic || {});
  const approvals = policy.approvedSemanticMismatches || [];
  const approved = [];
  const unapproved = [];
  for (const mismatch of rawMismatches) {
    const matchedRule = approvals.find((rule) => matchRule(mismatch, rule, viewportName));
    if (matchedRule) approved.push({ ...mismatch, rationale: matchedRule.rationale });
    else unapproved.push(mismatch);
  }
  const failures = [];
  const check = (condition, code, evidence) => {
    if (!condition) failures.push({ code, evidence });
  };
  const baselineNativeApiTampering = Array.isArray(result.semantic?.captureIntegrity?.baseline)
    ? result.semantic.captureIntegrity.baseline
    : ['capture-integrity-evidence-missing'];
  const candidateNativeApiTampering = Array.isArray(result.semantic?.captureIntegrity?.candidate)
    ? result.semantic.captureIntegrity.candidate
    : ['capture-integrity-evidence-missing'];
  check(baselineNativeApiTampering.length === 0,
    'BASELINE_CAPTURE_API_TAMPERING', baselineNativeApiTampering);
  check(candidateNativeApiTampering.length === 0,
    'CANDIDATE_CAPTURE_API_TAMPERING', candidateNativeApiTampering);
  check(!gates.requireDimensionsMatch || result.pixel?.dimensionsMatch === true,
    'DIMENSIONS', result.pixel?.dimensionsMatch);
  check(Number(result.pixel?.tolerantDiffPercent) <= gates.maxTolerantDiffPercent,
    'PIXEL_TOLERANT', result.pixel?.tolerantDiffPercent);
  check(Number(result.pixel?.strictDiffPercent) <= gates.maxStrictDiffPercent,
    'PIXEL_STRICT', result.pixel?.strictDiffPercent);
  check(!gates.requireCandidateStable || result.candidate?.stability?.stable === true,
    'CANDIDATE_UNSTABLE', result.candidate?.stability);
  check(Number(result.pixel?.maskedOnEitherPixels || 0) <= gates.maxMaskedPixels,
    'MASKED_PIXELS', result.pixel?.maskedOnEitherPixels || 0);
  check(candidateCriticalFailures(result) <= gates.maxCandidateCriticalFailures,
    'CANDIDATE_CRITICAL_RESOURCE', result.candidate?.telemetry?.failedGetResourcesByType || {});
  check(Number(result.candidate?.telemetry?.pageErrors || 0) <= gates.maxCandidatePageErrors,
    'CANDIDATE_PAGE_ERROR', result.candidate?.telemetry?.pageErrors || 0);
  check(Number(result.candidate?.telemetry?.consoleErrors || 0) <= gates.maxCandidateConsoleErrors,
    'CANDIDATE_CONSOLE_ERROR', result.candidate?.telemetry?.consoleErrors || 0);
  check((result.candidate?.telemetry?.blockedWrites || []).length <= gates.maxCandidateBlockedWrites,
    'CANDIDATE_BLOCKED_WRITE_ATTEMPT', result.candidate?.telemetry?.blockedWrites || []);
  check((result.candidate?.telemetry?.blockedPrivateReads || []).length <= gates.maxCandidateBlockedPrivateReads,
    'CANDIDATE_BLOCKED_PRIVATE_READ_ATTEMPT', result.candidate?.telemetry?.blockedPrivateReads || []);
  check(unapproved.length <= gates.maxUnapprovedSemanticMismatches,
    'SEMANTIC_UNAPPROVED', { count: unapproved.length, first: unapproved.slice(0, 20) });
  check(rawMismatches.length === Number(result.semantic?.mismatchCount || 0),
    'SEMANTIC_DETAILS_TRUNCATED', {
      reported: result.semantic?.mismatchCount || 0,
      retained: rawMismatches.length
    });
  return {
    viewport: result.viewport,
    pass: failures.length === 0,
    gates,
    metrics: {
      dimensionsMatch: result.pixel?.dimensionsMatch,
      strictChangedPixels: result.pixel?.strictChangedPixels,
      strictDiffPercent: result.pixel?.strictDiffPercent,
      tolerantChangedPixels: result.pixel?.tolerantChangedPixels,
      tolerantDiffPercent: result.pixel?.tolerantDiffPercent,
      maskedOnEitherPixels: result.pixel?.maskedOnEitherPixels,
      candidateStable: result.candidate?.stability?.stable,
      candidateCriticalFailures: candidateCriticalFailures(result),
      candidatePageErrors: result.candidate?.telemetry?.pageErrors || 0,
      candidateConsoleErrors: result.candidate?.telemetry?.consoleErrors || 0,
      candidateBlockedWrites: (result.candidate?.telemetry?.blockedWrites || []).length,
      candidateBlockedPrivateReads: (result.candidate?.telemetry?.blockedPrivateReads || []).length,
      baselineCaptureApiTampering: baselineNativeApiTampering.length,
      candidateCaptureApiTampering: candidateNativeApiTampering.length,
      rawSemanticMismatchCount: result.semantic?.mismatchCount || 0,
      approvedSemanticMismatchCount: approved.length,
      unapprovedSemanticMismatchCount: unapproved.length
    },
    approvedSemanticMismatches: approved,
    unapprovedSemanticMismatches: unapproved,
    failures
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  const summary = await readJson(options.summary);
  const policy = options.policy ? await readJson(options.policy) : { schemaVersion: 1 };
  validatePolicy(policy);
  if (!Array.isArray(summary.results) || !summary.results.length) throw new Error('Summary has no viewport results.');
  const results = summary.results.map((result) => evaluateResult(result, policy, options));
  const score = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    sourceSummary: options.summary,
    sourcePolicy: options.policy,
    pass: results.every((result) => result.pass),
    results
  };
  const serialized = `${JSON.stringify(score, null, 2)}\n`;
  if (options.out) await fs.writeFile(options.out, serialized);
  process.stdout.write(serialized);
  if (!score.pass) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
