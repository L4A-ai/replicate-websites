#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const defaultSkill = join(repositoryRoot, 'skills/pixel-by-pixel');
const defaultPrompt = join(repositoryRoot, 'evals/prompt.txt');
const trackedSkillPath = 'skills/pixel-by-pixel';
const gitShaPattern = /^[a-f0-9]{40}$/;
const promptByteLimit = 64 * 1024;
const execFileAsync = promisify(execFile);

function usage() {
  return `Create a pre-dispatch clean-slate evaluation attestation.

Usage:
  node init-case.mjs --run-id ID --case-id ID --workspace DIR --attestation FILE \\
    --git-sha SHA --builder-id ID --builder-writable-root DIR \\
    --filesystem-sandbox-enforced [options]

Options:
  --skill DIR       Immutable skill snapshot (default: repository skill)
  --prompt FILE     Exact prompt dispatched to the builder (default: evals/prompt.txt)
  --git-sha SHA     Required full 40-hex clean repository HEAD
  --builder-id ID   Stable identifier for the fresh builder/agent
  --builder-writable-root DIR
                    Writable root granted to the builder (repeatable)
  --filesystem-sandbox-enforced
                    Assert that the listed writable roots are enforced by the launcher
  --help            Show this message

The workspace must be absent or empty. The skill snapshot must contain only regular
files/directories and have no owner, group, or other write bits. The attestation
and prompt evidence must be outside the builder's writable roots, the skill snapshot,
and the evaluator repository. The CLI verifies that SHA is the clean repository HEAD
and that the frozen skill exactly matches the tracked skill tree at that revision.
`;
}

export function parseArguments(argv) {
  const options = {
    runId: null,
    caseId: null,
    workspace: null,
    attestation: null,
    skill: defaultSkill,
    prompt: defaultPrompt,
    gitSha: null,
    builderId: null,
    builderWritableRoots: [],
    filesystemSandboxEnforced: false,
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
      case '--run-id': options.runId = take(index, argument); index += 1; break;
      case '--case-id': options.caseId = take(index, argument); index += 1; break;
      case '--workspace': options.workspace = resolve(take(index, argument)); index += 1; break;
      case '--attestation': options.attestation = resolve(take(index, argument)); index += 1; break;
      case '--skill': options.skill = resolve(take(index, argument)); index += 1; break;
      case '--prompt': options.prompt = resolve(take(index, argument)); index += 1; break;
      case '--git-sha': options.gitSha = take(index, argument).toLowerCase(); index += 1; break;
      case '--builder-id': options.builderId = take(index, argument); index += 1; break;
      case '--builder-writable-root': options.builderWritableRoots.push(resolve(take(index, argument))); index += 1; break;
      case '--filesystem-sandbox-enforced': options.filesystemSandboxEnforced = true; break;
      case '--help': case '-h': options.help = true; break;
      default: throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (!options.help && (!options.runId || !options.caseId || !options.workspace || !options.attestation
    || !options.gitSha || !options.builderId || !options.builderWritableRoots.length
    || options.filesystemSandboxEnforced !== true)) {
    throw new Error('--run-id, --case-id, --workspace, --attestation, --git-sha, --builder-id, at least one --builder-writable-root, and --filesystem-sandbox-enforced are required.');
  }
  return options;
}

function isWithin(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (!pathFromParent.startsWith('..') && !isAbsolute(pathFromParent));
}

async function canonicalExisting(pathname, label) {
  try {
    return await fs.realpath(pathname);
  } catch (error) {
    throw new Error(`${label} does not exist or cannot be resolved: ${pathname} (${error.message})`);
  }
}

async function canonicalDirectory(pathname, label) {
  const requested = resolve(pathname);
  const stat = await fs.lstat(requested);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${label} must be a real, non-symlink directory: ${requested}`);
  }
  return fs.realpath(requested);
}

async function readRegularFile(pathname, maximumBytes, label) {
  const requested = resolve(pathname);
  const stat = await fs.lstat(requested);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`${label} must be a regular, non-symlink file: ${requested}`);
  }
  if (stat.size > maximumBytes) throw new Error(`${label} exceeds ${maximumBytes} bytes.`);
  return { path: await fs.realpath(requested), bytes: await fs.readFile(requested) };
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function gitBlobSha1(bytes) {
  return createHash('sha1')
    .update(`blob ${bytes.length}\0`)
    .update(bytes)
    .digest('hex');
}

async function runGit(args, label) {
  try {
    const { stdout } = await execFileAsync('git', ['-C', repositoryRoot, ...args], {
      encoding: args.includes('-z') ? 'buffer' : 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: 30000
    });
    return stdout;
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new Error(`${label} failed${detail ? `: ${detail}` : '.'}`);
  }
}

function parseGitTree(buffer) {
  const entries = [];
  for (const record of buffer.toString('utf8').split('\0')) {
    if (!record) continue;
    const match = /^(\d+)\s+(\S+)\s+([a-f0-9]{40})\t(.+)$/.exec(record);
    if (!match) throw new Error('Git returned a malformed tracked skill tree entry.');
    entries.push({ mode: match[1], type: match[2], objectId: match[3], path: match[4] });
  }
  return entries;
}

/**
 * Verify the production revision boundary. Tests may inject a verifier into
 * createAttestation, but the CLI always calls this implementation.
 */
export async function verifyGitRevision({ gitSha, skill }) {
  if (!gitShaPattern.test(gitSha || '')) {
    throw new Error('--git-sha must be a full lowercase 40-hex Git commit SHA.');
  }
  const canonicalRepository = await canonicalDirectory(repositoryRoot, 'Evaluator repository');
  const head = String(await runGit(['rev-parse', '--verify', 'HEAD^{commit}'], 'Git HEAD verification')).trim().toLowerCase();
  if (head !== gitSha) throw new Error(`--git-sha does not match the evaluator repository HEAD (${head}).`);
  const status = String(await runGit(['status', '--porcelain=v1', '--untracked-files=all'], 'Git cleanliness verification'));
  if (status.trim()) throw new Error('Evaluator repository must be completely clean, including untracked files, before dispatch.');

  const treeBuffer = await runGit(
    ['ls-tree', '-r', '-z', '--full-tree', gitSha, '--', trackedSkillPath],
    'Tracked skill tree verification'
  );
  const entries = parseGitTree(treeBuffer);
  if (!entries.length) throw new Error(`Revision ${gitSha} contains no tracked ${trackedSkillPath} files.`);
  const tracked = new Map();
  for (const entry of entries) {
    if (entry.type !== 'blob' || !['100644', '100755'].includes(entry.mode)) {
      throw new Error(`Tracked skill contains an unsupported entry at ${entry.path}.`);
    }
    const prefix = `${trackedSkillPath}/`;
    if (!entry.path.startsWith(prefix)) throw new Error('Tracked skill tree escaped its expected repository path.');
    const relativePath = entry.path.slice(prefix.length);
    if (!relativePath || tracked.has(relativePath)) throw new Error('Tracked skill tree contains a duplicate or empty path.');
    tracked.set(relativePath, entry);
  }

  const actualFiles = await collectSkillFiles(skill.skillRoot);
  const actualRelative = actualFiles.map((pathname) => relative(skill.skillRoot, pathname));
  if (actualRelative.length !== tracked.size
    || actualRelative.some((pathname) => !tracked.has(pathname))) {
    throw new Error('Frozen skill file inventory does not exactly match the tracked skill tree.');
  }
  const expectedDirectories = new Set();
  for (const pathname of tracked.keys()) {
    const parts = pathname.split('/');
    for (let index = 1; index < parts.length; index += 1) {
      expectedDirectories.add(parts.slice(0, index).join('/'));
    }
  }
  const actualDirectories = await collectSkillDirectories(skill.skillRoot);
  if (actualDirectories.length !== expectedDirectories.size
    || actualDirectories.some((pathname) => !expectedDirectories.has(pathname))) {
    throw new Error('Frozen skill directory inventory does not exactly match the tracked skill tree.');
  }
  for (const pathname of actualFiles) {
    const relativePath = relative(skill.skillRoot, pathname);
    const trackedEntry = tracked.get(relativePath);
    const bytes = await fs.readFile(pathname);
    if (gitBlobSha1(bytes) !== trackedEntry.objectId) {
      throw new Error(`Frozen skill content does not match revision ${gitSha}: ${relativePath}`);
    }
    const stat = await fs.lstat(pathname);
    const executable = (stat.mode & 0o111) !== 0;
    if (executable !== (trackedEntry.mode === '100755')) {
      throw new Error(`Frozen skill executable mode does not match revision ${gitSha}: ${relativePath}`);
    }
  }
  return {
    repositoryRoot: canonicalRepository,
    gitSha,
    repositoryClean: true,
    headMatchedRequestedSha: true,
    trackedSkillPath,
    trackedSkillMatched: true,
    trackedSkillFileCount: tracked.size,
    trackedSkillSha256: skill.sha256
  };
}

async function collectSkillFiles(skillRoot) {
  const files = [];
  async function visit(directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const pathname = join(directory, entry.name);
      if (['node_modules', '.git'].includes(entry.name)) {
        throw new Error(`Frozen skill snapshots must omit mutable dependency/VCS directories: ${pathname}`);
      }
      const stat = await fs.lstat(pathname);
      if (stat.isSymbolicLink()) {
        throw new Error(`Skill snapshots may not contain symbolic links: ${pathname}`);
      }
      if ((stat.mode & 0o222) !== 0) {
        throw new Error(`Skill snapshot is writable; freeze it before dispatch: ${pathname}`);
      }
      if (stat.isDirectory()) await visit(pathname);
      else if (stat.isFile()) files.push(pathname);
      else throw new Error(`Skill snapshot contains an unsupported entry: ${pathname}`);
    }
  }
  const rootStat = await fs.lstat(skillRoot);
  if (!rootStat.isDirectory()) throw new Error(`Skill path is not a directory: ${skillRoot}`);
  if ((rootStat.mode & 0o222) !== 0) {
    throw new Error(`Skill snapshot root is writable; freeze it before dispatch: ${skillRoot}`);
  }
  await visit(skillRoot);
  if (!files.length) throw new Error(`Skill snapshot contains no distributable files: ${skillRoot}`);
  return files.sort();
}

async function collectSkillDirectories(skillRoot) {
  const directories = [];
  async function visit(directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const pathname = join(directory, entry.name);
      const stat = await fs.lstat(pathname);
      if (stat.isSymbolicLink()) throw new Error(`Skill snapshots may not contain symbolic links: ${pathname}`);
      if (stat.isDirectory()) {
        directories.push(relative(skillRoot, pathname));
        await visit(pathname);
      }
    }
  }
  await visit(skillRoot);
  return directories.sort();
}

export async function hashReadOnlySkill(skillRoot) {
  const requestedStat = await fs.lstat(skillRoot);
  if (requestedStat.isSymbolicLink() || !requestedStat.isDirectory()) {
    throw new Error(`Skill snapshot root must be a real, non-symlink directory: ${skillRoot}`);
  }
  const canonicalSkill = await canonicalExisting(skillRoot, 'Skill snapshot');
  const files = await collectSkillFiles(canonicalSkill);
  const hash = createHash('sha256');
  for (const pathname of files) {
    hash.update(relative(canonicalSkill, pathname));
    hash.update('\0');
    hash.update((await fs.lstat(pathname)).mode & 0o111 ? '100755' : '100644');
    hash.update('\0');
    hash.update(await fs.readFile(pathname));
    hash.update('\0');
  }
  return { skillRoot: canonicalSkill, fileCount: files.length, sha256: hash.digest('hex') };
}

export async function hashEvaluatorHarness(root = repositoryRoot) {
  const canonicalRepository = await canonicalDirectory(root, 'Evaluator repository');
  const harnessRoot = join(canonicalRepository, 'evals');
  const files = [];
  let totalBytes = 0;
  async function visit(directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const pathname = join(directory, entry.name);
      const stat = await fs.lstat(pathname);
      if (stat.isSymbolicLink()) throw new Error(`Evaluator harness may not contain symbolic links: ${pathname}`);
      if (stat.isDirectory()) {
        await visit(pathname);
      } else if (stat.isFile()) {
        files.push(pathname);
        totalBytes += stat.size;
        if (files.length > 4096 || totalBytes > 64 * 1024 * 1024) {
          throw new Error('Evaluator harness exceeds its 4096-file or 64-MiB attestation bound.');
        }
      } else {
        throw new Error(`Evaluator harness contains an unsupported entry: ${pathname}`);
      }
    }
  }
  await visit(harnessRoot);
  if (!files.length) throw new Error('Evaluator harness contains no files.');
  const hash = createHash('sha256');
  for (const pathname of files.sort()) {
    hash.update(relative(canonicalRepository, pathname));
    hash.update('\0');
    hash.update((await fs.lstat(pathname)).mode & 0o111 ? '100755' : '100644');
    hash.update('\0');
    hash.update(await fs.readFile(pathname));
    hash.update('\0');
  }
  return {
    root: canonicalRepository,
    sha256: hash.digest('hex'),
    fileCount: files.length,
    totalBytes
  };
}

async function prepareEmptyWorkspace(pathname) {
  try {
    const stat = await fs.lstat(pathname);
    if (!stat.isDirectory()) throw new Error(`Workspace is not a directory: ${pathname}`);
    const entries = await fs.readdir(pathname);
    if (entries.length) throw new Error(`Workspace is not empty: ${pathname}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await fs.mkdir(pathname, { recursive: true });
  }
  return fs.realpath(pathname);
}

export async function createAttestation(options) {
  if (!gitShaPattern.test(options.gitSha || '')) {
    throw new Error('--git-sha must be a full lowercase 40-hex Git commit SHA.');
  }
  if (typeof options.builderId !== 'string' || !/^[a-z0-9][a-z0-9._:@/-]{0,127}$/i.test(options.builderId)) {
    throw new Error('--builder-id must be a non-empty stable identifier using only letters, digits, . _ : @ / or -.');
  }
  if (options.filesystemSandboxEnforced !== true) {
    throw new Error('The evaluator must explicitly attest --filesystem-sandbox-enforced.');
  }
  if (!Array.isArray(options.builderWritableRoots) || !options.builderWritableRoots.length) {
    throw new Error('At least one builder writable root is required.');
  }
  const workspace = await prepareEmptyWorkspace(options.workspace);
  const skill = await hashReadOnlySkill(options.skill);
  const evaluator = await hashEvaluatorHarness(repositoryRoot);
  const prompt = await readRegularFile(options.prompt || defaultPrompt, promptByteLimit, 'Builder prompt');
  if (!prompt.bytes.length) throw new Error('Builder prompt must not be empty.');
  const writableRoots = [...new Set(await Promise.all(options.builderWritableRoots.map(
    (pathname) => canonicalDirectory(pathname, 'Builder writable root')
  )))].sort();
  if (!writableRoots.includes(workspace)) {
    throw new Error('The attested empty workspace must itself be one exact builder writable root.');
  }
  for (const [index, root] of writableRoots.entries()) {
    for (const other of writableRoots.slice(index + 1)) {
      if (isWithin(root, other) || isWithin(other, root)) {
        throw new Error('Builder writable roots must be disjoint; nested roots weaken clean-slate isolation.');
      }
    }
    if (root !== workspace && (await fs.readdir(root)).length) {
      throw new Error(`Additional builder writable root was not empty before dispatch: ${root}`);
    }
  }
  if (isWithin(skill.skillRoot, workspace)) {
    throw new Error('The agent workspace must be outside the immutable skill snapshot.');
  }
  if (isWithin(workspace, resolve(options.attestation))) {
    throw new Error('The attestation must be stored outside the agent workspace.');
  }
  await fs.mkdir(dirname(options.attestation), { recursive: true });
  const attestationParent = await fs.realpath(dirname(options.attestation));
  const attestationPath = join(attestationParent, basename(options.attestation));
  if (isWithin(workspace, attestationPath)) {
    throw new Error('The attestation must be stored outside the agent workspace.');
  }
  if (isWithin(skill.skillRoot, attestationPath)) {
    throw new Error('The attestation must be stored outside the immutable skill snapshot.');
  }
  const promptCopyPath = `${attestationPath}.prompt.txt`;
  const protectedPaths = [
    ['Skill snapshot', skill.skillRoot],
    ['Evaluator repository', evaluator.root],
    ['Builder prompt', prompt.path],
    ['Attestation', attestationPath],
    ['Prompt evidence copy', promptCopyPath]
  ];
  for (const root of writableRoots) {
    for (const [label, pathname] of protectedPaths) {
      if (isWithin(root, pathname)) {
        throw new Error(`${label} must be outside every builder writable root: ${root}`);
      }
    }
  }
  if (isWithin(evaluator.root, attestationPath) || isWithin(evaluator.root, promptCopyPath)) {
    throw new Error('Attestation evidence must be outside the evaluator repository.');
  }
  if (isWithin(skill.skillRoot, promptCopyPath)) {
    throw new Error('Prompt evidence must be outside the immutable skill snapshot.');
  }
  const revisionVerifier = options.revisionVerifier || verifyGitRevision;
  const revision = await revisionVerifier({ gitSha: options.gitSha, skill, evaluator });
  if (revision?.gitSha !== options.gitSha
    || revision.repositoryRoot !== evaluator.root
    || revision.repositoryClean !== true
    || revision.headMatchedRequestedSha !== true
    || revision.trackedSkillPath !== trackedSkillPath
    || revision.trackedSkillMatched !== true
    || revision.trackedSkillFileCount !== skill.fileCount
    || revision.trackedSkillSha256 !== skill.sha256) {
    throw new Error('Revision verifier did not prove the clean HEAD and exact tracked skill snapshot.');
  }
  const attestation = {
    schemaVersion: 2,
    recordedAt: new Date().toISOString(),
    phase: 'pre-dispatch',
    runId: options.runId,
    caseId: options.caseId,
    workspace,
    builder: {
      id: options.builderId,
      writableRoots
    },
    skill: {
      root: skill.skillRoot,
      gitSha: options.gitSha,
      sha256: skill.sha256,
      fileCount: skill.fileCount
    },
    revision: {
      repositoryRoot: revision.repositoryRoot,
      gitSha: revision.gitSha,
      repositoryClean: true,
      headMatchedRequestedSha: true,
      trackedSkillPath: revision.trackedSkillPath,
      trackedSkillMatched: true,
      trackedSkillFileCount: revision.trackedSkillFileCount,
      trackedSkillSha256: revision.trackedSkillSha256
    },
    evaluator: {
      root: evaluator.root,
      gitSha: options.gitSha,
      sha256: evaluator.sha256,
      fileCount: evaluator.fileCount,
      totalBytes: evaluator.totalBytes,
      outsideBuilderWritableRoots: true
    },
    prompt: {
      source: prompt.path,
      copy: promptCopyPath,
      sha256: sha256(prompt.bytes),
      bytes: prompt.bytes.length
    },
    isolation: {
      workspaceWasEmpty: true,
      skillWasReadOnly: true,
      priorArtifactsVisible: false,
      filesystemSandboxEnforced: true,
      workspaceIsExactWritableRoot: true,
      skillOutsideBuilderWritableRoots: true,
      evaluatorOutsideBuilderWritableRoots: true,
      promptOutsideBuilderWritableRoots: true,
      attestationOutsideBuilderWritableRoots: true
    },
    evidence: {
      workspaceInspection: 'directory existed empty or was created empty before builder dispatch',
      skillInspection: 'recursive lstat found no symlinks and no write bits on the root, directories, or files',
      priorArtifactsScope: 'each builder writable root was empty and disjoint before dispatch; no prior artifacts were mounted into the evaluator-provided sandbox',
      filesystemSandbox: 'launcher enforcement was explicitly asserted and every writable root was enumerated',
      outsideWritableRoots: 'skill, evaluator, prompt, attestation, and prompt copy were canonicalized outside every builder writable root',
      revisionInspection: 'full requested Git SHA matched a completely clean HEAD and every frozen skill file/blob/mode matched the tracked skill tree'
    }
  };
  try {
    await fs.writeFile(promptCopyPath, prompt.bytes, { flag: 'wx', mode: 0o444 });
    await fs.writeFile(attestationPath, `${JSON.stringify(attestation, null, 2)}\n`, { flag: 'wx', mode: 0o444 });
    await fs.chmod(promptCopyPath, 0o444);
    await fs.chmod(attestationPath, 0o444);
  } catch (error) {
    await fs.unlink(promptCopyPath).catch(() => {});
    throw error;
  }
  return { attestation, attestationPath };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  const result = await createAttestation(options);
  process.stdout.write(`${JSON.stringify({
    attestation: result.attestationPath,
    workspace: result.attestation.workspace,
    skillSha256: result.attestation.skill.sha256
  }, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}
