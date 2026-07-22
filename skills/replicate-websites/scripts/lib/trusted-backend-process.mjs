import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, constants, promises as fs, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

const maximumPublicFiles = 2000;
const maximumPublicEntries = 2500;
const maximumPublicFileBytes = 15 * 1024 * 1024;
const maximumPublicTotalBytes = 100 * 1024 * 1024;

function isWithin(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (!pathFromParent.startsWith('..') && !isAbsolute(pathFromParent));
}

function removeStagingSync(stagingRoot) {
  try {
    const pending = [stagingRoot];
    while (pending.length) {
      const directory = pending.pop();
      chmodSync(directory, 0o700);
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (entry.isDirectory() && !entry.isSymbolicLink()) pending.push(join(directory, entry.name));
      }
    }
    rmSync(stagingRoot, { recursive: true, force: true });
  } catch {}
}

async function readNoFollow(pathname, maximumBytes) {
  const noFollow = typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
  const handle = await fs.open(pathname, constants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(maximumBytes)) throw new Error('PUBLIC_FILE_LIMIT');
    const body = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (body.byteLength > maximumBytes
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs) {
      throw new Error('PUBLIC_FILE_CHANGED_DURING_SNAPSHOT');
    }
    return body;
  } finally {
    await handle.close();
  }
}

async function stageVerifiedBackend(candidateRoot, verifiedServerBytes, expectedServerSha256) {
  if (!Buffer.isBuffer(verifiedServerBytes)) throw new Error('Verified server bytes are unavailable.');
  const serverSha256 = createHash('sha256').update(verifiedServerBytes).digest('hex');
  if (serverSha256 !== expectedServerSha256) throw new Error('Verified server byte hash changed before staging.');
  const stagingRoot = await fs.mkdtemp(join(tmpdir(), 'replicate-audited-backend-'));
  try {
    if (isWithin(candidateRoot, stagingRoot)) throw new Error('Evaluator staging must remain outside the candidate root.');
    const sourcePublic = join(candidateRoot, 'public');
    const sourcePublicStat = await fs.lstat(sourcePublic);
    if (sourcePublicStat.isSymbolicLink() || !sourcePublicStat.isDirectory()) {
      throw new Error('Candidate public root must be a real, non-symlink directory.');
    }
    const canonicalPublic = await fs.realpath(sourcePublic);
    if (!isWithin(candidateRoot, canonicalPublic)) throw new Error('Candidate public root escaped the candidate directory.');
    const stagedPublic = join(stagingRoot, 'public');
    await fs.mkdir(stagedPublic, { mode: 0o700 });
    const pending = [{ source: sourcePublic, destination: stagedPublic }];
    const stagedDirectories = [stagedPublic];
    let entryCount = 0;
    let fileCount = 0;
    let totalBytes = 0;
    while (pending.length) {
      const directory = pending.pop();
      const directoryStat = await fs.lstat(directory.source);
      if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
        throw new Error('Candidate public tree contains a non-directory traversal component.');
      }
      const canonicalDirectory = await fs.realpath(directory.source);
      if (!isWithin(canonicalPublic, canonicalDirectory)) throw new Error('Candidate public directory escaped its root.');
      const entries = await fs.readdir(directory.source, { withFileTypes: true });
      for (const entry of entries) {
        entryCount += 1;
        if (entryCount > maximumPublicEntries) throw new Error('Candidate public snapshot exceeds its entry-count limit.');
        const sourcePath = join(directory.source, entry.name);
        const destinationPath = join(directory.destination, entry.name);
        const stat = await fs.lstat(sourcePath);
        if (entry.isSymbolicLink() || stat.isSymbolicLink()) {
          throw new Error('Candidate public snapshot rejects symbolic links.');
        }
        if (stat.isDirectory()) {
          await fs.mkdir(destinationPath, { mode: 0o700 });
          stagedDirectories.push(destinationPath);
          pending.push({ source: sourcePath, destination: destinationPath });
          continue;
        }
        if (!stat.isFile()) throw new Error('Candidate public snapshot accepts only regular files and directories.');
        fileCount += 1;
        if (fileCount > maximumPublicFiles) throw new Error('Candidate public snapshot exceeds its file-count limit.');
        if (stat.size > maximumPublicFileBytes) throw new Error('Candidate public file exceeds its per-file limit.');
        const canonicalFile = await fs.realpath(sourcePath);
        if (!isWithin(canonicalPublic, canonicalFile)) throw new Error('Candidate public file escaped its root.');
        const body = await readNoFollow(sourcePath, maximumPublicFileBytes);
        totalBytes += body.byteLength;
        if (totalBytes > maximumPublicTotalBytes) throw new Error('Candidate public snapshot exceeds its total-size limit.');
        await fs.writeFile(destinationPath, body, { mode: 0o600, flag: 'wx' });
        await fs.chmod(destinationPath, 0o444);
      }
    }
    const stagedServerPath = join(stagingRoot, 'server.mjs');
    await fs.writeFile(stagedServerPath, verifiedServerBytes, { mode: 0o400, flag: 'wx' });
    for (const directory of stagedDirectories.reverse()) await fs.chmod(directory, 0o555);
    await fs.chmod(stagingRoot, 0o555);
    return {
      stagingRoot,
      stagedServerPath,
      evidence: {
        launchedPath: '[evaluator-temp]/server.mjs',
        serverSha256,
        publicFileCount: fileCount,
        publicTotalBytes: totalBytes,
        readOnlySnapshot: true,
        portSelection: 'kernel-assigned-port-zero',
        readinessChannel: 'ipc'
      }
    };
  } catch (error) {
    await fs.rm(stagingRoot, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

function minimalBackendEnvironment() {
  const environment = {
    PORT: '0',
    NODE_ENV: 'test',
    CI: 'true',
    NO_COLOR: '1',
    TZ: 'UTC',
    EMAIL_CONFIRMATION_ENABLED: 'false'
  };
  for (const name of ['SystemRoot', 'SYSTEMROOT', 'ComSpec', 'COMSPEC', 'PATHEXT', 'WINDIR']) {
    if (typeof process.env[name] === 'string') environment[name] = process.env[name];
  }
  return environment;
}

async function waitForReadyMessage(child, projectName, timeoutMs) {
  return new Promise((resolveReady, rejectReady) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener('message', onMessage);
      child.removeListener('error', onError);
      child.removeListener('exit', onExit);
      callback(value);
    };
    const onMessage = (message) => {
      const keys = message && typeof message === 'object' ? Object.keys(message).sort() : [];
      const expectedKeys = ['host', 'mode', 'port', 'schemaVersion', 'service', 'type'];
      if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)
        || message.schemaVersion !== 1
        || message.type !== 'replica-backend-ready'
        || message.service !== projectName
        || message.mode !== 'authorized-local'
        || message.host !== '127.0.0.1'
        || !Number.isInteger(message.port)
        || message.port < 1
        || message.port > 65535) {
        finish(rejectReady, new Error('AUDITED_BACKEND_READY_MESSAGE_MISMATCH'));
        return;
      }
      finish(resolveReady, message);
    };
    const onError = () => finish(rejectReady, new Error('AUDITED_BACKEND_SPAWN_FAILED'));
    const onExit = () => finish(rejectReady, new Error('AUDITED_BACKEND_EXITED_BEFORE_READY'));
    const timer = setTimeout(
      () => finish(rejectReady, new Error('AUDITED_BACKEND_READY_TIMEOUT')),
      timeoutMs
    );
    child.once('message', onMessage);
    child.once('error', onError);
    child.once('exit', onExit);
  });
}

function processIsRunning(child) {
  return Boolean(child) && child.exitCode === null && child.signalCode === null;
}

function signalProcessGroup(child, signal) {
  if (!processIsRunning(child)) return;
  try {
    if (process.platform === 'win32' || !child.pid) child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch {}
}

export async function stopTrustedBackend(child) {
  if (!processIsRunning(child)) return;
  const exited = new Promise((resolveExit) => child.once('exit', resolveExit));
  signalProcessGroup(child, 'SIGTERM');
  await Promise.race([
    exited,
    new Promise((resolveWait) => setTimeout(resolveWait, 3000))
  ]);
  if (processIsRunning(child)) {
    signalProcessGroup(child, 'SIGKILL');
    await Promise.race([
      exited,
      new Promise((resolveWait) => setTimeout(resolveWait, 2000))
    ]);
  }
}

async function exactHealthCheck(url, projectName, child, timeoutMs) {
  const startedAt = Date.now();
  let spawnError = null;
  child.once('error', (error) => { spawnError = error; });
  while (Date.now() - startedAt < timeoutMs) {
    if (spawnError) throw new Error('AUDITED_BACKEND_SPAWN_FAILED');
    if (!processIsRunning(child)) throw new Error('AUDITED_BACKEND_EXITED_BEFORE_HEALTH');
    try {
      const response = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store',
        signal: AbortSignal.timeout(Math.min(1000, Math.max(100, timeoutMs)))
      });
      const contentType = response.headers.get('content-type') || '';
      const declaredLength = Number(response.headers.get('content-length') || 0);
      if (declaredLength > 4096) throw new Error('AUDITED_BACKEND_HEALTH_MISMATCH');
      const text = await response.text();
      if (text.length > 4096) throw new Error('AUDITED_BACKEND_HEALTH_MISMATCH');
      let body = null;
      try { body = JSON.parse(text); } catch {}
      if (response.status !== 200
        || !/^application\/json\b/i.test(contentType)
        || response.headers.get('x-replica-mode') !== 'authorized-local'
        || body?.ok !== true
        || body?.service !== projectName) {
        throw new Error('AUDITED_BACKEND_HEALTH_MISMATCH');
      }
      if (!processIsRunning(child)) throw new Error('AUDITED_BACKEND_EXITED_AFTER_HEALTH');
      return;
    } catch (error) {
      if (/^AUDITED_BACKEND_/.test(error.message || '')) throw error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error('AUDITED_BACKEND_HEALTH_TIMEOUT');
}

export async function startTrustedBackend({
  candidateRoot,
  verifiedServerPath,
  verifiedServerBytes,
  expectedServerSha256,
  projectName,
  healthPath,
  timeoutMs = 30000
}) {
  const root = resolve(candidateRoot);
  if (resolve(verifiedServerPath) !== join(root, 'server.mjs') || dirname(resolve(verifiedServerPath)) !== root) {
    throw new Error('Verified backend path does not match the canonical candidate server.mjs.');
  }
  const staged = await stageVerifiedBackend(root, verifiedServerBytes, expectedServerSha256);
  let child;
  try {
    child = spawn(process.execPath, [staged.stagedServerPath], {
      cwd: staged.stagingRoot,
      env: minimalBackendEnvironment(),
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      detached: process.platform !== 'win32',
      windowsHide: true
    });
  } catch (error) {
    removeStagingSync(staged.stagingRoot);
    throw error;
  }
  const forceCleanupOnExit = () => {
    signalProcessGroup(child, 'SIGKILL');
    removeStagingSync(staged.stagingRoot);
  };
  process.once('exit', forceCleanupOnExit);
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    process.removeListener('exit', forceCleanupOnExit);
    await stopTrustedBackend(child);
    removeStagingSync(staged.stagingRoot);
  };
  try {
    const ready = await waitForReadyMessage(child, projectName, timeoutMs);
    const port = ready.port;
    const origin = `http://127.0.0.1:${port}`;
    await exactHealthCheck(new URL(healthPath, origin).href, projectName, child, timeoutMs);
    return { child, origin, port, evidence: staged.evidence, close };
  } catch (error) {
    await close();
    throw new Error(`Verified audited backend could not start (${error.message}).`);
  }
}
