import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { verifyTrustedBackend } from '../../skills/pixel-by-pixel/scripts/lib/trusted-backend.mjs';

const execFileAsync = promisify(execFile);
const skillRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../skills/pixel-by-pixel');
const interactionScript = join(skillRoot, 'scripts', 'test-application-flow.mjs');
const scaffoldScript = join(skillRoot, 'scripts', 'scaffold-replica.mjs');

async function rejection(args, submitPath = '/api/applications') {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-safety-'));
  const manifest = join(directory, 'manifest.json');
  await writeFile(manifest, `${JSON.stringify({ backend: { submitPath } })}\n`);
  try {
    await assert.rejects(
      execFileAsync(process.execPath, [interactionScript, '--manifest', manifest, ...args]),
      (error) => error.code === 1 && String(error.stderr).length > 0
    );
    try {
      await execFileAsync(process.execPath, [interactionScript, '--manifest', manifest, ...args]);
    } catch (error) {
      return String(error.stderr);
    }
    throw new Error('Expected interaction gate to reject.');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('interaction gate refuses all public mutation tests, even with an explicit source', async () => {
  const stderr = await rejection(['--candidate', 'https://replica.example.test/apply']);
  assert.match(stderr, /Refusing mutation tests against a public candidate/);

  const explicitPublic = await rejection([
    '--candidate', 'https://replica.example.test/apply',
    '--allow-public-candidate',
    '--source', 'https://source.example.test/job'
  ]);
  assert.match(explicitPublic, /Refusing mutation tests against a public candidate/);
});

test('interaction gate rejects an absolute backend submission URL before opening a browser', async () => {
  const stderr = await rejection(
    ['--candidate', 'http://127.0.0.1:4173/apply'],
    'https://jobs.example.test/live-submit'
  );
  assert.match(stderr, /root-relative path/);
});

test('interaction gate rejects owned/public modes and nested credential URLs before browser launch', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-mode-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [
      scaffoldScript,
      '--out', candidate,
      '--name', 'owned-interaction-fixture',
      '--mode', 'owned'
    ]);
    await assert.rejects(
      execFileAsync(process.execPath, [
        interactionScript,
        '--candidate', 'http://127.0.0.1:4173/',
        '--manifest', join(candidate, 'replica.manifest.json')
      ]),
      (error) => error.code === 1 && /authorized-local/.test(String(error.stderr))
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  const secret = 'must-not-appear-interaction-secret';
  const nested = `http://127.0.0.1:4173/?return=${encodeURIComponent(`https://example.test/apply?sig=${secret}`)}`;
  const stderr = await rejection(['--candidate', nested]);
  assert.match(stderr, /nested URL|sensitive query parameter|credential-like (?:nested|key\/value) data/);
  assert.doesNotMatch(stderr, new RegExp(secret));

  const sourceStderr = await rejection([
    '--candidate', 'http://127.0.0.1:4173/',
    '--source', `https://source.example.test/?next=${encodeURIComponent(`https://asset.example.test/?token=${secret}`)}`
  ]);
  assert.match(sourceStderr, /nested URL|sensitive query parameter|credential-like (?:nested|key\/value) data/);
  assert.doesNotMatch(sourceStderr, new RegExp(secret));
});

test('trusted backend verifier accepts only the immutable starter implementation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-trusted-backend-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [scaffoldScript, '--out', candidate, '--name', 'trusted-fixture']);
    const manifest = JSON.parse(await readFile(join(candidate, 'replica.manifest.json'), 'utf8'));
    const verified = await verifyTrustedBackend({ candidateRoot: candidate, skillRoot, manifest });
    assert.equal(verified.implementation, 'replicate-websites-starter-v1');
    assert.equal(verified.mode, 'authorized-local');

    const serverPath = join(candidate, 'server.mjs');
    await writeFile(serverPath, `${await readFile(serverPath, 'utf8')}\n// unauthorized mutation\n`);
    await assert.rejects(
      verifyTrustedBackend({ candidateRoot: candidate, skillRoot, manifest }),
      /does not exactly match/
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('trusted backend verifier rejects symlinked implementation files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-trusted-backend-symlink-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [scaffoldScript, '--out', candidate, '--name', 'symlink-fixture']);
    const manifest = JSON.parse(await readFile(join(candidate, 'replica.manifest.json'), 'utf8'));
    const serverPath = join(candidate, 'server.mjs');
    const externalServer = join(directory, 'external-server.mjs');
    await writeFile(externalServer, await readFile(serverPath));
    await unlink(serverPath);
    await symlink(externalServer, serverPath);
    await assert.rejects(
      verifyTrustedBackend({ candidateRoot: candidate, skillRoot, manifest }),
      /regular, non-symlink file/
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction gate reports a verified backend spawn failure without trusting the supplied process', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-trusted-backend-start-failure-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [scaffoldScript, '--out', candidate, '--name', 'start-failure-fixture']);
    const manifestPath = join(candidate, 'replica.manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.start.healthPath = '/not-the-audited-health-endpoint';
    await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
    await assert.rejects(
      execFileAsync(process.execPath, [
        interactionScript,
        '--candidate', 'http://127.0.0.1:9/',
        '--manifest', manifestPath,
        '--timeout-ms', '2000'
      ]),
      (error) => error.code === 1
        && /Verified audited backend could not start/.test(String(error.stderr))
        && !/applicant|smtp|authorization/i.test(String(error.stderr))
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('interaction manifest bounds reject adversarial delays, action counts, and upload contents before spawn', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-manifest-bounds-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [scaffoldScript, '--out', candidate, '--name', 'manifest-bounds-fixture']);
    const manifestPath = join(candidate, 'replica.manifest.json');
    const original = JSON.parse(await readFile(manifestPath, 'utf8'));
    const cases = [
      {
        label: 'settleMs',
        pattern: /settleMs must be an integer from 0 through 10000/,
        mutate: (manifest) => { manifest.interaction.settleMs = 10 ** 12; }
      },
      {
        label: 'actions',
        pattern: /actions must contain at most 64 actions/,
        mutate: (manifest) => {
          manifest.interaction.actions = Array.from({ length: 65 }, () => ({ action: 'click', selector: 'body' }));
        }
      },
      {
        label: 'upload contents',
        pattern: /contents.*at most 65536 characters|contents exceeds 65536 bytes/,
        mutate: (manifest) => {
          manifest.interaction.actions = [{
            action: 'upload',
            selector: 'input[type=file]',
            contents: 'x'.repeat((64 * 1024) + 1)
          }];
        }
      }
    ];
    for (const entry of cases) {
      const manifest = structuredClone(original);
      entry.mutate(manifest);
      await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
      const startedAt = Date.now();
      await assert.rejects(
        execFileAsync(process.execPath, [
          interactionScript,
          '--candidate', 'http://127.0.0.1:9/',
          '--manifest', manifestPath,
          '--timeout-ms', '2000'
        ]),
        (error) => error.code === 1 && entry.pattern.test(String(error.stderr)),
        entry.label
      );
      assert.ok(Date.now() - startedAt < 1500, `${entry.label} must fail before backend or browser startup`);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('trusted interaction runtime rejects symlinks while staging the bounded public snapshot', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-interaction-public-symlink-'));
  const candidate = join(directory, 'candidate');
  try {
    await execFileAsync(process.execPath, [scaffoldScript, '--out', candidate, '--name', 'public-symlink-fixture']);
    const outside = join(directory, 'outside.txt');
    await writeFile(outside, 'must not enter the trusted snapshot');
    await symlink(outside, join(candidate, 'public', 'linked.txt'));
    await assert.rejects(
      execFileAsync(process.execPath, [
        interactionScript,
        '--candidate', 'http://127.0.0.1:9/',
        '--manifest', join(candidate, 'replica.manifest.json'),
        '--timeout-ms', '2000'
      ]),
      (error) => error.code === 1 && /snapshot rejects symbolic links/.test(String(error.stderr))
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
