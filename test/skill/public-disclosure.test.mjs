import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);
const skillRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../skills/pixel-by-pixel');
const script = (name) => join(skillRoot, 'scripts', name);

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const { port } = server.address();
  await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
  return port;
}

async function waitForHealth(url, child) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Public-simulation fixture exited with ${child.exitCode}.`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error(`Timed out waiting for ${url}.`);
}

async function runIntegrity(inspection, manifest, out) {
  try {
    const result = await execFileAsync(process.execPath, [
      script('check-candidate-integrity.mjs'),
      '--inspection', inspection,
      '--source', 'https://source.example/application',
      '--manifest', manifest,
      '--out', out
    ], { maxBuffer: 20 * 1024 * 1024 });
    return { code: 0, ...result };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

test('public-simulation mode and disclosure are rendered integrity gates', { timeout: 180000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'replica-public-disclosure-'));
  const candidate = join(directory, 'candidate');
  let child;
  try {
    await execFileAsync(process.execPath, [
      script('scaffold-replica.mjs'),
      '--out', candidate,
      '--name', 'disclosed-simulation',
      '--mode', 'public-simulation'
    ]);
    const serverPath = join(candidate, 'server.mjs');
    const serverSource = await readFile(serverPath, 'utf8');
    await writeFile(serverPath, serverSource.replace(
      "if (request.method === 'GET' && url.pathname === '/healthz') {",
      `if (request.method === 'GET' && url.pathname === '/pending-disclosure.css') {
        response.writeHead(200, {
          'content-type': 'text/css; charset=utf-8',
          'content-length': '4096',
          'x-content-type-options': 'nosniff'
        });
        response.write('.replica-disclosure { display: none !important; }');
        return;
      }
      if (request.method === 'GET' && url.pathname === '/healthz') {`
    ));
    const port = await freePort();
    child = spawn(process.execPath, ['server.mjs'], {
      cwd: candidate,
      env: { ...process.env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const origin = `http://127.0.0.1:${port}`;
    await waitForHealth(`${origin}/healthz`, child);
    const documentResponse = await fetch(origin);
    assert.match(documentResponse.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
    assert.equal(documentResponse.headers.get('x-frame-options'), 'DENY');

    const inspect = async (name) => {
      const output = join(directory, name);
      await execFileAsync(process.execPath, [
        script('inspect-page.mjs'),
        '--url', origin,
        '--ready-selector', '[data-replica-ready]',
        '--viewport', 'desktop:800x600',
        '--wait-ms', '0',
        '--out', output
      ], { maxBuffer: 20 * 1024 * 1024 });
      return output;
    };

    const visibleInspection = await inspect('visible-inspection');
    const visibleContract = JSON.parse(await readFile(join(visibleInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.equal(visibleContract.page.replicaMode, 'public-simulation');
    assert.equal(visibleContract.integrity.mainResponseSecurityHeaders.xFrameOptions.disposition, 'deny');
    assert.equal(visibleContract.integrity.mainResponseSecurityHeaders.refresh.present, false);
    assert.ok(visibleContract.integrity.mainResponseSecurityHeaders.contentSecurityPolicy.policies.some((policy) => (
      policy.scriptSrc.mode === 'self'
      && policy.connectSrc.mode === 'self'
      && policy.formAction.mode === 'self'
      && policy.objectSrc.mode === 'none'
      && policy.frameAncestors.mode === 'none'
    )));
    assert.equal(visibleContract.integrity.disclosures.length, 1);
    assert.equal(visibleContract.integrity.disclosures[0].visible, true);
    assert.equal(visibleContract.integrity.disclosures[0].position, 'sticky');
    assert.equal(visibleContract.integrity.disclosures[0].visibleAtDocumentEnd, true);
    assert.equal(visibleContract.integrity.disclosures[0].unoccludedAtStart, true);
    assert.equal(visibleContract.integrity.disclosures[0].visibleAfterDelay, true);
    assert.equal(visibleContract.integrity.disclosures[0].unoccludedAfterDelay, true);
    assert.match(visibleContract.integrity.disclosures[0].visibleTextAtStart, /Simulation/);
    assert.ok(visibleContract.integrity.disclosures[0].minimumTextContrastRatioAtStart >= 3);
    assert.equal(visibleContract.integrity.disclosures[0].persistent, true);
    assert.equal(visibleContract.integrity.metaRefreshElements.length, 0);
    assert.equal(visibleContract.integrity.preFreezeDisclosureState.animationRiskCount, 0);
    assert.equal(visibleContract.integrity.preFreezeDisclosureState.transitionRiskCount, 0);
    assert.equal(visibleContract.integrity.preFreezeDisclosureState.pseudoElementOpaqueOverlayRiskCount, 0);
    assert.equal(visibleContract.integrity.delayedPersistenceNavigation.completed, true);
    assert.equal(visibleContract.integrity.delayedPersistenceNavigation.navigationCount, 0);
    assert.equal(visibleContract.integrity.scriptResponseInventory.responsesTruncated, false);
    assert.equal(visibleContract.integrity.scriptResponseInventory.bodyReadLimitReached, false);
    assert.ok(visibleContract.integrity.scriptResponseInventory.responses.some((entry) => (
      entry.url.endsWith('/app.js') && entry.sameOrigin && entry.matchesBundledStarterApp
    )));
    const manifest = join(candidate, 'replica.manifest.json');
    const passing = await runIntegrity(visibleInspection, manifest, join(directory, 'visible-integrity.json'));
    assert.equal(passing.code, 0, passing.stderr || passing.stdout);

    const stylesPath = join(candidate, 'public', 'styles.css');
    const styles = await readFile(stylesPath, 'utf8');
    const indexPath = join(candidate, 'public', 'index.html');
    const indexHtml = await readFile(indexPath, 'utf8');
    const appPath = join(candidate, 'public', 'app.js');
    const appJs = await readFile(appPath, 'utf8');

    await writeFile(indexPath, indexHtml.replace(
      '<title>',
      '<link rel="preload" as="style" href="/pending-disclosure.css"><title>'
    ));
    const pendingStyleInspection = await inspect('pending-style-inspection');
    const pendingStyleContract = JSON.parse(
      await readFile(join(pendingStyleInspection, 'desktop', 'contract.json'), 'utf8')
    ).contract;
    assert.ok(
      pendingStyleContract.integrity.executableStyleFinalQuiescence.completed !== true
      ||
      pendingStyleContract.integrity.executableStyleFinalQuiescence.pendingCount > 0
      || pendingStyleContract.integrity.executableStyleTerminalSnapshot.pendingCount > 0
      || pendingStyleContract.integrity.executableStyleTerminalSnapshot.failed.stylesheet > 0
      || pendingStyleContract.integrity.stylesheetResponseInventory.bodyReadLimitReached === true
    );
    const pendingStyle = await runIntegrity(
      pendingStyleInspection,
      manifest,
      join(directory, 'pending-style-integrity.json')
    );
    assert.equal(pendingStyle.code, 2);
    assert.match(pendingStyle.stdout, /PUBLIC_(?:EXECUTABLE_STYLE_RESOURCES_NOT_QUIESCENT|STYLESHEET_(?:RESPONSE_INVENTORY_INCOMPLETE|REQUEST_LIFECYCLE_MISMATCH))/);
    await writeFile(indexPath, indexHtml);

    await writeFile(stylesPath, `${styles}
      @media (prefers-color-scheme: dark) { .replica-disclosure { display: none !important; } }
      @media (prefers-reduced-motion: no-preference) { .replica-disclosure { display: none !important; } }
      @media (min-resolution: 2dppx) { .replica-disclosure { display: none !important; } }
    `);
    const mediaInspection = await inspect('conditional-media-hidden-inspection');
    const mediaContract = JSON.parse(await readFile(join(mediaInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.equal(mediaContract.integrity.publicDisclosureMediaMatrix.entries.length, 8);
    for (const name of ['dark-reduce-dpr1', 'light-no-preference-dpr1', 'light-reduce-dpr2']) {
      const entry = mediaContract.integrity.publicDisclosureMediaMatrix.entries.find((candidate) => (
        candidate.variant.name === name
      ));
      assert.ok(entry);
      assert.ok(
        entry.disclosures.every((disclosure) => disclosure.visibleAtStart !== true),
        JSON.stringify(entry)
      );
    }
    const mediaResult = await runIntegrity(
      mediaInspection,
      manifest,
      join(directory, 'conditional-media-hidden-integrity.json')
    );
    assert.equal(mediaResult.code, 2);
    assert.match(mediaResult.stdout, /PUBLIC_DISCLOSURE_MEDIA_MATRIX_FAILED/);
    await writeFile(stylesPath, styles);

    await writeFile(appPath, `${appJs}\n// unauthorized public script mutation\n`);
    const scriptMutationInspection = await inspect('script-mutation-inspection');
    const scriptMutationContract = JSON.parse(await readFile(join(scriptMutationInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.ok(scriptMutationContract.integrity.scriptResponseInventory.responses.some((entry) => (
      entry.sameOrigin && entry.matchesBundledStarterApp === false
    )));
    const scriptMutation = await runIntegrity(scriptMutationInspection, manifest, join(directory, 'script-mutation-integrity.json'));
    assert.equal(scriptMutation.code, 2);
    assert.match(scriptMutation.stdout, /PUBLIC_SCRIPT_RESPONSE_NOT_EXACT_STARTER/);
    await writeFile(appPath, appJs);

    await writeFile(indexPath, indexHtml.replace('<title>', '<meta http-equiv="refresh" content="999;url=/elsewhere"><title>'));
    const refreshInspection = await inspect('meta-refresh-inspection');
    const refreshContract = JSON.parse(await readFile(join(refreshInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.equal(refreshContract.integrity.metaRefreshElements.length, 1);
    assert.equal(refreshContract.integrity.cdpStructuralInventory.metaRefreshCount, 1);
    const refreshResult = await runIntegrity(refreshInspection, manifest, join(directory, 'meta-refresh-integrity.json'));
    assert.equal(refreshResult.code, 2);
    assert.match(refreshResult.stdout, /META_REFRESH_PRESENT/);
    await writeFile(indexPath, indexHtml);

    await writeFile(stylesPath, `${styles}\n@keyframes disclosure-fade { from { opacity: .8; } to { opacity: 1; } }\n.replica-disclosure { animation: disclosure-fade 1s infinite; }\n`);
    const animationInspection = await inspect('animation-inspection');
    const animationContract = JSON.parse(await readFile(join(animationInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.ok(animationContract.integrity.preFreezeDisclosureState.animationRiskCount >= 1);
    const animationResult = await runIntegrity(animationInspection, manifest, join(directory, 'animation-integrity.json'));
    assert.equal(animationResult.code, 2);
    assert.match(animationResult.stdout, /PUBLIC_DISCLOSURE_DYNAMIC_VISIBILITY_RISK/);

    await writeFile(stylesPath, `${styles}\n.replica-disclosure::after { content: ""; position: absolute; inset: 0; background: #fff; }\n`);
    const pseudoInspection = await inspect('pseudo-overlay-inspection');
    const pseudoContract = JSON.parse(await readFile(join(pseudoInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.ok(pseudoContract.integrity.preFreezeDisclosureState.pseudoElementOpaqueOverlayRiskCount >= 1);
    const pseudoResult = await runIntegrity(pseudoInspection, manifest, join(directory, 'pseudo-overlay-integrity.json'));
    assert.equal(pseudoResult.code, 2);
    assert.match(pseudoResult.stdout, /PUBLIC_DISCLOSURE_PSEUDO_OVERLAY_RISK/);

    await writeFile(stylesPath, styles);
    await writeFile(indexPath, indexHtml.replace(
      'Simulation — this is not the original website.',
      'Simulation — this is not the original website. This is the official authentic careers site.'
    ));
    const contradictoryInspection = await inspect('contradictory-inspection');
    const contradictory = await runIntegrity(contradictoryInspection, manifest, join(directory, 'contradictory-integrity.json'));
    assert.equal(contradictory.code, 2);
    assert.match(contradictory.stdout, /PUBLIC_DISCLOSURE_CONTRADICTORY_AUTHENTICITY/);
    await writeFile(indexPath, indexHtml);

    await writeFile(stylesPath, `${styles.replace('position: sticky;', 'position: static;')}\nbody { min-height: 2400px; }\n`);
    const staticInspection = await inspect('static-inspection');
    const staticContract = JSON.parse(await readFile(join(staticInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.equal(staticContract.integrity.disclosures[0].visible, true);
    assert.equal(staticContract.integrity.disclosures[0].persistent, false);
    const nonPersistent = await runIntegrity(staticInspection, manifest, join(directory, 'static-integrity.json'));
    assert.equal(nonPersistent.code, 2);
    assert.match(nonPersistent.stdout, /PUBLIC_DISCLOSURE_NOT_PERSISTENT/);

    await writeFile(stylesPath, styles.replace('color: #fff;', 'color: transparent;'));
    const hiddenInspection = await inspect('hidden-inspection');
    const hiddenContract = JSON.parse(await readFile(join(hiddenInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.equal(hiddenContract.integrity.disclosures[0].visible, false);
    const failing = await runIntegrity(hiddenInspection, manifest, join(directory, 'hidden-integrity.json'));
    assert.equal(failing.code, 2);
    assert.match(failing.stdout, /PUBLIC_DISCLOSURE_MISSING/);

    await writeFile(stylesPath, styles);
    await writeFile(indexPath, indexHtml.replace('</body>', '<div style="position:fixed;inset:0;z-index:2147483647;background:#fff"></div></body>'));
    const occludedInspection = await inspect('occluded-inspection');
    const occludedContract = JSON.parse(await readFile(join(occludedInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.equal(occludedContract.integrity.disclosures[0].unoccludedAtStart, false);
    assert.equal(occludedContract.integrity.disclosures[0].unoccludedSampleCountAtStart, 0);
    const occluded = await runIntegrity(occludedInspection, manifest, join(directory, 'occluded-integrity.json'));
    assert.equal(occluded.code, 2);
    assert.match(occluded.stdout, /PUBLIC_DISCLOSURE_OCCLUDED/);

    const requiredCopy = 'Simulation — this is not the original website. Submissions stay inside this mock.';
    await writeFile(indexPath, indexHtml.replace(requiredCopy, `<span style="filter:opacity(0)">${requiredCopy}</span><span>Careers notice</span>`));
    const hiddenCopyInspection = await inspect('hidden-copy-inspection');
    const hiddenCopyContract = JSON.parse(await readFile(join(hiddenCopyInspection, 'desktop', 'contract.json'), 'utf8')).contract;
    assert.match(hiddenCopyContract.integrity.disclosures[0].text, /Simulation/);
    assert.doesNotMatch(hiddenCopyContract.integrity.disclosures[0].geometricVisibleTextAtStart, /Simulation/);
    const hiddenCopy = await runIntegrity(hiddenCopyInspection, manifest, join(directory, 'hidden-copy-integrity.json'));
    assert.equal(hiddenCopy.code, 2);
    assert.match(hiddenCopy.stdout, /PUBLIC_DISCLOSURE_MISSING/);

    for (const [name, extraCss] of [
      ['tiny', '.replica-disclosure { font-size: 1px; transform: scale(0.1); transform-origin: top left; }'],
      ['thin-glyphs', '.replica-disclosure { transform: scaleX(0.01); transform-origin: top left; }'],
      ['blurred', '.replica-disclosure { filter: blur(4px); }'],
      ['no-contrast', '.replica-disclosure { color: rgb(139, 29, 29); background: rgb(139, 29, 29); }'],
      ['gradient-contrast', '.replica-disclosure { color: #000; background-color: transparent; background-image: linear-gradient(#000, #000); }']
    ]) {
      await writeFile(indexPath, indexHtml);
      await writeFile(stylesPath, `${styles}\n${extraCss}\n`);
      const unreadableInspection = await inspect(`${name}-inspection`);
      const unreadableContract = JSON.parse(await readFile(join(unreadableInspection, 'desktop', 'contract.json'), 'utf8')).contract;
      assert.doesNotMatch(unreadableContract.integrity.disclosures[0].geometricVisibleTextAtStart, /Simulation/);
      const unreadable = await runIntegrity(unreadableInspection, manifest, join(directory, `${name}-integrity.json`));
      assert.equal(unreadable.code, 2);
      assert.match(unreadable.stdout, /PUBLIC_DISCLOSURE_MISSING/);
    }
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    await rm(directory, { recursive: true, force: true });
  }
});
