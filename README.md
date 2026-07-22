# replicate-websites

`replicate-websites` is a Codex skill and deterministic Playwright toolchain for rebuilding
authorized webpages and proving visual fidelity across full-page desktop and mobile captures.

It treats pixel output, dimensions, DOM semantics, accessibility, deterministic rendering,
interaction behavior, and backend safety as separate release gates. Job application pages receive a
same-origin synthetic submission service with non-retention and email disabled by default.

## What it includes

- A sandboxed, GET-only rendered-DOM bootstrap for owned sites and private local evaluation
- A dependency-free Node candidate service with explicit local, owned, and disclosed-simulation modes
- Full-page strict and tolerant pixel comparison at named viewports
- Rendered contracts for layout, typography, resources, controls, labels, forms, links, and AX nodes
- Exact semantic-difference policies for deliberate safe-backend substitutions
- Diff-band diagnosis, iteration ledgers, regression detection, and best-score checkpoints
- Candidate integrity and synthetic application-flow audits
- A clean-slate benchmark harness and contamination checks

## Install

Requirements: Node.js 20+ and Chromium.

```bash
git clone https://github.com/L4A-ai/replicate-websites.git
cd replicate-websites
npm ci --ignore-scripts
npx playwright install chromium
```

The distributable skill is in `skills/replicate-websites`. The repository install above leaves its
dependencies in the workspace root, so the most reproducible Codex install is a symlink:

```bash
ln -s "$PWD/skills/replicate-websites" "${CODEX_HOME:-$HOME/.codex}/skills/replicate-websites"
```

If you copy the skill directory instead, install its pinned runtime dependencies and Chromium from
inside the copied directory before invoking `$replicate-websites`:

```bash
cp -R skills/replicate-websites "${CODEX_HOME:-$HOME/.codex}/skills/replicate-websites"
cd "${CODEX_HOME:-$HOME/.codex}/skills/replicate-websites"
npm install --ignore-scripts
npx playwright install chromium
```

## Quick start

First capture the source contract and confirm that repeated source captures are stable:

```bash
SKILL_DIR="$PWD/skills/replicate-websites"
TARGET_URL="https://example.com/authorized-page"

node "$SKILL_DIR/scripts/inspect-page.mjs" \
  --url "$TARGET_URL" \
  --viewport desktop:1440x1000 \
  --viewport tablet:768x1024 \
  --viewport mobile:390x844 \
  --viewport compact:360x800 \
  --out /tmp/source-contract

node "$SKILL_DIR/scripts/compare-pages.mjs" \
  --baseline "$TARGET_URL" \
  --candidate "$TARGET_URL" \
  --viewport desktop:1440x1000 \
  --viewport tablet:768x1024 \
  --viewport mobile:390x844 \
  --viewport compact:360x800 \
  --out /tmp/source-self
```

For an owned page or private authorized-local evaluation, generate a safe local starting point:

```bash
node "$SKILL_DIR/scripts/bootstrap-static-replica.mjs" \
  --url "$TARGET_URL" \
  --out /tmp/authorized-replica \
  --mode authorized-local \
  --ready-selector body

cd /tmp/authorized-replica
npm start
```

The bootstrap localizes observed visual assets, removes source scripts and embedded frames,
sanitizes opaque form values, routes forms to `/api/applications`, and emits
`fidelity-policy.json`. Use `--mode owned` only when the permission grant authorizes asset reuse and
deployment.

For a manual implementation, choose the mode at scaffold time. `authorized-local` is the safe
default and binds only to loopback; `owned` binds on all interfaces for an authorized deployment;
`public-simulation` also binds on all interfaces and includes a persistent visible disclosure:

```bash
node "$SKILL_DIR/scripts/scaffold-replica.mjs" \
  --out /tmp/disclosed-simulation \
  --mode public-simulation
```

Run the four-viewport fidelity loop and inspect the candidate. Exercise application mutations only
against the loopback-only immutable starter backend; public deployments receive read-only fidelity
and integrity checks:

```bash
node "$SKILL_DIR/scripts/run-fidelity-loop.mjs" \
  --baseline "$TARGET_URL" \
  --candidate http://127.0.0.1:4173/ \
  --viewport desktop:1440x1000 \
  --viewport tablet:768x1024 \
  --viewport mobile:390x844 \
  --viewport compact:360x800 \
  --policy /tmp/authorized-replica/fidelity-policy.json \
  --iteration initial \
  --out /tmp/fidelity-series
```

Read [`SKILL.md`](skills/replicate-websites/SKILL.md) for the complete workflow and release gates.

## Safety boundary

- Live targets remain GET-only; submissions, beacons, WebSockets, popups, downloads, and service
  workers are blocked.
- Browser processes run with Chromium sandboxing, and a public target cannot read a different
  private-network origin. A validating proxy performs fresh DNS resolution, rejects any
  private/reserved answer, and pins each connection to a vetted address.
- Generated candidates contain no live source scripts, external form actions, or opaque hidden
  payloads. Candidate pages receive a restrictive CSP.
- Persisted contracts and reports classify control values without retaining prefilled applicant
  names, email addresses, phone numbers, freeform text, or opaque provider values.
- `authorized-local` output binds to loopback and must stay private and out of git.
- Public third-party simulations require permission for copied content/assets and an unambiguous
  disclosure. This repository does not grant rights to third-party material.

See [`safety-and-provenance.md`](skills/replicate-websites/references/safety-and-provenance.md).

## Validate

```bash
npm run validate
node evals/scripts/hash-skill.mjs
```

CI installs Chromium, runs the synthetic browser/backend tests, runs the repository-owned skill
structure validator, and scans the entire repository for benchmark-specific names, IDs, selectors,
markup, CSS, captured/generated directories, raster/binary captures, image data URIs, and fixes.

Clean-slate benchmark runs use a two-step evaluator flow: `evals/scripts/init-case.mjs` requires a
full clean Git `HEAD`, verifies the frozen skill byte-for-byte against its tracked tree, binds a
fresh builder ID to exact launcher-enforced writable roots, copies and hashes the dispatch prompt,
and attests the empty workspace before dispatch. `evals/scripts/run-case.mjs` revalidates that v2
attestation and writes a schema-conformant run record.
The evaluator always supplies the exact fidelity gates; a generated candidate policy can contribute
only exact fingerprints for audited local-form actions, structurally inert source links, and
sanitized hidden placeholders. It cannot relax pixels, dimensions, stability, masks, resources, or
candidate error limits.

The scorer validates the candidate's manifest command but launches only an evaluator-staged copy of
the verified audited backend and a bounded read-only public snapshot. It also emits evaluator-owned
copies/hashes for the prompt and manifest, canonical target/viewports, an empty-base candidate patch
and complete bounded file-hash inventory, diff diagnosis, and immutable evaluator/revision metadata.
Use it only inside the evaluator-controlled experiment. See
[`eval-protocol.md`](skills/replicate-websites/references/eval-protocol.md) for the exact commands and
trust boundary.

## Repository boundaries

Downloaded pages, employer assets, screenshots, generated replicas, and raw evaluation runs are
intentionally excluded from git. Only reusable tooling, synthetic fixtures, benchmark definitions,
and aggregate evidence belong here.

## License

The reusable code and documentation in this repository are licensed under the MIT License. Captured
third-party content and assets are not covered and are not distributed here.
