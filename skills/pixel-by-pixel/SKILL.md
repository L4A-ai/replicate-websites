---
name: pixel-by-pixel
description: Replicate authorized or public webpages into local or deployable implementations with measured pixel, responsive, semantic, accessibility, interaction, and backend fidelity. Use when asked to clone, mock, recreate, reproduce, or visually match a webpage from a URL; build an ATS or job-application simulation; diagnose screenshot or form-label discrepancies; or iterate a frontend toward pixel-perfect equivalence across desktop and mobile.
---

# Pixel by Pixel

Reconstruct the rendered interface and its safe local behavior from evidence. Treat pixels,
geometry, semantics, accessibility, responsive states, and interactions as independent gates.

## Load the relevant guidance

- Read [references/safety-and-provenance.md](references/safety-and-provenance.md) before inspecting a third-party target or publishing a replica.
- Read [references/workflow.md](references/workflow.md) for the detailed capture-to-deploy loop.
- Read [references/diagnosis.md](references/diagnosis.md) when a comparison is not already near exact.
- Read [references/job-application-contract.md](references/job-application-contract.md) for any application form or mock submission backend.
- Read [references/provider-patterns.md](references/provider-patterns.md) only when the target is an ATS or employer careers page.

## Run the core workflow

Set the installed skill directory once:

```bash
SKILL_DIR=/absolute/path/to/pixel-by-pixel
```

After installing the skill, run `npm run setup` inside `SKILL_DIR` once. This installs the pinned
runtime dependencies and Chromium. Run `npm run doctor` to verify the runtime without modifying it.

Use an isolated, empty candidate workspace. Do not scaffold it until choosing the implementation
path in step 3; the rendered-DOM bootstrap creates the service itself.

### 1. Freeze the target state

Record the exact URL, viewport set, locale, light/dark state, consent state, expected route, and a
stable ready selector. Keep the live target GET-only. Never click a live submit button.

Measure source stability before writing candidate code:

```bash
node "$SKILL_DIR/scripts/compare-pages.mjs" \
  --baseline "$TARGET_URL" \
  --candidate "$TARGET_URL" \
  --ready-selector "$READY_SELECTOR" \
  --viewport desktop:1440x1000 \
  --viewport tablet:768x1024 \
  --viewport mobile:390x844 \
  --viewport compact:360x800 \
  --out "$WORK_DIR/source-self"
```

Do not set final gates below the source's repeat-capture noise floor. A nonzero strict self-diff can
come from rasterization while a zero tolerant self-diff remains stable evidence.

### 2. Capture the contract

Capture desktop and mobile contracts before styling:

```bash
node "$SKILL_DIR/scripts/inspect-page.mjs" \
  --url "$TARGET_URL" \
  --ready-selector "$READY_SELECTOR" \
  --viewport desktop:1440x1000 \
  --viewport tablet:768x1024 \
  --viewport mobile:390x844 \
  --viewport compact:360x800 \
  --out "$WORK_DIR/source-contract"
```

Inspect `summary.json`, each `contract.json`, and each `page.png`. Record section order, element
rectangles, computed box and typography styles, fonts, resources, controls, label relationships,
provider field names, visible option labels, safe value classifications, hidden-value lengths,
links, headings, and form actions. Never persist prefilled freeform values or opaque provider values
in a contract, report, generated candidate, or console log.

### 3. Choose the implementation path

For an owned site, or a private authorized-local evaluation of a public rendered state, start with
the safe static bootstrap. It renders source JavaScript in a sandbox, keeps source traffic GET-only,
localizes visual resources, removes executable source code and embedded frames, sanitizes opaque
form values, and emits an exact pixel policy with narrowly fingerprinted safe-backend differences:

```bash
node "$SKILL_DIR/scripts/bootstrap-static-replica.mjs" \
  --url "$TARGET_URL" \
  --out /absolute/path/to/candidate \
  --mode authorized-local \
  --ready-selector "$READY_SELECTOR"
```

Use `--mode owned` only when ownership or an equivalent permission grant authorizes asset reuse and
deployment. Keep `authorized-local` output private and out of git. The bootstrap captures one
rendered DOM at its primary viewport while collecting assets across the standard viewport set; use
a manual renderer when JavaScript produces materially different DOM trees per breakpoint or state.

Start the candidate and immediately run comparison plus integrity checks. Refine local HTML/CSS and
`public/app.js`; never restore source scripts, external asset fallbacks, live actions, or hidden
payloads merely to improve a score.

For a public simulation without asset-reuse rights, or when the page needs a genuine reusable
component implementation, scaffold the dependency-free service instead:

```bash
node "$SKILL_DIR/scripts/scaffold-replica.mjs" \
  --out /absolute/path/to/candidate \
  --name authorized-replica \
  --mode public-simulation
```

The `public-simulation` scaffold includes a persistent disclosure banner and binds on all
interfaces. Use `--mode owned` instead for an owner-authorized deployment, or the safe default
`--mode authorized-local` for a private implementation. Its integrity gate also requires an exact
bundled `app.js`, bounded and fully settled same-origin stylesheets, and readable disclosure state
across light/dark, reduced/no-preference motion, and DPR 1/2. Then implement semantics before
styling.

Encode repeated content and controls as target data. Match native tags, form names, option values,
required states, label nesting, whitespace, accessible names, and heading/link order before tuning
CSS. Preserve visible labels separately from submitted values when they differ.

For third-party pages, use permitted local assets or independently created equivalents. Never use
an iframe, reverse proxy, or full-page screenshot as the implementation.

### 4. Recreate behavior locally

Implement visible validation, conditionals, upload state, selection limits, autocomplete, and
submission transitions against the same-origin audited mock backend. Use synthetic values, validate
multipart data transiently, persist no applicant values or upload metadata, make submission
idempotent, and keep email disabled.

### 5. Compare and iterate without regressions

Run a named iteration across every required viewport:

```bash
node "$SKILL_DIR/scripts/run-fidelity-loop.mjs" \
  --baseline "$TARGET_URL" \
  --candidate "$CANDIDATE_URL" \
  --ready-selector "$READY_SELECTOR" \
  --viewport desktop:1440x1000 \
  --viewport tablet:768x1024 \
  --viewport mobile:390x844 \
  --viewport compact:360x800 \
  --policy "$WORK_DIR/fidelity-policy.json" \
  --iteration geometry-01 \
  --out "$WORK_DIR/series"
```

The loop preserves the best score and exits `3` on regression. Do not bypass it merely because one
viewport improved. `--ready-selector` is shared by baseline and candidate; when their stable markers
differ, pass `--baseline-ready-selector` and `--candidate-ready-selector` instead.
Fix in this order:

1. Truncated capture, failed resources, or unstable source/candidate
2. Semantic and accessibility mismatches
3. Document dimensions and the earliest upstream vertical offset
4. Container widths, padding, gaps, controls, and breakpoints
5. Font files, font metrics, line height, weight, and letter spacing
6. Color, borders, shadows, icons, and residual raster differences

Use contract-aware diagnosis after each meaningful comparison:

```bash
node "$SKILL_DIR/scripts/diagnose-diff.mjs" \
  --report "$REPORT_DIR" \
  --baseline-contract "$WORK_DIR/source-contract" \
  --candidate-contract "$WORK_DIR/candidate-contract" \
  --out "$WORK_DIR/diagnosis.json"
```

Change one causal cluster at a time. Rerun all viewports after typography, root layout, or shared
component changes. Preserve the previous best checkpoint.

### 6. Verify integrity and interactions

Inspect the candidate, then reject source iframes, source scripts, external form actions, and
full-page raster shortcuts:

```bash
node "$SKILL_DIR/scripts/inspect-page.mjs" \
  --url "$CANDIDATE_URL" \
  --ready-selector "$READY_SELECTOR" \
  --viewport desktop:1440x1000 \
  --viewport tablet:768x1024 \
  --viewport mobile:390x844 \
  --viewport compact:360x800 \
  --out "$WORK_DIR/candidate-contract"

node "$SKILL_DIR/scripts/check-candidate-integrity.mjs" \
  --inspection "$WORK_DIR/candidate-contract" \
  --source "$TARGET_URL" \
  --manifest /absolute/path/to/candidate/replica.manifest.json
```

For application forms, run the synthetic candidate-only flow with a loopback candidate locator and
the immutable audited starter backend produced by this skill. The gate verifies the candidate files,
starts its own isolated backend on a fresh loopback port, ignores any process already serving the
supplied URL, and terminates the isolated process after the run:
The verified server bytes and bounded, symlink-free `public/` tree are launched from a read-only
evaluator-owned temporary snapshot, so later candidate-file replacement cannot change the process.

```bash
node "$SKILL_DIR/scripts/test-application-flow.mjs" \
  --candidate "$CANDIDATE_URL" \
  --manifest /absolute/path/to/candidate/replica.manifest.json \
  --out "$WORK_DIR/interaction.json"
```

Never run mutation tests against a public deployment or a hand-written/untrusted backend. Public
deployments receive the read-only comparison and integrity gates only.

### 7. Run the final evidence triad

Run these without masks:

1. Source versus source to confirm current stability.
2. Candidate versus candidate to confirm deterministic rendering.
3. Source versus candidate for the actual fidelity score.

Require exact dimensions, stable candidate geometry, zero candidate document/stylesheet/font
failures, zero unexplained semantic mismatches, integrity pass, and interaction pass. Use explicit
semantic fingerprints with rationales for unavoidable safe-backend differences; never hide them in
a pixel mask or weaken the global comparator.

Only call a result **pixel perfect** when strict and tolerant changed pixels are both zero at every
required viewport with no masks. Call a result **near exact** when it passes a declared nonzero
budget, and report the raw percentages and remaining classified pixels.

### 8. Verify the deployed URL

Run the read-only comparison, determinism, and integrity gates against the public deployment. Keep
the application mutation gate on the loopback-only audited starter backend. If publishing a
third-party simulation, retain its unambiguous visible disclosure and report that measured residual
separately. Never infer production parity from localhost alone.
