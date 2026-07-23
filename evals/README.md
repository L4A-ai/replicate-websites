# Clean-slate skill evaluation

## Isolate every attempt

For each skill revision:

1. Commit the release revision, require a completely clean repository (including no untracked
   files), copy the tracked skill directory outside every builder-writable root, and remove every
   write bit without changing executable bits.
2. Render the exact prompt that will be dispatched and store it outside every builder-writable
   root. Run `init-case.mjs` before dispatch. Its CLI requires the full 40-hex clean `HEAD`, a
   builder ID, the complete writable-root grant, and an explicit filesystem-sandbox assertion. It
   verifies every frozen skill blob and executable mode against the tracked skill tree, hashes the
   evaluator harness, copies and hashes the prompt, and writes a read-only v2 attestation.
3. Give a fresh agent only the immutable skill folder, one target URL, the attested empty
   workspace, and the generic replica-manifest requirement.
4. Do not expose benchmark manifests, prior screenshots, expected selectors, previous candidate code, reports, diagnoses, or known fixes.
5. Use a fresh browser profile and cache. Keep prior artifacts outside the agent-visible workspace.
6. Let a separate evaluator run the bundled gates; do not trust the builder's self-reported score.
7. Collect all benchmark results before revising the skill.
8. Make only general workflow/tool improvements, then rerun every benchmark from an empty workspace.

Use a no-skill control under the same model and work budget when measuring whether the skill itself
causes improvement.

## Forward-test prompt

```text
Use $pixel-by-pixel at SKILL_PATH to build a locally runnable visual and behavioral replica of
TARGET_URL in the empty WORKSPACE. Inspect the source read-only and never submit to it. For an
application form, implement a synthetic same-origin backend and keep email disabled by default.
Finish only after running the bundled audit at every required viewport. Emit replica.manifest.json.
```

Do not tell the agent that it is testing a skill, what typically fails, or what score is expected.

## Attest and score a case

Freeze a copy of the skill before creating the case. The evaluator repository, frozen skill,
rendered prompt, attestation, prior run artifacts, and score output must all stay outside every
writable root supplied to the builder. The workspace must itself be one exact writable root; do
not grant a broad parent such as `/tmp`, which would expose sibling runs.

```bash
git status --short
git rev-parse HEAD
chmod -R a-w /srv/replicate-eval/release/skill

node evals/scripts/init-case.mjs \
  --run-id round-4 \
  --case-id case-a \
  --skill /srv/replicate-eval/release/skill \
  --prompt /srv/replicate-eval/prompts/round-4-case-a.txt \
  --git-sha FULL_40_HEX_CLEAN_HEAD \
  --builder-id round-4-case-a-builder \
  --builder-writable-root /sandbox/round-4-case-a-workspace \
  --filesystem-sandbox-enforced \
  --workspace /sandbox/round-4-case-a-workspace \
  --attestation /srv/replicate-eval/evidence/round-4-case-a-isolation.json
```

Dispatch the builder only after that command succeeds. When it finishes, run the evaluator-owned
scorer with the same IDs, skill path, and attestation:

```bash
node evals/scripts/run-case.mjs \
  --run-id round-4 \
  --case-id case-a \
  --isolation-attestation /srv/replicate-eval/evidence/round-4-case-a-isolation.json \
  --skill /srv/replicate-eval/release/skill \
  --target-url "$TARGET_URL" \
  --candidate-dir /sandbox/round-4-case-a-workspace/candidate \
  --out /srv/replicate-eval/evidence/round-4-case-a-score \
  --policy /sandbox/round-4-case-a-workspace/candidate/fidelity-policy.json
```

Use `evals/policies/exact.json` when the candidate has no intentional semantic substitutions. When
safe local form actions, structurally inert source links, or sanitized hidden placeholders produce
expected semantic differences, pass the candidate's generated `fidelity-policy.json`. The scorer
does not trust its gates: it always applies the evaluator-owned exact gates and imports only exact,
schema-validated fingerprints for those three safe substitutions. A candidate policy cannot approve
visual pixels, accessibility changes, missing content, looser resource limits, or broader patterns.
The effective evaluator policy is written beside the result for audit.

`run-case.mjs` is a post-build scorer, not the builder's filesystem sandbox. It validates the
manifest command shape but never runs builder-selected bytes. Instead, it verifies the exact
audited backend, stages those verified bytes and a bounded read-only public snapshot into an
evaluator-owned temporary directory, allocates the listening port inside that process, and removes
the process group and staging directory afterward. Still run it only for candidates produced inside
the evaluator-controlled experiment. The `priorArtifactsVisible: false` claim is backed by a fresh
builder ID, exact empty/disjoint writable roots, and launcher-enforced filesystem sandboxing.

The manifest may declare one local Node script directly or use `npm start`/`npm run start` when the
package start script is exactly `node RELATIVE_SCRIPT`. The scorer resolves and audits that script
inside the candidate, but launches only the verified evaluator-staged backend. Shells, flags,
absolute executables, and traversal paths are refused.

Because the scorer includes a synthetic mutation pass, it requires `manifest.mode` to be exactly
`authorized-local` before it validates or launches the candidate command. Owned and public
simulation deployments receive separate read-only fidelity/integrity checks. Candidate, manifest,
package, server, and start-script paths are canonicalized and rejected if any component below the
attested workspace/candidate root is a symbolic link.

The scorer refuses page and health URLs that are absolute, scheme-relative, or resolve anywhere
other than its freshly allocated `127.0.0.1` origin. It rehashes the frozen skill, evaluator
harness, and prompt copy; revalidates every v2 isolation/revision field; and refuses output inside
any builder-writable root. It emits a detailed `result.json` and a compact v2 `run-record.json`
conforming to `evals/schemas/run.schema.json`.

## Required evidence per case

- Source/source stability comparison
- Candidate/candidate determinism comparison
- Source/candidate comparison at desktop, tablet, mobile, and compact viewports
- Candidate inspection and integrity report
- Candidate-only synthetic interaction report when a form is present
- Read-only prompt and manifest copies with SHA-256
- Evaluator-owned target, ready selector, and four-viewport record
- Complete bounded candidate file/hash inventory plus a bounded empty-base evidence patch
- Diff diagnosis, or an explicit evaluator-generated preflight-failure diagnosis
- Immutable evaluator-harness hash, full revision metadata, builder ID, writable-root inventory,
  empty-workspace assertion, score, and compact evidence-index hash

Source/source stability is a mandatory exact gate: dimensions, strict pixels, tolerant pixels, and
semantic mismatches must all be zero and the repeat capture must declare stable geometry. The
evaluator uses a separate source-stability policy so blocked third-party analytics or source console
noise can be recorded without weakening any candidate gate. Merely recording live-source noise is
not a pass.

Store these under an evaluator-owned artifact directory that is never mounted into subsequent runs.

## Promotion gates

Use these as milestones, not substitutes for the user's requested quality:

| Stage | Tolerant diff | Semantics | Meaning |
|---|---:|---|---|
| Runnable | <= 5% | Inventory captured | Correct route and major content |
| Geometry | <= 2% | No visible critical mismatch | Dimensions and sections converge |
| Typography | <= 0.5% | No visible mismatch | Fonts and wrapping converge |
| Near exact | <= 0.15% | Approved backend-only differences | Release candidate with classified residuals |
| Pixel perfect | 0 strict and tolerant pixels | Zero unexplained mismatch | Exact at every required viewport |

Always require exact dimensions, zero masks, stable candidate geometry, zero candidate critical
resource failures, integrity pass, and interaction pass. A live source's repeat-capture strict noise
must be reported; it does not make a nonzero source/candidate result pixel perfect.

Use the bundled Chromium launch settings for every gate. They force software rasterization and an
sRGB color profile so GPU/color-management rounding does not masquerade as tens of thousands of
one-channel strict pixel changes. Source/source remains the required proof that the environment is
actually byte-stable.

Approve backend semantic differences only with exact fingerprints and rationales. Report raw,
approved, and unapproved counts separately.

Promote a skill revision only after two consecutive clean benchmark rounds with independent fresh
agents and the identical skill hash. Add at least one rotating hidden ATS and one non-ATS page before
claiming evidence beyond the named benchmark set.

## Contamination checks

Reject a revision containing benchmark-specific hostnames, company names, job IDs, screenshots,
captured HTML, prose, CSS, selectors, or expected fixes. Generic provider knowledge is allowed.
Reject candidate reuse, mutable skill mounts, shared browser state, source iframes/proxies/scripts,
full-page raster implementations, and source submission requests.
