# Capture-to-deploy workflow

## Contents

1. Evidence directory
2. Source contract
3. Implementation architecture
4. Iteration sequence
5. Final release evidence

## 1. Evidence directory

Keep evidence outside the candidate and outside the distributed skill:

```text
work/<target-id>/
├── source-self/
├── source-contract/
├── candidate-contract/
├── series/
│   ├── series.json
│   └── iterations/<id>/
├── candidate-self/
├── source-candidate/
├── fidelity-policy.json
├── integrity.json
└── interaction.json
```

Write down the exact target URL, browser state, capture timestamp, ready selector, viewports, and
source self-diff. A changed live page invalidates comparisons against an older screenshot.

## 2. Source contract

Inspect raw artifacts, not only the combined percentage:

- Full-page screenshots and exact content dimensions
- Top-level section boundaries and responsive order changes
- Every native control, including hidden inputs and file inputs
- Label association, nesting, pseudo-content, required markers, and accessible names
- Visible labels versus submitted values
- Form method/action/enctype and local-safe replacements
- Heading and link order
- Font family, actual loaded face, weight, size, line height, letter spacing, and smoothing
- Container widths, margins, padding, gaps, borders, radius, shadows, and backgrounds
- Images, SVGs, CSS resources, and failed document/stylesheet/font requests
- Conditional states, custom validation, focus behavior, and submission transition

Capture both wide and narrow states before designing a component hierarchy. A desktop-only
contract often encodes the wrong DOM order for mobile.

## 3. Implementation architecture

Separate observed data from reusable rendering and behavior:

```text
target data -> semantic renderer -> shared styles -> interaction adapter -> local backend
```

There are two implementation routes:

- **Rendered-DOM bootstrap:** best for an owned page or private authorized-local evaluation of one
  frozen state. It localizes observed visual assets and preserves the rendered DOM, then strips live
  execution and sanitizes backend-sensitive values. Treat its output as generated evidence, not as
  redistributable source.
- **Manual semantic renderer:** required when redistribution rights are absent, the product needs
  maintainable components, or responsive/state changes produce different DOM structures.

Choose the manual scaffold's operating mode explicitly: `authorized-local` binds to loopback,
`owned` binds on all interfaces for an authorized site, and `public-simulation` binds on all
interfaces with a persistent simulation disclosure. Do not remove that disclosure to improve a
third-party page's visual score; report its measured residual separately.

Both routes converge on the same pixel, semantic, integrity, interaction, and determinism gates.
The bootstrap is a starting implementation, not permission to skip contract inspection or the
candidate-only behavior pass.

Keep the behavior pass loopback-only and use the immutable audited starter backend. A public
deployment gets read-only fidelity, determinism, resource, and disclosure checks; do not submit its
forms during verification.

For application pages, place route metadata, field definitions, provider aliases, visible/submitted
value maps, validation rules, and state transitions in data modules. Keep rendering generic enough
to expose repeated errors once rather than fixing each field independently.

Use natural layout first. Add measured explicit dimensions only after fonts and responsive rules are
correct, and annotate any hard-coded height that intentionally freezes a static benchmark state.

## 4. Iteration sequence

### Semantic pass

Reach the correct control/label/link/heading inventory before chasing pixels. Verify exact native
element types and attribute presence; extra accessibility attributes can change the AX contract just
as missing ones can.

### Geometry pass

Match total dimensions, major section starts, columns, field rows, and responsive breakpoints.
Diagnose the earliest vertical displacement: downstream bands usually disappear when the first
upstream margin, line-wrap, or font metric is corrected.

### Typography pass

Serve the exact authorized font face locally when possible. Wait for `document.fonts.ready`. Compare
computed font family, weight, size, line height, letter spacing, text transform, and smoothing on a
single mismatched element before making a global change.

### Raster pass

Tune colors, borders, shadows, SVG strokes, icons, and antialias-sensitive details. Treat tolerant
and strict diffs separately. A zero tolerant self-diff with nonzero strict source noise defines what
the current browser can reproduce deterministically.

### Behavior pass

Exercise candidate-only validation, radios, checkboxes, selects, autocomplete, upload, conditionals,
submission, receipt, retry, and email-disabled behavior. Assert that every write remains on the
candidate origin.

### Regression rule

Compare a score vector in this order: dimension failures, unapproved semantic mismatches, worst
tolerant viewport, total tolerant diff, total strict diff. Reject a revision that improves one local
region while worsening the best cross-viewport vector unless the regression is explicitly explained.

## 5. Final release evidence

Require:

- Source self-comparison at the time of release
- Candidate self-comparison with deterministic dimensions and pixels
- Source/candidate comparison at all declared viewports, without masks
- Candidate integrity report
- Candidate-only interaction report when forms exist
- Unit/integration tests for multipart/canary validation, payload limits, idempotency, and non-retention
- Public deployment health check and a fresh public comparison

Report strict and tolerant percentages, exact dimensions, semantic raw/approved/unapproved counts,
mask count, stability, failed critical resources, and every intentional residual.
