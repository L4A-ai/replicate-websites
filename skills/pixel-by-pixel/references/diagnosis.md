# Fidelity diagnosis

## Diagnose in causal order

| Evidence | Likely cause | First probe |
|---|---|---|
| Different screenshot height | Wrapping, font, missing section, responsive order | Compare section start/end rectangles from the top |
| Repeated downstream horizontal bands | One upstream height/margin drift | Find the earliest changed row band |
| Text-only halos with correct boxes | Font file, weight, line height, smoothing | Compare computed styles on one glyph-bearing element |
| Desktop improves while mobile regresses | Shared rule or wrong breakpoint | Rerun every viewport and inspect the narrow contract |
| Controls look right but semantics differ | Label nesting, name/value, required/ARIA state | Inspect the semantic category and exact key |
| Semantics match but pixel diff is large | Box geometry or typography | Overlay images and rank row/column bands |
| Candidate changes between runs | Async content, font/image load, animation | Candidate self-diff and stability samples |
| Bootstrap captured a loader or skeleton | Ready selector matched before the rendered state | Reinspect and choose a content/state selector, then regenerate from an empty output |
| Full-page drift after a font change | Fallback font or global smoothing | Audit loaded faces and failed font requests |
| Text and logos disappear only in candidate | CSS dependency was uncaptured or blocked fail-closed | Inspect snapshot skips, local CSS URLs, CSP failures, and font/image requests |
| Small visual score but wrong question text | Semantic severity hidden by page area | Fix semantic mismatch before raster tuning |
| Empty upload changes the synthetic payload | Browser zero-byte file sentinel | Compare UI/retry multipart metadata transiently; persist neither metadata nor bytes |

## Use diff bands

Rank changed rows, then map the highest bands to candidate and source element rectangles. Fix the
smallest common ancestor that explains multiple child bands. Avoid adding downstream offsets to
compensate for an upstream error.

## Probe styles narrowly

Compare one baseline/candidate element at a time:

- `getBoundingClientRect()` including fractional coordinates
- `display`, `position`, box sizing, width constraints, margins, padding, and gaps
- Actual loaded font face, family, weight, size, line height, and letter spacing
- Color, background, border, radius, shadow, opacity, and transform
- `::before` and `::after` content and dimensions

Use the result to change the narrowest selector. Global font smoothing, root line height, or universal
box rules can improve one band while degrading thousands of otherwise matching pixels.

## Preserve semantic exactness

Do not add attributes merely because they seem helpful. `required`, `aria-required`, `aria-hidden`,
`role`, `autocomplete`, `accept`, `maxlength`, and grouping markup all affect DOM or AX parity.
Match the observed contract unless safety requires a documented difference.

Whitespace matters in accessible names. Preserve label nesting and literal spaces around required
markers. Keep visible label text and submitted provider values as separate properties.

## Classify residuals

Assign every remaining band and semantic mismatch to one of:

- `CAPTURE`: instability, truncation, failed critical resource
- `CONTENT`: wrong/missing text or asset
- `SEMANTICS`: control, label, heading, link, or AX mismatch
- `GEOMETRY`: dimensions, placement, wrapping, spacing
- `RESPONSIVE`: breakpoint or reordered layout
- `TYPOGRAPHY`: font metrics or rasterization
- `ASSETS`: image, icon, SVG, or font resource
- `INTERACTION`: client-side behavior
- `BACKEND`: mock request/receipt behavior
- `SAFETY`: intentional source isolation or disclosure
- `TOOLING`: comparator or environment defect

Never call an unexplained residual acceptable. Attach a rationale to every policy exception.
