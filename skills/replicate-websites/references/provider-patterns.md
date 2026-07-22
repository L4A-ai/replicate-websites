# ATS and careers-page patterns

Use provider recognition to choose an inspection path, not to hard-code a visual template. Employer
themes, provider versions, and configured questions vary.

## Hosted job-detail applications

Some hosted ATS pages render job metadata and description first, then expose an application tab,
drawer, route, or sticky apply control. Capture the exact URL state requested by the user. Do not
click into a live application merely because another state exists.

Inspect:

- Header/logo region, metadata sidebar, tabs, rich-text body, sticky apply control, and footer
- Mobile column collapse and sticky-control width/position
- Client-rendered fonts and CSS-in-JS class instability
- Application state only when it is already present at the supplied URL or available through a public GET route

## Employer-owned careers page with ATS handoff

Custom careers pages often use a bespoke header/hero/footer and job prose, with an apply button that
hands off to an ATS. Treat the supplied page as a custom marketing layout, not as the downstream ATS.

Inspect:

- Navigation and hero backgrounds, decorative grids, custom fonts, logos/icons, article width, and footer columns
- Fixed versus fluid typography at breakpoints
- Apply link destination and accessible name without following a write flow
- Analytics failures separately from document, stylesheet, image, and font failures

## Hosted direct application form

Direct application URLs commonly expose a provider-standard header, section headings, repeated field
rows, radio/checkbox groups, submit control, disclosure/footer, and many hidden inputs.

Inspect:

- Provider field names, visible/submitted option values, required markers, hidden-value lengths, and form action
- File-input proxy controls and status nodes
- Desktop label/input columns versus mobile stacking
- Provider fonts, unitless line heights, fractional row heights, legal copy, and footer geometry
- Cookie or privacy controls that may be duplicated for responsive states

Recreate provider-shaped semantics locally while replacing signed templates, account IDs, live form
actions, upload origins, and submission tokens with synthetic equivalents covered by explicit policy.

## General provider cautions

- Do not assume a provider's current page matches an older clone or another employer.
- Do not scrape or copy an opaque hidden template solely for semantic parity.
- Do not use provider scripts in the candidate; implement observed behavior locally.
- Pin and locally serve permitted fonts/assets to prevent network and version drift.
- Treat a provider migration or live job closure as a benchmark invalidation, not a candidate regression.
