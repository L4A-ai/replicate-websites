# Safety and provenance

## Choose the operating mode

| Mode | Allowed fidelity work | Required disclosure |
|---|---|---|
| Owned or explicitly authorized site | Reuse authorized source and assets within the permission grant | Follow the owner's requirements |
| Private localhost evaluation of a public page | Read public GET resources, reconstruct locally, use synthetic interactions | Add `replica-mode=authorized-local` metadata; do not expose publicly |
| Public third-party simulation | Use public facts and permitted/independently created assets; keep all writes local | Show a persistent, unambiguous simulation banner |

Stop before publication when authorization or intended audience is unclear. Exact local evaluation
does not authorize a deceptive public deployment.

The starter service encodes these boundaries as `authorized-local`, `owned`, and
`public-simulation` modes. The local mode binds only to `127.0.0.1`; the other modes bind to
`0.0.0.0`, and `public-simulation` records its mode in the manifest and renders a disclosure before
any implementation content. An unresolved or invalid starter mode fails closed to loopback.

## Keep source inspection read-only

- Permit only `GET`, `HEAD`, and harmless browser preflight requests to the target.
- Block form submissions, analytics beacons, XHR/fetch writes, WebSockets, popups, downloads, and service workers.
- Never enter credentials, real applicant data, resume bytes, cookies, tokens, or personal email addresses.
- Never create an account or advance a live application flow merely to expose another screenshot state.
- Use a synthetic candidate-only environment for validation, uploads, submission, receipts, OTP, CAPTCHA, and email flows.

The bundled inspection and comparison scripts enforce this network boundary. Their browser proxy
resolves each public destination at connection time, rejects every private/reserved answer, and
connects only to a vetted address while preserving the requested TLS server name. Browser routing
is a secondary audit/blocking layer, not the DNS-rebinding boundary. Do not add `--allow-non-get`
to live-source commands.

The static bootstrap additionally requires an explicit provenance mode, enables Chromium's sandbox,
blocks other private-network origins, caps requests/resources/markup/scroll work, removes live code
and navigation primitives, emits a restrictive candidate CSP, and stages output before an atomic
install. A local browser is still an execution boundary: run it only against a URL you are permitted
to inspect, without an authenticated profile or sensitive URL parameters.

## Handle content and assets deliberately

- Record source URLs and capture time as provenance.
- Do not commit downloaded pages, screenshots, proprietary prose, employer logos, fonts, or captured hidden payloads to the skill repository.
- Store raw captures and generated replicas in ignored eval directories outside the agent-visible skill mount.
- Treat bootstrap output from `authorized-local` mode as private generated evidence; never commit or deploy it.
- Prefer open fonts and independently created placeholders when redistribution rights are absent.
- Do not pad synthetic hidden values with copied provider templates merely to force semantic zero.
- Never implement the result as an iframe, reverse proxy, remote script shell, or full-page raster image.
- Persist only type-aware control/value classifications needed for structural comparison. Strip
  prefilled names, email addresses, phone numbers, freeform text, and opaque option/hidden values
  from captures, reports, console output, and serialized candidates.

## Keep the mock backend non-sensitive

- Accept provider-shaped names and values only on the local candidate origin.
- Use synthetic fixtures in tests and examples.
- Discard submitted values after validation; persist no credentials or applicant PII.
- Validate synthetic upload metadata transiently; persist neither metadata nor bytes.
- Make writes idempotent and isolate state by a synthetic run identifier.
- Keep external email disabled by default. A mock outbox may be explicitly enabled for testing.
- Run submission mutation tests only on loopback against the immutable audited starter backend.
  Let the interaction runner spawn and terminate the verified backend; never trust a process that
  merely happens to be listening at the supplied candidate URL.
  Treat public deployments as read-only comparison and integrity targets.

## Publish safely

Before deployment, verify the public host, form actions, network requests, storage behavior, robots
policy, disclosure, and domain ownership. Rerun the pixel report after adding disclosure and report
that intentional visual delta honestly. A public-simulation release must have no pending or failed
script/stylesheet requests at the capture boundary: the DOM, bounded response hashes, and final CSS
stylesheet graph must reconcile. Confirm the disclosure remains readable and persistent throughout
the light/dark × reduced/no-preference motion × DPR 1/2 media matrix.
