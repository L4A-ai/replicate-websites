# Job-application contract

## Capture the complete form surface

Record section order and every input, select, textarea, button, hidden field, label, option, required
state, default state, error/status node, and accessible role/name/state. Include fields revealed by
safe candidate-only interactions. Record hidden payload lengths or hashes instead of copying opaque
provider templates.

Treat these as independent values:

- Visible question text
- Native control `name`
- Submitted `value`
- Accessible name
- Internal normalized value

Providers often use different strings for each.

## Match browser semantics

- Use native controls where the source uses them.
- Preserve exact label nesting and `for`/`id` relationships.
- Preserve literal required markers and their pseudo-element placement.
- Model radio groups by shared name and exact option values.
- Preserve select placeholder options, disabled states, and option order.
- Preserve file-input indirection, filename/status text, replacement behavior, and empty-file sentinels.
- Reproduce conditionals, selection limits, autocomplete, focus, keyboard behavior, and validation timing locally.

Do not submit or interact with the live application. Derive behavior from public markup/scripts and
exercise it only on the candidate.

## Use the audited synthetic backend

Keep provider-shaped names and option values in the browser form. The bundled interaction backend
accepts them as opaque multipart parts; it deliberately does not normalize, persist, log, or return
applicant values. It transiently validates the request and then discards the body before issuing a
receipt. It enforces:

- A multipart body limit with framing overhead above the synthetic PDF limit
- Exact synthetic fixture header and hidden canary markers
- Well-formed multipart part metadata, bounded text fields, and part-count limits
- Only the generated `synthetic-resume.pdf`/`application/pdf` fixture (plus an empty browser file sentinel)
- Transient UI-versus-retry equivalence across field names, values, file metadata, and file bytes
- Idempotency for retries and double clicks
- Deterministic receipt and confirmation state
- Zero persistence of credentials, applicant values, upload metadata, or resume bytes
- Zero browser-side retention: cookies, local/session storage, IndexedDB, Cache Storage, and
  origin-private/file-system APIs are blocked, inventoried without values, and must remain empty
- Email disabled with no outbox or dispatch path

An owned production service that performs provider-specific normalization is outside this generic
mutation gate and needs a separate audited contract and tests. Do not substitute it for the bundled
backend when claiming this skill's interaction result.

Never reuse a live action URL, account identifier, authorization token, CAPTCHA, hidden signed
template, or upload endpoint. Declare these as approved semantic policy differences when they are
otherwise visible to the comparator.

## Candidate-only interaction gate

Run mutation checks only at a loopback URL against the immutable audited starter backend bundled
with this skill. Treat any public candidate as read-only: run fidelity, determinism, network, and
integrity checks there, but never submit its form. Do not use the interaction runner against a
hand-written or untrusted backend merely because it is same-origin. The interaction runner treats
the supplied loopback URL only as a locator: it verifies the candidate files, launches `node
server.mjs` itself with a scrubbed environment on a fresh port, and kills that process afterward.
The trusted process asks the kernel for port `0` and reports the assigned loopback port over a
strict IPC readiness message; it never releases a guessed port for another listener to claim.

At minimum:

1. Independently inventory every active form, including forms in open shadow roots; a manifest
   selector or `notApplicable` declaration may not hide one.
2. Trigger native/custom required validation with an empty submission.
3. Fill every visible required field with synthetic data and revalidate native and ARIA-required
   controls after all manifest actions.
4. Exercise radio, checkbox, select, textarea, autocomplete, and conditional controls.
5. Upload a generated harmless PDF fixture.
6. Submit to the same-origin mock endpoint.
7. Assert deterministic success UI and receipt state.
8. Retry with the same idempotency key and assert one logical submission.
9. Compare the UI and retry multipart payloads transiently, persist only counts/booleans, and require
   the synthetic canary in both.
10. Require every `[data-replica-source-link]`, including markers in open shadow roots, to have no
    `href` or `xlink:href`. Exercise each marker independently with pointer click, Enter, and Space;
    after every activation require the full candidate URL/origin, popup/download state, and request
    count to remain unchanged.
11. Assert no request reached the source host or an email provider.

## Manifest contract

Keep `replica.manifest.json` in the candidate root:

```json
{
  "schemaVersion": 1,
  "mode": "authorized-local",
  "start": { "command": ["npm", "start"], "healthPath": "/healthz" },
  "page": { "path": "/application", "readySelector": "[data-replica-ready]" },
  "backend": {
    "implementation": "replicate-websites-starter-v1",
    "submitPath": "/api/applications",
    "auditPath": "/api/replica-audit",
    "emailEnabledByDefault": false,
    "retainsApplicantValues": false
  },
  "interaction": {
    "submitSelector": "button[type=submit]",
    "successSelector": "[data-submission-success]",
    "settleMs": 1500,
    "actions": []
  }
}
```

Use `interaction.actions` only for controls that safe auto-fill cannot operate. Keep selectors generic
to the candidate implementation; do not encode benchmark-specific fixes in the distributed skill.
The integrity and interaction gates must reject an unknown backend implementation, a public
candidate origin, or a manifest whose declared mode differs from the rendered page metadata.
