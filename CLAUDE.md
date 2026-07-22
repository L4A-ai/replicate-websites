# replicate-websites

Standalone Codex skill for reconstructing authorized webpages and measuring full-page visual,
layout, form, and accessibility fidelity.

## Hard rules

- Keep third-party targets read-only. Never submit live forms, create accounts, upload files, enter
  credentials or personal data, or permit analytics/beacon writes during capture.
- Use replicas only for authorized development, local evaluation, or clearly disclosed simulations.
  Never deploy a deceptive third-party impersonation or reuse restricted assets without permission.
- Keep live page copies, downloaded assets, screenshots, and generated eval candidates out of git.
  Commit only the reusable skill, scripts, references, synthetic fixtures, and aggregate eval evidence.
- Treat `SKILL.md` as the workflow source of truth. Keep it concise and route detailed guidance to
  one-level `references/` files.
- Run the skill validator and script tests after every material workflow or tooling change.
- Keep `AGENTS.md` and `CLAUDE.md` byte-identical.
