# replicate-websites

Portable Agent Skill for reconstructing authorized webpages and measuring full-page visual,
layout, form, interaction, and accessibility fidelity.

## Hard rules

- Keep third-party targets read-only. Never submit live forms, create accounts, upload files, enter
  credentials or personal data, or permit analytics/beacon writes during capture.
- Use replicas only for authorized development, local evaluation, or clearly disclosed simulations.
  Never deploy a deceptive third-party impersonation or reuse restricted assets without permission.
- Keep live page copies, downloaded assets, screenshots, and generated eval candidates out of git.
  Commit only the reusable skill, scripts, references, synthetic fixtures, and aggregate eval evidence.
- Treat `SKILL.md` as the workflow source of truth. Keep it concise and route detailed guidance to
  one-level `references/` files.
- Keep exactly one distributable skill at `skills/replicate-websites`. Agent-specific adapters may
  reference it, but must never duplicate its instructions.
- Keep repository tests and evaluator internals outside the distributable skill directory.
- Run the skill validator and script tests after every material workflow or tooling change.
