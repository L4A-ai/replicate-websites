[English](README.md) | [简体中文](README.zh-CN.md)

[![skills.sh](https://skills.sh/b/l4a-ai/replicate-websites)](https://skills.sh/l4a-ai/replicate-websites/pixel-by-pixel)

# Pixel by Pixel

**Pixel by Pixel** (`pixel-by-pixel`) is a portable Agent Skill for rebuilding authorized webpages
and proving frontend fidelity with deterministic Playwright captures, semantic contracts,
accessibility checks, interaction tests, and pixel-by-pixel comparison.

The repository exposes one canonical skill at
[`skills/pixel-by-pixel`](skills/pixel-by-pixel). It works with Claude Code, Codex, and
other agents that support the open Agent Skills layout; no agent-specific copy of the instructions
is maintained.

> Renamed from `replicate-websites`: reinstall with `--skill pixel-by-pixel`, then remove the old
> installed skill directory so agents do not discover two copies.

## What it includes

- Sandboxed, GET-only inspection of an authorized source page
- Full-page strict and tolerant pixel comparison at four responsive viewports
- DOM, typography, resource, control, form-label, link, and accessibility contracts
- A safe static bootstrap and a dependency-free local candidate service
- Candidate integrity checks and synthetic application-flow tests
- A same-origin mock submission backend with non-retention and email disabled by default
- Regression-aware fidelity loops, diff diagnosis, and clean-slate evaluation tooling

## Requirements

- Node.js 20 or newer
- npm
- macOS, Linux, or Windows

The skill installer places the instructions and tools. A separate one-time setup command installs
the pinned npm runtime and Chromium.

## Install with the cross-agent installer

The recommended installation follows the same [`skills`](https://github.com/vercel-labs/skills)
workflow used by other portable Agent Skill repositories:

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --copy
```

The installer detects supported agents and prints the destination. Point `SKILL_DIR` at that
directory, then install and verify the runtime:

```bash
SKILL_DIR=/absolute/path/to/pixel-by-pixel
npm --prefix "$SKILL_DIR" run setup
npm --prefix "$SKILL_DIR" run doctor
```

`setup` installs `playwright`, `pixelmatch`, and `pngjs`, then downloads Chromium. It never installs
a background service. `doctor` is read-only and reports whether Node, the packages, and a usable
Chromium executable are present.

### Codex

Project install:

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent codex \
  --copy \
  -y

npm --prefix .agents/skills/pixel-by-pixel run setup
```

User install:

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent codex \
  --global \
  --copy \
  -y

npm --prefix ~/.agents/skills/pixel-by-pixel run setup
```

Codex discovers project skills in `.agents/skills` and user skills in `~/.agents/skills`.

### Claude Code

Project install:

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent claude-code \
  --copy \
  -y

npm --prefix .claude/skills/pixel-by-pixel run setup
```

User install:

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent claude-code \
  --global \
  --copy \
  -y

npm --prefix ~/.claude/skills/pixel-by-pixel run setup
```

### Multiple or other agents

Repeat `--agent` to install the same canonical skill for more than one agent:

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent codex \
  --agent claude-code \
  --copy \
  -y
```

For another supported agent, omit `--agent` and choose interactively, or pass an identifier
supported by the installer. For a custom agent that reads a skills directory, copy
`skills/pixel-by-pixel` into that directory and run `npm run setup` inside the copy.

## Use the skill

Ask the agent to use `pixel-by-pixel` and provide the authorized target URL, output directory,
and required deployment mode. For agents with explicit skill invocation, a prompt can begin with:

```text
Use $pixel-by-pixel to recreate this authorized webpage in an empty local workspace.
Keep the source GET-only, compare all four default viewports, and run the integrity gates.
```

Read [`SKILL.md`](skills/pixel-by-pixel/SKILL.md) for the complete capture, implementation,
comparison, diagnosis, interaction, and release workflow.

The core scripts can also be run directly:

```bash
SKILL_DIR=/absolute/path/to/pixel-by-pixel

node "$SKILL_DIR/scripts/compare-pages.mjs" \
  --baseline https://example.com/authorized-page \
  --candidate http://127.0.0.1:4173/ \
  --out /tmp/replica-comparison
```

The default viewport set is desktop `1440x1000`, tablet `768x1024`, mobile `390x844`, and compact
`360x800`.

## Safety boundary

- Inspect live third-party targets read-only; never submit their forms or send analytics writes.
- Use copied content and assets only with ownership or permission.
- Keep `authorized-local` output private and bound to loopback.
- Give public third-party simulations a persistent, unambiguous disclosure.
- Never use iframes, reverse proxies, source scripts, opaque hidden values, or full-page screenshots
  to fake fidelity.
- Keep applicant values and upload bytes transient; email remains disabled unless separately
  implemented and explicitly enabled.

See
[`safety-and-provenance.md`](skills/pixel-by-pixel/references/safety-and-provenance.md) for the
full boundary.

## Develop and validate

```bash
git clone https://github.com/L4A-ai/replicate-websites.git
cd replicate-websites
npm ci --ignore-scripts
npx playwright install chromium
npm run validate
npm run check:install
node evals/scripts/hash-skill.mjs
```

Repository layout:

| Path | Purpose |
|---|---|
| `skills/pixel-by-pixel/` | The only distributable Agent Skill |
| `test/skill/` | Repository-owned runtime and browser tests |
| `evals/` | Clean-slate evaluator, policies, schemas, and contributor documentation |
| `.github/workflows/skill-ci.yml` | Validation, discovery, package, and hash checks |

CI verifies that the repository exposes exactly one discoverable skill and that the npm tarball
contains only the intended skill runtime.

## License

The reusable code and documentation are licensed under the MIT License. Captured third-party
content and assets are not covered and are not distributed here.
