# wazuh-ai-analyzer

## Type
Python service: reads Wazuh `alerts.json`, batches alerts, has Gemini analyse them,
stores the result in SQLite and serves a login-protected dashboard.

## Where changes land
Analyzer changes are made and tracked **in this repo** (issues/PRs here). The
homelab (`Mozra-the-great/homelab-infra`) only **pins a commit** of this repo; it
never carries analyzer code. A change to `analyzer.py`, `static/index.html` or
`requirements.txt` therefore reaches the hosts only when that pin is bumped there.
CI-only changes (workflows, lint config, tests) need no pin bump.

## Stack
Python 3.10+ (CI runs 3.10 and 3.12), Flask + requests + werkzeug, SQLite (WAL),
vanilla-JS frontend, installed as a systemd service by `install.sh`. Docs and
code comments are German (README, scripts); keep that in existing files.

## Structure
```
analyzer.py          the whole service (config is read from env at import time)
static/index.html    dashboard
install.sh           installer; verifies downloads against checksums.sha256
scripts/release.sh   release helper: regenerates checksums.sha256, sets WAZUH_AI_REF
checksums.sha256     sha256 of analyzer.py, static/index.html, requirements.txt
requirements.in/.txt direct deps / fully hash-pinned lock (pip-compile --generate-hashes)
requirements-lint.*  ruff for the CI lint job (same scheme)
ruff.toml            lint rule set (pinned explicitly)
tests/               pytest, one module per topic; conftest.py isolates all paths
.github/workflows/   tests (pytest 3.10/3.12 + lint), workflow-lint, secret-scan,
                     claude (@claude), claude-code-review
```

## Commands
```sh
pip install --require-hashes -r requirements.txt && pip install pytest
python -m pytest -q                      # tests (no network, no real Gemini key)
pip install --require-hashes -r requirements-lint.txt && ruff check .
shellcheck install.sh scripts/release.sh
sha256sum --check --strict checksums.sha256
```
Bump a dependency: change the pin in `requirements.in`, then run the `pip-compile`
command from its header with **Python 3.12** and keep the file header intact (Dependabot
reads the Python version and the options from it).

## Rules that are easy to break
- **checksums.sha256** must match the three files it lists, in the same commit as any
  change to them: `sha256sum --text analyzer.py static/index.html requirements.txt > checksums.sha256`
  (use LF checkouts, see `.gitattributes`; the `lint` job fails otherwise).
- Required check names (ruleset): `pytest (3.10)`, `pytest (3.12)`, `lint`. Do not
  rename the jobs and do not add a `paths:` filter to workflows that provide them.
- The Gemini API key lives in the service environment only. Never print the
  environment, never commit `.env*`, never put real keys in tests (`conftest.py` uses a
  dummy).
- `ruff.toml` ignores a few harmless findings in `analyzer.py` on purpose; do not edit
  that file only to silence them (it would force a new pin).
- Workflows: actions pinned by full SHA with a `# vX.Y.Z` comment, minimal
  `permissions`, no `${{ github.event.* }}` inside `run:` (pass it via `env:`). Validate
  with `actionlint` and `zizmor` before pushing. The Claude workflows skip green
  while `CLAUDE_CODE_OAUTH_TOKEN` is not set.

---

## Working rules

These rules apply regardless of what's above. They mirror the operator's global
Claude Code configuration so this repo behaves consistently even if opened on a
different machine or by a collaborator.

### Language
- Chat responses: German
- Everything that goes into the repo (commit messages, branch names, PR
  descriptions, CHANGELOG): English. Existing German docs and comments in this repo
  stay German.

### Approach
Understand the task fully, think through edge cases and blast radius, then implement it
completely. No placeholders, no `TODO` without a resolution. Ask once if something
fundamental is unclear.

### Git workflow
- Never commit directly to `main` - always a feature branch (`feat/...`, `fix/...`, `ci/...`)
- Conventional Commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`
- Before every push: check `git status` and `git diff --staged`
- No `git push --force` on main

### Security
- `.env`, `.env.*`, `*.pem`, `*.key`, `*.secret` - never read, log, or commit
- No credentials/tokens/passwords in code
