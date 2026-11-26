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
Legacy service (`analyzer.py`): Python 3.10+, Flask + requests + werkzeug (the rewrite adds
waitress), SQLite (WAL),
vanilla-JS frontend, installed as a systemd service by `install.sh`. Docs and code comments
are German (README, scripts); keep that in existing files.

Rewrite (epic #81, package `wazuh_ai_analyzer/`): Python >= 3.11, built next to the legacy
service, which stays the deployed code path until the cutover. New code, tests and docs of
the rewrite are English, typed (`mypy --strict`) and linted with the stricter
`wazuh_ai_analyzer/ruff.toml`.

## Structure
```
analyzer.py          the whole legacy service (config is read from env at import time)
wazuh_ai_analyzer/   the rewrite: config.py, secret.py, permissions.py, logging_setup.py,
                     storage/ (db, schema = versioned additive migrations, repo, retention,
                     contract = frozen read interface); ingest/ (live tail, backlog,
                     watermark.json shared with analyzer.py, sanitize = the only gate for alert
                     fields); analysis/ (AnalysisBackend protocol, prompt + answer validation,
                     llm = Gemini over plain REST, decision = Gemini Decision 1 with the
                     versioned definitions in decisions/v1.json, text_templates, probe);
                     pipeline/ (retry queue, quota/upstream gates,
                     workers); metrics/runtime.py (the `runtime` block of /api/stats);
                     service.py (startup order, supervision, clean stop); instance_lock.py
                     (flock on data_dir/.lock, one service per data dir); web/ (waitress + Flask:
                     auth, server-side sessions, CSRF, CSP, JSON API, static files; web/ui/ holds the
                     generated dashboard build, git-ignored, see docs/web.md). `python -m wazuh_ai_analyzer check-config|migrate|run`
docs/configuration.md  every environment variable, defaults, valid ranges
docs/decision-api.md   Gemini Decision 1: verified API facts, mapping to findings, probe command
docs/web.md          web layer: auth, sessions, CSRF, headers, API, rules for the UI (P5)
pyproject.toml       project metadata, pytest and mypy configuration (no build backend)
static/index.html    dashboard
ui/                  the rewrite's dashboard: Vite + Svelte 5 + kern (source, lockfile, Vitest, Playwright e2e
                     with ui/e2e/server.py); `npm run build` writes wazuh_ai_analyzer/web/ui/ (git-ignored)
deploy/              release tarball files of the rewrite: hardened systemd unit (LoadCredential), unprivileged-LXC
                     drop-in, settings example, install.sh (tarball installer: releases/<version> + current symlink)
scripts/build_release.py  reproducible release tarball (stdlib only); docs/release.md = build, release and sandbox
                     notes, docs/install.md = install/upgrade notes (shipped in the tarball as INSTALL.md)
install.sh           legacy installer; verifies downloads against checksums.sha256
scripts/release.sh   release helper: regenerates checksums.sha256, sets WAZUH_AI_REF
checksums.sha256     sha256 of analyzer.py, static/index.html, requirements.txt
requirements.in/.txt direct deps / fully hash-pinned lock (pip-compile --generate-hashes)
requirements-lint.*  ruff, mypy, pip-audit for the CI jobs (same scheme)
requirements-test.*  pytest for the CI test jobs (same scheme)
ruff.toml            lint rule set of the legacy code (pinned explicitly); the rewrite has its own
tests/               legacy tests, one module per topic; conftest.py isolates all paths
tests/v2/            tests of the rewrite: unit/, contract/ (frozen DB interface, exporter SQL),
                     rollback/ (legacy analyzer on a migrated DB), differential/ (legacy and
                     new code on the same input must give the same batches)
.github/workflows/   tests (pytest 3.11/3.12, pytest (3.10) legacy, mypy, lint), ui (dashboard build +
                     Playwright under the real CSP), release (tarball built twice + systemd sandbox test on the runner;
                     publishes on `v*` tags only), dependency-audit, workflow-lint, secret-scan, claude (@claude), claude-code-review
```

## Commands
```sh
pip install --require-hashes -r requirements.txt -r requirements-test.txt
python -m pytest -q                      # tests (no network, no real Gemini key)
python -m pytest -q --ignore=tests/v2    # legacy tests only (what the 3.10 job runs)
pip install --require-hashes -r requirements-lint.txt && ruff check . && mypy
pip-audit --require-hashes --disable-pip -r requirements.txt
(cd ui && npm ci && npm run lint && npm run check && npm test && npm run build)   # dashboard
(cd ui && E2E_PYTHON=python npm run e2e)  # needs the build, the backend requirements, `npx playwright install chromium`
shellcheck install.sh scripts/release.sh deploy/install.sh
(cd ui && npm ci && npm run build) && python scripts/build_release.py --output dist   # release tarball
sha256sum --check --strict checksums.sha256
```
Bump a dependency: change the pin in the `.in` file, then run the `pip-compile`
command from its header with **Python 3.12** and keep the file header intact (Dependabot
reads the Python version and the options from it). Compile on Linux: on Windows pip-compile
adds `colorama`, which has to be removed by hand. `requirements-test.in` lists
`exceptiongroup` and `tomli` explicitly because the 3.10 job needs them and pip-compile on
3.12 would drop them.

## Rules that are easy to break
- **checksums.sha256** must match the three files it lists, in the same commit as any
  change to them: `sha256sum --text analyzer.py static/index.html requirements.txt > checksums.sha256`
  (use LF checkouts, see `.gitattributes`; the `lint` job fails otherwise).
- Required check names (ruleset "Schütz mein Baum", active since 2026-10-21): `pytest (3.10)`,
  `pytest (3.12)`, `lint`, `CodeQL` (GitHub default setup), `workflow-lint`, `gitleaks`.
  Do not rename the jobs and do not add a `paths:` filter to workflows that provide them.
  The rewrite needs 3.11, so `pytest (3.10)` is now the job `pytest-legacy` (legacy tests
  only). When the maintainer has replaced the required check `pytest (3.10)` by
  `pytest (3.11)` in the ruleset, delete that job. A new check becomes required only after
  it has been green on `main`.
  `claude-review` is not required yet; add it once `CLAUDE_CODE_OAUTH_TOKEN` is set.
- **The database schema is a public read interface** (the homelab exporter reads
  `batches`, `findings`, `sqlite_sequence` and the German `last_error` prefixes). Only
  additive changes, and every change goes through `storage/contract.py` and
  `tests/v2/contract/`. The legacy analyzer must keep working on a migrated database
  (`tests/v2/rollback/`, and the whole legacy suite runs on a migrated DB with
  `LEGACY_SUITE_ON_MIGRATED_DB=1`). Final `last_error` texts are built only by the
  `contract.error_*` helpers; `tests/v2/differential/test_pipeline_differential.py`
  compares them word for word with `analyzer.py`.
- Tests that touch the legacy module through the `az` fixture change its globals with
  `monkeypatch` only: a plain assignment leaks into every later test.
- **`watermark.json` is shared with `analyzer.py`** in both directions (cutover and
  rollback): keep its layout and the first-line digest (`ingest/archives.line_digest`)
  unchanged; `tests/v2/differential/` checks both directions.
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
