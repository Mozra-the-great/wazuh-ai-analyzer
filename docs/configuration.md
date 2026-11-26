# Configuration (rewrite, `wazuh_ai_analyzer`)

The service is configured through environment variables only. All 34 variables of the
legacy `analyzer.py` keep their names and defaults, so an existing env file works
unchanged. The configuration is parsed and validated once at startup.

```sh
python -m wazuh_ai_analyzer check-config      # validate and print the effective settings
python -m wazuh_ai_analyzer check-config --require-api-key
python -m wazuh_ai_analyzer migrate           # create or migrate the database
python -m wazuh_ai_analyzer run               # ingest + analysis until SIGTERM/SIGINT
```

`run` migrates the database first, so `migrate` is optional before it. Until the web layer
(#86) lands, `run` serves no dashboard; the deployed service is still `analyzer.py`.
`ANALYSIS_MODE=decision` runs the Gemini Decision 1 backend (#88); see
[decision-api.md](decision-api.md). `python -m wazuh_ai_analyzer probe-decision` makes one
real call with a made-up alert group (needs the API key, never part of CI).

Exit codes: `0` ok, `1` runtime failure (database, file system), `78` invalid configuration.

## Rules

- A wrong type, an out-of-range value, an unknown mode or an unusable key file stops
  the start with one message per offending variable. The message names the variable and
  the expectation, never the value (it could be a secret in the wrong variable).
- An unset or empty variable means the default.
- Booleans accept `true`, `1`, `yes`, `false`, `0`, `no`. The legacy parser treated every
  other word as true; the rewrite rejects `off`, `disabled` and the like instead of
  guessing, so a security setting cannot flip silently.
- Secrets are held in a wrapper whose `repr` is `***` and are masked in logs.

## Differences from `analyzer.py`

| Variable | Change |
| --- | --- |
| `GEMINI_MODEL` | Default is now `gemini-3.1-flash-lite`. The old default `gemini-1.5-flash` has been retired by Google. An env file that sets the model is unaffected. |
| `SESSION_COOKIE_SECURE` | Strict boolean, see above. With `true` the cookies are named `__Host-wai_*` and HSTS is sent. |
| `STATIC_DIR` | Accepted, ignored with a warning (the UI is part of the package). |
| `TRUSTED_PROXY_HOPS` | Same meaning; without a proxy, `X-Forwarded-*` headers are removed by the server itself. |
| session cookie | `SameSite=Strict` (was `Lax`), server-side sessions, name `wai_session` / `__Host-wai_session`. Existing sessions end at the cutover. |
| login / logout | `POST /api/login` and `POST /api/logout` (JSON, CSRF token); `GET /logout` is a confirmation page. See `docs/web.md`. |
| `/api/findings` | `limit` below 1 or non-numeric, a negative `offset` or an unknown `severity`/`source` is 400 (was: `limit=-1` returned all rows, non-numeric values were a 500). |
| numeric variables | Range-checked (see the table) instead of accepted blindly. |
| `RETENTION_CHUNK`, `GEMINI_CONCURRENCY` | A value below 1 is an error instead of being raised to 1. |

## Gemini API key

The key is read from the first source that is set:

1. `GEMINI_API_KEY`
2. `GEMINI_API_KEY_FILE`: path of a file that contains only the key
3. `$CREDENTIALS_DIRECTORY/gemini` (systemd `LoadCredential=gemini:...`)

A key file must be a regular file (no symlink), owned by the service user, with mode
`0600` or `0400`, at most 4096 bytes. Otherwise the service refuses to start. A key is
1 to 512 printable ASCII characters without whitespace.

The file in `$CREDENTIALS_DIRECTORY` is judged less strictly, because systemd owns that
directory and keeps it private to the service user. systemd normally chowns the credential
to the service user (mode `0400`). When it cannot, for example in a container without a
tmpfs for the credentials, it leaves the file owned by root and grants the service user read
access through an ACL, so the mode shows `0440`. Both are accepted there: the owner is the
service user or root, the group bits are ignored, and access for others is still refused.
`GEMINI_API_KEY_FILE` always keeps the strict rule above.

Without any key the service still starts (as `analyzer.py` does) and the dashboard shows
"no key". `check-config --require-api-key` fails in that case.

## Variables

| Variable | Default | Valid values |
| --- | --- | --- |
| `WAZUH_ALERTS_LOG` | `/var/ossec/logs/alerts/alerts.json` | path |
| `DB_PATH` | `/opt/wazuh-ai-analyzer/data/analyses.db` | path; `watermark.json` and `session.key` live next to it |
| `STATIC_DIR` | `/opt/wazuh-ai-analyzer/static` | path; **ignored with a start-up warning**: the dashboard ships inside the package (the legacy `static/index.html` has inline code that the strict CSP forbids) |
| `BATCH_MAX` | `25` | 1 to 10000 |
| `BATCH_TIMEOUT` | `300` | 1 to 604800 seconds |
| `BATCH_TIMEOUT_QUIET` | `0` | 0 to 604800 seconds; 0 = same as `BATCH_TIMEOUT` |
| `URGENT_LEVEL` | `10` | 0 to 15 |
| `MIN_LEVEL` | `5` | 0 to 15 |
| `HISTORY_BATCH` | `50` | 1 to 10000 |
| `HISTORY_PAUSE` | `8.0` | 0 to 3600 seconds |
| `GEMINI_API_KEY` | none | see above |
| `GEMINI_API_KEY_FILE` | none | path (new) |
| `GEMINI_MODEL` | `gemini-3.1-flash-lite` | letters, digits, `.`, `_`, `-`, up to 100 characters |
| `GEMINI_TEMPERATURE` | `0.15` | 0 to 2 |
| `GEMINI_CONCURRENCY` | `2` | 1 to 64 |
| `INFRA_CONTEXT` | `a self-hosted Linux server environment` | printable text, up to 2000 characters |
| `RETRY_BASE_DELAY` | `60` | above 0, up to 86400 seconds |
| `RETRY_MAX_DELAY` | `3600` | above 0, up to 604800 seconds, not below `RETRY_BASE_DELAY` |
| `RETRY_MAX_AGE_HOURS` | `72` | above 0, up to 8760 |
| `QUEUE_MAX_AGE_HOURS` | `72` | above 0, up to 8760 |
| `RETRY_BAD_RESPONSE_MAX` | `3` | 1 to 100 |
| `RETRY_POLL` | `30` | above 0, up to 86400 seconds |
| `RETRY_PACE` | `10` | 0 to 86400 seconds |
| `STALE_ANALYZING_SECONDS` | `900` | above 0, up to 604800 |
| `RETENTION_DAYS` | `0` | 0 to 36500; 0 keeps everything |
| `RETENTION_INTERVAL` | `3600` | above 0, up to 604800 seconds |
| `RETENTION_CHUNK` | `500` | 1 to 100000 |
| `LISTEN_HOST` | `127.0.0.1` | IP address or host name |
| `PORT` | `8765` | 1 to 65535 |
| `DASHBOARD_USER` | `admin` | 1 to 128 printable characters |
| `DASHBOARD_PASSWORD_HASH` | none (the dashboard answers 503) | Werkzeug hash `<method>$<salt>$<hash>` |
| `SESSION_LIFETIME` | `28800` | 60 to 2592000 seconds |
| `LOGIN_MAX_ATTEMPTS` | `5` | 1 to 1000 |
| `TRUSTED_PROXY_HOPS` | `0` | 0 to 10 |
| `SESSION_COOKIE_SECURE` | `true` | `true`, `1`, `yes`, `false`, `0`, `no` |
| `ANALYSIS_MODE` | `llm` | `llm`, `decision` (new) |
| `DECISION_MODEL` | `gemini-decision-1` | model name, as `GEMINI_MODEL` (new) |
| `DECISION_THRESHOLDS` | `critical=0.3,high=0.5,medium=0.6,low=0.7,info=never` | see below (new) |

### `DECISION_THRESHOLDS`

Comma-separated `<severity>=<value>` pairs. A value is a number above 0 up to 1, or
`never` (no finding of that severity). Severities that are not listed keep their default.
Example: `high=0.45,info=0.9`.

The value is the minimum probability of the `relevant` question for a group that the model
rates with that severity. The API clamps a yes/no probability to 0.01 to 0.99, so a value
of `1` behaves like `never`. In `decision` mode the key is read from the same places as in
`llm` mode, and `DECISION_MODEL` replaces `GEMINI_MODEL` (`GEMINI_TEMPERATURE` is not used).
`GEMINI_CONCURRENCY` bounds the batches in flight; a batch sends one request per alert group.

## Database

The database schema is a public read interface for external tools (the homelab metrics
exporter). Changes are additive only; see `wazuh_ai_analyzer/storage/contract.py` and
`tests/v2/contract/`. `python -m wazuh_ai_analyzer migrate` creates or migrates the
database in place. The previous release keeps working on a migrated database, which is
the rollback path (`tests/v2/rollback/`).
