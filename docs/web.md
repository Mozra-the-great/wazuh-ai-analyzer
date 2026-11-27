# Web layer (rewrite, `wazuh_ai_analyzer/web/`)

Waitress (one process, 8 threads) serves a Flask app. One process on purpose: the live
buffer, the quota and upstream gates and the counters live in it. This page is the
contract for the UI (P5, #87) and the reference for operators and reviewers.

## Authentication

* One user: `DASHBOARD_USER` / `DASHBOARD_PASSWORD_HASH` (Werkzeug hash). The hash is
  verified on every attempt, also for an unknown user name, so both cost the same.
* **Every `/api/*` path needs a session**, including `/api/stats` and `/api/findings`
  and unknown paths (401 before 404). The only exceptions are `GET /api/session` and
  `POST /api/login`. Without `DASHBOARD_PASSWORD_HASH` the API answers 503.
* Pages and files redirect to `/login?next=<path>` without a session, except the files
  the login and logout pages consist of (`PUBLIC_FILES` in `web/app.py`).
* **Server-side sessions** (`web_sessions`): the table stores `sha256(session id)`, the
  CSRF token, the user and the expiry. The id is 256 random bits issued by the server;
  a client-chosen id is never adopted (no session fixation). Login always creates a new
  id and deletes the session of a cookie that came along. Logout deletes the row, so a
  copied cookie is dead as well. The table is capped at 50 rows and pruned on use.
* Cookies: `__Host-wai_session` (and `__Host-wai_pre`, see below), `HttpOnly`,
  `Secure`, `SameSite=Strict`, `Path=/`, no `Domain`; lifetime `SESSION_LIFETIME`. With
  `SESSION_COOKIE_SECURE=false` (plain http, development) the names lose the `__Host-`
  prefix and the `Secure` flag, and no HSTS header is sent.
  `SameSite=Strict` means a link from another site arrives without the cookie and shows
  the login page first (`next` brings the user back).
* `session.key` (data directory, mode 0600, created with `O_CREAT|O_EXCL|O_NOFOLLOW`)
  keys the pre-session login token. It is shared with `analyzer.py`, so a rollback works.

## Login rate limit

`LOGIN_MAX_ATTEMPTS` failed logins per client in a sliding 60 s window, then 429 with
`Retry-After`. The state is bounded: at most 4096 clients (least recently used dropped
first), every entry expires with its window, and at most `LOGIN_MAX_ATTEMPTS` timestamps
are kept per client. IPv6 clients count per /64. An attempt is counted before the password is checked, so
parallel requests cannot exceed the limit. There is no global budget: an attacker with
more than 4096 addresses (or /64 networks) can evict its own entries, and the limit is
then the speed of the password hash. Behind a proxy with `TRUSTED_PROXY_HOPS=0` all
clients share one bucket, so set the variable.

The client address is the socket peer. `X-Forwarded-For` is used **only** when
`TRUSTED_PROXY_HOPS` is above 0 (Werkzeug `ProxyFix` plus waitress passing the headers
on); with 0, waitress removes the `X-Forwarded-*` headers before the app can see them.
`X-Forwarded-Host` is not trusted (the proxy must pass the `Host` header on). Sessions
are not tied to the password hash: after changing `DASHBOARD_PASSWORD_HASH`, restart
and run `DELETE FROM web_sessions` (or wait for `SESSION_LIFETIME`).
Set `TRUSTED_PROXY_HOPS` only when a reverse proxy really sits in front **and** the
service port cannot be reached around it (otherwise a client sends its own header). The
configuration enforces this: with `TRUSTED_PROXY_HOPS` above 0 the service starts only when
`LISTEN_HOST` is a loopback address (127.0.0.0/8, `::1`, `localhost`: the proxy runs on the same
host) or `TRUSTED_PROXY_ADDRESSES` lists the proxy (IP addresses or networks, e.g.
`192.168.0.5,10.0.0.0/24`). With that list the headers are believed only from those peers; a
request from any other address loses its `X-Forwarded-*` headers and counts under its socket address.

## CSRF

Every state-changing request needs, besides the cookie:

1. a same-origin request: `Sec-Fetch-Site` (when sent) must be `same-origin` or `none`,
   and `Origin` (when sent) must name this host (the scheme is not compared: behind a
   TLS-terminating proxy the app sees http), and
2. the token in the `X-CSRF-Token` header, compared in constant time.

* **Login** uses a pre-session token: `GET /api/session` (no session) sets the cookie
  `__Host-wai_pre` (random value) and returns `csrf_token` = HMAC(`session.key`, value).
  The token is only valid together with that cookie.
* **Everything else** (today only `POST /api/logout`) uses the per-session token, which
  `GET /api/session` returns for a logged-in session and `POST /api/login` returns on
  success.
* Bodies must be `application/json` (415 otherwise) and at most 16 KiB (413).

## Headers (every response, errors and redirects included)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none';
  base-uri 'none'; form-action 'self'
X-Content-Type-Options: nosniff        X-Frame-Options: DENY
Referrer-Policy: no-referrer           Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin   Permissions-Policy: (camera, microphone, ... off)
Strict-Transport-Security: max-age=31536000   (only with SESSION_COOKIE_SECURE)
Cache-Control: no-store                (every /api/* response and every HTML page)
```

No `unsafe-inline`, no `unsafe-eval`. A page that needs one inline script (kern's theme
script) adds its sha256 with `build_csp(script_hashes=...)` (`web/headers.py`); compute
the hash at build time, never by hand.

## API

All answers are JSON (`Content-Type: application/json`, `nosniff`). Errors are
`{"error": "...", "detail": "..."}`; `detail` never echoes the input; no stack traces.

| Request | Answer |
| --- | --- |
| `GET /api/session` | `{authenticated, csrf_token, [user, expires_at]}` |
| `POST /api/login` `{username, password, next?}` | `{ok, next, csrf_token, expires_at}`; 401 `{remaining_attempts}`, 429 `{retry_after}` |
| `POST /api/logout` | `{ok}` |
| `GET /api/stats` | the legacy keys, plus `mode` |
| `GET /api/findings?limit&offset&severity&source` | `{findings, total, limit, offset}` |
| `GET /api/findings/<id>` | one finding, plus `batch_summary`, `alert_count` |
| `GET /api/batches` | the last 50 batches, an explicit column list plus `finding_count` |

* A finding has the legacy keys plus `confidence` (number or null) and `mode`.
* `limit` is 1 to 200 (above 200 is cut to 200); `offset` is 0 or more; `severity` is one
  of `critical high medium low info`; `source` is `live` or `history`; an empty value
  means "no filter". Anything else is 400. (`limit=-1` used to return every row, and a
  non-numeric value used to be a 500.)
* `next` of the login is reduced to a local path (`/` otherwise).

## What the UI (P5, kern) must respect

* **Everything the model or the alert log influenced is attacker-influenced text**:
  finding `title`, `description`, `recommendation`, `affected_agents`, `rule_ids`, the
  batch `summary`, `raw_groups` and `last_error`, and `quota.last_error` /
  `upstream.last_error` in the stats. The API returns them as JSON strings, never HTML.
  Render them with `textContent` / framework text escaping only: **no `{@html}`, no
  `innerHTML`, no Markdown-to-HTML**, no building of URLs or attributes from them.
* **Mark recommendations and summaries as AI generated and unverified** next to the text.
* No inline script, no `style=` attribute, no `on*=` handler, no third-party origin
  (fonts included): the CSP forbids it. Styles set through the CSSOM
  (`el.style.width = ...`) are fine.
* Send `X-CSRF-Token` with `POST /api/logout`; log in through `GET /api/session` then
  `POST /api/login` (JSON); on a 401 go to `/login`. The login page may be a view of
  the SPA, but then the files it needs must be listed in `PUBLIC_FILES`.
* `GET /logout` is only a confirmation page; the logout itself is the POST.
* The dashboard is the kern build of `ui/` (see "The dashboard build" below); `UI_DIR` in
  `service.py` points at its output, `wazuh_ai_analyzer/web/ui/`.
  An unknown path without a file extension serves `index.html` (SPA routes); an unknown
  file with an extension is 404; only the file types of `web/static_files.py` are served.

## The dashboard build

`ui/` is a plain Vite SPA (Svelte 5, TypeScript strict; not SvelteKit, because kern's strict-CSP
test covers only the Vite path) on kern, theme `code` (dark by default, `code-light` through
kern's `ThemeToggle`, the choice is kept in `localStorage` under `wai-theme`). Texts are German.
The fonts are the three that kern prescribes for `code` (kern ships none): Inter and JetBrains Mono
from pinned `@fontsource-variable` packages, Silkscreen (weights 400 and 700, the display weight of
`code`) from the pinned `@fontsource/silkscreen` package. All are served from this origin (Latin
subset, `font-src 'self'`).

* **Build:** `cd ui && npm ci && npm run build` writes `wazuh_ai_analyzer/web/ui/`. The output is
  generated, git-ignored and shipped in the release tarball (P7); a checkout that was never built
  logs a warning at start-up and answers pages with 404. The build is reproducible (hashed asset names
  and the CSP hash are identical on a second build; the `ui` CI job checks it).
* **kern** is a release tarball in `ui/package.json`; `package-lock.json` holds its sha512
  integrity, `npm ci` fails on any other content. Update it with the install command of kern's
  consumer guide (a new URL, a new integrity value, nothing else in the diff).
* **Pages:** `index.html` (the dashboard, needs a session), `login.html` and `logout.html`
  (public). Each has exactly one inline script: kern's before-paint theme script.
* **`ui-manifest.json`** is written by the build next to the pages. The build re-reads the pages,
  fails on any other inline script, `<style>`, `style=`, `on*=` or non-local reference, hashes the
  theme script as it stands in the page, and lists the files the login and logout pages load.
  `load_ui_manifest()` (`web/ui_manifest.py`) validates it at start-up (plain relative names of
  existing files of an allowed type, a well-formed hash; anything else refuses the start) and
  `service.py` passes the hash to `build_csp(script_hashes=...)` and the file list to
  `create_app(public_files=...)`, which serves exactly those files (plus `PUBLIC_FILES`) without a
  session. A directory without a manifest adds neither.
* **Rules from this page that the build and the tests enforce:** no `{@html}` (lint rule), no
  `innerHTML` and friends (lint), model and log text only as text nodes, recommendations and
  summaries labelled "KI-generiert, nicht verifiziert", no foreign origin and no CSP violation
  (the Playwright test fails on any `securitypolicyviolation`, console error or foreign request).
* **Tests:** `npm test` (Vitest: parsing, API client, dashboard state, build helpers),
  `npm run e2e` (Playwright against `ui/e2e/server.py`: the real `create_app`, waitress and
  headers on a fixture database with hostile texts; login, filter, paging, detail, logout, banners,
  keyboard, 360 px, axe), `npm run screenshots` (the PR screenshot set).
* **Detail view:** the finding detail is a kern `Drawer` (native `<dialog>`: focus is trapped, Escape
  closes, focus returns to the row). It shows the list data at once and adds the batch summary and
  alert count from `GET /api/findings/<id>`.

## Static files

`StaticSite` serves from one root with `werkzeug.security.safe_join`, then resolves
symlinks and requires the result to stay inside the root; dot-files, directories and
other file types are not served. No answer depends on what exists outside the root, so
there is no file-existence oracle (#30). `STATIC_DIR` is accepted but ignored with a
start-up warning: the UI ships inside the package.

## Logs

Request logging is off. The redaction filter is attached to the root handlers and, after
the server is set up, to the `waitress` and `werkzeug` loggers. Uncaught exceptions of any
thread are logged through the same handlers. A failed login logs the client, never the
submitted user name or password.
