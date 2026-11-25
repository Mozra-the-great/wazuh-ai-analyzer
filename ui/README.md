# Dashboard (`ui/`)

The web UI of the Wazuh AI Analyzer rewrite: a plain Vite SPA (Svelte 5, TypeScript strict) on the
[kern](https://github.com/Mozra-the-great/kern) design kit, theme `code` (dark by default, light
through the theme toggle). The contract with the backend is `docs/web.md`; read its section "What
the UI must respect" before changing anything here.

```sh
cd ui
npm ci                 # exact versions from package-lock.json, kern checked by integrity hash
npm run lint           # eslint (typed), also bans {@html} and innerHTML
npm run check          # svelte-check, strict
npm test               # Vitest
npm run build          # writes ../wazuh_ai_analyzer/web/ui/ (git-ignored) + ui-manifest.json
E2E_PYTHON=python npm run e2e          # Playwright against the real backend, needs the build
E2E_PYTHON=python npm run screenshots  # writes e2e/.run/shots/*.png
```

Node >= 22. The tests start `e2e/server.py` (waitress + Flask + the real CSP on a fixture database) and
stop it again. For a quick look in a browser: `python e2e/server.py --port 8799 --run-dir e2e/.run`
(from `ui/`, after a build), then open `http://127.0.0.1:8799/login` (user `admin`, the dummy
password is in `e2e/server.py`). There is no Vite dev server flow: the dev server injects CSS as
`<style>`, which the backend CSP forbids, so always test the production build.

## Layout

| Path | Content |
| --- | --- |
| `src/app/` | dashboard (`Dashboard` state class with runes, one component per view) |
| `src/login/`, `src/logout/` | the two public pages |
| `src/lib/` | API client, response parsing, formatting, German texts, theme constants |
| `scripts/vite-csp.ts` | build step: theme script in every page, CSP checks, `ui-manifest.json` |
| `e2e/` | Playwright tests, screenshot spec, the fixture backend |

## Rules (enforced by lint, build and tests)

* Everything the API returns that a model or an alert log influenced is shown as text: no `{@html}`,
  no `innerHTML`, no Markdown or HTML rendering, no URLs or attributes built from it.
* Recommendations and summaries carry the label "KI-generiert, nicht verifiziert".
* No inline script (except kern's theme script, which the build hashes), no `style=`, no `on*=`, no
  third-party origin, no `data:` font or image in the build output.
* Only kern's standard theme and tokens (`--k-*`). A component that kern lacks is filed as an issue
  in the kern repository; until it ships, a small local stand-in styled with kern tokens is used.
