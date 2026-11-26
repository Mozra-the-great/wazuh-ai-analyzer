# Gemini Decision 1 (`decision` mode)

`ANALYSIS_MODE=decision` analyses every alert group with Google's Gemini Decision 1
(`gemini-decision-1`) through the Decisions API. The model returns calibrated
probabilities and no text, so titles, descriptions and recommendations are built from
facts and from the versioned definitions (#88). This page records what is verified about
the API, how the analyzer uses it, and what is still open.

## Verified facts

Read on 2026-11-26 from the official pages (Gemini Developer API only, not Vertex):

- Decisions API guide: <https://aistudio.google.com/docs/decisions-api>
- Model page: <https://aistudio.google.com/docs/models/gemini-decision-1>
- Rate limits: <https://aistudio.google.com/docs/rate-limits>
- Pricing, terms and the launch post are listed in the plan comment of #81.
- Python SDK walk-through (not used here): <https://codelabs.developers.google.com/getting-started-with-gemini-decisions-api>

| Topic | Fact |
| --- | --- |
| Endpoint | `POST https://generativelanguage.googleapis.com/v1beta/decisions`, header `x-goog-api-key`, JSON body. Only `v1beta` is documented. |
| Request | `model`, `input` (string, one content block or a list of blocks), `questions` (1 to 1000 entries, keys `[A-Za-z0-9_-]{1,64}`). |
| Question | `type` (`noul` yes/no, `choice`, `score`), `instructions` (text), `criteria` (`noul`: optional `true_description` / `false_description`; `choice`: option key to description, 2 to 255 options; `score`: ordered list of 2 to 255 levels). |
| Response | `answers.<key>`: `noul` is a probability in 0.01 to 0.99; `choice` has `choice`, `probabilities` (sum 1); `score` has `score`, `legend`, `probabilities`; every answer has `confidence`. `usage` counts input tokens only (output is always 0). |
| Confidence | "Estimated probability that the top answer is right". For a yes/no question it is `max(noul, 1 - noul)`, so only the `choice` confidence carries extra information. |
| Calibration | A vendor claim. No method or accuracy figure is published; the docs tell users to set thresholds from their own labelled traffic (#89 does that). |
| Limits | 262,144 input tokens per request (input plus all questions), JSON nesting depth 100, no output tokens. No caching, no Batch API. |
| Free tier | 200 RPM, 50,000 TPM, 10,000 RPD (limits are per project, TPM counts input tokens, RPD resets at midnight Pacific). Tier 1: 1,500 / 1,000,000 / 50,000. |
| Price | Free tier: no charge. Paid: $0.10 per 1M input tokens, output not billed. |
| Safety blocks | HTTP 400 `{"error": {"code": "<reason>", "message": "..."}}`, `code` one of `safety`, `prohibited_content`, `blocklist`, `image_safety`, `content_blocked`, and no `answers`. |
| Limit violations and key errors | HTTP 400 with a message that names the rule. No `code` value is documented. |

### Not documented (do not rely on it)

- The body, `Retry-After` header and per-minute versus per-day wording of an HTTP 429.
  The rate-limit page only describes `429 RESOURCE_EXHAUSTED` for spend limits.
- The shape of 5xx answers.
- The release stage (preview or stable) and any deprecation date. The model id therefore
  comes from `DECISION_MODEL` and is never hard-coded in a request path; `llm` mode stays
  the documented fallback.
- Data retention for this API. The Gemini API terms apply (see #81, finding R13).

The analyzer treats everything undocumented defensively: a 429 uses `Retry-After` when
present and otherwise the same waits as `llm` mode (an hour when the text names a daily or
quota limit, 65 seconds otherwise); a 5xx is `transient`; a 400 that mentions the API key or
a failed precondition is `config`; any other 400 is `permanent`.
`python -m wazuh_ai_analyzer probe-decision` records the real answers (below).

## How a batch is analysed

- One request per alert group: the cleaned group is the shared `input`, a JSON document
  `{"kind": "wazuh_alert_group", "untrusted_log_data": {...}}`. Log text can only be a
  JSON string value. Every instruction lives in `questions[*].instructions`, and the
  `INFRA_CONTEXT` of the operator is appended to the questions marked `infra_context`.
- The questions are in `wazuh_ai_analyzer/analysis/decisions/v1.json`: `relevant`
  (yes/no), `severity` (choice: `info`, `low`, `medium`, `high`, `critical`, each with a
  written definition), and the rubric items `known_benign`, `already_blocked`,
  `needs_action_now` (yes/no). The file is validated at startup; a broken file stops the
  start with exit code 78.
- `decision_version` is `<version>-<12 hex digits of the SHA-256 of the file's canonical JSON>`
  (for example `1-3f9a0c1d2b4e`). It is stored in `batches.decision_version`, and changing
  any definition changes it even if `version` is not bumped.
- A group becomes a finding when `relevant >= DECISION_THRESHOLDS[severity]` (defaults:
  critical 0.3, high 0.5, medium 0.6, low 0.7, info never). Otherwise it is counted in
  the batch summary only.
- `findings.confidence` is the confidence of the `severity` answer. `findings.decision` holds
  the validated answers and the thresholds used. `batches.mode` is `decision`.
- The title is the Wazuh rule description plus ` (N×)` for more than one alert; the
  description lists the facts (rule, level, agents, sample time span, sample addresses and
  users) and the rubric answers in words; the recommendation is the first of
  `needs_action_now`, `already_blocked`, `known_benign` that is likely (probability of at
  least `rubric_true_at`, 0.5), else the default. `already_blocked` and `known_benign` do
  not change the severity in v1.
- Safety guard: a group with Wazuh level 12 or higher that ends with no finding, or with
  `info` or `low`, is counted in `suspicious_downgrades` and named in the batch summary.
  It is never silently changed.
- A safety block (HTTP 400 with a safety `code`) is not an error of the batch. The group
  becomes a placeholder finding "Nicht analysierbar (vom Anbieter blockiert)" rated by its
  Wazuh level (0-3 info, 4-6 low, 7-11 medium, 12-14 high, 15 critical), counted in the new
  runtime counter `safety_blocked`.
- The batch is the retry unit. The answers of the groups that are done are kept in
  `batches.decision_partial` (schema v3), so a retry after a 429 or an outage asks only for
  the missing groups. The column is cleared when the batch is done, is never returned by the
  web API, and is ignored by the previous release.
- The key goes only into the `x-goog-api-key` header; redirects are not followed; error
  texts and log lines are scrubbed before they are cut.

## The real call (probe)

Not part of CI. With the key in a file (mode 0600/0400, owned by the service user):

```sh
GEMINI_API_KEY_FILE=/path/to/key python -m wazuh_ai_analyzer probe-decision
GEMINI_API_KEY_FILE=/path/to/key python -m wazuh_ai_analyzer probe-decision --invalid
```

The first command sends one made-up alert group (documentation address, no production
data) and prints the HTTP status, the `Retry-After` and `Content-Type` headers, the
scrubbed response body, the latency, and what the analyzer makes of it (the finding, or the
failure kind and the `last_error` text). The second sends a request without questions that
the API must refuse, to record the body of a 400. On a service host the systemd credential
`gemini` is read as usual. The key is never printed and never taken from the command line.

Open until the first real call (#82, P8): the 429 and 5xx bodies, p50/p95 latency, the
calibration of the thresholds (#89).

## Safety blocks in `llm` mode (#97)

`llm` mode now recognises a Gemini block (`promptFeedback.blockReason`, or a candidate
without parts whose `finishReason` is `SAFETY`, `PROHIBITED_CONTENT`, `BLOCKLIST`, `SPII`,
`IMAGE_SAFETY` or `RECITATION`) and reports it with its own text, for example
`Gemini blockiert die Anfrage (blockReason=SAFETY)`, instead of an opaque `KeyError`.
It stays a `bad_response` (a few retries, then a counted drop with
`bad_response nach N Versuchen: ...`). Setting `safetySettings` and bisecting a blocked
batch stay open in #97.

## Notes for operators and rollback

- Findings beyond `FINDINGS_MAX` (50) in one batch are counted in the summary; a group with
  Wazuh level 12 or higher that is cut is also counted in `suspicious_downgrades`. A group
  below the thresholds despite Wazuh level 7 or higher is named in the summary.
- A non-safety HTTP 400 for one group fails the whole batch as `permanent` (counted in
  `dropped_permanent`, with the usual streak guard that turns three in a row into `config`).
  This is deliberate: a request that the API refuses systematically must raise the existing
  `WazuhAiAnalyseFehlerquote` alert instead of filling the dashboard with placeholders.
- After a rollback to `analyzer.py`, its `SELECT b.*` on `/api/batches` also returns the
  scratch column `decision_partial` (validated probabilities only, `NULL` once a batch is
  done or failed).
