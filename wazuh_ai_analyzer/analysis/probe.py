"""`python -m wazuh_ai_analyzer probe-decision`: one real call to the Decisions API (#82).

For the operator, never for CI. It sends one made-up alert group (documentation
address, no production data) through the real request path and prints what came back:
the HTTP status, the headers that matter for retries, the response body (scrubbed and
capped), the latency and what the analyzer made of it (the answers as findings, or the
`BackendFailure` kind a failure maps to). `--invalid` sends a request the API must
refuse, to record the body of an HTTP 400.

The key is read like the service reads it (`GEMINI_API_KEY`, `GEMINI_API_KEY_FILE` or
the systemd credential), never from the command line, and never printed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final, TextIO

from ..ingest.sanitize import AlertGroup, sanitize_group
from .backend import BackendFailure
from .decision import API_URL, GeminiDecisionBackend

# Made up: a documentation address (RFC 5737) and a host that does not exist.
PROBE_GROUP: Final[AlertGroup] = sanitize_group(
    {
        "rule_id": "5710",
        "description": "sshd: Attempt to login using a non-existent user",
        "count": 14,
        "max_level": 5,
        "agents": ["probe-host"],
        "locations": ["journald"],
        "samples": [
            {
                "ts": "2026-01-01T10:00:00",
                "log": "Failed password for invalid user probe from 203.0.113.7 port 40022 ssh2",
                "src_ip": "203.0.113.7",
                "dst_user": "probe",
            }
        ],
    }
)
BODY_MAX: Final = 4000
HEADERS_SHOWN: Final = ("content-type", "retry-after")


def probe(
    backend: GeminiDecisionBackend,
    out: TextIO,
    *,
    invalid: bool = False,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Run the probe; 0 if the API answered with usable answers (or `--invalid` got its 400)."""
    payload = backend.request_payload(PROBE_GROUP)
    if invalid:
        payload["questions"] = {}  # the API requires 1 to 1000 questions
    count = 0 if invalid else len(backend.definitions.questions)
    print(f"POST {API_URL} (model {backend.model}, {count} questions)", file=out)
    started = clock()
    try:
        resp = backend.exchange(payload)
    except BackendFailure as failure:
        print(f"no response: {failure.kind}: {failure.message}", file=out)
        return 1
    elapsed_ms = round((clock() - started) * 1000)
    print(f"HTTP {resp.status_code} in {elapsed_ms} ms", file=out)
    headers = {str(k).lower(): v for k, v in resp.headers.items()}
    for name in HEADERS_SHOWN:
        if name in headers:
            print(f"header {name}: {backend.scrub(str(headers[name]))}", file=out)
    body = backend.scrub(resp.text)
    print(f"body: {body[:BODY_MAX]}{' [cut]' if len(body) > BODY_MAX else ''}", file=out)
    try:
        outcome = backend.interpret(resp)
    except BackendFailure as failure:
        print(f"classified as: {failure.kind} (retry after {failure.retry_after:g} s)", file=out)
        print(f"last_error text: {failure.message}", file=out)
        return 0 if invalid and resp.status_code == 400 else 1
    if invalid:
        print("the API accepted an invalid request", file=out)
        return 1
    result = backend.rate([PROBE_GROUP], [outcome])
    print(f"decision_version: {result.decision_version}", file=out)
    print(f"summary: {result.summary}", file=out)
    for finding in result.findings:
        print(f"finding [{finding.severity}] {finding.title}", file=out)
    if not result.findings:
        print("no finding (below the thresholds)", file=out)
    return 0
