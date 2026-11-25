"""Verbatim copy of what the homelab metrics exporter reads from `analyses.db`.

Source: Mozra-the-great/homelab-infra,
`ansible/roles/wazuh_ai_analyzer/files/wazuh-ai-findings-metrics`, as of commit
2f5f3bb6969f7b9f6b3a5ce23a757755bfc9c9f1 (2026-11-19). The SQL strings, the
`mode=ro` connection and the value normalisation are copied unchanged; only the
metric text formatting is left out. When the exporter changes, update this file in
the same step and keep the commit reference current.

The exporter is the reason the schema is a public read interface (R1, R2): it
classifies error batches by the text of `last_error`, counts findings per
severity and source, detects new findings through `sqlite_sequence.seq` and
parses `batches.created_at`.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SOURCES = ("live", "history")
STATUSES = ("pending", "analyzing", "done", "error")
ERROR_REASONS = ("expired", "dropped", "other")

FINDINGS_SQL = (
    "SELECT b.source, f.severity, COUNT(*), MAX(b.created_at) "
    "FROM findings f JOIN batches b ON b.id = f.batch_id "
    "GROUP BY b.source, f.severity"
)
BATCHES_SQL = "SELECT status, COUNT(*) FROM batches GROUP BY status"
ERRORS_SQL = (
    "SELECT CASE "
    "WHEN last_error LIKE 'expired:%' OR last_error LIKE 'seit %h nicht analysierbar%' THEN 'expired' "  # noqa: E501
    "WHEN last_error LIKE 'permanent:%' OR last_error LIKE 'bad_response nach%' THEN 'dropped' "
    "ELSE 'other' END, COUNT(*) FROM batches WHERE status = 'error' GROUP BY 1"
)
DONE_SQL = "SELECT MAX(created_at) FROM batches WHERE status = 'done' AND source = 'live'"
SEQUENCE_SQL = "SELECT seq FROM sqlite_sequence WHERE name = 'findings'"
NEW_FINDINGS_SQL = (
    "SELECT b.source, f.severity, COUNT(*) "
    "FROM findings f JOIN batches b ON b.id = f.batch_id "
    "WHERE f.id > ? AND f.id <= ? GROUP BY b.source, f.severity"
)


def epoch(iso: str | None) -> float | None:
    """'2026-10-07T11:37:41+00:00' -> unix seconds; None if unparsable."""
    if not iso:
        return None
    try:
        parsed = dt.datetime.fromisoformat(iso)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.timestamp()


def norm(value: str | None, known: tuple[str, ...], fallback: str) -> str:
    v = (value or "").strip().lower()
    return v if v in known else fallback


def new_findings(
    con: sqlite3.Connection, after_id: int | None
) -> tuple[int, list[tuple[str, str, int]]]:
    row = con.execute(SEQUENCE_SQL).fetchone()
    seq = int(row[0]) if row else 0
    if after_id is None:
        return seq, []
    if seq < after_id:
        after_id = 0
    rows = con.execute(NEW_FINDINGS_SQL, (after_id, seq)).fetchall()
    return seq, [(str(src), str(sev), int(n)) for src, sev, n in rows]


def collect(db: str, after_id: int | None = None) -> dict[str, Any]:
    """The numbers the exporter derives from the database, as plain data."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    try:
        con.execute("PRAGMA query_only = ON")
        findings = con.execute(FINDINGS_SQL).fetchall()
        batches = con.execute(BATCHES_SQL).fetchall()
        errors = con.execute(ERRORS_SQL).fetchall()
        done = con.execute(DONE_SQL).fetchone()[0]
        seq, fresh = new_findings(con, after_id)
    finally:
        con.close()

    count: dict[tuple[str, str], int] = {}
    newest: dict[tuple[str, str], float] = {}
    for src in SOURCES:
        for sev in SEVERITIES:
            count[(sev, src)] = 0
    for src, sev, n, last in findings:
        key = (norm(sev, SEVERITIES, "unknown"), norm(src, SOURCES, "other"))
        count[key] = count.get(key, 0) + int(n)
        ts = epoch(last)
        if ts is not None:
            newest[key] = max(newest.get(key, 0.0), ts)

    status_count = dict.fromkeys(STATUSES, 0)
    for status, n in batches:
        status_key = norm(status, STATUSES, "other")
        status_count[status_key] = status_count.get(status_key, 0) + int(n)

    error_count = dict.fromkeys(ERROR_REASONS, 0)
    for reason, n in errors:
        error_count[norm(reason, ERROR_REASONS, "other")] += int(n)

    return {
        "findings": count,
        "newest": newest,
        "batches": status_count,
        "errors": error_count,
        "last_done": epoch(done),
        "sequence": seq,
        "new": sorted(fresh),
    }
