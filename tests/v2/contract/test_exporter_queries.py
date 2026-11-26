"""The homelab exporter's queries against databases written by the new code (R1, R2, C2)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from v2.contract import exporter_sql
from v2.contract.exporter_sql import collect
from v2.helpers import FakeClock
from wazuh_ai_analyzer.storage import contract
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import NewFinding, Repository
from wazuh_ai_analyzer.storage.schema import migrate

ERROR_TEXTS: dict[str, list[str | None]] = {
    "expired": [
        contract.error_queue_expired(72),
        contract.error_unanalyzable(72, "transient", "Gemini HTTP 503"),
        contract.error_unanalyzable(24, "config", "Gemini HTTP 403"),
    ],
    "dropped": [
        contract.error_permanent("Gemini HTTP 400"),
        contract.error_bad_response(3, "Antwort nicht auswertbar"),
    ],
    "other": ["raw_groups nicht lesbar", "something unforeseen", None],
}


def finding(severity: str) -> NewFinding:
    return NewFinding(
        title=f"{severity} finding",
        severity=severity,  # type: ignore[arg-type]
        description="d",
        recommendation="r",
    )


def populate(repo: Repository, database: Database, clock: FakeClock, mode: str = "llm") -> None:
    """Batches in every state, findings of every severity and source, errors of every kind."""
    is_decision = mode == "decision"
    for source in contract.SOURCES:
        for severity in contract.SEVERITIES:
            clock.advance(60)
            batch_id = repo.insert_batch(
                alert_count=2,
                raw_groups="[]",
                source=source,  # type: ignore[arg-type]
                mode=mode,  # type: ignore[arg-type]
            )
            repo.complete_batch(
                batch_id,
                summary="s",
                overall_risk=severity,  # type: ignore[arg-type]
                findings=[finding(severity)] * (2 if source == "live" else 1),
                mode=mode,  # type: ignore[arg-type]
                decision_version="v1" if is_decision else None,
            )
    for texts in ERROR_TEXTS.values():
        for text in texts:
            batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
            if text is None:
                with database.transaction() as conn:  # the legacy rows without a reason
                    conn.execute("UPDATE batches SET status='error' WHERE id=?", (batch_id,))
            else:
                repo.fail_batch(batch_id, reason=text, attempts=3)
    repo.insert_batch(alert_count=1, raw_groups="[]", source="live", status="pending")
    repo.insert_batch(alert_count=1, raw_groups="[]", source="live")  # analyzing


@pytest.mark.parametrize("mode", ["llm", "decision"])
def test_exporter_numbers_from_a_database_written_by_the_new_code(
    database: Database, repo: Repository, clock: FakeClock, mode: str
) -> None:
    populate(repo, database, clock, mode)
    result = collect(str(database.path))

    findings = result["findings"]
    for severity in contract.SEVERITIES:
        assert findings[(severity, "live")] == 2
        assert findings[(severity, "history")] == 1
    assert not [key for key in findings if "unknown" in key or "other" in key]

    assert result["batches"] == {"pending": 1, "analyzing": 1, "done": 10, "error": 8}
    assert result["errors"] == {"expired": 3, "dropped": 2, "other": 3}
    assert result["sequence"] == 15
    assert result["last_done"] is not None
    assert all(ts > 0 for ts in result["newest"].values())


def test_new_finding_counters_use_the_sequence(
    database: Database, repo: Repository, clock: FakeClock
) -> None:
    populate(repo, database, clock)
    baseline = collect(str(database.path))["sequence"]
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    repo.complete_batch(
        batch_id,
        summary="s",
        overall_risk="critical",
        findings=[finding("critical"), finding("critical"), finding("low")],
    )
    after = collect(str(database.path), after_id=baseline)
    assert after["sequence"] == baseline + 3
    assert after["new"] == [("live", "critical", 2), ("live", "low", 1)]


def test_a_purge_does_not_lower_the_sequence(
    database: Database, repo: Repository, clock: FakeClock
) -> None:
    populate(repo, database, clock)
    before = collect(str(database.path))["sequence"]
    clock.advance(400 * 86400)
    assert repo.purge_old_batches(30) > 0
    assert collect(str(database.path))["sequence"] == before


def test_exporter_sql_is_unchanged_by_the_migration(tmp_path: Path, clock: FakeClock) -> None:
    """Same rows, schema v1 (legacy) versus the migrated schema: identical numbers."""
    legacy = tmp_path / "legacy.db"
    db = Database(legacy)
    assert migrate(db, up_to=1).to_version == 1  # the schema the legacy analyzer creates

    rows = _seed_legacy_rows(legacy, clock)
    before = collect(str(legacy), after_id=0)
    assert rows > 0

    assert migrate(db).applied == (2, 3)
    after = collect(str(legacy), after_id=0)
    assert after == before


def _seed_legacy_rows(path: Path, clock: FakeClock) -> int:
    """Rows exactly as the legacy analyzer writes them (no new columns)."""
    conn = sqlite3.connect(path)
    n = 0
    for source in ("live", "history"):
        for severity in ("critical", "info"):
            cur = conn.execute(
                "INSERT INTO batches (created_at, alert_count, raw_groups, status, source)"
                " VALUES (?, 1, '[]', 'done', ?)",
                (contract.iso_utc(clock.now + n), source),
            )
            conn.execute(
                "INSERT INTO findings (batch_id, title, severity, description, recommendation)"
                " VALUES (?, 't', ?, 'd', 'r')",
                (cur.lastrowid, severity),
            )
            n += 1
    for text in ("expired: laenger als 72h in der Warteschlange", "permanent: HTTP 400", None):
        conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status, last_error)"
            " VALUES (?, 1, '[]', 'error', ?)",
            (contract.iso_utc(clock.now), text),
        )
        n += 1
    conn.commit()
    conn.close()
    return n


LAST_ERRORS = [
    *(t for texts in ERROR_TEXTS.values() for t in texts),
    "EXPIRED: shouting",
    "Permanent: capitalised",
    "BAD_RESPONSE NACH 3 Versuchen",
    "SEIT 72H NICHT ANALYSIERBAR (x): y",
    "seit  nicht analysierbar",  # no "h" before the marker text: still 'other'
    "seit 72h nicht",
    "expired",  # no colon
    "xexpired: not a prefix",
    "",
]


@pytest.mark.parametrize("text", LAST_ERRORS, ids=[repr(t) for t in LAST_ERRORS])
def test_python_classification_equals_the_exporters_case_expression(
    database: Database, text: str | None
) -> None:
    with database.transaction() as conn:
        conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status, last_error)"
            " VALUES ('t', 1, '[]', 'error', ?)",
            (text,),
        )
    with database.reader() as conn:
        [(reason, count)] = conn.execute(exporter_sql.ERRORS_SQL).fetchall()
    assert count == 1
    assert contract.classify_error(text) == reason


def test_the_four_german_prefixes_word_for_word() -> None:
    assert contract.error_queue_expired(72) == "expired: laenger als 72h in der Warteschlange"
    assert contract.error_queue_expired(1.5) == "expired: laenger als 1.5h in der Warteschlange"
    assert (
        contract.error_unanalyzable(72, "transient", "m")
        == "seit 72h nicht analysierbar (transient): m"
    )
    assert contract.error_permanent("m") == "permanent: m"
    assert contract.error_bad_response(3, "m") == "bad_response nach 3 Versuchen: m"
