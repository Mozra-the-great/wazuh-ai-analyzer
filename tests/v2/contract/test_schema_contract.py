"""The frozen schema and value contract (R1, R2, R6, C2).

If one of these tests has to change, an external reader (the homelab exporter) is
affected. Change the contract only by adding to it.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from v2.contract.exporter_sql import collect
from v2.helpers import FakeClock
from wazuh_ai_analyzer.storage import contract
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import NewFinding, Repository
from wazuh_ai_analyzer.storage.schema import migrate

# (name, declared type, not null, default, primary key)
BATCHES_COLUMNS = [
    ("id", "INTEGER", 0, None, 1),
    ("created_at", "TEXT", 1, None, 0),
    ("alert_count", "INTEGER", 1, None, 0),
    ("raw_groups", "TEXT", 1, None, 0),
    ("summary", "TEXT", 0, None, 0),
    ("overall_risk", "TEXT", 0, "'unknown'", 0),
    ("status", "TEXT", 0, "'pending'", 0),
    ("source", "TEXT", 0, "'live'", 0),
    ("attempts", "INTEGER", 1, "0", 0),
    ("next_attempt", "REAL", 0, None, 0),
    ("first_error_at", "TEXT", 0, None, 0),
    ("last_error", "TEXT", 0, None, 0),
    ("claimed_at", "REAL", 0, None, 0),
    ("bad_responses", "INTEGER", 1, "0", 0),
    # added by the rewrite
    ("mode", "TEXT", 1, "'llm'", 0),
    ("decision_version", "TEXT", 0, None, 0),
    # scratch space of the decision backend (#88); not part of the read interface
    ("decision_partial", "TEXT", 0, None, 0),
]
FINDINGS_COLUMNS = [
    ("id", "INTEGER", 0, None, 1),
    ("batch_id", "INTEGER", 1, None, 0),
    ("title", "TEXT", 1, None, 0),
    ("severity", "TEXT", 1, None, 0),
    ("description", "TEXT", 1, None, 0),
    ("recommendation", "TEXT", 1, None, 0),
    ("affected_agents", "TEXT", 0, None, 0),
    ("rule_ids", "TEXT", 0, None, 0),
    # added by the rewrite
    ("confidence", "REAL", 0, None, 0),
    ("decision", "TEXT", 0, None, 0),
]
LEGACY_INDEXES = {
    "idx_findings_severity",
    "idx_findings_batch",
    "idx_batches_created",
    "idx_batches_source",
    "idx_batches_retry",
}


def columns(db: Database, table: str) -> list[tuple[Any, ...]]:
    with db.reader() as conn:
        # `table` is always a literal of this file.
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [(r["name"], r["type"], r["notnull"], r["dflt_value"], r["pk"]) for r in rows]


def test_value_sets_are_frozen() -> None:
    assert contract.SEVERITIES == ("critical", "high", "medium", "low", "info")
    assert contract.OVERALL_RISKS == ("critical", "high", "medium", "low", "info", "unknown")
    assert contract.SOURCES == ("live", "history")
    assert contract.STATUSES == ("pending", "analyzing", "done", "error")
    assert contract.ANALYSIS_MODES == ("llm", "decision")


def test_batches_and_findings_columns_are_frozen(database: Database) -> None:
    assert columns(database, "batches") == BATCHES_COLUMNS
    assert columns(database, "findings") == FINDINGS_COLUMNS


def test_the_migration_only_adds_columns_to_a_legacy_database(az: Any, tmp_path: Path) -> None:
    """Every column of the legacy schema is still there, with an identical definition."""
    legacy = Database(az.DB_PATH)  # built by the legacy init_db()
    before = {table: columns(legacy, table) for table in ("batches", "findings")}
    migrate(legacy)
    added = {"batches": 3, "findings": 2}
    for table in before:
        after = columns(legacy, table)
        assert after[: len(before[table])] == before[table]
        assert len(after) == len(before[table]) + added[table]
    fresh = Database(tmp_path / "fresh" / "analyses.db")
    (tmp_path / "fresh").mkdir()
    migrate(fresh)
    assert columns(legacy, "batches") == columns(fresh, "batches")
    assert columns(legacy, "findings") == columns(fresh, "findings")


def test_tables_stay_autoincrement(database: Database) -> None:
    with database.reader() as conn:
        for table in (contract.TABLE_BATCHES, contract.TABLE_FINDINGS):
            sql = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()[0]
            assert re.search(r"INTEGER PRIMARY KEY AUTOINCREMENT", sql), table


def test_indexes_are_kept(database: Database) -> None:
    with database.reader() as conn:
        indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert indexes >= LEGACY_INDEXES


def test_finding_ids_are_never_reused_and_sqlite_sequence_tracks_them(
    repo: Repository, database: Database
) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    finding = NewFinding(title="t", severity="low", description="d", recommendation="r")
    first = repo.complete_batch(batch_id, summary="s", overall_risk="low", findings=[finding] * 3)
    with database.transaction() as conn:
        conn.execute("DELETE FROM findings WHERE id=?", (first[-1],))
    with database.reader() as conn:
        assert (
            conn.execute("SELECT seq FROM sqlite_sequence WHERE name='findings'").fetchone()[0]
            == first[-1]
        )
    batch_two = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    [again] = repo.complete_batch(batch_two, summary="s", overall_risk="low", findings=[finding])
    assert again > first[-1]


def test_created_at_is_iso_8601_utc_with_seconds(repo: Repository, clock: FakeClock) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    batch = repo.get_batch(batch_id)
    assert batch is not None
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", batch.created_at)
    parsed = datetime.fromisoformat(batch.created_at)
    assert parsed.utcoffset() == timedelta(0)
    assert parsed.timestamp() == clock.now


@pytest.mark.parametrize("timestamp", [0.0, 1_700_000_000.4, 1_790_000_000.999])
def test_created_at_format_equals_the_legacy_format(az: Any, timestamp: float) -> None:
    assert contract.iso_utc(timestamp) == az._iso(timestamp)


def test_created_at_sorts_like_time(repo: Repository, clock: FakeClock) -> None:
    ids = []
    for _ in range(4):
        ids.append(repo.insert_batch(alert_count=1, raw_groups="[]", source="live"))
        clock.advance(3600 * 7)
    stamps = [b.created_at for i in ids if (b := repo.get_batch(i)) is not None]
    assert stamps == sorted(stamps)
    assert len(set(stamps)) == 4


# ── last_error texts: the new builders against the legacy implementation ─────
def _legacy_batch(az: Any, **columns_: Any) -> int:
    values = {"created_at": az._iso(az._now()), "alert_count": 1, "raw_groups": "[]", **columns_}
    names = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    with az._db() as conn:
        cur = conn.execute(f"INSERT INTO batches ({names}) VALUES ({marks})", list(values.values()))
        return int(cur.lastrowid)


def _legacy_last_error(az: Any, batch_id: int) -> str:
    with az._db() as conn:
        row = conn.execute(
            "SELECT status, last_error FROM batches WHERE id=?", (batch_id,)
        ).fetchone()
    assert row["status"] == "error"
    return str(row["last_error"])


def test_queue_expiry_text_equals_the_legacy_text(az: Any) -> None:
    old = az._iso(az._now() - (az.QUEUE_MAX_AGE_HOURS + 1) * 3600)
    batch_id = _legacy_batch(az, status="pending", created_at=old)
    assert az._expire_old_pending() == 1
    assert _legacy_last_error(az, batch_id) == contract.error_queue_expired(az.QUEUE_MAX_AGE_HOURS)


def test_permanent_text_equals_the_legacy_text(az: Any) -> None:
    batch_id = _legacy_batch(az, status="analyzing")
    az._handle_failure(batch_id, az.GeminiFailure("permanent", "Gemini HTTP 400: bad"))
    assert _legacy_last_error(az, batch_id) == contract.error_permanent("Gemini HTTP 400: bad")


def test_bad_response_text_equals_the_legacy_text(az: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(az, "RETRY_BAD_RESPONSE_MAX", 1)
    batch_id = _legacy_batch(az, status="analyzing")
    az._handle_failure(batch_id, az.GeminiFailure("bad_response", "Antwort nicht auswertbar"))
    assert _legacy_last_error(az, batch_id) == contract.error_bad_response(
        1, "Antwort nicht auswertbar"
    )


@pytest.mark.parametrize("kind", ["transient", "config"])
def test_unanalyzable_text_equals_the_legacy_text(az: Any, kind: str) -> None:
    long_ago = az._iso(az._now() - (az.RETRY_MAX_AGE_HOURS + 1) * 3600)
    batch_id = _legacy_batch(az, status="analyzing", first_error_at=long_ago)
    az._handle_failure(batch_id, az.GeminiFailure(kind, "Gemini HTTP 503"))
    assert _legacy_last_error(az, batch_id) == contract.error_unanalyzable(
        az.RETRY_MAX_AGE_HOURS, kind, "Gemini HTTP 503"
    )


def test_the_exporter_classifies_legacy_error_batches_like_the_contract(az: Any) -> None:
    """End to end: legacy writer, exporter reader, Python twin."""
    old = az._iso(az._now() - (az.QUEUE_MAX_AGE_HOURS + 1) * 3600)
    expired = _legacy_batch(az, status="pending", created_at=old)
    az._expire_old_pending()
    dropped = _legacy_batch(az, status="analyzing")
    az._handle_failure(dropped, az.GeminiFailure("permanent", "x"))
    result = collect(az.DB_PATH)
    assert result["errors"] == {"expired": 1, "dropped": 1, "other": 0}
    assert contract.classify_error(_legacy_last_error(az, expired)) == "expired"
    assert contract.classify_error(_legacy_last_error(az, dropped)) == "dropped"


def test_exporter_can_read_while_a_writer_holds_the_database_open(database: Database) -> None:
    """WAL: a `mode=ro` reader works next to an open write connection."""
    writer = database.connect()
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups) VALUES ('t', 1, '[]')"
        )
        assert collect(str(database.path))["batches"]["pending"] == 0
    finally:
        writer.rollback()
        writer.close()
    with pytest.raises(sqlite3.OperationalError), database.reader() as conn:
        conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups) VALUES ('t', 1, '[]')"
        )
