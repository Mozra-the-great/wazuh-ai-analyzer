"""Versioned, additive, idempotent migrations."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from v2.helpers import FakeClock
from wazuh_ai_analyzer.storage import schema
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.schema import (
    LATEST_VERSION,
    MigrationError,
    SchemaTooNewError,
    current_version,
    migrate,
    table_columns,
)

# The batches table as the very first release of analyzer.py created it, before the
# retry bookkeeping of #43.
PRE_RETRY_BATCHES = """
    CREATE TABLE batches (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at    TEXT    NOT NULL,
        alert_count   INTEGER NOT NULL,
        raw_groups    TEXT    NOT NULL,
        summary       TEXT,
        overall_risk  TEXT    DEFAULT 'unknown',
        status        TEXT    DEFAULT 'pending',
        source        TEXT    DEFAULT 'live'
    )
"""
FINDINGS = """
    CREATE TABLE findings (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id        INTEGER NOT NULL,
        title           TEXT    NOT NULL,
        severity        TEXT    NOT NULL,
        description     TEXT    NOT NULL,
        recommendation  TEXT    NOT NULL,
        affected_agents TEXT,
        rule_ids        TEXT,
        FOREIGN KEY (batch_id) REFERENCES batches(id)
    )
"""
INSERT_FINDING = (
    "INSERT INTO findings (batch_id, title, severity, description, recommendation,"
    " confidence, decision) VALUES (?, 't', 'low', 'd', 'r', ?, ?)"
)


def _query(db: Database, sql: str, *params: Any) -> list[sqlite3.Row]:
    with db.reader() as conn:
        return conn.execute(sql, params).fetchall()


def _insert_batch(db: Database) -> int:
    with db.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups) VALUES ('t', 1, '[]')"
        )
        assert cur.lastrowid is not None
        return cur.lastrowid


def test_fresh_database_reaches_the_latest_version(db_path: Path, clock: FakeClock) -> None:
    db_path.parent.mkdir()
    result = migrate(Database(db_path), clock=clock)
    assert (result.from_version, result.to_version) == (0, LATEST_VERSION)
    assert result.applied == (1, 2)
    rows = _query(Database(db_path), "SELECT version, name, applied_at FROM schema_version")
    assert [r["version"] for r in rows] == [1, 2]
    assert rows[0]["applied_at"] == "2026-11-25T12:00:00+00:00"


def test_second_run_is_a_no_op(database: Database) -> None:
    result = migrate(database)
    assert result.applied == ()
    assert result.from_version == result.to_version == LATEST_VERSION
    assert len(_query(database, "SELECT * FROM schema_version")) == 2


def test_new_columns_and_table(database: Database) -> None:
    with database.reader() as conn:
        assert {"mode", "decision_version"} <= table_columns(conn, "batches")
        assert {"confidence", "decision"} <= table_columns(conn, "findings")
        assert table_columns(conn, "web_sessions") == {
            "id_hash",
            "csrf_token",
            "username",
            "created_at",
            "expires_at",
        }


def test_decision_column_has_text_affinity(database: Database) -> None:
    # R6: a declared type of JSON would have NUMERIC affinity.
    with database.reader() as conn:
        types = {r["name"]: r["type"] for r in conn.execute("PRAGMA table_info(findings)")}
    assert types["decision"] == "TEXT"
    assert types["confidence"] == "REAL"


def test_check_constraints_guard_the_new_columns(database: Database) -> None:
    batch = _insert_batch(database)
    with database.transaction() as conn:
        conn.execute(INSERT_FINDING, (batch, 0.5, json.dumps({"relevant": 0.9})))
        conn.execute(INSERT_FINDING, (batch, None, None))
    for bad in ((batch, 1.5, None), (batch, -0.1, None), (batch, 0.5, "{not json")):
        with pytest.raises(sqlite3.IntegrityError), database.transaction() as conn:
            conn.execute(INSERT_FINDING, bad)
    with pytest.raises(sqlite3.IntegrityError), database.transaction() as conn:
        conn.execute("UPDATE batches SET mode='hybrid' WHERE id=?", (batch,))


def test_new_rows_get_the_default_mode(database: Database) -> None:
    batch = _insert_batch(database)
    row = _query(database, "SELECT mode, decision_version FROM batches WHERE id=?", batch)[0]
    assert (row["mode"], row["decision_version"]) == ("llm", None)


def test_pre_retry_database_is_adopted_and_keeps_its_data(db_path: Path) -> None:
    db_path.parent.mkdir()
    conn = sqlite3.connect(db_path)
    conn.execute(PRE_RETRY_BATCHES)
    conn.execute(FINDINGS)
    conn.execute("INSERT INTO batches (created_at, alert_count, raw_groups) VALUES ('a', 2, '[]')")
    conn.execute(
        "INSERT INTO findings (batch_id, title, severity, description, recommendation)"
        " VALUES (1, 't', 'high', 'd', 'r')"
    )
    conn.commit()
    conn.close()

    result = migrate(Database(db_path))
    assert result.applied == (1, 2)
    db = Database(db_path)
    with db.reader() as c:
        columns = table_columns(c, "batches")
    assert {"attempts", "next_attempt", "first_error_at", "last_error", "claimed_at"} <= columns
    row = _query(db, "SELECT * FROM batches")[0]
    assert (row["created_at"], row["alert_count"], row["attempts"], row["mode"]) == (
        "a",
        2,
        0,
        "llm",
    )
    finding = _query(db, "SELECT title, severity FROM findings")[0]
    assert (finding["title"], finding["severity"]) == ("t", "high")
    indexes = {r["name"] for r in _query(db, "SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_batches_retry", "idx_findings_severity", "idx_web_sessions_expires"} <= indexes


def test_autoincrement_and_sqlite_sequence_survive(db_path: Path) -> None:
    db_path.parent.mkdir()
    conn = sqlite3.connect(db_path)
    conn.execute(PRE_RETRY_BATCHES)
    conn.execute(FINDINGS)
    conn.execute("INSERT INTO batches (created_at, alert_count, raw_groups) VALUES ('a', 1, '[]')")
    for i in range(3):
        conn.execute(
            "INSERT INTO findings (batch_id, title, severity, description, recommendation)"
            f" VALUES (1, 't{i}', 'low', 'd', 'r')"
        )
    conn.execute("DELETE FROM findings WHERE id=3")  # the sequence must stay at 3
    conn.commit()
    conn.close()
    migrate(Database(db_path))
    seq = _query(Database(db_path), "SELECT seq FROM sqlite_sequence WHERE name='findings'")[0][0]
    assert seq == 3


def test_database_from_a_newer_release_is_refused(database: Database) -> None:
    with database.transaction() as conn:
        conn.execute(
            "INSERT INTO schema_version (version, name, applied_at) VALUES (99, 'future', 'x')"
        )
    with pytest.raises(SchemaTooNewError, match="newer"):
        migrate(database)


def test_a_failing_migration_rolls_back_completely(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path.parent.mkdir()
    original = schema._migrate_v2

    def broken(conn: sqlite3.Connection) -> None:
        original(conn)
        raise RuntimeError("boom after the DDL")

    monkeypatch.setattr(
        schema,
        "MIGRATIONS",
        (schema.MIGRATIONS[0], schema.Migration(2, "broken", broken)),
    )
    db = Database(db_path)
    with pytest.raises(RuntimeError, match="boom"):
        migrate(db)
    # Version 1 committed on its own; nothing of version 2 is left behind.
    with db.reader() as conn:
        assert current_version(conn) == 1
        assert "mode" not in table_columns(conn, "batches")
        assert "decision" not in table_columns(conn, "findings")
        assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name='web_sessions'").fetchone()
    monkeypatch.undo()
    assert migrate(db).applied == (2,)


def test_migration_is_idempotent_when_columns_already_exist(database: Database) -> None:
    # Simulates a crash between the DDL and the version row of an older run.
    with database.transaction() as conn:
        conn.execute("DELETE FROM schema_version WHERE version=2")
    assert migrate(database).applied == (2,)
    with database.reader() as conn:
        assert current_version(conn) == 2


def test_missing_json_functions_are_reported() -> None:
    class NoJson:
        def execute(self, sql: str) -> Any:
            raise sqlite3.OperationalError("no such function: json_valid")

    with pytest.raises(MigrationError, match="JSON"):
        schema._migrate_v2(NoJson())  # type: ignore[arg-type]


def test_foreign_keys_are_enforced_on_connections(database: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError), database.transaction() as conn:
        conn.execute(
            "INSERT INTO findings (batch_id, title, severity, description, recommendation)"
            " VALUES (999, 't', 'low', 'd', 'r')"
        )


def test_connections_use_wal(database: Database) -> None:
    with database.reader() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_read_only_connections_cannot_write(database: Database) -> None:
    with database.reader() as conn, pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM batches")
