"""Schema and versioned, additive migrations.

Rules (C2, C3, R1, R2, R6):

* Tables `batches` and `findings` keep their names, columns, types and
  `AUTOINCREMENT`. External tools read them directly.
* Migrations only add: a column, an index, a table. No rename, no drop, no type
  change. The previous analyzer therefore keeps working on a migrated database,
  which is the rollback path.
* Every migration runs in one transaction and is idempotent: the existing
  columns and tables are inspected first, and the version is re-checked after
  the write lock is taken, so two processes starting together cannot both apply
  it.

Versions:

* 1 - adopt the schema of the legacy `analyzer.py` (also for databases that
  predate the retry columns of #43, and for a database that does not exist yet).
* 2 - rewrite additions: `batches.mode`, `batches.decision_version`,
  `findings.confidence`, `findings.decision`, table `web_sessions`.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass

from .contract import iso_utc
from .db import Database

log = logging.getLogger(__name__)

# ── version 1: the schema of the legacy analyzer.py ──────────────────────────
_V1_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS batches (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at    TEXT    NOT NULL,
        alert_count   INTEGER NOT NULL,
        raw_groups    TEXT    NOT NULL,
        summary       TEXT,
        overall_risk  TEXT    DEFAULT 'unknown',
        status        TEXT    DEFAULT 'pending',
        source        TEXT    DEFAULT 'live',
        attempts      INTEGER NOT NULL DEFAULT 0,
        next_attempt  REAL,
        first_error_at TEXT,
        last_error    TEXT,
        claimed_at    REAL,
        bad_responses INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
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
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_batch    ON findings(batch_id)",
    "CREATE INDEX IF NOT EXISTS idx_batches_created   ON batches(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_batches_source    ON batches(source)",
)

# Retry bookkeeping added for #43: databases created before it get the columns.
_V1_BATCH_RETRY_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("batches", "attempts", "INTEGER NOT NULL DEFAULT 0"),
    ("batches", "next_attempt", "REAL"),
    ("batches", "first_error_at", "TEXT"),
    ("batches", "last_error", "TEXT"),
    ("batches", "claimed_at", "REAL"),
    ("batches", "bad_responses", "INTEGER NOT NULL DEFAULT 0"),
)

# ── version 2: additions of the rewrite ──────────────────────────────────────
# `decision` is TEXT, not JSON: a declared type of JSON has NUMERIC affinity in
# SQLite (R6). json_valid() in the CHECK keeps it a JSON document.
_V2_COLUMNS: tuple[tuple[str, str, str], ...] = (
    (
        "batches",
        "mode",
        "TEXT NOT NULL DEFAULT 'llm' CHECK (mode IN ('llm', 'decision'))",
    ),
    ("batches", "decision_version", "TEXT"),
    (
        "findings",
        "confidence",
        "REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))",
    ),
    ("findings", "decision", "TEXT CHECK (decision IS NULL OR json_valid(decision))"),
)

# Server-side sessions (R5). Only a sha256 of the session id is stored, so a
# leaked database cannot be replayed as a cookie.
_V2_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS web_sessions (
        id_hash    TEXT PRIMARY KEY,
        csrf_token TEXT NOT NULL,
        username   TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at)",
)


class MigrationError(Exception):
    """The database cannot be migrated safely."""


class SchemaTooNewError(MigrationError):
    """The database was written by a newer version of the analyzer."""


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Column names of a table. `table` must be a literal, never user input."""
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_missing_columns(
    conn: sqlite3.Connection, columns: tuple[tuple[str, str, str], ...]
) -> list[str]:
    added: list[str] = []
    existing: dict[str, set[str]] = {}
    for table, name, ddl in columns:
        have = existing.setdefault(table, table_columns(conn, table))
        if name not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
            have.add(name)
            added.append(f"{table}.{name}")
    return added


def _migrate_v1(conn: sqlite3.Connection) -> None:
    for statement in _V1_STATEMENTS:
        conn.execute(statement)
    added = _add_missing_columns(conn, _V1_BATCH_RETRY_COLUMNS)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_batches_retry ON batches(status, next_attempt)")
    for column in added:
        log.info("Database migrated: added %s", column)


def _migrate_v2(conn: sqlite3.Connection) -> None:
    # The CHECK on findings.decision calls json_valid() on every insert. A SQLite
    # build without the JSON functions would then reject every finding, also
    # when the old analyzer writes it after a rollback. Refuse up front.
    try:
        conn.execute("SELECT json_valid('{}')").fetchone()
    except sqlite3.OperationalError as exc:
        raise MigrationError(
            "this SQLite build has no JSON functions (json_valid); cannot migrate"
        ) from exc
    for column in _add_missing_columns(conn, _V2_COLUMNS):
        log.info("Database migrated: added %s", column)
    for statement in _V2_STATEMENTS:
        conn.execute(statement)


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "adopt legacy schema", _migrate_v1),
    Migration(2, "mode, decision columns and web sessions", _migrate_v2),
)
LATEST_VERSION = MIGRATIONS[-1].version

_SCHEMA_VERSION_DDL = """
    CREATE TABLE IF NOT EXISTS schema_version (
        version    INTEGER PRIMARY KEY,
        name       TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
"""


def current_version(conn: sqlite3.Connection) -> int:
    """Highest applied migration; 0 for a database without `schema_version`."""
    has_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if has_table is None:
        return 0
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0] or 0)


@dataclass(frozen=True, slots=True)
class MigrationResult:
    from_version: int
    to_version: int
    applied: tuple[int, ...]


def migrate(
    db: Database, *, up_to: int = LATEST_VERSION, clock: Callable[[], float] = time.time
) -> MigrationResult:
    """Bring the database to `up_to` (default `LATEST_VERSION`), creating it if needed.

    `up_to` exists for tests that need a database in an older state.

    Raises `SchemaTooNewError` for a database from a newer analyzer, so an older
    release never writes to a schema it does not know.
    """
    conn = db.connect()
    try:
        # Manual transaction control: DDL must be inside BEGIN ... COMMIT, and
        # the sqlite3 module must not open or close transactions behind our back.
        conn.isolation_level = None
        before = current_version(conn)
        _refuse_newer(before)
        applied: list[int] = []
        if before < up_to:
            for migration in MIGRATIONS:
                if migration.version <= up_to and _apply(conn, migration, clock):
                    applied.append(migration.version)
        return MigrationResult(before, current_version(conn), tuple(applied))
    finally:
        conn.close()


def _refuse_newer(version: int) -> None:
    if version > LATEST_VERSION:
        raise SchemaTooNewError(
            f"database schema version {version} is newer than this release "
            f"supports ({LATEST_VERSION}); upgrade the analyzer instead of downgrading it"
        )


def _apply(conn: sqlite3.Connection, migration: Migration, clock: Callable[[], float]) -> bool:
    """Apply one migration in its own transaction; False if it was already applied."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(_SCHEMA_VERSION_DDL)
        version = current_version(conn)
        _refuse_newer(version)
        if version >= migration.version:
            conn.execute("COMMIT")
            return False
        migration.apply(conn)
        conn.execute(
            "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
            (migration.version, migration.name, iso_utc(clock())),
        )
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    log.info("Database schema at version %d (%s)", migration.version, migration.name)
    return True
