"""All SQL of the analyzer lives here.

P1 provides what the contract and the retention need: writing batches in every
state, completing a batch with findings, and the retention purge. The pipeline
(#85) adds the retry queue: claim, defer, requeue of stale rows and expiry. The
web layer (#86) adds the read queries behind `/api/*` (section "read API"): they take
only validated values, bind every parameter, name every column explicitly (a future
internal column cannot leak into an API response by accident) and never use
`sqlite3.Row.get()` (#47: a Row has no such method).

Values that external tools depend on (severity, source, status, mode, risk) are
validated here before they reach the database: the schema of an existing install
cannot carry CHECK constraints for them, so this is the only gate.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, fields
from typing import cast

from .contract import (
    ANALYSIS_MODES,
    OVERALL_RISKS,
    SEVERITIES,
    SOURCES,
    STATUSES,
    AnalysisMode,
    OverallRisk,
    Severity,
    Source,
    Status,
    iso_utc,
)
from .db import Database

log = logging.getLogger(__name__)

SECONDS_PER_DAY = 86400.0

# The columns `/api/batches` has always returned (`SELECT b.*` of the legacy code), plus
# the additive ones of the rewrite. `raw_groups` and `last_error` hold attacker-influenced
# text: the API returns them as JSON data and the UI must never render them as HTML.
BATCH_API_COLUMNS = (
    "id",
    "created_at",
    "alert_count",
    "raw_groups",
    "summary",
    "overall_risk",
    "status",
    "source",
    "attempts",
    "next_attempt",
    "first_error_at",
    "last_error",
    "claimed_at",
    "bad_responses",
    "mode",
    "decision_version",
)
BATCHES_API_LIMIT = 50

JsonObject = dict[str, object]

_DELETE_FINDINGS_CHUNK = (
    "DELETE FROM findings WHERE batch_id IN ("
    "SELECT id FROM batches WHERE status IN ('done', 'error') AND created_at < ?"
    " ORDER BY id LIMIT ?)"
)
_DELETE_BATCHES_CHUNK = (
    "DELETE FROM batches WHERE id IN ("
    "SELECT id FROM batches WHERE status IN ('done', 'error') AND created_at < ?"
    " ORDER BY id LIMIT ?)"
)


def _check(name: str, value: str, allowed: tuple[str, ...]) -> None:
    if value not in allowed:
        raise ValueError(f"invalid {name} {value!r}, expected one of {', '.join(allowed)}")


@dataclass(frozen=True, slots=True)
class NewFinding:
    """A finding as the analysis backends hand it to storage."""

    title: str
    severity: Severity
    description: str
    recommendation: str
    affected_agents: Sequence[str] = ()
    rule_ids: Sequence[str] = ()
    confidence: float | None = None
    # Raw decision answers (decision mode). Stored as a JSON document in a TEXT column.
    decision: Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True)
class BatchRecord:
    id: int
    created_at: str
    alert_count: int
    raw_groups: str
    summary: str | None
    overall_risk: str | None
    status: str
    source: str
    attempts: int
    next_attempt: float | None
    first_error_at: str | None
    last_error: str | None
    claimed_at: float | None
    bad_responses: int
    mode: str
    decision_version: str | None


@dataclass(frozen=True, slots=True)
class StatsSnapshot:
    """Database part of `/api/stats`, read in one transaction."""

    total_findings: int
    by_severity: dict[str, int]
    last_analysis: str | None
    batch_count: int  # status 'done'
    by_status: dict[str, int]
    history_batches_done: int


@dataclass(frozen=True, slots=True)
class RetryState:
    """The retry bookkeeping of one batch (#43)."""

    attempts: int
    first_error_at: str | None
    bad_responses: int


@dataclass(frozen=True, slots=True)
class ClaimedBatch:
    """A queued batch the retry worker has just moved to `analyzing`."""

    id: int
    raw_groups: str
    source: Source


@dataclass(frozen=True, slots=True)
class FindingRecord:
    id: int
    batch_id: int
    title: str
    severity: str
    description: str
    recommendation: str
    affected_agents: list[str]
    rule_ids: list[str]
    confidence: float | None
    decision: dict[str, object] | None


class Repository:
    """Typed access to `batches` and `findings`."""

    def __init__(self, db: Database, *, clock: Callable[[], float] = time.time) -> None:
        self._db = db
        self._clock = clock

    # ── batches ──────────────────────────────────────────────────────────────
    def insert_batch(
        self,
        *,
        alert_count: int,
        raw_groups: str,
        source: Source,
        status: Status = "analyzing",
        mode: AnalysisMode = "llm",
        claimed_at: float | None = None,
    ) -> int:
        """Persist a batch before the analysis starts; returns its id.

        The default status `analyzing` plus `claimed_at` is what makes the batch
        survive a restart: it is either finished or re-queued.
        """
        _check("source", source, SOURCES)
        _check("status", status, STATUSES)
        _check("mode", mode, ANALYSIS_MODES)
        if claimed_at is None and status == "analyzing":
            claimed_at = self._clock()
        with self._db.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO batches (created_at, alert_count, raw_groups, status, source,"
                " claimed_at, mode) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (iso_utc(self._clock()), alert_count, raw_groups, status, source, claimed_at, mode),
            )
            batch_id = cur.lastrowid
        if batch_id is None:  # pragma: no cover - sqlite always sets it after an INSERT
            raise RuntimeError("INSERT did not return a row id")
        return batch_id

    def complete_batch(
        self,
        batch_id: int,
        *,
        summary: str,
        overall_risk: OverallRisk,
        findings: Sequence[NewFinding],
        mode: AnalysisMode = "llm",
        decision_version: str | None = None,
    ) -> list[int]:
        """Mark a batch `done` and store its findings in one transaction.

        Clears `next_attempt` and `last_error`, like the legacy `_save_result`.
        Returns the new finding ids.
        """
        _check("overall_risk", overall_risk, OVERALL_RISKS)
        _check("mode", mode, ANALYSIS_MODES)
        for finding in findings:
            _check("severity", finding.severity, SEVERITIES)
        ids: list[int] = []
        with self._db.transaction() as conn:
            updated = conn.execute(
                "UPDATE batches SET summary=?, overall_risk=?, status='done', mode=?,"
                " decision_version=?, next_attempt=NULL, last_error=NULL, decision_partial=NULL"
                " WHERE id=?",
                (summary, overall_risk, mode, decision_version, batch_id),
            ).rowcount
            if updated != 1:
                raise LookupError(f"batch {batch_id} does not exist")
            for finding in findings:
                cur = conn.execute(
                    "INSERT INTO findings (batch_id, title, severity, description,"
                    " recommendation, affected_agents, rule_ids, confidence, decision)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        batch_id,
                        finding.title,
                        finding.severity,
                        finding.description,
                        finding.recommendation,
                        json.dumps(list(finding.affected_agents)),
                        json.dumps(list(finding.rule_ids)),
                        finding.confidence,
                        None if finding.decision is None else json.dumps(finding.decision),
                    ),
                )
                if cur.lastrowid is None:  # pragma: no cover
                    raise RuntimeError("INSERT did not return a row id")
                ids.append(cur.lastrowid)
        return ids

    # ── history for the analysis ─────────────────────────────────────────────
    def recent_fact_batches(self, *, exclude_batch: int, hours: float, limit: int) -> list[str]:
        """`raw_groups` of the newest batches of the last `hours` whose groups carry facts.

        The severity calibration looks here for package activity that happened before
        the batch at hand (#118-#120). The LIKE only skips batches without any fact; the
        caller parses and re-sanitises the documents.
        """
        since = iso_utc(self._clock() - hours * 3600.0)
        with self._db.reader() as conn:
            rows = conn.execute(
                "SELECT raw_groups FROM batches WHERE id != ? AND created_at >= ?"
                " AND raw_groups LIKE '%\"facts\"%' ORDER BY id DESC LIMIT ?",
                (exclude_batch, since, limit),
            ).fetchall()
        return [str(row[0]) for row in rows]

    # ── decision scratch space (#88) ─────────────────────────────────────────
    def load_decision_partial(self, batch_id: int) -> str | None:
        """The answers a decision-mode batch already has (a JSON document), if any."""
        with self._db.reader() as conn:
            row = conn.execute(
                "SELECT decision_partial FROM batches WHERE id=?", (batch_id,)
            ).fetchone()
        return None if row is None or row[0] is None else str(row[0])

    def save_decision_partial(self, batch_id: int, document: str) -> None:
        """Keep the answers so far; `complete_batch` clears them."""
        with self._db.transaction() as conn:
            conn.execute("UPDATE batches SET decision_partial=? WHERE id=?", (document, batch_id))

    def set_pending(
        self,
        batch_id: int,
        *,
        next_attempt: float,
        message: str,
        attempts: int,
        first_error_at: str | None,
        bad_responses: int,
    ) -> None:
        """Park a batch for a later attempt after a failed one."""
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE batches SET status='pending', next_attempt=?, last_error=?,"
                " attempts=?, first_error_at=?, bad_responses=? WHERE id=?",
                (next_attempt, message, attempts, first_error_at, bad_responses, batch_id),
            )

    def fail_batch(self, batch_id: int, *, reason: str, attempts: int = 0) -> None:
        """Final failure: status `error` with `reason` as `last_error`.

        Build `reason` with the helpers in `contract` (`error_permanent`, ...): the
        text is read by external tools.
        """
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE batches SET status='error', next_attempt=NULL, last_error=?,"
                " attempts=MAX(attempts, ?), decision_partial=NULL WHERE id=?",
                (reason, attempts, batch_id),
            )

    # ── retry queue (#43, #85) ───────────────────────────────────────────────
    def defer_batch(self, batch_id: int, *, next_attempt: float) -> None:
        """Park a batch without having sent anything (gate closed): no attempt is used."""
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE batches SET status='pending', next_attempt=? WHERE id=?",
                (next_attempt, batch_id),
            )

    def retry_state(self, batch_id: int) -> RetryState | None:
        with self._db.reader() as conn:
            row = conn.execute(
                "SELECT attempts, first_error_at, bad_responses FROM batches WHERE id=?",
                (batch_id,),
            ).fetchone()
        if row is None:
            return None
        return RetryState(
            attempts=int(row["attempts"] or 0),
            first_error_at=row["first_error_at"],
            bad_responses=int(row["bad_responses"] or 0),
        )

    def requeue_stale(self, *, claimed_before: float, busy: Collection[int]) -> list[int]:
        """Put `analyzing` batches nobody works on back into the queue.

        A row qualifies when it was claimed at or before `claimed_before` (or has no
        `claimed_at`, as rows of old versions do) and its id is not in `busy`. Returns
        the ids that were re-queued; they are due at once.
        """
        now = self._clock()
        with self._db.transaction() as conn:
            rows = conn.execute(
                "SELECT id FROM batches WHERE status='analyzing'"
                " AND (claimed_at IS NULL OR claimed_at <= ?) ORDER BY id",
                (claimed_before,),
            ).fetchall()
            ids: list[int] = []
            for row in rows:
                batch_id = int(row["id"])
                if batch_id in busy:
                    continue
                updated = conn.execute(
                    "UPDATE batches SET status='pending', next_attempt=?"
                    " WHERE id=? AND status='analyzing'",
                    (now, batch_id),
                ).rowcount
                if updated == 1:
                    ids.append(batch_id)
        return ids

    def expire_pending(self, *, created_before: str, reason: str) -> list[int]:
        """Final failure for every `pending` batch created before `created_before`.

        `created_before` is a `created_at` value (`contract.iso_utc`); the strings sort
        like time. Build `reason` with `contract.error_queue_expired`. Returns the ids.
        """
        with self._db.transaction() as conn:
            rows = conn.execute(
                "SELECT id FROM batches WHERE status='pending' AND created_at < ? ORDER BY id",
                (created_before,),
            ).fetchall()
            ids: list[int] = []
            for row in rows:
                updated = conn.execute(
                    "UPDATE batches SET status='error', next_attempt=NULL, last_error=?,"
                    " decision_partial=NULL WHERE id=? AND status='pending'",
                    (reason, row["id"]),
                ).rowcount
                if updated == 1:
                    ids.append(int(row["id"]))
        return ids

    def claim_next_due(self, now: float) -> ClaimedBatch | None:
        """Move the next due `pending` batch to `analyzing` and return it.

        Order: live batches first, then the newest (the queue is drained newest first,
        so what expires under a long quota shortage is the oldest backlog). Returns
        None when nothing is due or another worker claimed the row first.
        """
        with self._db.transaction() as conn:
            row = conn.execute(
                "SELECT id, raw_groups, source FROM batches"
                " WHERE status='pending' AND COALESCE(next_attempt, 0) <= ?"
                " ORDER BY (source = 'live') DESC, id DESC LIMIT 1",
                (now,),
            ).fetchone()
            if row is None:
                return None
            claimed = conn.execute(
                "UPDATE batches SET status='analyzing', claimed_at=?"
                " WHERE id=? AND status='pending'",
                (now, row["id"]),
            ).rowcount
        if claimed != 1:
            return None
        source = row["source"]
        return ClaimedBatch(
            id=int(row["id"]),
            raw_groups=str(row["raw_groups"]),
            # Rows of old versions may carry NULL; the column default is 'live'.
            source=cast(Source, source) if source in SOURCES else "live",
        )

    def get_batch(self, batch_id: int) -> BatchRecord | None:
        with self._db.reader() as conn:
            row = conn.execute("SELECT * FROM batches WHERE id=?", (batch_id,)).fetchone()
        if row is None:
            return None
        return BatchRecord(**{f.name: row[f.name] for f in fields(BatchRecord)})

    def count_batches_by_status(self) -> dict[str, int]:
        with self._db.reader() as conn:
            rows = conn.execute("SELECT status, COUNT(*) FROM batches GROUP BY status").fetchall()
        return {str(status): int(count) for status, count in rows}

    # ── findings ─────────────────────────────────────────────────────────────
    def findings_for_batch(self, batch_id: int) -> list[FindingRecord]:
        with self._db.reader() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE batch_id=? ORDER BY id", (batch_id,)
            ).fetchall()
        return [_finding_record(row) for row in rows]

    # ── read API (#86) ───────────────────────────────────────────────────────
    def stats_snapshot(self) -> StatsSnapshot:
        with self._db.reader() as conn:
            conn.execute("BEGIN")  # one snapshot for all queries
            total = int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
            by_severity = {
                str(row[0]): int(row[1])
                for row in conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
            }
            last = conn.execute(
                "SELECT created_at FROM batches WHERE status='done' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            by_status = {
                str(row[0]): int(row[1])
                for row in conn.execute("SELECT status, COUNT(*) FROM batches GROUP BY status")
            }
            history_done = int(
                conn.execute(
                    "SELECT COUNT(*) FROM batches WHERE source='history' AND status='done'"
                ).fetchone()[0]
            )
        return StatsSnapshot(
            total_findings=total,
            by_severity=by_severity,
            last_analysis=None if last is None else str(last[0]),
            batch_count=by_status.get("done", 0),
            by_status=by_status,
            history_batches_done=history_done,
        )

    def list_findings(
        self, *, limit: int, offset: int, severity: str | None, source: str | None
    ) -> tuple[list[JsonObject], int]:
        """A page of findings (newest first) and the total for the same filter.

        `limit` and `offset` must be validated integers (`limit >= 1`: SQLite reads a
        negative LIMIT as "no limit"); `severity` and `source` must be whitelisted.
        """
        if limit < 1 or offset < 0:
            raise ValueError("limit must be at least 1 and offset must not be negative")
        conditions: list[str] = []
        params: list[object] = []
        if severity is not None:
            _check("severity", severity, SEVERITIES)
            conditions.append("f.severity = ?")
            params.append(severity)
        if source is not None:
            _check("source", source, SOURCES)
            # NULL (rows of old versions) counts as 'live', like in the response.
            conditions.append("COALESCE(b.source, 'live') = ?")
            params.append(source)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        join = "FROM findings f JOIN batches b ON f.batch_id = b.id"
        with self._db.reader() as conn:
            conn.execute("BEGIN")
            rows = conn.execute(
                f"SELECT {_FINDING_COLUMNS} {join} {where} ORDER BY f.id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) {join} {where}",
                    params,
                ).fetchone()[0]
            )
        return [_finding_json(row) for row in rows], total

    def get_finding(self, finding_id: int) -> JsonObject | None:
        if not 0 <= finding_id <= _SQLITE_MAX_INT:
            return None
        with self._db.reader() as conn:
            row = conn.execute(
                f"SELECT {_FINDING_COLUMNS}, b.summary AS batch_summary"  # noqa: S608
                " FROM findings f JOIN batches b ON f.batch_id = b.id WHERE f.id = ?",
                (finding_id,),
            ).fetchone()
        if row is None:
            return None
        detail = _finding_json(row)
        detail["batch_summary"] = row["batch_summary"]
        detail["alert_count"] = row["alert_count"]
        return detail

    def list_batches(self, limit: int = BATCHES_API_LIMIT) -> list[JsonObject]:
        columns = ", ".join(f"b.{name}" for name in BATCH_API_COLUMNS)
        with self._db.reader() as conn:
            rows = conn.execute(
                f"SELECT {columns},"  # noqa: S608 - constants only
                " (SELECT COUNT(*) FROM findings WHERE batch_id = b.id) AS finding_count"
                " FROM batches b ORDER BY b.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        names = (*BATCH_API_COLUMNS, "finding_count")
        return [{name: row[name] for name in names} for row in rows]

    # ── retention (#283) ─────────────────────────────────────────────────────
    def purge_old_batches(self, retention_days: float, *, chunk: int = 500) -> int:
        """Delete done/error batches (with their findings) older than `retention_days`.

        `retention_days <= 0` keeps everything. pending/analyzing rows are never
        deleted: the queue age limit bounds them instead. The work is split into
        transactions of `chunk` batches so the write lock stays short next to the
        live writers. Freed pages are reused by SQLite, so the file stops growing
        without a (locking, space-doubling) VACUUM. Returns the number of deleted
        batches.
        """
        if retention_days <= 0:
            return 0
        if chunk < 1:
            raise ValueError("chunk must be at least 1")
        cutoff = iso_utc(self._clock() - retention_days * SECONDS_PER_DAY)
        # The same chunk selection feeds both deletes. It runs inside one write
        # transaction, so findings and batches refer to the same ids, and no
        # variable-count limit applies to large chunks.
        deleted = 0
        while True:
            with self._db.transaction() as conn:
                conn.execute(_DELETE_FINDINGS_CHUNK, (cutoff, chunk))
                count = conn.execute(_DELETE_BATCHES_CHUNK, (cutoff, chunk)).rowcount
            deleted += count
            if count < chunk:
                break
        if deleted:
            self._checkpoint()
            log.info(
                "Retention: deleted %d done/error batches older than %g days with their findings",
                deleted,
                retention_days,
            )
        return deleted

    def _checkpoint(self) -> None:
        try:
            with self._db.transaction() as conn:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            log.debug("WAL checkpoint after retention failed", exc_info=True)


_SQLITE_MAX_INT = 2**63 - 1
_FINDING_COLUMNS = (
    "f.id, f.batch_id, f.title, f.severity, f.description, f.recommendation,"
    " f.affected_agents, f.rule_ids, f.confidence, b.created_at AS batch_time,"
    " b.alert_count, b.source AS batch_source, b.mode AS batch_mode"
)


def _json_list(raw: object) -> list[str]:
    """A stored JSON list of strings; anything else (corrupt, wrong shape) is empty."""
    try:
        value = json.loads(raw) if isinstance(raw, str) and raw else []
    except ValueError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _finding_json(row: sqlite3.Row) -> JsonObject:
    """One finding as `/api/findings` returns it: the legacy keys, plus `confidence`
    and `mode`. Every text field is data for the client, never markup."""
    return {
        "id": row["id"],
        "batch_id": row["batch_id"],
        "title": row["title"],
        "severity": row["severity"],
        "description": row["description"],
        "recommendation": row["recommendation"],
        "affected_agents": _json_list(row["affected_agents"]),
        "rule_ids": _json_list(row["rule_ids"]),
        "batch_time": row["batch_time"],
        "source": row["batch_source"] or "live",
        "confidence": row["confidence"],
        "mode": row["batch_mode"] or "llm",
    }


def _finding_record(row: sqlite3.Row) -> FindingRecord:
    decision = row["decision"]
    return FindingRecord(
        id=row["id"],
        batch_id=row["batch_id"],
        title=row["title"],
        severity=row["severity"],
        description=row["description"],
        recommendation=row["recommendation"],
        affected_agents=json.loads(row["affected_agents"] or "[]"),
        rule_ids=json.loads(row["rule_ids"] or "[]"),
        confidence=row["confidence"],
        decision=None if decision is None else json.loads(decision),
    )
