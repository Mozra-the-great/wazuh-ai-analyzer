"""All SQL of the analyzer lives here.

P1 provides what the contract and the retention need: writing batches in every
state, completing a batch with findings, and the retention purge. The pipeline
(#85) adds the retry queue: claim, defer, requeue of stale rows and expiry. The
read queries of the web layer (#86) are added to this class by that package.

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
                " decision_version=?, next_attempt=NULL, last_error=NULL WHERE id=?",
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
                " attempts=MAX(attempts, ?) WHERE id=?",
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
                    "UPDATE batches SET status='error', next_attempt=NULL, last_error=?"
                    " WHERE id=? AND status='pending'",
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
