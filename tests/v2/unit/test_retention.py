"""Retention (#283), ported from tests/test_retention.py.

Mapping old test -> new test:

* test_disabled_by_default_deletes_nothing -> test_disabled_deletes_nothing
* test_purges_old_done_and_error_with_findings -> test_purges_old_done_and_error_with_findings
* test_pending_and_analyzing_are_never_deleted -> same name
* test_deletes_in_chunks -> same name (plus a chunk larger than SQLite's variable limit)
* test_cutoff_uses_configured_days -> test_cutoff_uses_the_given_days
* test_periodic_purge_respects_interval -> test_periodic_purge_respects_interval
* test_stats_expose_retention -> belongs to the web layer (#86): it asserts a field of
  GET /api/stats, not a storage behaviour.
"""

from __future__ import annotations

import logging

import pytest

from v2.helpers import FakeClock
from wazuh_ai_analyzer.storage import contract
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import Repository
from wazuh_ai_analyzer.storage.retention import RetentionPurger

DAY = 86400.0


def add_batch(
    database: Database, clock: FakeClock, status: str, days_ago: float, findings: int = 1
) -> int:
    with database.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status)"
            " VALUES (?, 1, '[]', ?)",
            (contract.iso_utc(clock.now - days_ago * DAY), status),
        )
        batch_id = cur.lastrowid
        assert batch_id is not None
        for i in range(findings):
            conn.execute(
                "INSERT INTO findings (batch_id, title, severity, description, recommendation)"
                " VALUES (?, ?, 'low', 'd', 'r')",
                (batch_id, f"f{i}"),
            )
    return batch_id


def ids(database: Database, table: str = "batches") -> set[int]:
    with database.reader() as conn:
        # `table` is one of two literals in this file.
        return {r[0] for r in conn.execute(f"SELECT id FROM {table}")}


def test_disabled_deletes_nothing(repo: Repository, database: Database, clock: FakeClock) -> None:
    old = add_batch(database, clock, "done", 900)
    assert repo.purge_old_batches(0) == 0
    assert repo.purge_old_batches(-5) == 0
    assert old in ids(database)


def test_purges_old_done_and_error_with_findings(
    repo: Repository, database: Database, clock: FakeClock
) -> None:
    add_batch(database, clock, "done", 200, findings=3)
    add_batch(database, clock, "error", 190, findings=0)
    fresh_done = add_batch(database, clock, "done", 10, findings=2)
    fresh_err = add_batch(database, clock, "error", 1)
    assert repo.purge_old_batches(180) == 2
    assert ids(database) == {fresh_done, fresh_err}
    with database.reader() as conn:
        left = {r[0] for r in conn.execute("SELECT DISTINCT batch_id FROM findings")}
    assert left == {fresh_done, fresh_err}


def test_pending_and_analyzing_are_never_deleted(
    repo: Repository, database: Database, clock: FakeClock
) -> None:
    pending = add_batch(database, clock, "pending", 400, findings=0)
    analyzing = add_batch(database, clock, "analyzing", 400, findings=0)
    assert repo.purge_old_batches(30) == 0
    assert {pending, analyzing} <= ids(database)


@pytest.mark.parametrize("chunk", [2, 1, 5000])
def test_deletes_in_chunks(
    repo: Repository, database: Database, clock: FakeClock, chunk: int
) -> None:
    old = [add_batch(database, clock, "done", 365) for _ in range(5)]
    keep = add_batch(database, clock, "done", 5)
    assert repo.purge_old_batches(180, chunk=chunk) == 5
    assert ids(database) == {keep}
    assert not set(old) & ids(database)
    assert ids(database, "findings") != set()  # the finding of `keep` survives


def test_a_chunk_of_one_is_the_smallest_allowed(repo: Repository) -> None:
    with pytest.raises(ValueError, match="chunk"):
        repo.purge_old_batches(30, chunk=0)


def test_cutoff_uses_the_given_days(repo: Repository, database: Database, clock: FakeClock) -> None:
    older = add_batch(database, clock, "done", 8)
    newer = add_batch(database, clock, "done", 6)
    assert repo.purge_old_batches(7) == 1
    assert ids(database) == {newer}
    assert older not in ids(database)


def test_purge_logs_a_line(
    repo: Repository, database: Database, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    add_batch(database, clock, "done", 400)
    with caplog.at_level(logging.INFO):
        repo.purge_old_batches(30)
    assert "Retention: deleted 1 done/error batches" in caplog.text


def test_periodic_purge_respects_interval(
    repo: Repository, database: Database, clock: FakeClock
) -> None:
    ticks = [1000.0]
    purger = RetentionPurger(repo, days=30, interval=3600, chunk=500, monotonic=lambda: ticks[0])
    first = add_batch(database, clock, "done", 100)
    assert purger.run_if_due() == 1
    assert first not in ids(database)

    second = add_batch(database, clock, "done", 100)
    ticks[0] += 100
    assert purger.run_if_due() == 0  # within the interval: skipped
    assert second in ids(database)

    ticks[0] += 3600
    assert purger.run_if_due() == 1
    assert second not in ids(database)


def test_purger_with_retention_disabled_never_touches_the_database(
    repo: Repository, database: Database, clock: FakeClock
) -> None:
    old = add_batch(database, clock, "done", 900)
    assert RetentionPurger(repo, days=0, interval=1, chunk=500).run_if_due() == 0
    assert old in ids(database)
