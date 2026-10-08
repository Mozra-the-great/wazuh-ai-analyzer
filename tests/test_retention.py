"""Retention for analyses.db (#283): old done/error batches go, pending stays."""
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("flask")


def _ts(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")


def _batch(az, status, days_ago, findings=1):
    with az._db() as conn:
        cur = conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status) VALUES (?, 1, '[]', ?)",
            (_ts(days_ago), status))
        batch_id = cur.lastrowid
        for i in range(findings):
            conn.execute(
                "INSERT INTO findings (batch_id, title, severity, description, recommendation) "
                "VALUES (?, ?, 'low', 'd', 'r')", (batch_id, f"f{i}"))
    return batch_id


def _ids(az, table="batches"):
    with az._db() as conn:
        return {r[0] for r in conn.execute(f"SELECT id FROM {table}")}


def test_disabled_by_default_deletes_nothing(az):
    assert az.RETENTION_DAYS == 0
    old = _batch(az, "done", 900)
    assert az.purge_old_batches() == 0
    assert old in _ids(az)


def test_purges_old_done_and_error_with_findings(az):
    old_done = _batch(az, "done", 200, findings=3)
    old_err = _batch(az, "error", 190, findings=0)
    fresh_done = _batch(az, "done", 10, findings=2)
    fresh_err = _batch(az, "error", 1)
    assert az.purge_old_batches(180) == 2
    assert _ids(az) == {fresh_done, fresh_err}
    with az._db() as conn:
        left = {r[0] for r in conn.execute("SELECT DISTINCT batch_id FROM findings")}
    assert left == {fresh_done, fresh_err}
    assert az._stats["purged_batches"] == 2


def test_pending_and_analyzing_are_never_deleted(az):
    pending = _batch(az, "pending", 400, findings=0)
    analyzing = _batch(az, "analyzing", 400, findings=0)
    assert az.purge_old_batches(30) == 0
    assert {pending, analyzing} <= _ids(az)


def test_deletes_in_chunks(az, monkeypatch):
    monkeypatch.setattr(az, "RETENTION_CHUNK", 2)
    old = [_batch(az, "done", 365) for _ in range(5)]
    keep = _batch(az, "done", 5)
    assert az.purge_old_batches(180) == 5
    assert _ids(az) == {keep}
    assert not set(old) & _ids(az)
    assert _ids(az, "findings") != set()  # keep's finding survives


def test_cutoff_uses_configured_days(az, monkeypatch):
    monkeypatch.setattr(az, "RETENTION_DAYS", 7)
    a = _batch(az, "done", 8)
    b = _batch(az, "done", 6)
    assert az.purge_old_batches() == 1
    assert _ids(az) == {b} and a not in _ids(az)


def test_periodic_purge_respects_interval(az, monkeypatch):
    monkeypatch.setattr(az, "RETENTION_DAYS", 30)
    monkeypatch.setattr(az, "RETENTION_INTERVAL", 3600)
    monkeypatch.setattr(az, "_last_purge", 0.0)
    first = _batch(az, "done", 100)
    az._purge_if_due()
    assert first not in _ids(az)
    second = _batch(az, "done", 100)
    az._purge_if_due()          # within the interval: skipped
    assert second in _ids(az)
    monkeypatch.setattr(az, "_last_purge", az.time.monotonic() - 3601)
    az._purge_if_due()
    assert second not in _ids(az)


def test_stats_expose_retention(az, client, monkeypatch):
    monkeypatch.setattr(az, "RETENTION_DAYS", 180)
    body = client.get("/api/stats").get_json()
    assert body["retention_days"] == 180
    assert body["runtime"]["purged_batches"] == 0
