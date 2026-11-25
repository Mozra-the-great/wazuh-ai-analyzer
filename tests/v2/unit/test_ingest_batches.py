"""Batch building and the live flush window.

The first four tests are the port of `tests/test_batch_timeout.py`.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from v2.helpers import FakeClock
from v2.ingest_support import DEFAULT_BATCHING
from wazuh_ai_analyzer.ingest.batches import BatchWriter, LiveBuffer, flush_timeout
from wazuh_ai_analyzer.ingest.sanitize import group_alerts
from wazuh_ai_analyzer.storage.repo import Repository


def a(level: Any) -> dict[str, Any]:
    return {"rule": {"id": "1", "level": level}}


# ── port of tests/test_batch_timeout.py ───────────────────────────────────────


def test_default_keeps_single_timeout() -> None:
    assert DEFAULT_BATCHING.batch_timeout_quiet == 0
    assert flush_timeout([a(5), a(12)], DEFAULT_BATCHING) == DEFAULT_BATCHING.batch_timeout


def test_quiet_buffer_waits_longer_but_urgent_does_not() -> None:
    cfg = replace(DEFAULT_BATCHING, batch_timeout=300, batch_timeout_quiet=900, urgent_level=10)
    assert flush_timeout([a(5), a(7), a(9)], cfg) == 900
    assert flush_timeout([a(5), a(10)], cfg) == 300
    assert flush_timeout([a(15)], cfg) == 300


def test_malformed_alerts_do_not_break_the_decision() -> None:
    cfg = replace(DEFAULT_BATCHING, batch_timeout_quiet=900)
    assert flush_timeout([{}, {"rule": "x"}, {"rule": {"level": "n/a"}}], cfg) == 900


def test_quiet_window_is_never_shorter_than_the_normal_timeout() -> None:
    cfg = replace(DEFAULT_BATCHING, batch_timeout=300, batch_timeout_quiet=60)
    assert flush_timeout([a(5)], cfg) == 300
    # tests / small setups follow BATCH_TIMEOUT
    cfg = replace(DEFAULT_BATCHING, batch_timeout=2, batch_timeout_quiet=0)
    assert flush_timeout([a(5)], cfg) == 2


# ── LiveBuffer ────────────────────────────────────────────────────────────────


def test_buffer_reports_full_at_batch_max() -> None:
    buf = LiveBuffer(replace(DEFAULT_BATCHING, batch_max=2), clock=FakeClock())
    assert buf.add(a(7)) is False
    assert buf.add(a(7)) is True
    assert len(buf) == 2


def test_buffer_is_due_after_the_window_since_the_last_flush() -> None:
    clock = FakeClock()
    cfg = replace(DEFAULT_BATCHING, batch_timeout=300, batch_timeout_quiet=900, urgent_level=10)
    buf = LiveBuffer(cfg, clock=clock)
    assert buf.is_due() is False  # empty is never due
    buf.add(a(5))
    clock.advance(899)
    assert buf.is_due() is False
    clock.advance(1)
    assert buf.is_due() is True
    buf.add(a(12))  # urgent: the shorter window applies at once
    assert buf.is_due() is True
    buf.remove_flushed(2)
    assert len(buf) == 0
    buf.add(a(12))
    assert buf.is_due() is False  # the window restarted with the flush
    clock.advance(300)
    assert buf.is_due() is True


def test_failed_store_restarts_the_window_but_keeps_the_alerts() -> None:
    clock = FakeClock()
    buf = LiveBuffer(replace(DEFAULT_BATCHING, batch_timeout=10), clock=clock)
    buf.add(a(5))
    clock.advance(10)
    assert buf.is_due()
    buf.touch()
    assert not buf.is_due()
    assert len(buf) == 1


# ── BatchWriter ───────────────────────────────────────────────────────────────


def test_writer_stores_an_analyzing_batch_with_sanitised_groups(repo: Repository) -> None:
    alerts: list[dict[str, Any]] = [
        {"rule": {"id": "5710", "level": 7, "description": "sshd"}, "full_log": "x\x00y"},
        {"rule": {"id": "5710", "level": 9}, "agent": {"name": "ct100"}},
        {"rule": {"id": "31100", "level": 12}},
    ]
    stored = BatchWriter(repo).store(alerts, "live")
    row = repo.get_batch(stored.batch_id)
    assert row is not None
    assert (row.status, row.source, row.alert_count, row.mode) == ("analyzing", "live", 3, "llm")
    assert row.claimed_at is not None
    assert json.loads(row.raw_groups) == stored.groups == group_alerts(alerts)
    assert row.raw_groups == json.dumps(group_alerts(alerts))
    assert stored.groups[0]["rule_id"] == "31100"  # highest level first
    assert "\x00" not in row.raw_groups


def test_writer_passes_the_analysis_mode(repo: Repository) -> None:
    stored = BatchWriter(repo, mode="decision").store([a(7)], "history")
    row = repo.get_batch(stored.batch_id)
    assert row is not None
    assert (row.mode, row.source) == ("decision", "history")
