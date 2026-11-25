"""Port of `tests/test_ingest_resume.py` (#44): the watermark follows the file, not the path.

Every test of the legacy module has an equivalent here with the same name and the
same expected behaviour; only internal names changed (see the mapping table in
the PR of #84). Log assertions use the English messages of the rewrite.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from v2.ingest_support import (
    Harness,
    archive_path,
    ev,
    lines,
    rotate,
    wait_for,
    write,
    write_gz,
)
from wazuh_ai_analyzer.ingest.live import LiveTailer
from wazuh_ai_analyzer.ingest.watermark import WATERMARK_VERSION
from wazuh_ai_analyzer.storage.repo import Repository

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX rename/hard-link semantics for open files"
)


@pytest.fixture
def h(tmp_path: Path, repo: Repository) -> Harness:
    return Harness(
        alerts_log=tmp_path / "alerts" / "alerts.json",
        watermark_path=tmp_path / "data" / "watermark.json",
        repo=repo,
    )


def today() -> datetime:
    return datetime.now()


# ── first start / migration ───────────────────────────────────────────────────


def test_first_start_analyses_existing_log_once_and_goes_live_at_the_end(h: Harness) -> None:
    write(h.alerts_log, lines(1, 2, 3) + lines(4)[:20])  # last line still being written
    cursor = h.start()
    assert cursor["offset"] == len(lines(1, 2, 3))
    h.drain()
    assert h.flat() == ev(1, 2, 3)
    assert h.counters.snapshot().history_done is True


def test_legacy_line_number_watermark_migrates_without_reanalysis(h: Harness) -> None:
    """#44 as seen in production: {"alerts.json": 1186} must not cause a re-read."""
    log = h.alerts_log
    write(log, lines(*range(1, 31)))
    h.watermark_path.parent.mkdir(parents=True, exist_ok=True)
    h.watermark_path.write_text(json.dumps({str(log): 1186}, indent=2))

    cursor = h.start()

    assert cursor["offset"] == log.stat().st_size
    h.drain()
    assert h.flat() == []  # no burst of duplicate batches
    saved = json.loads(h.watermark_path.read_text())
    assert saved["version"] == WATERMARK_VERSION
    assert saved["backlog"] == []
    assert saved["live"]["offset"] == log.stat().st_size
    assert saved["live"]["head"]
    backup = h.watermark_path.with_name("watermark.json.v1.bak")
    assert json.loads(backup.read_text()) == {str(log): 1186}  # old file kept for rollback

    # second start: plain v2 file, picks up only what is new
    write(log, lines(31, 32), "ab")
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(31, 32)


def test_unreadable_watermark_starts_at_the_end_and_keeps_a_copy(h: Harness) -> None:
    write(h.alerts_log, lines(1, 2, 3))
    write(h.watermark_path, b"{not json")
    h.start()
    h.drain()
    assert h.flat() == []
    assert h.watermark_path.with_name("watermark.json.corrupt").exists()


# ── restart on the same file ──────────────────────────────────────────────────


def test_restart_continues_at_the_saved_offset(h: Harness) -> None:
    write(h.alerts_log, lines(1, 2, 3))
    h.start()
    h.drain()
    write(h.alerts_log, lines(4, 5), "ab")  # written while we were down
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 5)


def test_restart_with_nothing_new_analyses_nothing(h: Harness) -> None:
    write(h.alerts_log, lines(1, 2, 3))
    h.start()
    h.drain()
    h.batches.clear()
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == []


def test_same_content_under_a_new_inode_is_still_the_same_file(h: Harness) -> None:
    log = h.alerts_log
    write(log, lines(1, 2))
    h.start()
    h.drain()
    data = log.read_bytes() + lines(3)
    log.unlink()
    write(log, data)  # restored/copied: new inode, same content
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3)


def test_shrunk_file_is_read_from_the_start(h: Harness) -> None:
    write(h.alerts_log, lines(1, 2, 3, 4))
    h.start()
    h.drain()
    write(h.alerts_log, lines(1, 2))  # same first line, but shorter than our offset
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 1, 2)


def test_log_that_was_empty_at_the_last_stop(h: Harness) -> None:
    write(h.alerts_log, b"")
    h.start()
    write(h.alerts_log, lines(1, 2), "ab")
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2)


# ── rotation while we were down ───────────────────────────────────────────────


def test_rotation_between_stop_and_start_no_duplicates_no_gaps(h: Harness) -> None:
    log = h.alerts_log
    write(log, lines(1, 2, 3, 4, 5))
    h.start()
    h.drain()  # run 1 analysed 1..5 and stopped
    day = today().date()
    old = log.read_bytes() + lines(6, 7, 8)  # arrived before midnight, while we were down
    rotate(log, day, old, lines(9, 10, 11))  # rotation at 00:00, new alerts after it
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
    assert len(set(h.flat())) == len(h.flat())


def test_several_days_of_downtime_are_caught_up_in_order(h: Harness) -> None:
    log = h.alerts_log
    write(log, lines(1, 2))
    h.start()
    h.drain()
    day = today().date()
    old = log.read_bytes() + lines(3)
    # downtime spans three midnights: days D, D+1, D+2 are archived, D+3 is live
    rotate(log, day, old, lines(4, 5))
    write_gz(archive_path(log, day + timedelta(days=1)), lines(4, 5))
    write_gz(archive_path(log, day + timedelta(days=2)), lines(6, 7, 8))
    write(log, lines(9))
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 5, 6, 7, 8, 9)


def test_unfinished_previous_file_still_uncompressed(h: Harness) -> None:
    """Rotation done but the .json not yet gzipped by Wazuh."""
    log = h.alerts_log
    write(log, lines(1, 2))
    h.start()
    h.drain()
    rotate(log, today().date(), log.read_bytes() + lines(3), lines(4), compress=False)
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4)


def test_text_format_archives_are_ignored(h: Harness) -> None:
    log = h.alerts_log
    write(log, lines(1))
    h.start()
    h.drain()
    day = today().date()
    rotate(log, day, log.read_bytes(), lines(2))
    write_gz(archive_path(log, day + timedelta(days=1), ".log.gz"), b"** Alert 1: - syslog\n" * 5)
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2)


def test_previous_file_gone_reads_only_what_exists(
    h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    log = h.alerts_log
    write(log, lines(1, 2))
    h.start()
    h.drain()
    log.unlink()
    write(log, lines(3, 4))  # rotated, archive purged by retention
    h.restart()
    with caplog.at_level("WARNING"):
        h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4)
    assert any("previous file not found" in r.getMessage() for r in caplog.records)


@posix_only
def test_todays_dated_hard_link_is_not_read_twice(h: Harness) -> None:
    """Wazuh keeps alerts.json and ossec-alerts-DD.json as one inode all day."""
    log = h.alerts_log
    day = today().date()
    write(log, lines(1, 2))
    plain_today = archive_path(log, day, ".json")
    plain_today.parent.mkdir(parents=True, exist_ok=True)
    os.link(log, plain_today)
    h.start()
    h.drain()
    write(log, lines(3), "ab")  # visible through both names
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3)

    # midnight: yesterday's file stays as .json (not compressed yet), today's is a new link
    tomorrow = day + timedelta(days=1)
    new_log = log.with_name("new.json")
    write(new_log, lines(4, 5))
    new_log.replace(log)
    link = archive_path(log, tomorrow, ".json")
    os.link(log, link)
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 5)


def test_archive_selection_prefers_plain_json_and_skips_the_live_inode(h: Harness) -> None:
    log = h.alerts_log
    day = today().date()
    gz, plain = archive_path(log, day), archive_path(log, day, ".json")
    for p in (gz, plain):
        write(p, b"x")
    other = archive_path(log, day - timedelta(days=1))
    write(other, b"x")
    write(archive_path(log, day, ".log.gz"), b"x")
    got = h.files.list_dated_archives()
    assert got == [(day - timedelta(days=1), other), (day, plain)]
    live_link = archive_path(log, day + timedelta(days=1), ".json")  # today's name for alerts.json
    write(live_link, b"x")
    st = live_link.stat()
    assert h.files.list_dated_archives(exclude=(st.st_dev, st.st_ino)) == got


# ── backlog segments survive crashes ──────────────────────────────────────────


def test_backlog_progress_is_persisted_between_batches(h: Harness) -> None:
    h.configure(history_batch=2)
    write(h.alerts_log, lines(*range(1, 8)))
    h.start()

    calls: list[int] = []

    def crash_on_third(*_: object) -> None:
        calls.append(1)
        if len(calls) == 3:
            raise RuntimeError("process died")

    h.writer.fail = crash_on_third
    with pytest.raises(RuntimeError):
        h.drain()
    assert h.flat() == ev(1, 2, 3, 4)

    h.writer.fail = None
    h.restart()
    h.watermark.load()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 5, 6, 7)  # resumed at 5, nothing twice


def test_segment_follows_its_file_into_the_archive(h: Harness) -> None:
    """A planned segment of alerts.json must survive the file being rotated before it was read."""
    log = h.alerts_log
    write(log, lines(1, 2, 3))
    h.start()  # segment [0, end) of alerts.json is queued
    rotate(log, today().date(), log.read_bytes(), lines(4))
    h.drain()
    assert h.flat() == ev(1, 2, 3)


def test_segment_with_unknown_file_is_skipped_not_fatal(h: Harness) -> None:
    log = h.alerts_log
    write(log, lines(1, 2))
    h.start()
    log.unlink()
    write(log, lines(7, 8, 9))  # different content under the same path
    h.drain()
    assert h.flat() == []
    assert h.watermark.first_segment() is None


def test_watermark_file_is_private_and_written_atomically(h: Harness) -> None:
    write(h.alerts_log, lines(1))
    h.start()
    assert not h.watermark_path.with_name("watermark.json.tmp").exists()
    if sys.platform != "win32":
        assert stat.S_IMODE(h.watermark_path.stat().st_mode) == 0o600
    data = json.loads(h.watermark_path.read_text())
    assert data["version"] == 2
    assert data["live"]["head"]


# ── the live tailer itself ────────────────────────────────────────────────────


@posix_only
def test_live_watcher_survives_rotation_without_loss_or_duplicates(h: Harness) -> None:
    h.configure(batch_max=3, batch_timeout=1)
    log = h.alerts_log
    write(log, lines(1, 2))

    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)
        h.drain()  # backlog: the two alerts present at start
        assert h.flat() == ev(1, 2)

        with log.open("ab") as fh:
            fh.write(lines(3, 4))
            fh.write(lines(5)[:25])  # a line still being written
            fh.flush()
            time.sleep(0.6)
            fh.write(lines(5)[25:])
            fh.write(lines(6))
        assert wait_for(lambda: len(h.flat()) == 6)

        # rotation: the last alerts land in the old file just before it is moved
        with log.open("ab") as fh:
            fh.write(lines(7, 8))
        arch = archive_path(log, today().date(), ".json")
        arch.parent.mkdir(parents=True, exist_ok=True)
        log.rename(arch)
        write(log, lines(9, 10))
        assert wait_for(lambda: len(h.flat()) == 10)

        assert h.flat() == ev(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

        def committed_at_end() -> bool:
            live = h.watermark.live
            st = log.stat()
            return live is not None and live["ino"] == st.st_ino and live["offset"] == st.st_size

        assert wait_for(committed_at_end)
    finally:
        t.close()
    assert t.error is None

    # a restart after all this finds nothing left to do
    h.batches.clear()
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == []


def test_live_watcher_commits_position_only_after_the_batch_is_stored(h: Harness) -> None:
    """Alerts sitting in the buffer are not covered by the watermark: after a
    crash they are read again instead of being lost."""
    h.configure(batch_max=100, batch_timeout=3600)
    log = h.alerts_log
    write(log, lines(1))
    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)
        h.drain()
        base = log.stat().st_size
        with log.open("ab") as fh:
            fh.write(lines(2, 3))
        assert wait_for(lambda: len(h.tailer.buffer) == 2)
        time.sleep(0.8)
        live = h.watermark.live
        assert live is not None
        assert live["offset"] == base
    finally:
        t.close()
    h.batches.clear()
    h.restart()  # "crash": the buffer is gone
    h.start()
    h.drain()
    assert h.flat() == ev(2, 3)


# ── review follow-ups ─────────────────────────────────────────────────────────


def test_stopped_on_an_empty_file_then_a_full_day_rotated_away(h: Harness) -> None:
    """Cursor without a first-line hash + rotation during downtime: the archive
    of the day we never read must not be skipped."""
    log = h.alerts_log
    write(log, b"")  # just after midnight: empty alerts.json
    h.start()
    rotate(log, today().date(), lines(1, 2, 3), lines(4))  # that day's alerts got archived
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4)


def test_empty_cursor_and_same_inode_stays_on_that_file(h: Harness) -> None:
    write(h.alerts_log, b"")
    h.start()
    write(h.alerts_log, lines(1, 2), "ab")
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2)


def test_broken_hard_link_copy_of_the_live_file_is_not_planned_twice(h: Harness) -> None:
    log = h.alerts_log
    write(log, lines(1, 2))
    h.start()
    h.drain()
    day = today().date()
    # midnight: yesterday archived, today's alerts.json restored as a *copy* of the dated file
    new_content = lines(3, 4)
    rotate(log, day, log.read_bytes(), new_content)
    write(archive_path(log, day + timedelta(days=1), ".json"), new_content)
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4)


def test_plan_ready_and_history_done_only_after_planning(h: Harness) -> None:
    assert h.worker.run_once() is False
    assert h.counters.snapshot().history_done is False  # nothing planned yet
    write(h.alerts_log, lines(1))
    h.start()
    h.drain()
    assert h.plan_ready.is_set()
    assert h.counters.snapshot().history_done is True


def test_watermark_save_failure_does_not_abort_the_segment(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h.configure(history_batch=2)
    write(h.alerts_log, lines(1, 2, 3, 4))
    h.start()
    real = h.watermark.advance_segment
    calls: list[int] = []

    def flaky(seg_id: int, offset: int) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise OSError("No space left on device")
        real(seg_id, offset)

    monkeypatch.setattr(h.watermark, "advance_segment", flaky)
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4)
    assert h.watermark.first_segment() is None


def test_supervisor_restarts_a_crashed_live_watcher(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs: list[int] = []

    def flaky_tail(self: LiveTailer, stop: threading.Event) -> None:
        runs.append(1)
        if len(runs) == 1:
            raise RuntimeError("boom")

    monkeypatch.setattr(LiveTailer, "tail", flaky_tail)
    h.tailer.run(threading.Event())
    assert len(runs) == 2


@posix_only
def test_live_watcher_ignores_a_relinked_or_copied_alerts_json(h: Harness) -> None:
    """alerts.json vanishing for a moment / being replaced by an identical copy
    must not make the watcher re-read the whole day."""
    h.configure(batch_max=2, batch_timeout=1)
    log = h.alerts_log
    write(log, lines(1, 2, 3))
    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)
        h.drain()
        assert h.flat() == ev(1, 2, 3)

        # 1) same inode, path unlinked and linked back
        tmp = log.with_name("elsewhere.json")
        os.link(log, tmp)
        log.unlink()
        time.sleep(0.8)
        os.link(tmp, log)
        with log.open("ab") as fh:
            fh.write(lines(4))
        assert wait_for(lambda: len(h.flat()) == 4)

        # 2) new inode, identical content
        data = log.read_bytes()
        replacement = log.with_name("copy.json")
        replacement.write_bytes(data)
        replacement.replace(log)
        time.sleep(0.8)
        with log.open("ab") as fh:
            fh.write(lines(5))
        assert wait_for(lambda: len(h.flat()) == 5)
        time.sleep(1.5)
        assert h.flat() == ev(1, 2, 3, 4, 5)
    finally:
        t.close()
    assert t.error is None
