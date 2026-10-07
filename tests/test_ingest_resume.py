"""Regression tests for #44: the watermark follows the file, not the path."""
import gzip
import json
import os
import stat
import sys
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("flask")

posix_only = pytest.mark.skipif(sys.platform == "win32",
                                reason="needs POSIX rename/hard-link semantics for open files")


def alert(n, level=7):
    return {"timestamp": "2026-10-07T10:00:00.000+0000", "id": f"evt-{n}",
            "rule": {"id": "5710", "level": level, "description": "sshd"},
            "agent": {"name": "ct100"}, "location": "journald", "full_log": f"evt-{n}"}


def lines(*numbers, level=7):
    return "".join(json.dumps(alert(n, level)) + "\n" for n in numbers).encode()


def write(path, data, mode="wb"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode) as fh:
        fh.write(data)


def archive_path(az, day: date, suffix=".json.gz") -> Path:
    root = Path(az.ALERTS_LOG).parent
    return root / f"{day.year}" / az._MONTHS[day.month - 1] / f"ossec-alerts-{day.day:02d}{suffix}"


@pytest.fixture
def seen(az, monkeypatch):
    """Records every alert that would go to Gemini, in order, instead of calling it."""
    batches = []

    def fake_group(alerts):
        batches.append([a["full_log"] for a in alerts])
        return [{"rule_id": "5710", "count": len(alerts)}]

    monkeypatch.setattr(az, "group_alerts", fake_group)
    monkeypatch.setattr(az, "_do_gemini_and_save", lambda *a, **k: None)

    class Seen(list):
        def flat(self):
            return [x for b in batches for x in b]
    result = Seen(batches)
    result.batches = batches
    return result


def ev(*numbers):
    return [f"evt-{n}" for n in numbers]


def start(az):
    """What the live thread does at startup, minus the endless loop."""
    az.watermark.load()
    with open(az.ALERTS_LOG, "rb") as f:
        return az.plan_resume(f)


def drain(az):
    while az.run_backlog_once():
        pass


def restart(az):
    """A new process: nothing in memory, only watermark.json on disk."""
    az.watermark = az.WatermarkStore(az.watermark.path)
    az._segment_failures.clear()
    az.live_cursor = az._LiveCursor()


# ── first start / migration ───────────────────────────────────────────────────

def test_first_start_analyses_existing_log_once_and_goes_live_at_the_end(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3) + lines(4)[:20])          # last line still being written
    cursor = start(az)
    assert cursor["offset"] == len(lines(1, 2, 3))
    drain(az)
    assert seen.flat() == ev(1, 2, 3)
    assert az._stats["history_done"] is True


def test_legacy_line_number_watermark_migrates_without_reanalysis(az, seen):
    """#44 as seen in production: {"alerts.json": 1186} must not cause a re-read."""
    log = Path(az.ALERTS_LOG)
    write(log, lines(*range(1, 31)))
    az.watermark.path.write_text(json.dumps({str(log): 1186}, indent=2))

    cursor = start(az)

    assert cursor["offset"] == log.stat().st_size
    drain(az)
    assert seen.flat() == []                              # no burst of duplicate batches
    saved = json.loads(az.watermark.path.read_text())
    assert saved["version"] == az.WATERMARK_VERSION and saved["backlog"] == []
    assert saved["live"]["offset"] == log.stat().st_size and saved["live"]["head"]
    backup = az.watermark.path.with_name("watermark.json.v1.bak")
    assert json.loads(backup.read_text()) == {str(log): 1186}   # old file kept for rollback

    # second start: plain v2 file, picks up only what is new
    write(log, lines(31, 32), "ab")
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(31, 32)


def test_unreadable_watermark_starts_at_the_end_and_keeps_a_copy(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3))
    az.watermark.path.write_text("{not json")
    start(az)
    drain(az)
    assert seen.flat() == []
    assert az.watermark.path.with_name("watermark.json.corrupt").exists()


# ── restart on the same file ──────────────────────────────────────────────────

def test_restart_continues_at_the_saved_offset(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3))
    start(az)
    drain(az)
    write(log, lines(4, 5), "ab")                         # written while we were down
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4, 5)


def test_restart_with_nothing_new_analyses_nothing(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3))
    start(az)
    drain(az)
    seen.batches.clear()
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == []


def test_same_content_under_a_new_inode_is_still_the_same_file(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2))
    start(az)
    drain(az)
    data = log.read_bytes() + lines(3)
    log.unlink()
    write(log, data)                                       # restored/copied: new inode, same content
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3)


def test_shrunk_file_is_read_from_the_start(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3, 4))
    start(az)
    drain(az)
    write(log, lines(1, 2))                                # same first line, but shorter than our offset
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4, 1, 2)


def test_log_that_was_empty_at_the_last_stop(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, b"")
    start(az)
    write(log, lines(1, 2), "ab")
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2)


# ── rotation while we were down ───────────────────────────────────────────────

def rotate(az, day: date, final_content: bytes, new_content: bytes, *, compress=True):
    """Wazuh's midnight rotation: yesterday's alerts become a dated archive,
    alerts.json starts over as a new file."""
    log = Path(az.ALERTS_LOG)
    arch = archive_path(az, day, ".json.gz" if compress else ".json")
    arch.parent.mkdir(parents=True, exist_ok=True)
    if compress:
        with gzip.open(arch, "wb") as fh:
            fh.write(final_content)
    else:
        arch.write_bytes(final_content)
    log.unlink()
    write(log, new_content)
    return arch


def test_rotation_between_stop_and_start_no_duplicates_no_gaps(az, seen):
    """The regression test the issue asks for."""
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3, 4, 5))
    start(az)
    drain(az)                                              # run 1 analysed 1..5 and stopped
    day = datetime.now().date()
    old = log.read_bytes() + lines(6, 7, 8)                # arrived before midnight, while we were down
    rotate(az, day, old, lines(9, 10, 11))                 # rotation at 00:00, new alerts after it
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
    assert len(set(seen.flat())) == len(seen.flat())


def test_several_days_of_downtime_are_caught_up_in_order(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2))
    start(az)
    drain(az)
    day = datetime.now().date()
    old = log.read_bytes() + lines(3)
    # downtime spans three midnights: days D, D+1, D+2 are archived, D+3 is live
    rotate(az, day, old, lines(4, 5))
    day1 = archive_path(az, day + timedelta(days=1))
    day1.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(day1, "wb") as fh:
        fh.write(lines(4, 5))
    day2 = archive_path(az, day + timedelta(days=2))
    day2.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(day2, "wb") as fh:
        fh.write(lines(6, 7, 8))
    write(log, lines(9))
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4, 5, 6, 7, 8, 9)


def test_unfinished_previous_file_still_uncompressed(az, seen):
    """Rotation done but the .json not yet gzipped by Wazuh."""
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2))
    start(az)
    drain(az)
    day = datetime.now().date()
    rotate(az, day, log.read_bytes() + lines(3), lines(4), compress=False)
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4)


def test_text_format_archives_are_ignored(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1))
    start(az)
    drain(az)
    day = datetime.now().date()
    rotate(az, day, log.read_bytes(), lines(2))
    txt = archive_path(az, day + timedelta(days=1), ".log.gz")
    with gzip.open(txt, "wb") as fh:
        fh.write(b"** Alert 1: - syslog\n" * 5)
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2)


def test_previous_file_gone_reads_only_what_exists(az, seen, caplog):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2))
    start(az)
    drain(az)
    log.unlink()
    write(log, lines(3, 4))                                # rotated, archive purged by retention
    restart(az)
    with caplog.at_level("WARNING"):
        start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4)
    assert any("nicht gefunden" in r.getMessage() for r in caplog.records)


@posix_only
def test_todays_dated_hard_link_is_not_read_twice(az, seen):
    """Wazuh keeps alerts.json and ossec-alerts-DD.json as one inode all day."""
    log = Path(az.ALERTS_LOG)
    day = datetime.now().date()
    write(log, lines(1, 2))
    plain_today = archive_path(az, day, ".json")
    plain_today.parent.mkdir(parents=True, exist_ok=True)
    os.link(log, plain_today)
    start(az)
    drain(az)
    write(log, lines(3), "ab")                             # visible through both names
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3)

    # midnight: yesterday's file stays as .json (not compressed yet), today's is a new link
    tomorrow = day + timedelta(days=1)
    new_log = log.with_name("new.json")
    write(new_log, lines(4, 5))
    os.replace(new_log, log)
    link = archive_path(az, tomorrow, ".json")
    os.link(log, link)
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4, 5)


def test_archive_selection_prefers_plain_json_and_skips_the_live_inode(az):
    day = datetime.now().date()
    gz, plain = archive_path(az, day), archive_path(az, day, ".json")
    for p in (gz, plain):
        write(p, b"x")
    other = archive_path(az, day - timedelta(days=1))
    write(other, b"x")
    write(archive_path(az, day, ".log.gz"), b"x")
    got = az.list_dated_archives()
    assert got == [(day - timedelta(days=1), str(other)), (day, str(plain))]
    live_link = archive_path(az, day + timedelta(days=1), ".json")   # today's name for alerts.json
    write(live_link, b"x")
    st = live_link.stat()
    assert az.list_dated_archives(exclude=(st.st_dev, st.st_ino)) == got


# ── backlog segments survive crashes ──────────────────────────────────────────

def test_backlog_progress_is_persisted_between_batches(az, seen, monkeypatch):
    monkeypatch.setattr(az, "HISTORY_BATCH", 2)
    log = Path(az.ALERTS_LOG)
    write(log, lines(*range(1, 8)))
    start(az)

    real, calls = az._store_batch, []

    def crash_on_third(alerts, source):
        calls.append(1)
        if len(calls) == 3:
            raise RuntimeError("process died")
        return real(alerts, source)

    monkeypatch.setattr(az, "_store_batch", crash_on_third)
    with pytest.raises(RuntimeError):
        drain(az)
    assert seen.flat() == ev(1, 2, 3, 4)

    monkeypatch.setattr(az, "_store_batch", real)
    restart(az)
    az.watermark.load()
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4, 5, 6, 7)          # resumed at 5, nothing twice


def test_segment_follows_its_file_into_the_archive(az, seen):
    """A planned segment of alerts.json must survive the file being rotated before it was read."""
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3))
    start(az)                                              # segment [0, end) of alerts.json is queued
    rotate(az, datetime.now().date(), log.read_bytes(), lines(4))
    drain(az)
    assert seen.flat() == ev(1, 2, 3)


def test_segment_with_unknown_file_is_skipped_not_fatal(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2))
    start(az)
    log.unlink()
    write(log, lines(7, 8, 9))                             # different content under the same path
    drain(az)
    assert seen.flat() == []
    assert az.watermark.first_segment() is None


def test_watermark_file_is_private_and_written_atomically(az):
    write(Path(az.ALERTS_LOG), lines(1))
    start(az)
    assert not az.watermark.path.with_name("watermark.json.tmp").exists()
    if sys.platform != "win32":
        assert stat.S_IMODE(az.watermark.path.stat().st_mode) == 0o600
    data = json.loads(az.watermark.path.read_text())
    assert data["version"] == 2 and data["live"]["head"]


# ── the live watcher itself ───────────────────────────────────────────────────

def wait_for(predicate, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@posix_only
def test_live_watcher_survives_rotation_without_loss_or_duplicates(az, seen, monkeypatch):
    monkeypatch.setattr(az, "BATCH_MAX", 3)
    monkeypatch.setattr(az, "BATCH_TIMEOUT", 1)
    monkeypatch.setattr(az, "WATERMARK_IDLE_COMMIT", 0)
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2))

    stop = threading.Event()
    t = threading.Thread(target=az.tail_alerts, args=(stop,), daemon=True)
    t.start()
    try:
        assert az.plan_ready.wait(10)
        drain(az)                                          # backlog: the two alerts present at start
        assert seen.flat() == ev(1, 2)

        with open(log, "ab") as fh:
            fh.write(lines(3, 4))
            fh.write(lines(5)[:25])                        # a line still being written
            fh.flush()
            time.sleep(0.6)
            fh.write(lines(5)[25:])
            fh.write(lines(6))
        assert wait_for(lambda: len(seen.flat()) == 6)

        # rotation: the last alerts land in the old file just before it is moved
        with open(log, "ab") as fh:
            fh.write(lines(7, 8))
        arch = archive_path(az, datetime.now().date(), ".json")
        arch.parent.mkdir(parents=True, exist_ok=True)
        os.rename(log, arch)
        write(log, lines(9, 10))
        assert wait_for(lambda: len(seen.flat()) == 10)

        assert seen.flat() == ev(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        assert wait_for(lambda: az.watermark.live and az.watermark.live["ino"] == log.stat().st_ino
                        and az.watermark.live["offset"] == log.stat().st_size)
    finally:
        stop.set()
        t.join(10)
    assert not t.is_alive()

    # a restart after all this finds nothing left to do
    seen.batches.clear()
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == []


@posix_only
def test_live_watcher_commits_position_only_after_the_batch_is_stored(az, seen, monkeypatch):
    """Alerts sitting in the buffer are not covered by the watermark: after a
    crash they are read again instead of being lost."""
    monkeypatch.setattr(az, "BATCH_MAX", 100)
    monkeypatch.setattr(az, "BATCH_TIMEOUT", 3600)
    monkeypatch.setattr(az, "WATERMARK_IDLE_COMMIT", 0)
    log = Path(az.ALERTS_LOG)
    write(log, lines(1))
    stop = threading.Event()
    t = threading.Thread(target=az.tail_alerts, args=(stop,), daemon=True)
    t.start()
    try:
        assert az.plan_ready.wait(10)
        drain(az)
        base = log.stat().st_size
        with open(log, "ab") as fh:
            fh.write(lines(2, 3))
        assert wait_for(lambda: len(az.alert_buffer) == 2)
        time.sleep(0.8)
        assert az.watermark.live["offset"] == base         # buffered, not committed
    finally:
        stop.set()
        t.join(10)
    seen.batches.clear()
    restart(az)                                            # "crash": the buffer is gone
    start(az)
    drain(az)
    assert seen.flat() == ev(2, 3)


# ── review follow-ups ─────────────────────────────────────────────────────────

def test_stopped_on_an_empty_file_then_a_full_day_rotated_away(az, seen):
    """Cursor without a first-line hash + rotation during downtime: the archive
    of the day we never read must not be skipped."""
    log = Path(az.ALERTS_LOG)
    write(log, b"")                                        # just after midnight: empty alerts.json
    start(az)
    day = datetime.now().date()
    rotate(az, day, lines(1, 2, 3), lines(4))              # that day's alerts got archived meanwhile
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4)


def test_empty_cursor_and_same_inode_stays_on_that_file(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, b"")
    start(az)
    write(log, lines(1, 2), "ab")
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2)


def test_broken_hard_link_copy_of_the_live_file_is_not_planned_twice(az, seen):
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2))
    start(az)
    drain(az)
    day = datetime.now().date()
    # midnight: yesterday archived, today's alerts.json restored as a *copy* of the dated file
    new_content = lines(3, 4)
    rotate(az, day, log.read_bytes(), new_content)
    write(archive_path(az, day + timedelta(days=1), ".json"), new_content)
    restart(az)
    start(az)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4)


def test_plan_ready_and_history_done_only_after_planning(az, seen):
    assert az.run_backlog_once() is False
    assert az._stats["history_done"] is False              # nothing planned yet
    write(Path(az.ALERTS_LOG), lines(1))
    start(az)
    drain(az)
    assert az.plan_ready.is_set() and az._stats["history_done"] is True


def test_watermark_save_failure_does_not_abort_the_segment(az, seen, monkeypatch):
    monkeypatch.setattr(az, "HISTORY_BATCH", 2)
    write(Path(az.ALERTS_LOG), lines(1, 2, 3, 4))
    start(az)
    real = az.watermark.advance_segment
    calls = []

    def flaky(seg_id, offset):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("No space left on device")
        return real(seg_id, offset)

    monkeypatch.setattr(az.watermark, "advance_segment", flaky)
    drain(az)
    assert seen.flat() == ev(1, 2, 3, 4)
    assert az.watermark.first_segment() is None


def test_supervisor_restarts_a_crashed_live_watcher(az, monkeypatch):
    runs = []
    stop = threading.Event()

    def flaky_tail(ev_stop):
        runs.append(1)
        if len(runs) == 1:
            raise RuntimeError("boom")

    class FastStop(threading.Event):
        def wait(self, timeout=None):
            return super().wait(0.01)

    monkeypatch.setattr(az, "tail_alerts", flaky_tail)
    az.live_watcher(FastStop())
    assert len(runs) == 2


@posix_only
def test_live_watcher_ignores_a_relinked_or_copied_alerts_json(az, seen, monkeypatch):
    """alerts.json vanishing for a moment / being replaced by an identical copy
    must not make the watcher re-read the whole day."""
    monkeypatch.setattr(az, "BATCH_MAX", 2)
    monkeypatch.setattr(az, "BATCH_TIMEOUT", 1)
    monkeypatch.setattr(az, "WATERMARK_IDLE_COMMIT", 0)
    log = Path(az.ALERTS_LOG)
    write(log, lines(1, 2, 3))
    stop = threading.Event()
    t = threading.Thread(target=az.tail_alerts, args=(stop,), daemon=True)
    t.start()
    try:
        assert az.plan_ready.wait(10)
        drain(az)
        assert seen.flat() == ev(1, 2, 3)

        # 1) same inode, path unlinked and linked back
        tmp = log.with_name("elsewhere.json")
        os.link(log, tmp)
        os.unlink(log)
        time.sleep(0.8)
        os.link(tmp, log)
        with open(log, "ab") as fh:
            fh.write(lines(4))
        assert wait_for(lambda: len(seen.flat()) == 4)

        # 2) new inode, identical content
        data = log.read_bytes()
        replacement = log.with_name("copy.json")
        replacement.write_bytes(data)
        os.replace(replacement, log)
        time.sleep(0.8)
        with open(log, "ab") as fh:
            fh.write(lines(5))
        assert wait_for(lambda: len(seen.flat()) == 5)
        time.sleep(1.5)
        assert seen.flat() == ev(1, 2, 3, 4, 5)
    finally:
        stop.set()
        t.join(10)
