"""Input hardening of the ingest (#84, R3): line limit, strict parsing, path
confinement, corrupt watermark, crash windows."""

from __future__ import annotations

import io
import json
import stat
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from v2.ingest_support import Harness, archive_path, ev, lines, wait_for, write
from wazuh_ai_analyzer.ingest.archives import HEAD_LINE_MAX, first_line_digest, line_digest
from wazuh_ai_analyzer.ingest.lines import ALERT_LINE_MAX, LineKind, read_line
from wazuh_ai_analyzer.ingest.parse import MAX_DEPTH, LineOutcome, parse_alert_line
from wazuh_ai_analyzer.ingest.watermark import WATERMARK_MAX_BYTES, WatermarkStore
from wazuh_ai_analyzer.storage.repo import Repository


@pytest.fixture
def h(tmp_path: Path, repo: Repository) -> Harness:
    return Harness(
        alerts_log=tmp_path / "alerts" / "alerts.json",
        watermark_path=tmp_path / "data" / "watermark.json",
        repo=repo,
    )


def oversized(size: int = ALERT_LINE_MAX + 10) -> bytes:
    """A syntactically valid alert line longer than the limit."""
    head = b'{"rule": {"level": 9, "id": "1"}, "full_log": "'
    return head + b"A" * (size - len(head) - 3) + b'"}\n'


def can_symlink(tmp_path: Path) -> bool:
    try:
        (tmp_path / "probe-link").symlink_to(tmp_path)
    except (OSError, NotImplementedError):
        return False
    (tmp_path / "probe-link").unlink()
    return True


# ── bounded line reading ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("data", "final", "kind", "consumed"),
    [
        (b"abc\nrest", False, LineKind.LINE, 4),
        (b"abc", False, LineKind.PARTIAL, 3),
        (b"abc", True, LineKind.LINE, 3),
        (b"", False, LineKind.EOF, 0),
        (b"12345678\n", False, LineKind.LINE, 9),  # exactly the limit plus newline
        (b"123456789\nnext\n", False, LineKind.OVERSIZED, 10),
        (b"123456789" * 100 + b"\nnext\n", False, LineKind.OVERSIZED, 901),
        (b"123456789" * 100, False, LineKind.OVERSIZED_OPEN, 900),
        (b"123456789" * 100, True, LineKind.OVERSIZED, 900),
    ],
)
def test_read_line(data: bytes, final: bool, kind: LineKind, consumed: int) -> None:
    f = io.BytesIO(data)
    result = read_line(f, final=final, limit=8)
    assert (result.kind, result.consumed) == (kind, consumed)
    if kind is LineKind.OVERSIZED:
        assert len(result.data) == 9  # only limit + 1 bytes are ever held
        assert f.tell() == consumed


def test_oversized_lines_in_the_backlog_are_skipped_and_counted(h: Harness) -> None:
    big = oversized()
    write(h.alerts_log, lines(1) + big + lines(2) + b"x" * (ALERT_LINE_MAX + 5) + b"\n" + lines(3))
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3)
    assert h.counters.snapshot().oversized_lines == 2


def test_a_line_just_at_the_limit_is_still_an_alert(h: Harness) -> None:
    exact = oversized(ALERT_LINE_MAX + 1)  # ALERT_LINE_MAX bytes plus the newline
    assert len(exact.rstrip(b"\n")) == ALERT_LINE_MAX
    write(h.alerts_log, exact + lines(1))
    h.start()
    h.drain()
    assert len(h.flat()) == 2
    assert h.counters.snapshot().oversized_lines == 0


def test_live_skips_an_oversized_line_even_while_it_is_being_written(h: Harness) -> None:
    h.configure(batch_max=1)
    log = h.alerts_log
    write(log, lines(1))
    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)
        h.drain()
        base = log.stat().st_size
        big = oversized(ALERT_LINE_MAX * 2)
        with log.open("ab") as fh:
            fh.write(big[: ALERT_LINE_MAX + 100])  # longer than the limit, no end yet
        time.sleep(0.5)
        # nothing counted yet, and the position stays at the start of the open line
        assert h.counters.snapshot().oversized_lines == 0
        assert h.tailer.cursor.value is not None
        assert h.tailer.cursor.value["offset"] == base
        with log.open("ab") as fh:
            fh.write(big[ALERT_LINE_MAX + 100 :])
            fh.write(lines(2))
        assert wait_for(lambda: h.flat() == ev(1, 2))
        assert h.counters.snapshot().oversized_lines == 1

        def committed() -> bool:
            live = h.watermark.live
            return live is not None and live["offset"] == log.stat().st_size

        assert wait_for(committed)
    finally:
        t.close()
    assert t.error is None


def test_oversized_first_line_gets_the_same_digest_as_the_planner_computes(h: Harness) -> None:
    big = oversized()
    write(h.alerts_log, big + lines(1))
    with h.alerts_log.open("rb") as f:
        planned = first_line_digest(f, closed=False)
    assert planned == line_digest(big[: ALERT_LINE_MAX + 1])
    assert planned == line_digest(big[:HEAD_LINE_MAX])


# ── strict parsing ────────────────────────────────────────────────────────────


def nested(depth: int) -> bytes:
    return b'{"rule": {"level": 9}, "x": ' + b"[" * depth + b"]" * depth + b"}"


@pytest.mark.parametrize(
    ("line", "outcome"),
    [
        (b'{"rule": {"level": 7}}', LineOutcome.ALERT),
        (b'  {"rule": {"level": 7}}\r\n', LineOutcome.ALERT),
        (b'{"rule": {"level": 7.5}}', LineOutcome.ALERT),
        (b'{"rule": {"level": 4}}', LineOutcome.BELOW_MIN_LEVEL),
        (b"{}", LineOutcome.BELOW_MIN_LEVEL),  # no rule: level 0, as before
        (b'{"rule": {"level": true}}', LineOutcome.BELOW_MIN_LEVEL),
        (b"", LineOutcome.BLANK),
        (b" \t\r\n", LineOutcome.BLANK),
        (b"[1, 2]", LineOutcome.INVALID),
        (b'"text"', LineOutcome.INVALID),
        (b"42", LineOutcome.INVALID),
        (b"null", LineOutcome.INVALID),
        (b"{not json", LineOutcome.INVALID),
        (b'{"rule": "x"}', LineOutcome.INVALID),
        (b'{"rule": null}', LineOutcome.INVALID),
        (b'{"rule": {"level": "7"}}', LineOutcome.INVALID),
        (b'{"rule": {"level": null}}', LineOutcome.INVALID),
        (b'{"rule": {"level": NaN}}', LineOutcome.INVALID),
        (b'{"rule": {"level": Infinity}}', LineOutcome.INVALID),
        (b'{"rule": {"level": 1e400}}', LineOutcome.INVALID),
        (b'{"rule": {"level": 9}} trailing', LineOutcome.INVALID),
        (b"\xff\xfe garbage", LineOutcome.INVALID),
        (nested(MAX_DEPTH - 2), LineOutcome.ALERT),
        (nested(MAX_DEPTH), LineOutcome.INVALID),
        (nested(200_000), LineOutcome.INVALID),  # deeper than the interpreter's recursion limit
    ],
)
def test_parse_alert_line(line: bytes, outcome: LineOutcome) -> None:
    parsed = parse_alert_line(line, min_level=5)
    assert parsed.outcome is outcome
    assert (parsed.alert is not None) == (outcome is LineOutcome.ALERT)


def test_invalid_lines_are_dropped_and_counted_live_and_in_the_backlog(h: Harness) -> None:
    h.configure(batch_max=1)
    junk = b'[1]\n"x"\n{"rule": "x"}\n{broken\n\n'
    write(h.alerts_log, lines(1) + junk + lines(2))
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2)
    assert h.counters.snapshot().invalid_lines == 4
    h.plan_ready.clear()  # wait for the tailer's own planning, not the one above
    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)
        with h.alerts_log.open("ab") as fh:
            fh.write(junk + lines(3))
        assert wait_for(lambda: h.flat() == ev(1, 2, 3))
        assert h.counters.snapshot().invalid_lines == 8
    finally:
        t.close()


# ── path confinement ──────────────────────────────────────────────────────────


def test_symlinks_out_of_the_alerts_directory_are_not_followed(h: Harness, tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("creating symlinks is not permitted here")
    outside = tmp_path / "outside"
    write(outside / "secret.json", lines(66))
    write(outside / "2020" / "Jan" / "ossec-alerts-01.json", lines(67))
    log = h.alerts_log
    day = datetime.now().date()
    write(log, lines(1))
    h.start()
    h.drain()

    # a file link and a year-directory link that leave the tree, one link that stays inside
    evil = archive_path(log, day)
    evil.parent.mkdir(parents=True, exist_ok=True)
    evil.with_name(f"ossec-alerts-{day.day:02d}.json").symlink_to(outside / "secret.json")
    (log.parent / "2020").symlink_to(outside / "2020", target_is_directory=True)
    inside_target = log.parent / "keep" / "day.json"
    tomorrow = day + timedelta(days=1)
    write(inside_target, lines(2))
    good = archive_path(log, tomorrow, ".json")
    good.parent.mkdir(parents=True, exist_ok=True)
    good.symlink_to(inside_target)
    (log.parent / "alerts.json.evil").symlink_to(outside / "secret.json")

    listed = [p for _, p in h.files.list_dated_archives()]
    assert listed == [good]
    assert h.files.find_sibling_files() == []
    assert not h.files.is_confined(outside / "secret.json")
    assert not h.files.is_confined(log.parent / ".." / "outside" / "secret.json")
    assert h.files.is_confined(good)


def test_a_tampered_watermark_cannot_make_the_backlog_read_other_files(
    h: Harness, tmp_path: Path
) -> None:
    secret = tmp_path / "elsewhere" / "secret.json"
    write(secret, lines(66))
    write(h.alerts_log, lines(1))
    h.start()
    h.drain()
    data = json.loads(h.watermark_path.read_text())
    for path in (str(secret), str(h.alerts_log.parent / ".." / "elsewhere" / "secret.json")):
        data["backlog"].append({"path": path, "offset": 0, "end": None, "head": None, "id": 99})
    h.watermark_path.write_text(json.dumps(data))
    h.restart()
    h.start()
    h.drain()
    assert "evt-66" not in h.flat()
    assert h.watermark.first_segment() is None


# ── corrupt watermark ─────────────────────────────────────────────────────────

CORRUPT = [
    b"{not json",
    b"\x00\xff\xfe binary",
    b"[]",
    b'"text"',
    b'{"version": 3, "live": null, "backlog": []}',
    b'{"version": 2, "live": {"path": "x"}, "backlog": []}',
    b'{"version": 2, "live": null, "backlog": {}}',
    b'{"version": 2, "live": null, "backlog": [{"id": "1"}]}',
    b'{"version": 2, "live": null, "backlog": [], "next_id": "7"}',
    b'{"version": 2, "live": {"path": "a", "dev": 1, "ino": 2, "offset": -1, "head": null,'
    b' "ts": 1}, "backlog": []}',
    b'{"version": 2, "live": {"path": "a", "dev": true, "ino": 2, "offset": 0, "head": null,'
    b' "ts": 1}, "backlog": []}',
    b"[" * 100_000 + b"]" * 100_000,
]


@pytest.mark.parametrize("content", CORRUPT)
def test_corrupt_watermark_falls_back_to_a_safe_resume(
    h: Harness, content: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    write(h.alerts_log, lines(1, 2, 3))
    write(h.watermark_path, content)
    with caplog.at_level("WARNING"):
        cursor = h.start()
    h.drain()
    assert h.flat() == []  # nothing analysed twice
    assert cursor["offset"] == h.alerts_log.stat().st_size
    kept = h.watermark_path.with_name("watermark.json.corrupt")
    assert kept.read_bytes() == content
    if sys.platform != "win32":
        assert stat.S_IMODE(kept.stat().st_mode) == 0o600
    assert any("Watermark" in r.getMessage() for r in caplog.records)
    assert json.loads(h.watermark_path.read_text())["version"] == 2
    # and it keeps working afterwards
    write(h.alerts_log, lines(4), "ab")
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(4)


def test_oversized_watermark_is_not_parsed(h: Harness) -> None:
    write(h.watermark_path, b" " * (WATERMARK_MAX_BYTES + 1))
    store = WatermarkStore(h.watermark_path)
    store.load()
    assert store.legacy
    assert store.live is None


def test_segment_ids_are_never_reused_even_after_a_hand_edit(h: Harness) -> None:
    write(
        h.watermark_path,
        json.dumps(
            {
                "version": 2,
                "live": None,
                "backlog": [{"path": "a", "offset": 0, "end": None, "head": None, "id": 9}],
                "next_id": 2,
            }
        ).encode(),
    )
    store = WatermarkStore(h.watermark_path)
    store.load()
    store.apply_plan(
        {"path": "p", "dev": 1, "ino": 2, "offset": 0, "head": None},
        [{"path": "b", "offset": 0, "end": None, "head": None}],
    )
    assert [s.get("id") for s in store.backlog()] == [9, 10]


# ── crash windows (#43, #44) ──────────────────────────────────────────────────


class Crash(BaseException):
    """A process death: not an Exception, so nothing in the code catches it."""


def batch_rows(repo: Repository) -> int:
    return sum(repo.count_batches_by_status().values())


def test_backlog_crash_between_insert_and_watermark_write_loses_nothing(
    h: Harness, repo: Repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    h.configure(history_batch=2)
    write(h.alerts_log, lines(1, 2, 3, 4, 5))
    h.start()
    real = h.watermark.advance_segment
    calls: list[int] = []

    def crash_on_second(seg_id: int, offset: int) -> None:
        calls.append(1)
        if len(calls) == 2:
            raise Crash
        real(seg_id, offset)

    monkeypatch.setattr(h.watermark, "advance_segment", crash_on_second)
    with pytest.raises(Crash):
        h.drain()
    assert h.flat() == ev(1, 2, 3, 4)  # batch [3, 4] is stored, its offset is not
    assert batch_rows(repo) == 2

    h.restart()
    h.start()
    h.drain()
    # at-least-once: exactly the one batch of the crash window is stored again
    assert h.flat() == ev(1, 2, 3, 4, 3, 4, 5)
    assert batch_rows(repo) == 4
    assert h.watermark.first_segment() is None


def test_backlog_crash_before_the_insert_neither_loses_nor_duplicates(
    h: Harness, repo: Repository
) -> None:
    h.configure(history_batch=2)
    write(h.alerts_log, lines(1, 2, 3, 4, 5))
    h.start()
    calls: list[int] = []

    def crash_on_second(*_: object) -> None:
        calls.append(1)
        if len(calls) == 2:
            raise Crash

    h.writer.fail = crash_on_second
    with pytest.raises(Crash):
        h.drain()
    h.writer.fail = None
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 5)
    assert batch_rows(repo) == 3


def test_live_crash_between_insert_and_watermark_write_loses_nothing(
    h: Harness, repo: Repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    h.configure(batch_max=2, batch_timeout=3600)
    write(h.alerts_log, b"")
    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)

        def crash(cursor: object) -> None:
            raise Crash

        monkeypatch.setattr(h.watermark, "commit_live", crash)
        with h.alerts_log.open("ab") as fh:
            fh.write(lines(1, 2, 3))
        assert wait_for(lambda: t.error is not None)
    finally:
        t.close()
    assert isinstance(t.error, Crash)
    assert h.flat() == ev(1, 2)
    assert batch_rows(repo) == 1
    monkeypatch.undo()
    h.restart()
    h.start()
    h.drain()
    # the stored batch [1, 2] is read again (at-least-once), 3 is not lost
    assert h.flat() == ev(1, 2, 1, 2, 3)


def test_live_store_failure_keeps_the_alerts_and_the_position(h: Harness, repo: Repository) -> None:
    h.configure(batch_max=2, batch_timeout=3600)
    write(h.alerts_log, b"")
    calls: list[int] = []

    def db_down_once(*_: object) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise OSError("database is locked")

    h.writer.fail = db_down_once
    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)
        with h.alerts_log.open("ab") as fh:
            fh.write(lines(1, 2))
        assert wait_for(lambda: len(calls) == 1)
        assert len(h.tailer.buffer) == 2
        assert h.flat() == []
        live = h.watermark.live
        assert live is not None
        assert live["offset"] == 0
        with h.alerts_log.open("ab") as fh:
            fh.write(lines(3))
        assert wait_for(lambda: h.flat() == ev(1, 2, 3))  # the next flush carries all three
    finally:
        t.close()
    assert t.error is None
    assert batch_rows(repo) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="renames a file that is open")
def test_rotation_in_the_middle_of_a_batch_then_crash_loses_nothing(h: Harness) -> None:
    """Alerts of the old and the new file share one buffered batch; the process
    dies before it is stored. The restart finds the rest of the old file in the
    archive and reads the new file from the start."""
    h.configure(batch_max=100, batch_timeout=3600)
    log = h.alerts_log
    write(log, lines(1))
    t = h.run_tailer()
    try:
        assert h.plan_ready.wait(10)
        h.drain()
        with log.open("ab") as fh:
            fh.write(lines(2, 3))
        assert wait_for(lambda: len(h.tailer.buffer) == 2)
        arch = archive_path(log, datetime.now().date(), ".json")
        arch.parent.mkdir(parents=True, exist_ok=True)
        log.rename(arch)
        write(log, lines(4, 5))
        assert wait_for(lambda: len(h.tailer.buffer) == 4)
    finally:
        t.close()  # the buffer [2, 3, 4, 5] dies with the process
    assert h.flat() == ev(1)
    h.restart()
    h.start()
    h.drain()
    assert h.flat() == ev(1, 2, 3, 4, 5)
