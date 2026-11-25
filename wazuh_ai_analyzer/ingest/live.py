"""The live tailer: follows `alerts.json`, starting where the watermark says.

* Rotation (the path points at another inode that is not the same file): the old
  file is read to its end through the still-open handle, even an unterminated
  last line, then the new file from byte 0. Nothing is skipped or read twice.
* A path that only changed its inode (re-linked, restored as a copy) but still
  holds our file (same first-line digest, at least as long) is not a rotation.
* A file that shrank in place was truncated and is read from the start.
* A half-written line is left alone until its newline arrives.
* A line longer than `ALERT_LINE_MAX` is skipped (and counted) without ever being
  held in memory; while its end is not written yet, the cursor stays at its start.

The position is committed to the watermark only after the batch holding every
alert read so far is stored (or, with an empty buffer, after
`WATERMARK_IDLE_COMMIT` seconds of idleness), so a crash re-reads but never loses.

Backpressure: while the database refuses the batch, the buffered alerts stay in memory
and the position stays put. Reading stops once `BACKPRESSURE_FACTOR * BATCH_MAX` alerts
are buffered, so a long outage cannot fill the memory (or, while draining a rotated
file, read it to its end into the buffer). The store is retried with an exponential
backoff, and the error is logged in full once and then at most once a minute.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Final

from ..config import BatchingConfig
from .archives import AlertFiles, first_line_digest, ident_of, line_digest
from .batches import BatchWriter, LiveBuffer, StoredBatch
from .counters import IngestCounters
from .lines import LineKind, read_line, skip_to_newline
from .parse import LineOutcome, parse_alert_line
from .planner import cursor_at_end, plan_resume
from .watermark import Cursor, WatermarkStore

log = logging.getLogger(__name__)

# Minimum gap between two idle commits of the live position (seconds).
WATERMARK_IDLE_COMMIT: Final = 5.0
POLL_INTERVAL: Final = 0.3
RESTART_DELAY: Final = 10.0
# Reading pauses when this many batches' worth of alerts wait for a failing store.
BACKPRESSURE_FACTOR: Final = 2
STORE_RETRY_BASE: Final = 1.0
STORE_RETRY_MAX: Final = 30.0
STORE_FAILURE_LOG_INTERVAL: Final = 60.0


class CursorTracker:
    """Where the tailer is in the log. Only the tailer thread moves it."""

    def __init__(self, watermark: WatermarkStore, clock: Callable[[], float]) -> None:
        self._watermark = watermark
        self._clock = clock
        self.value: Cursor | None = None
        self.committed: Cursor | None = None
        self.last_commit = 0.0

    def set(self, path: str, dev: int, ino: int, offset: int, head: str | None) -> None:
        self.value = {"path": path, "dev": dev, "ino": ino, "offset": offset, "head": head}

    def dirty(self) -> bool:
        return self.value is not None and self.value != self.committed

    def commit(self) -> None:
        if self.value is None:
            return
        try:
            self._watermark.commit_live(self.value)
        except OSError as exc:
            # The batch is stored; a lost commit only means re-reading a few lines
            # after the next restart, so keep running.
            log.error("Watermark could not be saved: %s", exc)
            return
        self.committed = Cursor(**self.value)
        self.last_commit = self._clock()


class LiveTailer:
    def __init__(
        self,
        *,
        files: AlertFiles,
        watermark: WatermarkStore,
        writer: BatchWriter,
        dispatch: Callable[[StoredBatch], None],
        counters: IngestCounters,
        plan_ready: threading.Event,
        batching: BatchingConfig,
        clock: Callable[[], float] = time.time,
        idle_commit: float = WATERMARK_IDLE_COMMIT,
        poll_interval: float = POLL_INTERVAL,
        restart_delay: float = RESTART_DELAY,
        store_retry_base: float = STORE_RETRY_BASE,
        store_retry_max: float = STORE_RETRY_MAX,
    ) -> None:
        self._files = files
        self._path = str(files.alerts_log)
        self._watermark = watermark
        self._writer = writer
        self._dispatch = dispatch
        self._counters = counters
        self._plan_ready = plan_ready
        self._min_level = batching.min_level
        self._clock = clock
        self._idle_commit = idle_commit
        self._poll = poll_interval
        self._restart_delay = restart_delay
        self.buffer = LiveBuffer(batching, clock=clock)
        self.cursor = CursorTracker(watermark, clock)
        self._buffer_limit = BACKPRESSURE_FACTOR * batching.batch_max
        self._retry_base = store_retry_base
        self._retry_max = store_retry_max
        self._store_failures = 0  # consecutive failed stores
        self._retry_at = 0.0  # no store attempt before this time while failing
        self._next_failure_log = 0.0
        self._failures_since_log = 0

    # ── alerts → batches ─────────────────────────────────────────────────────
    def _handle_line(self, data: bytes) -> None:
        parsed = parse_alert_line(data, self._min_level)
        if parsed.outcome is LineOutcome.INVALID:
            self._counters.inc("invalid_lines")
            log.debug("Live: dropped a line that is not a valid alert")
            return
        if parsed.outcome is LineOutcome.BELOW_MIN_LEVEL:
            self._counters.inc("skipped")
            return
        if parsed.alert is None:  # blank
            return
        self._counters.inc("processed")
        if self.buffer.add(parsed.alert) and self._store_allowed():
            self.flush()

    def _oversized(self, end: int) -> None:
        self._counters.inc("oversized_lines")
        log.warning(
            "Live: skipped a line of more than the line limit in %s (ends at byte %d)",
            self._path,
            end,
        )

    def _store_allowed(self) -> bool:
        """False while a failed store is backing off (one attempt per backoff step)."""
        return self._store_failures == 0 or self._clock() >= self._retry_at

    def _store_failed(self, count: int) -> None:
        self._store_failures += 1
        delay = min(self._retry_max, self._retry_base * 2.0 ** min(self._store_failures - 1, 16))
        now = self._clock()
        self._retry_at = now + delay
        self.buffer.touch()
        self._failures_since_log += 1
        if now >= self._next_failure_log:
            self._next_failure_log = now + STORE_FAILURE_LOG_INTERVAL
            log.exception(
                "Batch could not be stored (%d failed attempt(s) so far), %d alert(s) stay in"
                " the buffer, next attempt in %gs",
                self._failures_since_log,
                count,
                delay,
            )
            self._failures_since_log = 0

    def flush(self) -> bool:
        """Store the buffered alerts as one batch, then commit the position.

        Returns False when the batch could not be stored: the alerts and the old
        position are kept, and the next attempt waits for the backoff.
        """
        alerts = self.buffer.peek()
        if not alerts:
            return True
        try:
            stored = self._writer.store(alerts, "live")
        except Exception:
            self._store_failed(len(alerts))
            return False
        if self._store_failures:
            log.info("Batch storage works again, %d buffered alert(s) stored", len(alerts))
            self._store_failures = 0
        self.buffer.remove_flushed(len(alerts))
        self._counters.inc("batches_sent")
        self.cursor.commit()
        try:
            self._dispatch(stored)
        except Exception:
            # The batch is stored as `analyzing`; the pipeline re-queues it.
            log.exception("Live: dispatching batch %d failed", stored.batch_id)
        return True

    def _wait_for_room(self, stop: threading.Event) -> bool:
        """Block while the buffer is full because the store keeps failing.

        Returns True when more lines may be read, False when `stop` was set meanwhile.
        """
        while len(self.buffer) >= self._buffer_limit:
            if stop.is_set():
                return False
            if self._store_allowed():
                self.flush()
                continue
            stop.wait(max(0.0, min(self._poll, self._retry_at - self._clock())))
        return True

    # ── the file ─────────────────────────────────────────────────────────────
    def _open_live_log(self, stop: threading.Event) -> BinaryIO | None:
        """Open alerts.json, waiting for it to exist (briefly absent during rotation)."""
        warned = False
        while not stop.is_set():
            try:
                return Path(self._path).open("rb")
            except OSError:
                if not warned:
                    log.warning("Alert log not found: %s - waiting", self._path)
                    warned = True
                stop.wait(1.0)
        return None

    def _plan(self, f: BinaryIO) -> Cursor:
        try:
            return plan_resume(
                f, files=self._files, watermark=self._watermark, counters=self._counters
            )
        except Exception:
            # Never lose the live tailer over a planning problem: start at the end
            # and say so. Nothing is saved, the next start plans again.
            log.exception("Resume planning failed, starting at the end of the log")
            return cursor_at_end(f, self._path)
        finally:
            self._plan_ready.set()

    def tail(self, stop: threading.Event) -> None:
        f = self._open_live_log(stop)
        if f is None:
            return
        log.info("Live: following %s", self._path)
        # Whatever is buffered belongs to a previous run; the position was not
        # moved past it, so the planner reads it again.
        self.buffer.clear()
        try:
            cursor = self._plan(f)
            dev, ino, pos, head = cursor["dev"], cursor["ino"], cursor["offset"], cursor["head"]
            self.cursor.set(self._path, dev, ino, pos, head)
            self.cursor.committed = Cursor(**cursor)
            f.seek(pos)
            skipping = False  # inside a too long line whose end is not written yet

            while not stop.is_set():
                if not self._wait_for_room(stop):
                    break
                if skipping:
                    _, complete = skip_to_newline(f, final=False)
                    if complete:
                        skipping = False
                        pos = f.tell()
                        self.cursor.set(self._path, dev, ino, pos, head)
                        self._oversized(pos)
                        continue
                else:
                    result = read_line(f, final=False)
                    if result.kind is LineKind.LINE:
                        if pos == 0 and head is None:
                            head = line_digest(result.data)
                        pos += result.consumed
                        self.cursor.set(self._path, dev, ino, pos, head)
                        self._handle_line(result.data)
                        continue
                    if result.kind is LineKind.OVERSIZED:
                        if pos == 0 and head is None:
                            head = line_digest(result.data)
                        pos += result.consumed
                        self.cursor.set(self._path, dev, ino, pos, head)
                        self._oversized(pos)
                        continue
                    if result.kind is LineKind.OVERSIZED_OPEN:
                        # Its first bytes are final: the file digest can be taken.
                        if pos == 0 and head is None:
                            head = line_digest(result.data)
                            self.cursor.set(self._path, dev, ino, pos, head)
                        skipping = True
                    elif result.kind is LineKind.PARTIAL:
                        f.seek(pos)  # half-written line: wait for its end

                # No complete new line: check for rotation before sleeping.
                try:
                    disk = os.stat(self._path)  # noqa: PTH116 - plain string path
                    disk_ident: tuple[int, int] | None = ident_of(disk)
                    disk_size = disk.st_size
                except OSError:
                    disk_ident, disk_size = None, 0

                if disk_ident != (dev, ino):
                    # The path no longer points at our inode, or is missing for a
                    # moment. Look at what is there before calling it a rotation.
                    new_f = self._open_live_log(stop)
                    if new_f is None:
                        return
                    st = os.fstat(new_f.fileno())
                    same_file = ident_of(st) == (dev, ino) or (
                        head is not None
                        and st.st_size >= pos
                        and first_line_digest(new_f, closed=False) == head
                    )
                    if same_file:
                        log.info(
                            "alerts.json changed its inode but holds the same file:"
                            " no rotation, continuing at the saved position"
                        )
                        scan = f.tell()
                        f.close()
                        f, dev, ino = new_f, st.st_dev, st.st_ino
                        f.seek(scan if skipping else pos)
                        self.cursor.set(self._path, dev, ino, pos, head)
                        continue
                    log.info(
                        "Log rotation detected (inode %d -> %d): reading the old file"
                        " to its end from byte %d",
                        ino,
                        st.st_ino,
                        pos,
                    )
                    pos = self._drain_rotated(f, dev, ino, pos, head, skipping, stop)
                    skipping = False
                    f.close()
                    f = new_f
                    f.seek(0)
                    dev, ino, pos, head = st.st_dev, st.st_ino, 0, None
                    self.cursor.set(self._path, dev, ino, pos, head)
                    log.info("Live: reopened %s (inode %d), reading from byte 0", self._path, ino)
                    continue

                known = f.tell() if skipping else pos
                if disk_size < known:
                    log.warning(
                        "%s was truncated (%d -> %d bytes): reading it from the start",
                        self._path,
                        known,
                        disk_size,
                    )
                    f.seek(0)
                    pos, head, skipping = 0, None, False
                    self.cursor.set(self._path, dev, ino, pos, head)
                    continue

                # Truly no data: sleep, maybe flush, maybe persist the position.
                stop.wait(self._poll)
                if len(self.buffer):
                    if self._store_failures:
                        if self._store_allowed():
                            self.flush()  # retry the failed store
                    elif self.buffer.is_due():
                        log.info("Timeout flush: %d alerts", len(self.buffer))
                        self.flush()
                elif (
                    self.cursor.dirty()
                    and self._clock() - self.cursor.last_commit >= self._idle_commit
                ):
                    self.cursor.commit()
        finally:
            f.close()

    def _drain_rotated(
        self,
        f: BinaryIO,
        dev: int,
        ino: int,
        pos: int,
        head: str | None,
        skipping: bool,
        stop: threading.Event,
    ) -> int:
        """Read a rotated file to its end; the writer is gone, so an unterminated
        last line counts. Returns the final position."""
        if skipping:
            skip_to_newline(f, final=True)
            pos = f.tell()
            self.cursor.set(self._path, dev, ino, pos, head)
            self._oversized(pos)
        while True:
            if not self._wait_for_room(stop):
                return pos
            result = read_line(f, final=True)
            if result.kind is LineKind.EOF:
                return pos
            pos += result.consumed
            self.cursor.set(self._path, dev, ino, pos, head)
            if result.kind is LineKind.LINE:
                self._handle_line(result.data)
            else:
                self._oversized(pos)

    def run(self, stop: threading.Event) -> None:
        """`tail` under supervision: an unexpected error must not leave the service
        running without anyone watching the log."""
        while not stop.is_set():
            try:
                self.tail(stop)
                return
            except Exception:
                log.exception("Live tailer crashed, restarting in %gs", self._restart_delay)
                stop.wait(self._restart_delay)
