"""The backlog worker: catches up on whatever the watermark says is still unread.

Segments (rest of a rotated file, days of downtime, the history at first start)
are read oldest first, in batches of `HISTORY_BATCH` with a pause of
`HISTORY_PAUSE` seconds between them, and each batch waits for the upstream gate
(quota or failure backoff) before it is stored. Order per batch:

1. store the batch (`analyzing`),
2. move the segment's offset past it in `watermark.json`,
3. hand it to the analysis (synchronously: that is the pacing).

A crash between 1 and 2 re-reads that one batch after the restart (it is stored
twice, nothing is lost); a crash before 1 loses nothing either. A file that
cannot be read is retried `SEGMENT_MAX_READ_FAILURES` times before the segment is
given up.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final, Literal

from ..config import BatchingConfig
from .archives import READ_ERRORS, AlertFiles, file_head_digest, open_alert_file
from .batches import BatchWriter, StoredBatch
from .counters import IngestCounters
from .lines import LineKind, read_line
from .parse import Alert, LineOutcome, parse_alert_line
from .watermark import Segment, WatermarkStore

log = logging.getLogger(__name__)

SEGMENT_MAX_READ_FAILURES: Final = 5
SEGMENT_RETRY_DELAY: Final = 60.0
IDLE_POLL: Final = 5.0
ERROR_PAUSE: Final = 30.0
GATE_POLL_MAX: Final = 120.0

SegmentOutcome = Literal["done", "retry", "stopped"]


class _Stopped(Exception):
    """The stop event was set while waiting: unwind without finishing the segment."""


def open_gate() -> float:
    """Default upstream gate: never closed."""
    return 0.0


class BacklogWorker:
    def __init__(
        self,
        *,
        files: AlertFiles,
        watermark: WatermarkStore,
        writer: BatchWriter,
        analyse: Callable[[StoredBatch], None],
        counters: IngestCounters,
        plan_ready: threading.Event,
        batching: BatchingConfig,
        stop: threading.Event,
        gate: Callable[[], float] = open_gate,
        clock: Callable[[], float] = time.time,
        retry_delay: float = SEGMENT_RETRY_DELAY,
    ) -> None:
        self._files = files
        self._watermark = watermark
        self._writer = writer
        self._analyse = analyse
        self._counters = counters
        self._plan_ready = plan_ready
        self._batching = batching
        self._stop = stop
        self._gate = gate
        self._clock = clock
        self._retry_delay = retry_delay
        self._failures: dict[int, int] = {}

    # ── locating ─────────────────────────────────────────────────────────────
    def locate(self, seg: Segment) -> Path | None:
        """The file a segment refers to, or None.

        Normally `seg["path"]`. It may have been compressed since, and a segment of
        alerts.json outlives midnight: the path then holds the next day's file and
        the wanted one is in the archive. Whatever is found must carry the
        first-line digest recorded with the segment and lie below the alerts
        directory (a tampered watermark must not make us read other files).
        """
        path = seg["path"]
        twin = path[:-3] if path.endswith(".gz") else path + ".gz"
        for candidate in (path, twin):
            if not os.path.exists(candidate):  # noqa: PTH110 - plain string paths
                continue
            if not self._files.is_confined(candidate):
                log.warning("Backlog: %s is outside the alerts directory, not read", candidate)
                continue
            if seg["head"] is None or file_head_digest(candidate) == seg["head"]:
                return Path(candidate)
        if seg["head"] is not None:
            found = self._files.find_previous_file(seg["head"], self._clock())
            if found is not None:
                return found[0]
        return None

    # ── reading ──────────────────────────────────────────────────────────────
    def _wait_for_gate(self) -> None:
        while True:
            remaining = self._gate()
            if remaining <= 0:
                return
            log.info("Backlog: waiting for the upstream gate (%ds left)", int(remaining))
            if self._stop.wait(min(remaining + 2, GATE_POLL_MAX)):
                raise _Stopped

    def _send(self, seg_id: int, alerts: list[Alert], offset: int) -> None:
        self._wait_for_gate()
        stored = self._writer.store(alerts, "history")
        try:
            self._watermark.advance_segment(seg_id, offset)
        except OSError as exc:
            # A full disk is not a read error of the segment. The next successful
            # save carries the newer offset; only a crash before that re-reads.
            log.error("Watermark could not be saved: %s", exc)
        try:
            self._analyse(stored)
        except Exception:
            # The batch is stored as `analyzing`; the pipeline re-queues it.
            log.exception("Backlog: analysis of batch %d failed", stored.batch_id)

    def process_segment(self, seg: Segment) -> SegmentOutcome:
        seg_id = seg.get("id", 0)
        path = self.locate(seg)
        if path is None:
            log.warning("Backlog: %s can no longer be found, skipped", seg["path"])
            return "done"
        offset, end = seg["offset"], seg["end"]
        log.info("Backlog: %s (from byte %d%s)", path, offset, "" if end is None else f" to {end}")
        buf: list[Alert] = []
        count = 0
        min_level = self._batching.min_level
        try:
            with open_alert_file(path) as f:
                f.seek(offset)
                while end is None or offset < end:
                    if self._stop.is_set():
                        return "stopped"
                    result = read_line(f, final=True)
                    if result.kind is LineKind.EOF:
                        break
                    offset += result.consumed
                    if result.kind is not LineKind.LINE:
                        self._counters.inc("oversized_lines")
                        log.warning(
                            "Backlog: skipped a line of more than the line limit in %s"
                            " (ends at byte %d)",
                            path,
                            offset,
                        )
                        continue
                    parsed = parse_alert_line(result.data, min_level)
                    if parsed.outcome is LineOutcome.INVALID:
                        self._counters.inc("invalid_lines")
                        continue
                    if parsed.alert is None:
                        continue
                    buf.append(parsed.alert)
                    count += 1
                    self._counters.inc("history_alerts")
                    if len(buf) >= self._batching.history_batch:
                        self._send(seg_id, buf, offset)
                        buf = []
                        if self._stop.wait(self._batching.history_pause):
                            return "stopped"
                if buf:
                    self._send(seg_id, buf, offset)
        except _Stopped:
            return "stopped"
        except READ_ERRORS as exc:
            log.error("Backlog: error reading %s: %s", path, exc)
            return "retry"
        log.info("Backlog: %s done (%d alerts from byte %d)", path, count, seg["offset"])
        return "done"

    def run_once(self) -> bool:
        """Work on the oldest backlog segment. False if there is none."""
        seg = self._watermark.first_segment()
        if seg is None:
            if self._plan_ready.is_set():
                self._counters.set_history_done(True)
            return False
        seg_id = seg.get("id", 0)
        self._counters.set_history_done(False)
        outcome = self.process_segment(seg)
        if outcome == "stopped":
            return True
        if outcome == "retry":
            failures = self._failures[seg_id] = self._failures.get(seg_id, 0) + 1
            if failures < SEGMENT_MAX_READ_FAILURES:
                self._stop.wait(self._retry_delay)
                return True
            log.error("Backlog: %s given up after %d read errors", seg["path"], failures)
        self._failures.pop(seg_id, None)
        self._watermark.finish_segment(seg_id)
        self._counters.inc("history_files_done")
        if self._watermark.first_segment() is None:
            self._counters.set_history_done(True)
            log.info(
                "Backlog finished: %d alerts processed", self._counters.snapshot().history_alerts
            )
        return True

    def run(self) -> None:
        """Runs until the stop event is set."""
        while not self._stop.is_set():
            try:
                if not self.run_once():
                    self._stop.wait(IDLE_POLL)
            except Exception:
                log.exception("Backlog: unexpected error")
                self._stop.wait(ERROR_PAUSE)
