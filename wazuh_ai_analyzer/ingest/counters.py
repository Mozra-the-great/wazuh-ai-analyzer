"""Runtime counters of the ingest layer (shown by `/api/stats` from #86 on)."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass
from typing import Literal

CounterName = Literal[
    "processed",
    "skipped",
    "invalid_lines",
    "oversized_lines",
    "batches_sent",
    "history_alerts",
    "history_files_total",
    "history_files_done",
]


@dataclass(slots=True)
class IngestStats:
    """A consistent copy of the counters.

    `processed`, `skipped`, `batches_sent`, `history_*` keep the names and meaning
    of the legacy `runtime` block. `invalid_lines` (not a JSON object, broken
    nesting, a level that is not a number) and `oversized_lines` (longer than
    `ALERT_LINE_MAX`) are new: the legacy code dropped such lines silently.
    """

    processed: int = 0
    skipped: int = 0
    invalid_lines: int = 0
    oversized_lines: int = 0
    batches_sent: int = 0
    history_alerts: int = 0
    history_files_total: int = 0
    history_files_done: int = 0
    history_done: bool = False

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


class IngestCounters:
    """Thread-safe counters shared by the live tailer and the backlog worker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stats = IngestStats()

    def inc(self, name: CounterName, n: int = 1) -> None:
        with self._lock:
            setattr(self._stats, name, getattr(self._stats, name) + n)

    def set_history_done(self, done: bool) -> None:
        with self._lock:
            self._stats.history_done = done

    def snapshot(self) -> IngestStats:
        with self._lock:
            return IngestStats(**asdict(self._stats))
