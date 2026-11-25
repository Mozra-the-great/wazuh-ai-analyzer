"""Runtime counters of the pipeline (part of the `runtime` block of `/api/stats`).

Every final failure ends in exactly one of `dropped_permanent`,
`dropped_bad_response` or `expired`, and in `errors`, so `errors` can always be
explained. The names are those of `analyzer.py`.
"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass
from typing import Literal

CounterName = Literal[
    "errors",
    "retries_scheduled",
    "retries_succeeded",
    "recovered_stale",
    "dropped_permanent",
    "dropped_bad_response",
    "expired",
    "suspicious_downgrades",
    "purged_batches",
]
DropCounter = Literal["dropped_permanent", "dropped_bad_response", "expired"]


@dataclass(slots=True)
class PipelineStats:
    errors: int = 0
    retries_scheduled: int = 0
    retries_succeeded: int = 0
    recovered_stale: int = 0
    dropped_permanent: int = 0
    dropped_bad_response: int = 0
    expired: int = 0
    # The model rated a rule of level >= 12 as info/low (#38): flagged, never changed.
    suspicious_downgrades: int = 0
    # Batches deleted by the retention cleanup (RETENTION_DAYS).
    purged_batches: int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


class PipelineCounters:
    """Thread-safe counters shared by the live workers, the backlog and the retry worker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stats = PipelineStats()

    def inc(self, name: CounterName, n: int = 1) -> int:
        """Add `n`; returns the new value."""
        with self._lock:
            value: int = getattr(self._stats, name) + n
            setattr(self._stats, name, value)
            return value

    def snapshot(self) -> PipelineStats:
        with self._lock:
            return PipelineStats(**asdict(self._stats))
