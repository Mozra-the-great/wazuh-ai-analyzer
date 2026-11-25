"""From alerts to a stored batch, and when a part-filled live batch is due.

A batch is stored as `analyzing` *before* any analysis starts (through
`Repository.insert_batch`): from then on it survives a restart, it is either
finished or re-queued by the pipeline. Only after that does the ingest move its
watermark past the alerts in it, so a crash re-reads but never loses (#43, #44).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ..config import BatchingConfig
from ..storage.contract import AnalysisMode, Source
from ..storage.repo import Repository
from .parse import Alert, urgency_level
from .sanitize import AlertGroup, group_alerts


@dataclass(frozen=True, slots=True)
class StoredBatch:
    """A batch that is in the database (status `analyzing`) and ready for analysis."""

    batch_id: int
    groups: list[AlertGroup]
    source: Source
    alert_count: int


class BatchWriter:
    """Groups and sanitises alerts and stores them as one batch."""

    def __init__(self, repo: Repository, *, mode: AnalysisMode = "llm") -> None:
        self._repo = repo
        self._mode: AnalysisMode = mode

    def store(self, alerts: Sequence[Alert], source: Source) -> StoredBatch:
        groups = group_alerts(alerts)
        batch_id = self._repo.insert_batch(
            alert_count=len(alerts),
            raw_groups=json.dumps(groups),
            source=source,
            mode=self._mode,
        )
        return StoredBatch(batch_id=batch_id, groups=groups, source=source, alert_count=len(alerts))


def flush_timeout(buffered: Sequence[Alert], batching: BatchingConfig) -> int:
    """How long a part-filled live batch may wait since the last flush.

    `BATCH_TIMEOUT` if any buffered alert is urgent (level >= `URGENT_LEVEL`), else
    the quiet window `max(BATCH_TIMEOUT_QUIET, BATCH_TIMEOUT)`.
    """
    for alert in buffered:
        if urgency_level(alert) >= batching.urgent_level:
            return batching.batch_timeout
    return batching.effective_quiet_timeout


class LiveBuffer:
    """Alerts of the live log that are read but not stored in a batch yet.

    Only the tailer thread adds and takes; other threads may read the size.
    """

    def __init__(self, batching: BatchingConfig, *, clock: Callable[[], float] = time.time) -> None:
        self._batching = batching
        self._clock = clock
        self._lock = threading.Lock()
        self._alerts: list[Alert] = []
        self.last_flush = clock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._alerts)

    def add(self, alert: Alert) -> bool:
        """Buffer an alert; True when the batch is full (`BATCH_MAX`)."""
        with self._lock:
            self._alerts.append(alert)
            return len(self._alerts) >= self._batching.batch_max

    def peek(self) -> list[Alert]:
        with self._lock:
            return list(self._alerts)

    def remove_flushed(self, count: int) -> None:
        """Drop the first `count` alerts after they were stored, and restart the window."""
        with self._lock:
            del self._alerts[:count]
        self.touch()

    def touch(self) -> None:
        """Restart the flush window (also after a failed store, like the legacy code)."""
        self.last_flush = self._clock()

    def clear(self) -> None:
        with self._lock:
            self._alerts.clear()

    def is_due(self) -> bool:
        """True if the buffer is not empty and its flush window has passed."""
        with self._lock:
            if not self._alerts:
                return False
            timeout = flush_timeout(self._alerts, self._batching)
        return self._clock() - self.last_flush >= timeout
