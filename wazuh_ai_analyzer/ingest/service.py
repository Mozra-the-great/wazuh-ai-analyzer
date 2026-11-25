"""Wiring of the ingest layer: one watermark, one tailer, one backlog worker.

The pipeline (#85) creates an `Ingest`, calls `load()` once at startup (after the
database migration and the stale-batch requeue) and runs `live_watcher` and
`history_worker` in their own threads with a shared stop event.

* `dispatch(batch)` receives every stored live batch. It runs on the tailer
  thread, so it must hand the batch off (to a worker or queue) and return.
* `analyse(batch)` receives every stored backlog batch and may block: the backlog
  is paced by it, like the legacy code that analysed history batches inline.
* `gate()` returns the seconds until the upstream (quota / failure backoff)
  accepts requests again; the backlog waits for it before storing a batch.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from ..config import Config
from ..storage.repo import Repository
from .archives import AlertFiles
from .backlog import BacklogWorker, open_gate
from .batches import BatchWriter, StoredBatch
from .counters import IngestCounters, IngestStats
from .live import LiveTailer
from .watermark import WatermarkStore


class Ingest:
    def __init__(
        self,
        config: Config,
        repo: Repository,
        *,
        dispatch: Callable[[StoredBatch], None],
        analyse: Callable[[StoredBatch], None],
        stop: threading.Event,
        gate: Callable[[], float] = open_gate,
        clock: Callable[[], float] = time.time,
    ) -> None:
        batching = config.batching
        self.files = AlertFiles(config.paths.alerts_log)
        self.watermark = WatermarkStore(config.paths.watermark_file, clock=clock)
        self.counters = IngestCounters()
        self.plan_ready = threading.Event()
        self.stop = stop
        writer = BatchWriter(repo, mode=config.analysis.mode)
        self.live = LiveTailer(
            files=self.files,
            watermark=self.watermark,
            writer=writer,
            dispatch=dispatch,
            counters=self.counters,
            plan_ready=self.plan_ready,
            batching=batching,
            clock=clock,
        )
        self.backlog = BacklogWorker(
            files=self.files,
            watermark=self.watermark,
            writer=writer,
            analyse=analyse,
            counters=self.counters,
            plan_ready=self.plan_ready,
            batching=batching,
            stop=stop,
            gate=gate,
            clock=clock,
        )

    def load(self) -> None:
        """Read `watermark.json` (never raises for bad content)."""
        self.watermark.load()

    def live_watcher(self) -> None:
        self.live.run(self.stop)

    def history_worker(self) -> None:
        self.backlog.run()

    def buffered_alerts(self) -> int:
        return len(self.live.buffer)

    def stats(self) -> IngestStats:
        return self.counters.snapshot()
