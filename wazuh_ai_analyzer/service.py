"""The running service: startup order, thread supervision and a clean stop.

Startup order (that of `analyzer.py`):

0. the instance lock (`<data dir>/.lock`): a second service on the same data
   directory exits with an error before it touches anything;
1. data directory and database: create/migrate, tighten the modes;
2. the analysis backend for `ANALYSIS_MODE`;
3. re-queue every `analyzing` batch (a restart killed whatever was in flight);
4. `Ingest` (created only now, so its first batches cannot be swept by step 3)
   and `Ingest.load()` for `watermark.json`;
5. threads: live workers, `history` (backlog), `live` (tail), `retry` (queue and
   retention).

`stop()` (SIGTERM/SIGINT through `__main__`) sets one event that every loop waits
on. Each batch in flight is then either stored or put back to `pending`; a
request that does not return within the grace period leaves its row `analyzing`,
which the next start re-queues. A transaction is never half-written.

If a worker thread dies, the service stops with a failure exit code so systemd
restarts it, instead of running on without anyone watching the log.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Final

from .analysis import AnalysisBackend, create_backend
from .config import Config
from .ingest import Ingest
from .instance_lock import InstanceLock
from .logging_setup import RedactSecrets
from .metrics.runtime import runtime_counters
from .permissions import heal_database_files, prepare_data_dir
from .pipeline import Pipeline
from .storage.db import Database
from .storage.repo import Repository
from .storage.schema import migrate

log = logging.getLogger(__name__)

# How long the stop waits for threads; below systemd's default TimeoutStopSec (90 s).
STOP_GRACE_SECONDS: Final = 30.0
SUPERVISE_INTERVAL: Final = 1.0

BackendFactory = Callable[[Config], AnalysisBackend]


class Service:
    def __init__(
        self,
        config: Config,
        *,
        backend_factory: BackendFactory = create_backend,
        stop: threading.Event | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.stop_event = stop if stop is not None else threading.Event()
        prepare_data_dir(config.paths.data_dir)
        self._lock = InstanceLock(config.paths.data_dir)
        self._lock.acquire()
        try:
            self._init(config, backend_factory, clock)
        except BaseException:
            self._lock.release()
            raise

    def _init(
        self, config: Config, backend_factory: BackendFactory, clock: Callable[[], float]
    ) -> None:
        db = Database(config.paths.db_path)
        result = migrate(db)
        heal_database_files(config.paths.db_path)
        if result.applied:
            log.info("Database migrated: version %d -> %d", result.from_version, result.to_version)
        self.repo = Repository(db, clock=clock)
        self.backend = backend_factory(config)
        self.pipeline = Pipeline(
            config,
            self.repo,
            self.backend,
            stop=self.stop_event,
            scrub=RedactSecrets(config.secret_values()).scrub,
            clock=clock,
        )
        self.pipeline.requeue_stale(0)
        self.ingest = Ingest(
            config,
            self.repo,
            dispatch=self.pipeline.dispatch,
            analyse=self.pipeline.analyse,
            stop=self.stop_event,
            gate=self.pipeline.gate_wait,
            clock=clock,
        )
        self.ingest.load()
        self._threads: list[threading.Thread] = []
        self.failed = False

    def start(self) -> None:
        self.pipeline.start()
        for name, target in (
            ("history", self.ingest.history_worker),
            ("live", self.ingest.live_watcher),
            ("retry", self.pipeline.run_retry_worker),
        ):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        self._log_settings()

    def stop(self) -> None:
        self.stop_event.set()

    def wait(self) -> None:
        """Block until `stop()`, supervising the worker threads meanwhile."""
        while not self.stop_event.wait(SUPERVISE_INTERVAL):
            dead = [t.name for t in self._threads if not t.is_alive()]
            if dead:
                log.error("Worker thread(s) %s ended unexpectedly, stopping", ", ".join(dead))
                self.failed = True
                self.stop_event.set()

    def shutdown(self, grace: float = STOP_GRACE_SECONDS) -> bool:
        """Stop everything; True if every thread ended within `grace` seconds."""
        self.stop_event.set()
        deadline = time.monotonic() + grace
        for thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        clean = self.pipeline.shutdown(max(0.0, deadline - time.monotonic()))
        self._lock.release()
        hanging = [t.name for t in self._threads if t.is_alive()]
        if hanging or not clean:
            log.warning(
                "Stopped with work in flight (%s); it is re-queued at the next start",
                ", ".join(hanging) or "live workers",
            )
            return False
        log.info("Stopped cleanly")
        return True

    def runtime(self) -> dict[str, int | bool]:
        """The `runtime` block of `/api/stats`."""
        return runtime_counters(self.ingest.stats(), self.pipeline.counters.snapshot())

    def _log_settings(self) -> None:
        c = self.config
        if c.gemini.api_key is None:
            log.warning("No Gemini API key configured: batches stay queued until one is set")
        b = c.batching
        log.info(
            "Batch: %d alerts / %ds timeout (%ds below level %d) | min level %d",
            b.batch_max,
            b.batch_timeout,
            b.effective_quiet_timeout,
            b.urgent_level,
            b.min_level,
        )
        log.info("History: %d alerts per batch | %gs pause", b.history_batch, b.history_pause)
        log.info(
            "Analysis: mode %s, model %s, %d parallel request(s)",
            self.backend.name,
            c.gemini.model,
            c.gemini.concurrency,
        )
        if c.retention.days > 0:
            log.info(
                "Retention: done/error batches and findings older than %g days are deleted"
                " (checked every %gs)",
                c.retention.days,
                c.retention.interval,
            )
        else:
            log.info("Retention: disabled (RETENTION_DAYS=0), analyses.db grows without limit")
