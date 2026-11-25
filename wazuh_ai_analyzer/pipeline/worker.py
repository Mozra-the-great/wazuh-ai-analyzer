"""The analysis pipeline: attempts, the persistent retry queue and its workers (#43, #85).

A batch is in the database (status `analyzing`) before the pipeline sees it. From
there every attempt ends in exactly one of three states, each written in one
transaction:

* `done`    the result and its findings are stored;
* `pending` queued for a later attempt (`next_attempt`), with the retry bookkeeping;
* `error`   a final failure, counted and logged, with a `last_error` built by
            `storage.contract` (the homelab exporter classifies these texts).

If the process dies in between, the row stays `analyzing`; the startup requeue
(`requeue_stale(0)`) and the runtime sweep put it back into the queue. Nothing is
ever half-written and no batch is dropped for a 5xx, a timeout or a connection error.

Threads:

* live batches come from the tailer through `dispatch()`, which only queues them;
  `GEMINI_CONCURRENCY` live workers run the attempts;
* backlog batches come through `analyse()`, which blocks (the backlog is paced by it);
* the retry worker (`run_retry_worker`) drains the queue, expires old rows and runs
  the retention.

All attempts share one semaphore of `GEMINI_CONCURRENCY` slots and the two gates.
"""

from __future__ import annotations

import json
import logging
import queue
import random
import threading
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Final

from ..analysis.backend import AnalysisBackend, BackendFailure, BatchContext
from ..config import Config
from ..ingest.batches import StoredBatch
from ..ingest.sanitize import AlertGroup, sanitize_group
from ..storage import contract
from ..storage.contract import Source
from ..storage.repo import Repository
from ..storage.retention import RetentionPurger
from .counters import DropCounter, PipelineCounters
from .gates import Jitter, QuotaState, UpstreamState, backoff_delay

log = logging.getLogger(__name__)

# Consecutive batches dropped as `permanent`. One poisoned payload hits one batch;
# many in a row mean the request itself is wrong (key, region, model), and the
# queue must not be emptied into the error state.
PERMANENT_STREAK_LIMIT: Final = 3
SECONDS_PER_HOUR: Final = 3600.0
INTERNAL_ERROR_PREFIX: Final = "interner Fehler"


def parse_iso(value: str | None) -> float:
    """ISO timestamp -> epoch seconds; 0.0 for anything unparseable."""
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return 0.0


def groups_from_json(raw_groups: str) -> list[AlertGroup] | None:
    """The stored groups, sanitised again (older versions stored them uncleaned).

    None when `raw_groups` is not a JSON array.
    """
    try:
        parsed = json.loads(raw_groups)
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, list):
        return None
    return [sanitize_group(g) for g in parsed if isinstance(g, dict)]


class Pipeline:
    def __init__(
        self,
        config: Config,
        repo: Repository,
        backend: AnalysisBackend,
        *,
        stop: threading.Event,
        scrub: Callable[[str], str],
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        jitter: Jitter = random.uniform,
    ) -> None:
        self._retry = config.retry
        self._repo = repo
        self._backend = backend
        self._stop = stop
        self._scrub = scrub
        self._clock = clock
        self._jitter = jitter
        self.counters = PipelineCounters()
        self.quota = QuotaState(clock=clock)
        self.upstream = UpstreamState(
            base_delay=config.retry.base_delay,
            max_delay=config.retry.max_delay,
            clock=clock,
            jitter=jitter,
        )
        self.purger = RetentionPurger(
            repo,
            days=config.retention.days,
            interval=config.retention.interval,
            chunk=config.retention.chunk,
            monotonic=monotonic,
        )
        self._slots = threading.BoundedSemaphore(config.gemini.concurrency)
        self._concurrency = config.gemini.concurrency
        # Batch ids a thread of this process works on right now. The stale sweep
        # must not requeue those, or a slow request would be sent twice.
        self._inflight: set[int] = set()
        self._inflight_lock = threading.Lock()
        self._streak = 0
        self._streak_lock = threading.Lock()
        self._live: queue.Queue[StoredBatch | None] = queue.Queue()
        self._live_workers: list[threading.Thread] = []
        self._accepting = True
        self._accept_lock = threading.Lock()

    # ── gates ────────────────────────────────────────────────────────────────
    def gate_wait(self) -> float:
        """Seconds until the backend may be contacted again: the longer of the quota
        backoff and the transient-failure backoff."""
        return max(self.quota.wait_seconds(), self.upstream.wait_seconds())

    def inflight(self) -> frozenset[int]:
        with self._inflight_lock:
            return frozenset(self._inflight)

    def _backoff(self, attempt: int) -> float:
        return backoff_delay(
            attempt, base=self._retry.base_delay, maximum=self._retry.max_delay, jitter=self._jitter
        )

    # ── entry points of the ingest layer ─────────────────────────────────────
    def start(self) -> None:
        """Start the live workers (idempotent)."""
        if self._live_workers:
            return
        for n in range(self._concurrency):
            worker = threading.Thread(
                target=self._live_worker, name=f"analysis-live-{n}", daemon=True
            )
            worker.start()
            self._live_workers.append(worker)

    def dispatch(self, batch: StoredBatch) -> None:
        """Hand a stored live batch to a live worker. Returns at once (tailer thread)."""
        with self._accept_lock:
            if self._accepting:
                self._mark_inflight(batch.batch_id)
                self._live.put(batch)
                return
        # Stopping: queue it in the database instead; the next start picks it up.
        self._requeue_now(batch.batch_id)

    def analyse(self, batch: StoredBatch) -> None:
        """Run one attempt for a stored backlog batch; blocks until it is settled."""
        self.run_attempt(batch.batch_id, batch.groups, batch.source)

    def _live_worker(self) -> None:
        while True:
            batch = self._live.get()
            if batch is None:
                return
            try:
                if self._stop.is_set():
                    self._requeue_now(batch.batch_id)
                else:
                    self.run_attempt(batch.batch_id, batch.groups, batch.source)
            except Exception:
                log.exception("Live worker: batch %d could not be settled", batch.batch_id)
            finally:
                self._discard_inflight(batch.batch_id)

    def _mark_inflight(self, batch_id: int) -> None:
        with self._inflight_lock:
            self._inflight.add(batch_id)

    def _discard_inflight(self, batch_id: int) -> None:
        with self._inflight_lock:
            self._inflight.discard(batch_id)

    def _requeue_now(self, batch_id: int) -> None:
        try:
            self._repo.defer_batch(batch_id, next_attempt=self._clock())
        except Exception:
            # The row stays `analyzing`; the startup requeue picks it up.
            log.exception("Batch %d could not be queued", batch_id)

    # ── one attempt ──────────────────────────────────────────────────────────
    def run_attempt(
        self,
        batch_id: int,
        groups: Sequence[AlertGroup],
        source: Source,
        *,
        is_retry: bool = False,
    ) -> None:
        """One analysis attempt for a stored batch.

        Whatever happens, the batch ends up `done`, `pending` or `error` (counted),
        or, if the database itself fails, stays `analyzing` for the stale sweep.
        """
        self._mark_inflight(batch_id)
        try:
            failure: BackendFailure | None = None
            with self._slots:
                wait = self.gate_wait()
                if wait > 0 or self._stop.is_set():
                    # Another request just failed, the quota is empty or the service
                    # is stopping: do not send, park without using up an attempt.
                    self._repo.defer_batch(batch_id, next_attempt=self._clock() + wait)
                    log.info(
                        "Batch %d deferred (%ds): %s",
                        batch_id,
                        int(wait),
                        "service is stopping" if wait <= 0 else "upstream gate closed",
                    )
                    return
                context = BatchContext(batch_id=batch_id, source=source, is_retry=is_retry)
                try:
                    result = self._backend.analyse(groups, context)
                except BackendFailure as exc:
                    failure = exc
                    self._note_failure(exc)
                else:
                    self.quota.mark_success()
                    self.upstream.mark_success()
            if failure is not None:
                self.handle_failure(batch_id, failure)
                return
            if result.suspicious_downgrades:
                self.counters.inc("suspicious_downgrades", result.suspicious_downgrades)
            log.info(
                "[%s] Batch %d: risk=%s | %d findings",
                "retry" if is_retry else source,
                batch_id,
                result.overall_risk,
                len(result.findings),
            )
            self._repo.complete_batch(
                batch_id,
                summary=result.summary,
                overall_risk=result.overall_risk,
                findings=result.findings,
                mode=result.mode,
                decision_version=result.decision_version,
            )
            with self._streak_lock:
                self._streak = 0
            if is_retry:
                self.counters.inc("retries_succeeded")
        except Exception as exc:
            log.exception("Batch %d: unexpected error", batch_id)
            try:
                self.handle_failure(
                    batch_id, BackendFailure("bad_response", f"{INTERNAL_ERROR_PREFIX}: {exc!r}")
                )
            except Exception:
                # The database itself is failing; the row is still `analyzing` and
                # the stale sweep re-queues it once the database is back.
                log.exception("Batch %d: could not be queued", batch_id)
        finally:
            self._discard_inflight(batch_id)

    def _note_failure(self, failure: BackendFailure) -> None:
        """Gate bookkeeping that the legacy code did while the request slot was held."""
        if failure.kind == "quota":
            self.quota.mark_exhausted(self._scrub(failure.message), failure.retry_after)
            self.upstream.mark_success()  # the API answered, only the quota is empty
        elif failure.kind == "permanent":
            self.upstream.mark_success()  # reachable, this payload is the problem

    def handle_failure(self, batch_id: int, failure: BackendFailure) -> None:
        """Decide between `pending` (with backoff) and a final, counted `error`."""
        now = self._clock()
        message = self._scrub(failure.message)[: contract.LAST_ERROR_MESSAGE_MAX]
        state = self._repo.retry_state(batch_id)
        attempts = (state.attempts if state else 0) + 1
        first_error_at = state.first_error_at if state else None
        bad_responses = state.bad_responses if state else 0
        kind = failure.kind

        if kind == "permanent":
            with self._streak_lock:
                self._streak += 1
                streak = self._streak
            if streak >= PERMANENT_STREAK_LIMIT:
                log.error(
                    "%d batches in a row with a permanent error, the configuration is"
                    " probably wrong; batch %d is kept",
                    streak,
                    batch_id,
                )
                kind = "config"
            else:
                self.drop(
                    batch_id, contract.error_permanent(message), "dropped_permanent", attempts
                )
                return
        else:
            with self._streak_lock:
                self._streak = 0

        if kind == "quota":
            # Waiting for the quota reset is not a failure of the batch: it keeps its
            # place for as long as it takes, and the API answered, so an earlier
            # outage no longer counts towards the expiry.
            next_attempt = max(self.quota.retry_at or now, now)
            self._repo.set_pending(
                batch_id,
                next_attempt=next_attempt,
                message=message,
                attempts=attempts,
                first_error_at=None,
                bad_responses=bad_responses,
            )
            self.counters.inc("retries_scheduled")
            log.warning(
                "Batch %d paused for the quota (again in %ds)", batch_id, int(next_attempt - now)
            )
            return

        if kind == "bad_response":
            bad_responses += 1
            if bad_responses >= self._retry.bad_response_max:
                self.drop(
                    batch_id,
                    contract.error_bad_response(bad_responses, message),
                    "dropped_bad_response",
                    attempts,
                )
                return
        else:  # transient / config
            started = parse_iso(first_error_at) or now
            max_age = self._retry.max_age_hours
            if now - started > max_age * SECONDS_PER_HOUR:
                self.drop(
                    batch_id,
                    contract.error_unanalyzable(max_age, kind, message),
                    "expired",
                    attempts,
                )
                return
            if first_error_at is None:
                first_error_at = contract.iso_utc(now)
            self.upstream.mark_failure(message, failure.retry_after)

        next_attempt = now + max(self._backoff(attempts), self.upstream.wait_seconds())
        self._repo.set_pending(
            batch_id,
            next_attempt=next_attempt,
            message=message,
            attempts=attempts,
            first_error_at=first_error_at,
            bad_responses=bad_responses,
        )
        self.counters.inc("retries_scheduled")
        log.warning(
            "Batch %d: %s (%s), attempt %d, again in %ds",
            batch_id,
            kind,
            message,
            attempts,
            int(next_attempt - now),
        )

    def drop(self, batch_id: int, reason: str, counter: DropCounter, attempts: int = 0) -> None:
        """Final failure. Always logged and counted: dropping must never be silent."""
        self._repo.fail_batch(batch_id, reason=reason, attempts=attempts)
        self.counters.inc("errors")
        total = self.counters.inc(counter)
        log.error("Batch %d dropped (%s=%d): %s", batch_id, counter, total, reason)

    # ── the queue ────────────────────────────────────────────────────────────
    def requeue_stale(self, older_than: float) -> int:
        """Put `analyzing` batches nobody works on back into the queue.

        A restart kills every request in flight, so at startup `older_than` is 0 and
        all of them qualify; at runtime the in-flight set protects live requests.
        """
        ids = self._repo.requeue_stale(
            claimed_before=self._clock() - older_than, busy=self.inflight()
        )
        if ids:
            self.counters.inc("recovered_stale", len(ids))
            log.warning("%d stuck batches (analyzing) queued again: %s", len(ids), ids[:10])
        return len(ids)

    def expire_old_pending(self) -> int:
        """Batches that waited longer than QUEUE_MAX_AGE_HOURS become `error`, counted."""
        max_age = self._retry.queue_max_age_hours
        ids = self._repo.expire_pending(
            created_before=contract.iso_utc(self._clock() - max_age * SECONDS_PER_HOUR),
            reason=contract.error_queue_expired(max_age),
        )
        if ids:
            self.counters.inc("errors", len(ids))
            total = self.counters.inc("expired", len(ids))
            log.warning(
                "%d batches dropped after %gh in the queue (expired=%d), oldest ids: %s",
                len(ids),
                max_age,
                total,
                ids[:5],
            )
        return len(ids)

    def retry_once(self) -> bool:
        """Run at most one due batch. Returns True if an attempt was made."""
        self.requeue_stale(self._retry.stale_analyzing_seconds)
        self.expire_old_pending()
        if self.gate_wait() > 0:
            return False
        claimed = self._repo.claim_next_due(self._clock())
        if claimed is None:
            return False
        groups = groups_from_json(claimed.raw_groups)
        if groups is None:
            self.drop(claimed.id, contract.error_unreadable_groups(), "dropped_permanent")
            return True
        log.info("Retry worker: analysing batch %d again (source: %s)", claimed.id, claimed.source)
        self.run_attempt(claimed.id, groups, claimed.source, is_retry=True)
        return True

    def run_retention(self) -> int:
        purged = self.purger.run_if_due()
        if purged:
            self.counters.inc("purged_batches", purged)
        return purged

    def run_retry_worker(self) -> None:
        """Runs until the stop event is set: retention, then at most one due batch,
        then a pause of RETRY_PACE (after an attempt) or RETRY_POLL (idle)."""
        while not self._stop.is_set():
            did_work = False
            try:
                self.run_retention()
                did_work = self.retry_once()
            except Exception:
                log.exception("Retry worker: unexpected error")
            self._stop.wait(self._retry.pace if did_work else self._retry.poll)

    # ── stopping ─────────────────────────────────────────────────────────────
    def shutdown(self, timeout: float) -> bool:
        """Stop taking live batches and wait up to `timeout` seconds for the workers.

        Queued live batches that were not started are put back into the database
        queue. Returns False if a request was still in flight at the deadline; its
        row stays `analyzing` and is re-queued at the next start.
        """
        with self._accept_lock:
            self._accepting = False
        while True:
            try:
                batch = self._live.get_nowait()
            except queue.Empty:
                break
            if batch is not None:
                self._requeue_now(batch.batch_id)
                self._discard_inflight(batch.batch_id)
        for _ in self._live_workers:
            self._live.put(None)
        deadline = time.monotonic() + timeout
        for worker in self._live_workers:
            worker.join(max(0.0, deadline - time.monotonic()))
        return not any(worker.is_alive() for worker in self._live_workers)
