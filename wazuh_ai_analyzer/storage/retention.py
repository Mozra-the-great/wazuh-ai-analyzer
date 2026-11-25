"""Periodic retention: runs `Repository.purge_old_batches` at most once per interval."""

from __future__ import annotations

import time
from collections.abc import Callable

from .repo import Repository


class RetentionPurger:
    """Port of the legacy `_purge_if_due`.

    The retry worker (#85) calls `run_if_due()` on every loop; the purger decides
    whether the interval has passed. `days <= 0` disables retention. The first call
    runs immediately, so a restart cleans up without waiting a full interval.
    """

    def __init__(
        self,
        repo: Repository,
        *,
        days: float,
        interval: float,
        chunk: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._repo = repo
        self._days = days
        self._interval = interval
        self._chunk = chunk
        self._monotonic = monotonic
        self._last_run: float | None = None

    def run_if_due(self) -> int:
        """Purge when due; returns the number of deleted batches (0 if skipped)."""
        if self._days <= 0:
            return 0
        now = self._monotonic()
        if self._last_run is not None and now - self._last_run < self._interval:
            return 0
        self._last_run = now
        return self._repo.purge_old_batches(self._days, chunk=self._chunk)
