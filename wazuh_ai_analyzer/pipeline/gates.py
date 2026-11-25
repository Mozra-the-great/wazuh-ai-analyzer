"""Backoff maths and the two shared gates in front of the analysis backend (#43).

* `QuotaState`    the provider's quota is used up: nobody sends until `retry_at`.
                  Drives the countdown in the dashboard.
* `UpstreamState` transient failures (5xx, timeouts, connection errors) close the gate
                  for everybody, with a delay that grows while failures keep coming.
                  Per-batch backoff alone is not enough: after a long outage every
                  parked batch would probe the API on its own schedule.

`as_dict()` of both is what `/api/stats` shows; the keys are those of `analyzer.py`.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Callable
from typing import Final

from ..storage.contract import iso_utc

log = logging.getLogger(__name__)

UPSTREAM_ERROR_MAX: Final = 200
_EXPONENT_MAX: Final = 32
JITTER_LOW: Final = 0.8
JITTER_HIGH: Final = 1.2

Jitter = Callable[[float, float], float]


def backoff_delay(
    attempt: int, *, base: float, maximum: float, jitter: Jitter = random.uniform
) -> float:
    """Exponential backoff with +-20 % jitter: `base * 2**(attempt-1)`, never above `maximum`."""
    exponent = max(0, min(attempt, _EXPONENT_MAX) - 1)
    delay = min(maximum, base * (2.0**exponent))
    return min(maximum, delay * jitter(JITTER_LOW, JITTER_HIGH))


class QuotaState:
    """Quota exhaustion of the provider and when the next request is allowed."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self.exhausted = False
        self.exhausted_since: str | None = None
        self.retry_at: float | None = None
        self.retry_count = 0
        self.last_error_msg = ""
        self.last_success_at: str | None = None

    def mark_exhausted(self, message: str, retry_after: float) -> None:
        with self._lock:
            now = self._clock()
            if not self.exhausted:
                self.exhausted_since = iso_utc(now)
            self.exhausted = True
            self.retry_count += 1
            self.retry_at = now + retry_after
            self.last_error_msg = message
            retry_at = iso_utc(self.retry_at)
        log.warning("Quota exhausted: %s | next attempt: %s", message, retry_at)

    def mark_success(self) -> None:
        with self._lock:
            if self.exhausted:
                log.info("Quota restored, analysis is running again")
            self.exhausted = False
            self.exhausted_since = None
            self.retry_at = None
            self.retry_count = 0
            self.last_error_msg = ""
            self.last_success_at = iso_utc(self._clock())

    def wait_seconds(self) -> float:
        """Seconds until the quota backoff allows the next request (0 = now)."""
        with self._lock:
            if not self.exhausted:
                return 0.0
            return max(0.0, (self.retry_at or 0) - self._clock())

    def as_dict(self) -> dict[str, object]:
        with self._lock:
            now = self._clock()
            return {
                "exhausted": self.exhausted,
                "exhausted_since": self.exhausted_since,
                "retry_at": iso_utc(self.retry_at) if self.retry_at else None,
                "retry_in_seconds": (
                    max(0, int((self.retry_at or 0) - now)) if self.exhausted else 0
                ),
                "retry_count": self.retry_count,
                "last_error": self.last_error_msg,
                "last_success_at": self.last_success_at,
            }


class UpstreamState:
    """Shared backoff for transient failures of the backend's upstream."""

    def __init__(
        self,
        *,
        base_delay: float,
        max_delay: float,
        clock: Callable[[], float] = time.time,
        jitter: Jitter = random.uniform,
    ) -> None:
        self._lock = threading.Lock()
        self._base = base_delay
        self._max = max_delay
        self._clock = clock
        self._jitter = jitter
        self.consecutive_failures = 0
        self.next_ok_at = 0.0
        self.last_error = ""

    def mark_failure(self, message: str, retry_after: float = 0.0) -> float:
        """Close the gate; returns the delay in seconds."""
        with self._lock:
            self.consecutive_failures += 1
            delay = max(
                min(retry_after, self._max),
                backoff_delay(
                    self.consecutive_failures,
                    base=self._base,
                    maximum=self._max,
                    jitter=self._jitter,
                ),
            )
            self.next_ok_at = self._clock() + delay
            self.last_error = message[:UPSTREAM_ERROR_MAX]
            count = self.consecutive_failures
        log.warning(
            "Upstream unreachable or overloaded (failure #%d in a row), next attempt in %ds",
            count,
            int(delay),
        )
        return delay

    def mark_success(self) -> None:
        with self._lock:
            recovered = self.consecutive_failures > 0
            self.consecutive_failures = 0
            self.next_ok_at = 0.0
            self.last_error = ""
        if recovered:
            log.info("Upstream reachable again, retry gate lifted")

    def wait_seconds(self) -> float:
        with self._lock:
            return max(0.0, self.next_ok_at - self._clock())

    def as_dict(self) -> dict[str, object]:
        with self._lock:
            return {
                "consecutive_failures": self.consecutive_failures,
                "retry_in_seconds": int(max(0.0, self.next_ok_at - self._clock())),
                "last_error": self.last_error,
            }
