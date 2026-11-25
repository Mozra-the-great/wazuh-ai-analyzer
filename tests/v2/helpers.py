"""Small helpers shared by the tests of the rewrite."""

from __future__ import annotations

import socket
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

# A fixed "now" so created_at values and cutoffs are reproducible.
NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC).timestamp()


def free_port() -> int:
    """A TCP port nobody listens on right now (the service binds its web port at start)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FakeClock:
    """A settable replacement for `time.time`."""

    def __init__(self, now: float = NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RecordingEnv(dict[str, str]):
    """An environment that remembers which variables were looked up."""

    def __init__(self, data: Mapping[str, str] | None = None) -> None:
        super().__init__(data or {})
        self.looked_up: set[str] = set()

    def get(self, key: str, default: Any = None) -> Any:
        self.looked_up.add(key)
        return super().get(key, default)
