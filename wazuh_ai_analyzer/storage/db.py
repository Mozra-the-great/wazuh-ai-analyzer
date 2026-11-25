"""SQLite connections: WAL, one short-lived connection per unit of work."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

BUSY_TIMEOUT_SECONDS = 30.0


class Database:
    """A database file plus the rules for opening it.

    Connections are cheap and not shared between threads: every unit of work
    opens its own through `transaction()`, which commits on success, rolls back
    on an exception and always closes.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        """Open a new connection. The caller must close it.

        Read-only connections use `mode=ro` plus `query_only`, like the metrics
        exporter does, and never create the file or its WAL side files.
        """
        if read_only:
            conn = sqlite3.connect(
                f"{self.path.resolve().as_uri()}?mode=ro",
                uri=True,
                timeout=BUSY_TIMEOUT_SECONDS,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            return conn
        conn = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_SECONDS, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # WAL allows readers next to the single writer and removes most
        # "database is locked" errors under multi-threaded load.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, faster than FULL
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Open a connection, commit on success, roll back on error, always close."""
        conn = self.connect()
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def reader(self) -> Iterator[sqlite3.Connection]:
        """A read-only connection that is closed afterwards."""
        conn = self.connect(read_only=True)
        try:
            yield conn
        finally:
            conn.close()
