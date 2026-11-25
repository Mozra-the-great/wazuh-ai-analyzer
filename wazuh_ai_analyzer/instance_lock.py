"""One running service per data directory.

Two instances on the same database would both claim the same `pending` batches,
both tail the same log and overwrite each other's `watermark.json`. The lock is an
exclusive, non-blocking `flock` on `<data dir>/.lock`, taken before the database is
touched. The kernel drops it when the process ends, however it ends, so a crash
never leaves a stale lock behind.

The lock file is created with `O_NOFOLLOW` and mode 0600; a symlink in its place is
refused instead of followed. It holds the pid of the owner, for the error message.
(Windows has no `flock`; there `msvcrt.locking` serves local development and tests.)
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path
from typing import Final

if sys.platform == "win32":
    import msvcrt

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

    def _write_owner(fd: int) -> None:
        """The locked byte cannot be read by the other process: no pid is recorded."""

    def _read_owner(fd: int) -> str:
        return "owner unknown"

else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    def _write_owner(fd: int) -> None:
        """Record our pid for the error message of a second instance (best effort)."""
        with contextlib.suppress(OSError):
            os.ftruncate(fd, 0)
            os.pwrite(fd, f"{os.getpid()}{chr(10)}".encode(), 0)
            os.fchmod(fd, LOCK_FILE_MODE)

    def _read_owner(fd: int) -> str:
        """`pid 123` of the lock holder, if the file says so (never raises)."""
        try:
            text = os.pread(fd, _PID_READ_MAX, 0).decode("ascii", "replace").strip()
        except OSError:
            return "owner unknown"
        return f"pid {text}" if text.isdigit() else "owner unknown"


LOCK_FILE_NAME: Final = ".lock"
LOCK_FILE_MODE: Final = 0o600
_PID_READ_MAX: Final = 32


class InstanceLockError(Exception):
    """The lock cannot be taken: another instance runs, or the file is unusable."""


class InstanceLock:
    """An exclusive lock on the data directory, held until `release()`."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / LOCK_FILE_NAME
        self._fd: int | None = None

    def is_held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        """Take the lock or raise `InstanceLockError` with a message for the operator."""
        if self._fd is not None:
            return
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            fd = os.open(self.path, flags, LOCK_FILE_MODE)
        except OSError as exc:
            raise InstanceLockError(
                f"cannot open the lock file {self.path}: {exc.strerror or 'error'}"
                " (a symlink in its place is refused)"
            ) from None
        try:
            _lock(fd)
        except OSError:
            owner = _read_owner(fd)
            os.close(fd)
            raise InstanceLockError(
                f"another instance is already running on {self.path.parent}"
                f" ({owner}); stop it first, two instances would corrupt each other's state"
            ) from None
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        _write_owner(fd)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        with contextlib.suppress(OSError):
            _unlock(fd)
        with contextlib.suppress(OSError):
            os.close(fd)

    def __enter__(self) -> InstanceLock:
        self.acquire()
        return self

    def __exit__(self, *_: object) -> None:
        self.release()
