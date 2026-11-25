"""Server-side sessions (R5) and the session key file.

A session is a row in `web_sessions`: the sha256 of the session id (never the id
itself, so a leaked database cannot be replayed as a cookie), the per-session CSRF
token, the user and the expiry. The id is 256 random bits and is issued only by
`SessionStore.create`; the server never accepts an id chosen by the client, so
session fixation is impossible by construction. Login always creates a new id,
logout deletes the row.

`session.key` (shared with the legacy `analyzer.py`, where it signed Flask's cookie)
now keys the pre-session login CSRF token (`web.csrf`). It is created with
`O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600, so a planted symlink is never followed
and an existing file is never overwritten by a race.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import re
import secrets
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..permissions import DATA_FILE_MODE, restrict
from ..storage.db import Database

log = logging.getLogger(__name__)

SESSION_ID_BYTES: Final = 32
# What `secrets.token_urlsafe(32)` produces; anything else is rejected before it is hashed.
SESSION_ID_RE: Final = re.compile(r"^[A-Za-z0-9_-]{43}$")
# Only one user can log in, but every login adds a row: keep the table small.
MAX_SESSIONS: Final = 50
SESSION_KEY_BYTES: Final = 64
SESSION_KEY_MIN_BYTES: Final = 32
SESSION_KEY_MAX_BYTES: Final = 4096


@dataclass(frozen=True, slots=True)
class Session:
    """A valid, unexpired session."""

    username: str
    csrf_token: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class NewSession:
    """What login hands to the client: the id goes into the cookie, only there."""

    session_id: str
    csrf_token: str
    expires_at: float


def hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("ascii")).hexdigest()


class SessionStore:
    def __init__(
        self, db: Database, *, lifetime: float, clock: Callable[[], float] = time.time
    ) -> None:
        self._db = db
        self._lifetime = lifetime
        self._clock = clock

    def create(self, username: str) -> NewSession:
        """Issue a new session (a fresh id every time) and prune old rows."""
        now = self._clock()
        session_id = secrets.token_urlsafe(SESSION_ID_BYTES)
        csrf_token = secrets.token_urlsafe(SESSION_ID_BYTES)
        expires_at = now + self._lifetime
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM web_sessions WHERE expires_at <= ?", (now,))
            conn.execute(
                "INSERT INTO web_sessions (id_hash, csrf_token, username, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (hash_session_id(session_id), csrf_token, username, now, expires_at),
            )
            conn.execute(
                "DELETE FROM web_sessions WHERE id_hash IN ("
                "SELECT id_hash FROM web_sessions ORDER BY created_at DESC, rowid DESC"
                " LIMIT -1 OFFSET ?)",
                (MAX_SESSIONS,),
            )
        return NewSession(session_id=session_id, csrf_token=csrf_token, expires_at=expires_at)

    def lookup(self, session_id: str | None) -> Session | None:
        """The session behind a cookie value, or None (unknown, malformed, expired)."""
        if session_id is None or not SESSION_ID_RE.match(session_id):
            return None
        id_hash = hash_session_id(session_id)
        with self._db.reader() as conn:
            row = conn.execute(
                "SELECT username, csrf_token, expires_at FROM web_sessions WHERE id_hash = ?",
                (id_hash,),
            ).fetchone()
        if row is None:
            return None
        expires_at = float(row["expires_at"])
        if expires_at <= self._clock():
            self._delete_hash(id_hash)
            return None
        return Session(
            username=str(row["username"]),
            csrf_token=str(row["csrf_token"]),
            expires_at=expires_at,
        )

    def delete(self, session_id: str | None) -> None:
        """Log a session out on the server (unknown ids are ignored)."""
        if session_id is not None and SESSION_ID_RE.match(session_id):
            self._delete_hash(hash_session_id(session_id))

    def count(self) -> int:
        with self._db.reader() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM web_sessions").fetchone()[0])

    def _delete_hash(self, id_hash: str) -> None:
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM web_sessions WHERE id_hash = ?", (id_hash,))


# ── session.key ──────────────────────────────────────────────────────────────
class SessionKeyError(Exception):
    """`session.key` cannot be used and cannot be replaced safely."""


def _open_flags(*extra: int) -> int:
    flags = os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    for flag in extra:
        flags |= flag
    return flags


def _read_key(path: Path) -> bytes | None:
    """The key file's content, or None if it does not exist. Never follows a symlink."""
    try:
        fd = os.open(path, _open_flags(os.O_RDONLY))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SessionKeyError(
            f"{path}: cannot be opened ({exc.strerror or 'error'}); remove it to create a new key"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SessionKeyError(f"{path}: not a regular file")
        return os.read(fd, SESSION_KEY_MAX_BYTES + 1)
    finally:
        os.close(fd)


def _create_key(path: Path) -> bytes | None:
    """Create the key file exclusively; None if somebody else created it first."""
    key = secrets.token_bytes(SESSION_KEY_BYTES)
    flags = _open_flags(os.O_WRONLY, os.O_CREAT, os.O_EXCL)
    try:
        fd = os.open(path, flags, DATA_FILE_MODE)
    except FileExistsError:
        return None
    except OSError as exc:
        raise SessionKeyError(f"{path}: cannot be created ({exc.strerror or 'error'})") from None
    try:
        view = memoryview(key)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            path.unlink()
        raise
    os.close(fd)
    return key


def load_or_create_session_key(path: Path) -> bytes:
    """The persistent secret of the web layer. Generated once, then reused.

    An existing key keeps its content (a rollback to `analyzer.py` keeps working)
    and is healed to mode 0600. A file that is empty or too short to be a key is
    replaced: nothing that matters is signed with it any more.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(3):
        key = _read_key(path)
        if key is None:
            created = _create_key(path)
            if created is not None:
                return created
            continue  # lost a race with another creator: read what it wrote
        if SESSION_KEY_MIN_BYTES <= len(key) <= SESSION_KEY_MAX_BYTES:
            restrict(path, DATA_FILE_MODE)
            return key
        log.warning("%s is not a usable key (%d bytes), replacing it", path, len(key))
        path.unlink()
    raise SessionKeyError(f"{path}: could not create a usable key")
