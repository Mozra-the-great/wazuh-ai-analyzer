"""The persistent ingest position: `watermark.json`, format version 2 (#44).

The file is shared with the legacy `analyzer.py`, in both directions: a cutover
continues where the old code stopped, and a rollback continues where the new
code stopped. The layout below is therefore frozen (keys, their order, the
digest algorithm in `archives.line_digest`):

    {
      "version": 2,
      "live": {"path", "dev", "ino", "offset", "head", "ts"} | null,
      "backlog": [{"path", "offset", "end", "head", "id"}, ...],
      "next_id": int,
      "updated_at": ISO 8601 UTC
    }

* `live` is bound to the file identity (dev/inode plus the sha256 of its first
  line), not to the path. `ts` is when it was committed.
* `backlog` holds ranges still to be analysed (rest of a rotated file, days of
  downtime, the history at first start), oldest first.

The file is written atomically (temp file, fsync, rename, directory fsync) with
mode 0600 and only by this class, which the live tailer and the backlog worker
share. A file in the old v1 format (`{path: line number}`) or an unreadable one
is kept aside for inspection and the reader starts at the end of the live log:
the real position is unknown, and guessing "the start" is exactly the double
analysis of #44.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final, NotRequired, TypedDict, TypeGuard

from ..permissions import DATA_FILE_MODE, restrict
from ..storage.contract import iso_utc

log = logging.getLogger(__name__)

WATERMARK_VERSION: Final = 2
# A larger file is not something this class wrote: treat it as corrupt.
WATERMARK_MAX_BYTES: Final = 16 * 1024 * 1024
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)


class Cursor(TypedDict):
    """A position in a file, bound to the file's identity."""

    path: str
    dev: int
    ino: int
    offset: int
    head: str | None  # sha256 of the first line, None while the file has no complete line


class LiveCursor(Cursor):
    ts: float


class Segment(TypedDict):
    """A byte range of a file that still has to be analysed. `end` None = to EOF."""

    path: str
    offset: int
    end: int | None
    head: str | None
    id: NotRequired[int]


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_offset(value: object) -> TypeGuard[int]:
    return _is_int(value) and value >= 0


def _is_head(value: object) -> TypeGuard[str | None]:
    return value is None or isinstance(value, str)


def _parse_cursor(value: object) -> LiveCursor | None:
    if not isinstance(value, dict):
        return None
    path, dev, ino, offset = (value.get(k) for k in ("path", "dev", "ino", "offset"))
    head, ts = value.get("head"), value.get("ts")
    if not (isinstance(path, str) and _is_int(dev) and _is_int(ino) and _is_offset(offset)):
        return None
    if not _is_head(head) or isinstance(ts, bool) or not isinstance(ts, int | float):
        return None
    return {"path": path, "dev": dev, "ino": ino, "offset": offset, "head": head, "ts": float(ts)}


def _parse_segment(value: object) -> Segment | None:
    if not isinstance(value, dict):
        return None
    seg_id, path, offset = value.get("id"), value.get("path"), value.get("offset")
    end, head = value.get("end"), value.get("head")
    if not (_is_int(seg_id) and isinstance(path, str) and _is_offset(offset)):
        return None
    if not _is_head(head) or not (end is None or _is_int(end)):
        return None
    return {"path": path, "offset": offset, "end": end, "head": head, "id": seg_id}


def fsync_dir(path: Path) -> None:
    """Best effort: make a rename in `path` durable (not supported on Windows)."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class WatermarkStore:
    """Thread-safe owner of `watermark.json`."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        self._live: LiveCursor | None = None
        self._backlog: list[Segment] = []
        self._next_id = 1
        # True when the file held the v1 format or something unreadable: the real
        # position is unknown and the planner starts at the end of the live log.
        self._legacy = False

    # ── loading ──────────────────────────────────────────────────────────────
    def load(self) -> None:
        """Read the file. Never raises for bad content: see the module docstring."""
        with self._lock:
            self._live, self._backlog, self._next_id, self._legacy = None, [], 1, False
            try:
                st = self.path.stat()
            except FileNotFoundError:
                return
            except OSError as exc:
                self._set_aside("corrupt", f"not readable ({exc.__class__.__name__})")
                return
            if st.st_size > WATERMARK_MAX_BYTES:
                self._set_aside("corrupt", "too large")
                return
            try:
                data: object = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError, RecursionError) as exc:
                self._set_aside("corrupt", f"not readable ({exc.__class__.__name__})")
                return
            if (
                isinstance(data, dict)
                and "version" not in data
                and all(_is_int(v) for v in data.values())
            ):
                self._set_aside("v1.bak", "in the old line-number format (per path)", rename=False)
                return
            parsed = self._parse(data)
            if parsed is None:
                self._set_aside("corrupt", "in an unknown format")
                return
            self._live, self._backlog, self._next_id = parsed

    @staticmethod
    def _parse(data: object) -> tuple[LiveCursor | None, list[Segment], int] | None:
        if not isinstance(data, dict) or data.get("version") != WATERMARK_VERSION:
            return None
        raw_live = data.get("live")
        live = None if raw_live is None else _parse_cursor(raw_live)
        if raw_live is not None and live is None:
            return None
        raw_backlog = data.get("backlog", [])
        if not isinstance(raw_backlog, list):
            return None
        backlog: list[Segment] = []
        for raw in raw_backlog:
            seg = _parse_segment(raw)
            if seg is None:
                return None
            backlog.append(seg)
        next_id = data.get("next_id", 1)
        if not _is_int(next_id):
            return None
        # Never hand out an id twice, even if the file was edited by hand.
        next_id = max([next_id, *(s.get("id", 0) + 1 for s in backlog)])
        return live, backlog, next_id

    def _set_aside(self, suffix: str, why: str, *, rename: bool = True) -> None:
        """Keep the unusable file for inspection (owner-only) and start at the end."""
        target = self.path.with_name(f"{self.path.name}.{suffix}")
        try:
            if rename:
                self.path.replace(target)
            else:
                content = self.path.read_bytes()
                fd = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW, DATA_FILE_MODE
                )
                with os.fdopen(fd, "wb") as fh:
                    fh.write(content)
            restrict(target, DATA_FILE_MODE)
        except OSError as exc:
            log.warning("Could not keep %s as %s: %s", self.path.name, target.name, exc)
        self._legacy = True
        log.warning(
            "Watermark %s - copy kept as %s; reading starts at the end of the live log,"
            " alerts already there are not analysed again",
            why,
            target.name,
        )

    # ── writing ──────────────────────────────────────────────────────────────
    def _save_locked(self) -> None:
        payload = {
            "version": WATERMARK_VERSION,
            "live": self._live,
            "backlog": self._backlog,
            "next_id": self._next_id,
            "updated_at": iso_utc(self._clock()),
        }
        tmp = self.path.with_name(self.path.name + ".tmp")
        # os.open applies the mode only when it creates the file; restrict() below
        # fixes a temp file left over with other modes.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW, DATA_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        restrict(tmp, DATA_FILE_MODE)
        tmp.replace(self.path)
        fsync_dir(self.path.parent)

    # ── accessors ────────────────────────────────────────────────────────────
    @property
    def legacy(self) -> bool:
        with self._lock:
            return self._legacy

    @property
    def live(self) -> LiveCursor | None:
        with self._lock:
            return None if self._live is None else LiveCursor(**self._live)

    def backlog(self) -> list[Segment]:
        with self._lock:
            return [Segment(**s) for s in self._backlog]

    def commit_live(self, cursor: Cursor) -> None:
        """Persist the live position. Raises OSError if it cannot be written."""
        with self._lock:
            self._live = _stamp(cursor, self._clock())
            self._save_locked()

    def apply_plan(self, cursor: Cursor, segments: Sequence[Segment]) -> None:
        """Store the startup plan: new backlog segments plus the live position."""
        with self._lock:
            for seg in segments:
                self._backlog.append(
                    {
                        "path": seg["path"],
                        "offset": seg["offset"],
                        "end": seg["end"],
                        "head": seg["head"],
                        "id": self._next_id,
                    }
                )
                self._next_id += 1
            self._live = _stamp(cursor, self._clock())
            self._legacy = False
            self._save_locked()

    def first_segment(self) -> Segment | None:
        with self._lock:
            return Segment(**self._backlog[0]) if self._backlog else None

    def advance_segment(self, seg_id: int, offset: int) -> None:
        """Move a segment's start past what is stored. Raises OSError on a write error."""
        with self._lock:
            for seg in self._backlog:
                if seg.get("id") == seg_id:
                    seg["offset"] = max(seg["offset"], offset)
            self._save_locked()

    def finish_segment(self, seg_id: int) -> None:
        with self._lock:
            self._backlog = [s for s in self._backlog if s.get("id") != seg_id]
            self._save_locked()


def _stamp(cursor: Cursor, ts: float) -> LiveCursor:
    return {
        "path": cursor["path"],
        "dev": cursor["dev"],
        "ino": cursor["ino"],
        "offset": cursor["offset"],
        "head": cursor["head"],
        "ts": ts,
    }
