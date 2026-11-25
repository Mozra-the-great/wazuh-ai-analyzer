"""Startup: reconcile the saved watermark with what is on disk (#44).

Everything written while the service was not looking becomes a backlog segment
(read paced and gated by the backlog worker); the live tailer itself then starts
at the current end of `alerts.json`. Cases:

* v1 or unreadable watermark: start at the end, plan nothing (no re-analysis).
* No watermark (first start): the existing history becomes backlog.
* Same file as before (first-line digest, or the inode while the file had no
  complete line and no newer archive exists): the rest since the saved offset;
  a file shorter than the offset was truncated and is read from the start.
* Otherwise Wazuh rotated it: the rest of the previous file (found by its digest
  in the archive), every archive of a later day, and the new `alerts.json`.
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta
from typing import BinaryIO

from .archives import (
    AlertFiles,
    file_head_digest,
    first_line_digest,
    ident_of,
    last_line_boundary,
    local_date,
)
from .counters import IngestCounters
from .watermark import Cursor, Segment, WatermarkStore

log = logging.getLogger(__name__)


def segment(path: str, offset: int, end: int | None, head: str | None) -> Segment:
    return {"path": path, "offset": offset, "end": end, "head": head}


def cursor_at_end(f: BinaryIO, path: str) -> Cursor:
    """A cursor after the last complete line of the open live log."""
    st = os.fstat(f.fileno())
    return {
        "path": path,
        "dev": st.st_dev,
        "ino": st.st_ino,
        "offset": last_line_boundary(f, 0, st.st_size),
        "head": first_line_digest(f, closed=False),
    }


def plan_resume(
    f: BinaryIO, *, files: AlertFiles, watermark: WatermarkStore, counters: IngestCounters
) -> Cursor:
    """Plan the backlog for the opened live log `f`, persist it, return the live cursor."""
    live_path = str(files.alerts_log)
    st = os.fstat(f.fileno())
    ident = ident_of(st)
    boundary = last_line_boundary(f, 0, st.st_size)
    head_now = first_line_digest(f, closed=False)
    live = watermark.live
    segments: list[Segment] = []

    if watermark.legacy:
        log.info(
            "Watermark migration: live cursor moves to the end of %s, nothing is analysed again",
            live_path,
        )
    elif live is None:
        log.info("First start without a watermark: existing alert logs become history")
        for path in files.find_sibling_files(exclude=ident):
            segments.append(segment(str(path), 0, None, file_head_digest(path)))
        if boundary > 0:
            segments.append(segment(live_path, 0, boundary, head_now))
    elif (
        head_now == live["head"]
        if live["head"] is not None
        else (live["dev"], live["ino"]) == ident and not files.archives_since(live["ts"], ident)
    ):
        # Same file as before: continue where we stopped. A cursor without a
        # first-line digest means the file was still empty; the inode alone cannot
        # tell it from a later file (freed inodes are reused at once), so it only
        # counts if no archive of that day or later has appeared.
        start = live["offset"] if live["head"] is not None else 0
        if st.st_size < start:
            log.warning(
                "%s is smaller than the saved position (%d < %d): it was truncated,"
                " reading it from the start",
                live_path,
                st.st_size,
                start,
            )
            start = 0
        if boundary > start:
            log.info("Catching up: %d bytes in %s since the last stop", boundary - start, live_path)
            segments.append(segment(live_path, start, boundary, head_now))
    else:
        # The file we were reading is no longer alerts.json: Wazuh rotated it.
        found = (
            files.find_previous_file(live["head"], live["ts"]) if live["head"] is not None else None
        )
        if found is not None:
            prev_path, day = found
            log.info(
                "Rotated since the last stop: finishing %s from byte %d", prev_path, live["offset"]
            )
            segments.append(segment(str(prev_path), live["offset"], None, live["head"]))
        elif live["head"] is None:
            # The cursor sat on an empty file, so nothing of that day was read:
            # every archive from that day on is new to us.
            day = local_date(live["ts"]) - timedelta(days=1)
        else:
            day = local_date(live["ts"])
            log.warning(
                "Rotated previous file not found (retention expired?): its rest cannot be caught up"
            )
        for arch_day, path in files.list_dated_archives(exclude=ident):
            if arch_day <= day:
                continue
            digest = file_head_digest(path)
            if head_now is not None and digest == head_now:
                continue  # a copy of the live file (broken hard link), planned below
            log.info("Catching up: archive %s", path)
            segments.append(segment(str(path), 0, None, digest))
        if boundary > 0:
            segments.append(segment(live_path, 0, boundary, head_now))

    cursor: Cursor = {
        "path": live_path,
        "dev": st.st_dev,
        "ino": st.st_ino,
        "offset": boundary,
        "head": head_now,
    }
    watermark.apply_plan(cursor, segments)
    counters.inc("history_files_total", len(segments))
    return cursor
