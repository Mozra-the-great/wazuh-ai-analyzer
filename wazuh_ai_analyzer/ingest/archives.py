"""Alert files on disk: identity, first-line digests and Wazuh's rotated archives.

Wazuh rotates `alerts.json` at midnight into `YYYY/Mon/ossec-alerts-DD.json` and
compresses it to `.json.gz` later. While a day runs, `alerts.json` and that day's
dated file are hard links of one inode.

A file is recognised by the sha256 of its first line (`HEAD_LINE_MAX` bytes at
most), not by its inode: compressing creates a new inode and freed inodes are
reused at once (#44). The digest algorithm is part of the `watermark.json` format
and must stay the same as in the legacy code.

Every path this module hands out lies below the alerts directory. Symbolic links
are followed only when their target stays below it (resolved and prefix-checked),
so a link planted in the archive tree cannot make the analyzer read and forward
another file.
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import os
import re
import stat
import zlib
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import BinaryIO, Final, cast

log = logging.getLogger(__name__)

HEAD_LINE_MAX: Final = 64 * 1024
MONTHS: Final = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_DATED_RE: Final = re.compile(r"^ossec-alerts-(\d{2})\.json(\.gz)?$")
SKIP_SUFFIXES: Final = (".sum", ".sig", ".md5", ".sha256", ".tmp")
# Files that cannot be read as alerts at all, so a read error is not a surprise.
READ_ERRORS: Final = (OSError, EOFError, zlib.error)

FileIdent = tuple[int, int]  # (st_dev, st_ino)


def open_alert_file(path: Path | str) -> BinaryIO:
    """Open an alert file for binary reading, transparently gunzipping `.gz`."""
    if str(path).endswith(".gz"):
        return cast(BinaryIO, gzip.open(path, "rb"))
    return Path(path).open("rb")


def line_digest(line: bytes) -> str:
    """sha256 of the first `HEAD_LINE_MAX` bytes of a line, without its line break."""
    return hashlib.sha256(line[:HEAD_LINE_MAX].rstrip(b"\r\n")).hexdigest()


def first_line_digest(f: BinaryIO, *, closed: bool) -> str | None:
    """Digest of the first line of an open file, or None if there is no complete line.

    A live file may end in a half-written line (`closed=False`); a rotated one gets
    no more data, so its last line counts. Moves the file position.
    """
    f.seek(0)
    line = f.readline(HEAD_LINE_MAX)
    if not line:
        return None
    if not (line.endswith(b"\n") or len(line) >= HEAD_LINE_MAX or closed):
        return None
    return line_digest(line)


def file_head_digest(path: Path | str) -> str | None:
    try:
        with open_alert_file(path) as f:
            return first_line_digest(f, closed=True)
    except READ_ERRORS:
        return None


def last_line_boundary(f: BinaryIO, lo: int, hi: int) -> int:
    """Start offset of the first incomplete line in [lo, hi): right after the last
    newline, or `lo` if there is none."""
    pos = hi
    while pos > lo:
        start = max(lo, pos - 64 * 1024)
        f.seek(start)
        idx = f.read(pos - start).rfind(b"\n")
        if idx >= 0:
            return start + idx + 1
        pos = start
    return lo


def local_date(ts: float) -> date:
    """Local calendar day: Wazuh names its archives after the manager's local date."""
    return datetime.fromtimestamp(ts).date()


def ident_of(st: os.stat_result) -> FileIdent:
    return (st.st_dev, st.st_ino)


class AlertFiles:
    """The alerts directory: the live `alerts.json` and everything rotated from it."""

    def __init__(self, alerts_log: Path) -> None:
        self.alerts_log = Path(alerts_log)
        self.root = self.alerts_log.parent

    # ── confinement ──────────────────────────────────────────────────────────
    def _real_root(self) -> Path | None:
        try:
            return self.root.resolve(strict=True)
        except OSError:
            return None

    def is_confined(self, path: Path | str) -> bool:
        """True if `path` exists and, with every link resolved, lies below the
        alerts directory. The configured live log itself is always allowed."""
        candidate = Path(path)
        if candidate == self.alerts_log:
            return True
        real_root = self._real_root()
        if real_root is None:
            return False
        try:
            real = candidate.resolve(strict=True)
        except (OSError, RuntimeError):  # missing, or a symlink loop
            return False
        return real != real_root and real.is_relative_to(real_root)

    def _confined_dirs(self, parent: Path, real_root: Path) -> list[Path]:
        out: list[Path] = []
        for entry in parent.iterdir():
            try:
                real = entry.resolve(strict=True)
                if real.is_relative_to(real_root) and entry.is_dir():
                    out.append(entry)
            except (OSError, RuntimeError):
                continue
        return out

    def _regular_file(self, entry: Path, real_root: Path) -> os.stat_result | None:
        """stat of `entry` if it is (a link inside the root to) a regular file."""
        try:
            real = entry.resolve(strict=True)
            if not real.is_relative_to(real_root):
                log.warning("Ignoring %s: it points outside the alerts directory", entry)
                return None
            st = entry.stat()
        except (OSError, RuntimeError):
            return None
        return st if stat.S_ISREG(st.st_mode) else None

    # ── listings ─────────────────────────────────────────────────────────────
    def list_dated_archives(self, exclude: FileIdent | None = None) -> list[tuple[date, Path]]:
        """[(day, path)] of Wazuh's rotated JSON alerts, oldest first.

        `exclude` is the live file's identity: today's dated hard link of
        `alerts.json` must not be read twice. Text-format (`.log`) archives are
        ignored. When both `.json` and `.json.gz` exist for a day, the plain file
        wins: the `.gz` may still be being written.
        """
        found: dict[date, Path] = {}
        real_root = self._real_root()
        if real_root is None:
            return []
        try:
            year_dirs = [
                d
                for d in self._confined_dirs(self.root, real_root)
                if d.name.isdigit() and len(d.name) == 4
            ]
            for ydir in year_dirs:
                for mdir in self._confined_dirs(ydir, real_root):
                    if mdir.name not in MONTHS:
                        continue
                    for entry in mdir.iterdir():
                        m = _DATED_RE.match(entry.name)
                        if not m:
                            continue
                        try:
                            day = date(int(ydir.name), MONTHS.index(mdir.name) + 1, int(m.group(1)))
                        except ValueError:
                            continue
                        st = self._regular_file(entry, real_root)
                        if st is None:
                            continue
                        if exclude is not None and ident_of(st) == exclude:
                            continue
                        previous = found.get(day)
                        if previous is None or (previous.name.endswith(".gz") and not m.group(2)):
                            found[day] = entry
        except OSError as exc:
            log.warning("Archive directory %s is not readable: %s", self.root, exc)
        return sorted(found.items())

    def find_sibling_files(self, exclude: FileIdent | None = None) -> list[Path]:
        """Files next to alerts.json (alerts.json.1, alerts.json.gz ...), oldest first."""
        real_root = self._real_root()
        if real_root is None:
            return []
        base = self.alerts_log.name
        out: list[tuple[float, str, Path]] = []
        try:
            entries = list(self.root.iterdir())
        except OSError as exc:
            log.warning("Alerts directory %s is not readable: %s", self.root, exc)
            return []
        for entry in entries:
            name = entry.name
            if name == base or not name.startswith(base) or name.endswith(SKIP_SUFFIXES):
                continue
            st = self._regular_file(entry, real_root)
            if st is None:
                continue
            if exclude is not None and ident_of(st) == exclude:
                continue
            out.append((st.st_mtime, str(entry), entry))
        return [path for _, _, path in sorted(out)]

    def find_previous_file(self, head: str, ts: float) -> tuple[Path, date] | None:
        """The rotated copy of the file whose first-line digest is `head`.

        Candidates: siblings of alerts.json, then the archives from the day before
        `ts` on, then all older archives, newest first.
        """
        saved_day = local_date(ts)
        archives = self.list_dated_archives()
        cutoff = saved_day - timedelta(days=1)
        near = [a for a in archives if a[0] >= cutoff]
        far = [a for a in reversed(archives) if a[0] < cutoff]
        siblings = [(saved_day, p) for p in self.find_sibling_files()]
        for day, path in siblings + near + far:
            if file_head_digest(path) == head:
                return path, day
        return None

    def archives_since(self, ts: float, exclude: FileIdent | None) -> list[tuple[date, Path]]:
        """Dated archives of the local day of `ts` or later."""
        since = local_date(ts)
        return [a for a in self.list_dated_archives(exclude=exclude) if a[0] >= since]
