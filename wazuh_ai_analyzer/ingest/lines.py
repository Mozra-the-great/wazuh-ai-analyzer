"""Bounded line reading from alert files (R3).

The legacy code used an unbounded `readline()`: one endless line in `alerts.json`
(a broken writer, a corrupted archive) was loaded into memory whole. Here a line
may hold at most `ALERT_LINE_MAX` bytes before its newline. A longer line is
skipped in chunks of `SKIP_CHUNK` bytes up to its newline, so memory stays
bounded no matter how long it is, and the caller counts it.

1 MiB and not the 64 KiB of `HEAD_LINE_MAX`: Wazuh FIM and Windows event alerts
can exceed 64 KiB, and dropping real alerts would be a loss (F1).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO, Final

ALERT_LINE_MAX: Final = 1024 * 1024  # bytes per alert line, the newline not counted
SKIP_CHUNK: Final = 64 * 1024


class LineKind(Enum):
    LINE = "line"  # a complete line (or the unterminated last line of a final file)
    PARTIAL = "partial"  # an unterminated line of a growing file: nothing consumed
    OVERSIZED = "oversized"  # a too long line, skipped up to and including its newline
    OVERSIZED_OPEN = "oversized_open"  # a too long line whose end is not written yet
    EOF = "eof"


@dataclass(frozen=True, slots=True)
class ReadResult:
    kind: LineKind
    # LINE: the line including its newline. OVERSIZED*: the first bytes of the
    # line (enough for the first-line digest). Empty otherwise.
    data: bytes
    # Bytes the file position moved forward. PARTIAL leaves the position after
    # the partial data: the caller seeks back to the line start.
    consumed: int


def read_line(f: BinaryIO, *, final: bool, limit: int = ALERT_LINE_MAX) -> ReadResult:
    """Read the next line from the current position.

    `final` means the file gets no more data (an archive, a rotated file, a
    backlog range): its unterminated last line counts as a line. In a growing
    file such a line is still being written and comes back as PARTIAL.
    """
    line = f.readline(limit + 1)
    if not line:
        return ReadResult(LineKind.EOF, b"", 0)
    if line.endswith(b"\n"):
        return ReadResult(LineKind.LINE, line, len(line))
    if len(line) <= limit:
        if final:
            return ReadResult(LineKind.LINE, line, len(line))
        return ReadResult(LineKind.PARTIAL, b"", len(line))
    skipped, complete = skip_to_newline(f, final=final)
    kind = LineKind.OVERSIZED if complete else LineKind.OVERSIZED_OPEN
    return ReadResult(kind, line, len(line) + skipped)


def skip_to_newline(f: BinaryIO, *, final: bool) -> tuple[int, bool]:
    """Consume bytes up to and including the next newline, chunk by chunk.

    Returns (bytes consumed, line complete). In a final file the end of the
    file also ends the line.
    """
    consumed = 0
    while True:
        chunk = f.readline(SKIP_CHUNK)
        consumed += len(chunk)
        if chunk.endswith(b"\n"):
            return consumed, True
        if not chunk:
            return consumed, final
