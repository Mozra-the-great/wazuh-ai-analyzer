"""Strict parsing of one alert line. All content is untrusted data.

Rules, applied before any field of the alert is used:

* the line is UTF-8 (invalid bytes become U+FFFD, like the legacy code) holding
  one JSON object; anything else is INVALID;
* `NaN`, `Infinity` and numbers that overflow to infinity are rejected (the
  legacy code accepted them, and an infinite level crashed the grouping);
* nesting deeper than `MAX_DEPTH` is INVALID (the line length is already capped
  by `lines.ALERT_LINE_MAX`, which bounds the size);
* `rule` must be an object if present and `rule.level` a number if present;
  a missing level counts as 0, as before.

The `MIN_LEVEL` filter itself is unchanged: `level < min_level` is skipped.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Final

from .sanitize import as_dict, as_int

# Wazuh alerts nest about 6 levels deep (data.win.eventdata.*); 64 leaves room
# for unusual decoders without accepting pathological input.
MAX_DEPTH: Final = 64

Alert = dict[str, object]


class LineOutcome(Enum):
    ALERT = "alert"  # an alert at or above the minimum level
    BELOW_MIN_LEVEL = "below_min_level"
    BLANK = "blank"  # empty or whitespace only: ignored, not counted
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class ParsedLine:
    outcome: LineOutcome
    alert: Alert | None = None


_BLANK: Final = ParsedLine(LineOutcome.BLANK)
_INVALID: Final = ParsedLine(LineOutcome.INVALID)
_BELOW: Final = ParsedLine(LineOutcome.BELOW_MIN_LEVEL)


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-finite number {name} is not allowed")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


def _too_deep(value: object, limit: int) -> bool:
    """True if `value` nests deeper than `limit` containers (iterative walk)."""
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            children: list[object] = list(item.values())
        elif isinstance(item, list):
            children = item
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children if isinstance(child, dict | list))
    return False


def decode_json_object(text: str) -> Alert | None:
    """The JSON object in `text`, or None if it is not a valid one. Never raises."""
    try:
        value = json.loads(text, parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or _too_deep(value, MAX_DEPTH):
        return None
    return value


def alert_level(alert: Alert) -> float | None:
    """`rule.level` as a number (missing = 0), or None if the alert is malformed."""
    rule = alert.get("rule", {})
    if not isinstance(rule, dict):
        return None
    level = rule.get("level", 0)
    if isinstance(level, int | float):  # bool is an int, as before
        return level
    return None


def parse_alert_line(line: bytes, min_level: int) -> ParsedLine:
    """Classify one raw line (newline included or not).

    Surrounding whitespace in the sense of `str.strip` is ignored, as in the
    legacy code.
    """
    text = line.decode("utf-8", errors="replace").strip()
    if not text:
        return _BLANK
    alert = decode_json_object(text)
    if alert is None:
        return _INVALID
    level = alert_level(alert)
    if level is None:
        return _INVALID
    if level < min_level:
        return _BELOW
    return ParsedLine(LineOutcome.ALERT, alert)


def urgency_level(alert: Alert) -> int:
    """The level used for the urgent-flush decision (lenient, like the legacy code)."""
    return as_int(as_dict(alert.get("rule")).get("level"))
