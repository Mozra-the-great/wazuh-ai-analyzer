"""The single gate between untrusted alert data and everything downstream (#38, #9).

Alert fields such as `full_log`, `agent.name`, `data.srcip` or `data.dstuser` can be
worded by an attacker (an SSH user name in an auth log is enough). They only leave
the ingest layer as cleaned, length-capped values inside the groups built here.
`group_alerts` is the only producer of the `raw_groups` stored with a batch, and
`sanitize_group` re-cleans groups read back from the database (older versions
stored them uncleaned), so the analysis backends never see a raw alert field.

The behaviour is a faithful port of `analyzer.py` (`_clean_text`, `group_alerts`,
`_sanitize_group`): the differential tests compare both on the same input, because
the JSON of the groups is stored in `batches.raw_groups` and must not change with
the rewrite.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Final, TypedDict

# ── field caps (shared with the analysis backends) ────────────────────────────
FIELD_MAX: Final = 200  # description, location, agent name
LOG_MAX: Final = 250  # full_log excerpt per sample
SHORT_MAX: Final = 64  # rule id, source ip, timestamp
USER_MAX: Final = 100  # data.dstuser
AGENTS_MAX: Final = 20  # agents per group / per finding
LOCATIONS_MAX: Final = 3
SAMPLES_MAX: Final = 3
TITLE_MAX: Final = 200
SUMMARY_MAX: Final = 2000
TEXT_MAX: Final = 5000  # finding description / recommendation
FINDINGS_MAX: Final = 50
RULE_IDS_MAX: Final = 50
# A sample timestamp keeps `YYYY-MM-DDTHH:MM:SS` only, like the legacy code.
SAMPLE_TS_MAX: Final = 19

_DROP_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_LINE_CATEGORIES: Final = frozenset({"Zl", "Zp"})
_MULTILINE_SPACES = re.compile(r"[ \t]*\n[ \t]*")
_MANY_NEWLINES = re.compile(r"\n{3,}")
_MANY_SPACES = re.compile(r" {2,}")


class AlertSample(TypedDict):
    ts: str
    log: str
    src_ip: str
    dst_user: str


class AlertGroup(TypedDict):
    rule_id: str
    description: str
    count: int
    max_level: int
    agents: list[str]
    locations: list[str]
    samples: list[AlertSample]


def clean_text(value: object, limit: int, *, multiline: bool = False) -> str:
    """Plain, bounded text.

    Drops control, format (zero-width, bidi override), surrogate, private-use and
    unassigned characters; turns line breaks into spaces (unless `multiline`);
    defuses the prompt's data delimiters `<<<`/`>>>`; returns at most `limit`
    characters. Anything that is not a string or a number becomes "".
    """
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        return ""
    text = str(value)[: limit * 4 + 16]  # bound the work on huge inputs
    out: list[str] = []
    for ch in text:
        if ch in "\n\r":
            out.append("\n" if multiline else " ")
        elif ch == "\t" or unicodedata.category(ch) in _LINE_CATEGORIES:
            out.append(" ")
        elif unicodedata.category(ch) not in _DROP_CATEGORIES:
            out.append(ch)
    text = "".join(out)
    if multiline:
        text = _MULTILINE_SPACES.sub("\n", text)
        text = _MANY_NEWLINES.sub("\n\n", text)
    else:
        text = _MANY_SPACES.sub(" ", text)
    text = text.replace("<<<", "<<").replace(">>>", ">>")
    return text.strip()[:limit].strip()


def as_dict(value: object) -> Mapping[str, object]:
    """`value` if it is a JSON object, else an empty mapping."""
    return value if isinstance(value, dict) else {}


def as_int(value: object) -> int:
    """Lenient integer conversion: 0 for booleans and anything unconvertible."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        try:
            return int(value)
        except (OverflowError, ValueError):  # inf / nan
            return 0
    if isinstance(value, str | bytes | bytearray):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def clean_list(value: object, item_max: int, limit: int) -> list[str]:
    """Sorted, de-duplicated, cleaned strings from a list (anything else -> [])."""
    if not isinstance(value, list | tuple | set | frozenset):
        return []
    items = {clean_text(v, item_max) for v in value}
    return sorted(i for i in items if i)[:limit]


def sanitize_sample(sample: object) -> AlertSample:
    data = as_dict(sample)
    return {
        "ts": clean_text(data.get("ts"), SHORT_MAX),
        "log": clean_text(data.get("log"), LOG_MAX),
        "src_ip": clean_text(data.get("src_ip"), SHORT_MAX),
        "dst_user": clean_text(data.get("dst_user"), USER_MAX),
    }


def sanitize_group(group: object) -> AlertGroup:
    """Idempotent. Applied to groups read back from the database as well."""
    data = as_dict(group)
    samples = data.get("samples")
    return {
        "rule_id": clean_text(data.get("rule_id"), SHORT_MAX) or "unknown",
        "description": clean_text(data.get("description"), FIELD_MAX),
        "count": max(as_int(data.get("count")), 0),
        "max_level": max(as_int(data.get("max_level")), 0),
        "agents": clean_list(data.get("agents"), FIELD_MAX, AGENTS_MAX),
        "locations": clean_list(data.get("locations"), FIELD_MAX, LOCATIONS_MAX),
        "samples": (
            [sanitize_sample(x) for x in samples[:SAMPLES_MAX]] if isinstance(samples, list) else []
        ),
    }


class _GroupBuilder:
    __slots__ = ("agents", "count", "description", "levels", "locations", "samples")

    def __init__(self) -> None:
        self.description = ""
        self.count = 0
        self.agents: set[str] = set()
        self.levels: list[int] = []
        self.locations: set[str] = set()
        self.samples: list[AlertSample] = []


def group_alerts(alerts: Iterable[object]) -> list[AlertGroup]:
    """Group alerts by rule id; every value in the result is cleaned and capped.

    The order of the groups (highest level first, ties in order of first
    appearance) and of the keys is the one of the legacy code, so the JSON
    stored in `batches.raw_groups` is byte-identical.
    """
    builders: dict[str, _GroupBuilder] = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        rule = as_dict(alert.get("rule"))
        data = as_dict(alert.get("data"))
        rule_id = clean_text(rule.get("id", "unknown"), SHORT_MAX) or "unknown"
        group = builders.get(rule_id)
        if group is None:
            group = builders[rule_id] = _GroupBuilder()
        # Last one wins, like the legacy code.
        group.description = clean_text(rule.get("description"), FIELD_MAX)
        group.count += 1
        group.levels.append(as_int(rule.get("level")))
        agent = clean_text(as_dict(alert.get("agent")).get("name"), FIELD_MAX)
        group.agents.add(agent or "unknown")
        group.locations.add(clean_text(alert.get("location"), FIELD_MAX))
        if len(group.samples) < SAMPLES_MAX:
            group.samples.append(
                sanitize_sample(
                    {
                        "ts": clean_text(alert.get("timestamp"), SAMPLE_TS_MAX),
                        "log": alert.get("full_log"),
                        "src_ip": data.get("srcip"),
                        "dst_user": data.get("dstuser"),
                    }
                )
            )
    result: list[AlertGroup] = [
        {
            "rule_id": rule_id,
            "description": g.description,
            "count": g.count,
            "max_level": max(g.levels) if g.levels else 0,
            "agents": sorted(g.agents)[:AGENTS_MAX],
            "locations": sorted(g.locations)[:LOCATIONS_MAX],
            "samples": g.samples,
        }
        for rule_id, g in builders.items()
    ]
    return sorted(result, key=lambda g: g["max_level"], reverse=True)
