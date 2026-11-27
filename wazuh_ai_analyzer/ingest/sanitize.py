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

One addition over the legacy grouping (#118-#120): alerts of three families (file
integrity, dpkg log, vulnerability detector) also leave a short, whitelisted *fact*
in their group (`facts`, see `facts.py`). A group without such alerts is byte-for-byte
the legacy group.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Final, NotRequired, Required, TypedDict

from . import facts as fx

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
FACTS_MAX: Final = 60  # facts kept per group
FACTS_COLLECT_MAX: Final = 500  # distinct facts a group builder remembers while grouping
FACT_PATH_MAX: Final = 200
FACT_NAME_MAX: Final = 120  # package, CVE id, condition
FACT_ATTRS_MAX: Final = 80

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


class AlertFact(TypedDict, total=False):
    """One whitelisted observation of an alert (`facts.py`). All values are short strings.

    `k` is the kind (`fim`, `pkg`, `vuln`), `agent` the agent name. The other keys
    depend on the kind: fim: `path`, `ev`, `mode`, `chg`, `ind`; pkg: `ts`, `pkg`,
    `st`, `ver`; vuln: `cve`, `sev`, `status`, `pkg`, `ver`, `cond`.
    """

    k: Required[str]
    agent: str
    ts: str
    path: str
    ev: str
    mode: str
    chg: str
    ind: str
    pkg: str
    st: str
    ver: str
    cve: str
    sev: str
    status: str
    cond: str


class AlertGroup(TypedDict):
    rule_id: str
    description: str
    count: int
    max_level: int
    agents: list[str]
    locations: list[str]
    samples: list[AlertSample]
    # Only present for alerts of the fact families, see `AlertFact`.
    facts: NotRequired[list[AlertFact]]
    # How many facts were left out because of `FACTS_MAX` (only when > 0).
    facts_more: NotRequired[int]


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
    result: AlertGroup = {
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
    raw_facts = data.get("facts")
    if isinstance(raw_facts, list):
        kept = [f for f in map(sanitize_fact, raw_facts[:FACTS_MAX]) if f is not None]
        if kept:
            result["facts"] = kept
            more = max(as_int(data.get("facts_more")), 0) + max(len(raw_facts) - FACTS_MAX, 0)
            if more:
                result["facts_more"] = more
    return result


# ── facts ─────────────────────────────────────────────────────────────────────
def _enum_or_empty(value: object, allowed: Iterable[str]) -> str:
    text = clean_text(value, SHORT_MAX).lower()
    return text if text in allowed else ""


def sanitize_fact(raw: object) -> AlertFact | None:
    """A fact with only known keys and cleaned or whitelisted values, or None.

    Idempotent. Facts read back from the database go through here as well, so the
    deterministic checks and the prompt only ever see this shape.
    """
    data = as_dict(raw)
    kind = data.get("k")
    if not isinstance(kind, str) or kind not in fx.FACT_KINDS:
        return None
    fact: AlertFact = {"k": kind}
    agent = clean_text(data.get("agent"), FIELD_MAX)
    if agent:
        fact["agent"] = agent
    if kind == fx.FACT_FIM:
        path = clean_text(data.get("path"), FACT_PATH_MAX)
        if not path:
            return None
        fact["path"] = path
        if event := _enum_or_empty(data.get("ev"), fx.FIM_EVENTS):
            fact["ev"] = event
        if mode := _enum_or_empty(data.get("mode"), fx.FIM_MODES):
            fact["mode"] = mode
        if chg := clean_text(data.get("chg"), FACT_ATTRS_MAX):
            fact["chg"] = chg
        if ind := _enum_or_empty(data.get("ind"), fx.FIM_INDICATORS):
            fact["ind"] = ind
    elif kind == fx.FACT_PKG:
        state = _enum_or_empty(data.get("st"), fx.PKG_STATES)
        package = clean_text(data.get("pkg"), FACT_NAME_MAX)
        if not state or not package:
            return None
        fact["st"] = state
        fact["pkg"] = package
        if stamp := clean_text(data.get("ts"), SAMPLE_TS_MAX):
            fact["ts"] = stamp
        if version := clean_text(data.get("ver"), FACT_NAME_MAX):
            fact["ver"] = version
    else:
        cve = clean_text(data.get("cve"), FACT_NAME_MAX)
        if not cve:
            return None
        fact["cve"] = cve
        if sev := fx.vuln_severity(clean_text(data.get("sev"), SHORT_MAX)):
            fact["sev"] = sev
        if status := clean_text(data.get("status"), SHORT_MAX):
            fact["status"] = status
        if package := clean_text(data.get("pkg"), FACT_NAME_MAX):
            fact["pkg"] = package
        if version := clean_text(data.get("ver"), FACT_NAME_MAX):
            fact["ver"] = version
        if cond := clean_text(data.get("cond"), FACT_NAME_MAX):
            fact["cond"] = cond
    return fact


def _attribute_list(value: object) -> str:
    if not isinstance(value, list):
        return ""
    names = {clean_text(v, 20).lower() for v in value if isinstance(v, str)}
    return ",".join(sorted(n for n in names if n))[:FACT_ATTRS_MAX]


def _fim_fact(syscheck: Mapping[str, object]) -> AlertFact | None:
    path = clean_text(syscheck.get("path"), FACT_PATH_MAX)
    if not path:
        return None
    event = _enum_or_empty(syscheck.get("event"), fx.FIM_EVENTS)
    chg = _attribute_list(syscheck.get("changed_attributes"))
    fact: AlertFact = {"k": fx.FACT_FIM, "path": path}
    if event:
        fact["ev"] = event
    if mode := _enum_or_empty(syscheck.get("mode"), fx.FIM_MODES):
        fact["mode"] = mode
    if chg:
        fact["chg"] = chg
    if indicator := fx.fim_indicator(path, event, frozenset(chg.split(",")) - {""}):
        fact["ind"] = indicator
    return fact


def _vuln_fact(vulnerability: Mapping[str, object]) -> AlertFact | None:
    cve = clean_text(vulnerability.get("cve"), FACT_NAME_MAX)
    if not cve:
        return None
    package = as_dict(vulnerability.get("package"))
    fact: AlertFact = {"k": fx.FACT_VULN, "cve": cve}
    if sev := fx.vuln_severity(clean_text(vulnerability.get("severity"), SHORT_MAX)):
        fact["sev"] = sev
    if status := clean_text(vulnerability.get("status"), SHORT_MAX):
        fact["status"] = status
    if name := clean_text(package.get("name"), FACT_NAME_MAX):
        fact["pkg"] = name
    if version := clean_text(package.get("version"), FACT_NAME_MAX):
        fact["ver"] = version
    if cond := clean_text(package.get("condition"), FACT_NAME_MAX):
        fact["cond"] = cond
    return fact


def _pkg_fact(alert: Mapping[str, object]) -> AlertFact | None:
    location = clean_text(alert.get("location"), FIELD_MAX)
    if not location.rsplit("/", 1)[-1].startswith(fx.DPKG_LOG_BASENAME):
        # Only the real dpkg log counts: an attacker can write the same words to any other log.
        return None
    full_log = alert.get("full_log")
    parsed = fx.parse_dpkg_line(full_log) if isinstance(full_log, str) else None
    if parsed is None:
        return None
    state, package, version = parsed
    fact: AlertFact = {"k": fx.FACT_PKG, "pkg": package, "st": state}
    if stamp := clean_text(alert.get("timestamp"), SAMPLE_TS_MAX):
        fact["ts"] = stamp
    if version:
        fact["ver"] = version
    return fact


def extract_fact(alert: Mapping[str, object]) -> AlertFact | None:
    """The fact of one alert, if it belongs to a fact family (`facts.py`), else None.

    * file integrity: the top-level `syscheck` object (decoders cannot create it from log text);
    * vulnerability detector: `data.vulnerability` of an alert from `vulnerability-detector`;
    * dpkg: a status or action line of a `dpkg.log` source.
    """
    fact: AlertFact | None = None
    syscheck = alert.get("syscheck")
    vulnerability = as_dict(alert.get("data")).get("vulnerability")
    if isinstance(syscheck, dict):
        fact = _fim_fact(syscheck)
    elif (
        isinstance(vulnerability, dict)
        and clean_text(alert.get("location"), FIELD_MAX) == fx.VULN_LOCATION
    ):
        fact = _vuln_fact(vulnerability)
    else:
        fact = _pkg_fact(alert)
    if fact is not None:
        agent = clean_text(as_dict(alert.get("agent")).get("name"), FIELD_MAX)
        fact["agent"] = agent or "unknown"
    return fact


def _fact_priority(fact: AlertFact) -> int:
    """Lower is kept first when a group has more facts than `FACTS_MAX`.

    What speaks against a downgrade must never be the part that is cut off: file
    changes with an indicator, the most severe CVEs and the unfinished package states.
    """
    kind = fact["k"]
    if kind == fx.FACT_FIM:
        return 0 if "ind" in fact else 1
    if kind == fx.FACT_VULN:
        severity = fact.get("sev", "")
        return fx.VULN_SEVERITIES.index(severity) if severity in fx.VULN_SEVERITIES else 4
    return 0 if fact.get("st") in fx.PKG_TRANSIENT_STATES else 1


class _GroupBuilder:
    __slots__ = (
        "agents",
        "count",
        "description",
        "facts",
        "facts_lost",
        "facts_stored",
        "levels",
        "locations",
        "samples",
    )

    def __init__(self) -> None:
        self.description = ""
        self.count = 0
        self.agents: set[str] = set()
        self.levels: list[int] = []
        self.locations: set[str] = set()
        self.samples: list[AlertSample] = []
        # Facts by priority (`_fact_priority`): when the builder is full, a more important
        # fact pushes out a less important one, so an indicator can never be lost to
        # ordinary facts that came first.
        self.facts: dict[int, dict[tuple[tuple[str, object], ...], AlertFact]] = {}
        self.facts_stored = 0
        self.facts_lost = 0  # distinct facts that were pushed out or did not fit

    def add_fact(self, fact: AlertFact) -> None:
        key = tuple(sorted(fact.items()))
        priority = _fact_priority(fact)
        bucket = self.facts.setdefault(priority, {})
        if key in bucket:
            return
        if self.facts_stored >= FACTS_COLLECT_MAX:
            worst = max((p for p, b in self.facts.items() if b), default=priority)
            self.facts_lost += 1
            if priority >= worst:
                return
            self.facts[worst].popitem()  # the newest one of the least important kind
            self.facts_stored -= 1
        bucket[key] = fact
        self.facts_stored += 1

    def kept_facts(self) -> tuple[list[AlertFact], int]:
        """At most FACTS_MAX facts, the ones that matter most first, and how many are missing."""
        ordered = [f for p in sorted(self.facts) for f in self.facts[p].values()]
        return ordered[:FACTS_MAX], max(len(ordered) - FACTS_MAX, 0) + self.facts_lost


def group_alerts(alerts: Iterable[object]) -> list[AlertGroup]:
    """Group alerts by rule id; every value in the result is cleaned and capped.

    The order of the groups (highest level first, ties in order of first
    appearance) and of the keys is the one of the legacy code, so the JSON
    stored in `batches.raw_groups` is byte-identical. The only difference are the
    `facts` of the three fact families (see the module docstring).
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
        if (fact := extract_fact(alert)) is not None:
            group.add_fact(fact)
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
    result: list[AlertGroup] = []
    for rule_id, g in builders.items():
        entry: AlertGroup = {
            "rule_id": rule_id,
            "description": g.description,
            "count": g.count,
            "max_level": max(g.levels) if g.levels else 0,
            "agents": sorted(g.agents)[:AGENTS_MAX],
            "locations": sorted(g.locations)[:LOCATIONS_MAX],
            "samples": g.samples,
        }
        facts, missing = g.kept_facts()
        if facts:
            entry["facts"] = facts
            if missing:
                entry["facts_more"] = missing
        result.append(entry)
    return sorted(result, key=lambda g: g["max_level"], reverse=True)
