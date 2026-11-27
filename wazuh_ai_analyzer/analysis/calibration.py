"""Deterministic severity calibration of finished findings (#118, #119, #120).

The model (or the decision thresholds) rate what an alert says, but they cannot see
what the alert is *about*: a scheduled file-integrity change after a package upgrade
looks like tampering, a vulnerability alert for a package that was just updated looks
like a live CVE, and a dpkg state in the middle of an upgrade looks like a broken
package. The checks here use the facts that `ingest.sanitize` attaches to the groups
(`ingest/facts.py`) plus the facts of earlier batches, and they only ever *lower* a
severity:

* A downgrade is never silent. The reason is appended to the description, the
  recommendation starts with the check that settles the question, and in decision
  mode the change is recorded in `findings.decision["calibration"]`.
* Nothing is dropped. A finding keeps its place; at worst it ends up as `info`.
* Evidence beats rating: whatever speaks for real tampering (a sensitive path, a
  path no package installs to, changed owner/permissions, a changed hash without a
  changed size or mtime, other high-level alerts of the same agent, a change in a
  system directory without any package activity) switches the downgrade off.
* Missing data switches it off as well. A group without facts is never downgraded. When
  a group has more facts than fit, the ones that speak against a downgrade (file
  changes with an indicator, the most severe CVEs, unfinished package states) are kept
  first (`sanitize`); checks that would otherwise rely on the missing ones (the CVE
  severity, the end of a package list, "no package activity") treat a cut-off group as
  unknown and leave the rating alone.

The module works on the result of any backend, so the LLM and the decision mode get
the same treatment. It never raises for odd input; the pipeline additionally keeps the
uncalibrated result if a check fails.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Final, Protocol, cast

from ..ingest import facts as fx
from ..ingest.sanitize import (
    SUMMARY_MAX,
    TEXT_MAX,
    TITLE_MAX,
    AlertFact,
    AlertGroup,
    clean_text,
    sanitize_group,
)
from ..storage.contract import SEVERITIES, OverallRisk, Severity
from ..storage.repo import NewFinding
from .backend import AnalysisResult
from .prompt import SUSPICIOUS_LEVEL

log = logging.getLogger(__name__)

# How far back package activity of earlier batches counts as "nearby" for a change that
# a scheduled scan reports only some time after it happened.
PACKAGE_WINDOW_HOURS: Final = 24.0
HISTORY_BATCHES_MAX: Final = 400
NOTE_TITLE: Final = "Automatische Plausibilitätsprüfung"

_LEVEL_SEVERITY: Final[tuple[tuple[int, Severity], ...]] = (
    (15, "critical"),
    (12, "high"),
    (7, "medium"),
    (4, "low"),
)


class History(Protocol):
    """Where the facts of earlier batches come from (`Repository`)."""

    def recent_fact_batches(self, *, exclude_batch: int, hours: float, limit: int) -> list[str]:
        """The `raw_groups` documents of batches of the last `hours` that hold facts."""
        ...


def rank(severity: str) -> int:
    """0 for critical ... 4 for info: lower is more severe."""
    return SEVERITIES.index(severity)


def severity_for_level(level: int) -> Severity:
    """Wazuh's own level as a severity (0-3 info, 4-6 low, 7-11 medium, 12-14 high, 15 critical)."""
    for minimum, severity in _LEVEL_SEVERITY:
        if level >= minimum:
            return severity
    return "info"


def one_step_above(severity: Severity) -> Severity:
    return cast(Severity, SEVERITIES[max(rank(severity) - 1, 0)])


def lowered(severity: Severity, cap: Severity) -> Severity:
    """`severity`, but no more severe than `cap`."""
    return cap if rank(severity) < rank(cap) else severity


def less_severe(a: Severity, b: Severity) -> Severity:
    return a if rank(a) >= rank(b) else b


@dataclass(frozen=True, slots=True)
class Adjustment:
    """What one check wants for a finding.

    `cap` is the most severe rating the finding may keep (None: no change of the
    severity, only the note and the recommendation). `reason` is one German sentence,
    `first_step` the check that has to come first.
    """

    tag: str
    reason: str
    cap: Severity | None = None
    first_step: str = ""


# ── what the checks can see ──────────────────────────────────────────────────
class Evidence:
    """The groups of the batch plus, lazily, the package facts of the last day."""

    def __init__(
        self,
        groups: Sequence[AlertGroup],
        history: History | None,
        batch_id: int,
    ) -> None:
        self.groups = list(groups)
        self._history = history
        self._batch_id = batch_id
        self._package_facts: list[AlertFact] | None = None

    def package_facts(self) -> list[AlertFact]:
        if self._package_facts is None:
            found = [f for g in self.groups for f in g.get("facts", []) if f["k"] == fx.FACT_PKG]
            for group in self._history_groups():
                found.extend(f for f in group.get("facts", []) if f["k"] == fx.FACT_PKG)
            self._package_facts = found
        return self._package_facts

    def _history_groups(self) -> list[AlertGroup]:
        if self._history is None:
            return []
        try:
            documents = self._history.recent_fact_batches(
                exclude_batch=self._batch_id,
                hours=PACKAGE_WINDOW_HOURS,
                limit=HISTORY_BATCHES_MAX,
            )
        except Exception:
            log.warning(
                "Calibration: the facts of earlier batches could not be read", exc_info=True
            )
            return []
        groups: list[AlertGroup] = []
        for document in documents:
            try:
                parsed = json.loads(document)
            except (ValueError, RecursionError):
                continue
            if isinstance(parsed, list):
                groups.extend(sanitize_group(g) for g in parsed if isinstance(g, dict))
        return groups

    def has_package_activity(self, agent: str) -> bool:
        return any(f.get("agent") == agent for f in self.package_facts())

    def finished_after(self, agent: str, package: str, stamp: str) -> bool:
        """A final dpkg state of `package` on `agent` at or after `stamp`."""
        base = fx.package_base_name(package)
        return any(
            f.get("agent") == agent
            and fx.package_base_name(f.get("pkg", "")) == base
            and f.get("st") in fx.PKG_FINAL_STATES
            and bool(stamp)
            and f.get("ts", "") >= stamp
            for f in self.package_facts()
        )

    def installed_version(self, agent: str, package: str, version: str) -> bool:
        """The package manager put exactly this version on `agent` (batch or last day)."""
        base = fx.package_base_name(package)
        return bool(version) and any(
            f.get("agent") == agent
            and fx.package_base_name(f.get("pkg", "")) == base
            and f.get("ver") == version
            and f.get("st") in {"installed", "install", "upgrade"}
            for f in self.package_facts()
        )


@dataclass(frozen=True, slots=True)
class Scope:
    """The part of the batch one finding is about."""

    finding: NewFinding
    groups: list[AlertGroup]

    def facts(self, kind: str) -> list[AlertFact]:
        agents = set(self.finding.affected_agents)
        return [
            f
            for g in self.groups
            for f in g.get("facts", [])
            if f["k"] == kind and (not agents or f.get("agent") in agents)
        ]

    def only_kind(self, kind: str) -> bool:
        """Every covered group has facts, and all of them are of `kind`."""
        return bool(self.groups) and all(
            g.get("facts") and all(f["k"] == kind for f in g["facts"]) for g in self.groups
        )

    @property
    def truncated(self) -> bool:
        return any(g.get("facts_more", 0) > 0 for g in self.groups)


def _scope(finding: NewFinding, groups: Sequence[AlertGroup]) -> Scope:
    rules = set(finding.rule_ids)
    return Scope(finding, [g for g in groups if g["rule_id"] in rules])


# ── #119: vulnerability alerts ───────────────────────────────────────────────
VULN_FIRST_STEP: Final = (
    "Die installierte Paketversion mit der behobenen Version im Security-Tracker der"
    " Distribution vergleichen (Debian: security-tracker.debian.org). Ist die installierte"
    " Version dort als behoben geführt, ist der Alert ein Feed-Rückstand."
)


def _group_vuln_severities(group: AlertGroup) -> set[str] | None:
    """The severities a vulnerability group can stand for, or None if that is unknown.

    Facts decide when they are complete; otherwise the rule's own severity does.
    """
    facts = [f for f in group.get("facts", []) if f["k"] == fx.FACT_VULN]
    from_rule = fx.VULN_RULE_SEVERITY.get(group["rule_id"])
    if facts and not group.get("facts_more"):
        active = [f for f in facts if f.get("status", "").lower() != fx.VULN_STATUS_SOLVED]
        severities: set[str] = set()
        for fact in active:
            label = fact.get("sev", "") or (from_rule or "")
            if not label:
                return None
            severities.add(label)
        return severities
    return {from_rule} if from_rule else None


def check_vulnerability(scope: Scope, evidence: Evidence) -> list[Adjustment]:
    """Cap at the severity the alerts carry; a CVE marked `Solved` is info; flag feed lag."""
    if not scope.groups or not all(
        fx.VULN_RULE_SEVERITY.get(g["rule_id"])
        or any(f["k"] == fx.FACT_VULN for f in g.get("facts", []))
        for g in scope.groups
    ):
        return []
    facts = scope.facts(fx.FACT_VULN)
    active = [f for f in facts if f.get("status", "").lower() != fx.VULN_STATUS_SOLVED]
    complete = (
        bool(facts)
        and not scope.truncated
        and all(any(f["k"] == fx.FACT_VULN for f in g.get("facts", [])) for g in scope.groups)
    )
    adjustments: list[Adjustment] = []

    if complete and not active:
        return [
            Adjustment(
                "vuln-solved",
                "Alle betroffenen Schwachstellen sind im Alert als „Solved“ markiert, das Paket"
                " ist also bereits behoben.",
                cap="info",
            )
        ]

    levels: set[str] = set()
    known = True
    for group in scope.groups:
        found = _group_vuln_severities(group)
        if found is None:
            known = False
            break
        levels |= found
    cap: Severity | None = None
    if known and levels:
        cap = cast(Severity, min(levels, key=rank))
        adjustments.append(
            Adjustment(
                "vuln-severity",
                f"Die Alerts selbst nennen höchstens den Schweregrad „{cap}“"
                " (Wazuh-Schwachstellenerkennung); eine höhere Einstufung ist nicht belegt.",
                cap=cap,
            )
        )

    default_status = [f for f in active if f.get("cond", "").lower() == fx.VULN_CONDITION_DEFAULT]
    if default_status:
        adjustments.append(
            Adjustment(
                "vuln-no-fixed-version",
                "Der Alert nennt keine behobene Version bei „Package default status“. Nach einem"
                " Paket-Update ist das häufig ein Rückstand des Schwachstellen-Feeds und kein"
                " Hinweis auf eine verwundbare Version.",
                first_step=VULN_FIRST_STEP,
            )
        )
    if (
        complete
        and active
        and all(
            f.get("cond", "").lower() == fx.VULN_CONDITION_DEFAULT
            and evidence.installed_version(f.get("agent", ""), f.get("pkg", ""), f.get("ver", ""))
            for f in active
        )
    ):
        adjustments.append(
            Adjustment(
                "vuln-fresh-package",
                "Die betroffenen Paketversionen wurden laut dpkg-Log in den letzten"
                f" {PACKAGE_WINDOW_HOURS:g} Stunden installiert; ohne bekannte behobene Version"
                " ist das wahrscheinlich ein Feed-Rückstand.",
                cap="medium",
                first_step=VULN_FIRST_STEP,
            )
        )
    return adjustments


# ── #120: transient dpkg states ──────────────────────────────────────────────
AUDIT_FIRST_STEP: Final = (
    "Auf dem Agent `dpkg --audit` ausführen. Ist die Ausgabe leer und das Paket installiert,"
    " war der Zustand nur ein Zwischenschritt während eines Updates."
)


def check_transient_package_state(scope: Scope, evidence: Evidence) -> list[Adjustment]:
    """A half-configured package that a later `installed` line settled is only a snapshot."""
    if not scope.only_kind(fx.FACT_PKG):
        return []
    facts = scope.facts(fx.FACT_PKG)
    if not facts or any(f.get("st") not in fx.PKG_TRANSIENT_STATES for f in facts):
        return []
    unresolved = [
        f
        for f in facts
        if not evidence.finished_after(f.get("agent", ""), f.get("pkg", ""), f.get("ts", ""))
    ]
    if not unresolved and not scope.truncated:
        return [
            Adjustment(
                "pkg-transient-resolved",
                "Für jedes gemeldete Paket folgt im dpkg-Log ein Eintrag „installed“: der Zustand"
                " war nur ein Zwischenschritt während eines Updates.",
                cap="info",
            )
        ]
    return [
        Adjustment(
            "pkg-transient-unknown",
            "Der Endzustand der Pakete ist aus den Alerts nicht bekannt (es folgte kein Eintrag"
            " „installed“ oder die Liste ist unvollständig); ein Zwischenstand während eines"
            " Updates ist wahrscheinlicher als ein defektes Paket.",
            cap="medium",
            first_step=AUDIT_FIRST_STEP,
        )
    ]


# ── #118: file integrity changes ─────────────────────────────────────────────
FIM_FIRST_STEP: Final = (
    "Zuerst prüfen: Paket der Datei mit `dpkg -S <Pfad>` ermitteln und mit `dpkg -V <Paket>`"
    " (rpm: `rpm -V <Paket>`) verifizieren, ob die Datei dem Paket entspricht, und die Änderung"
    " mit dem dpkg-Log vergleichen. Erst wenn die Prüfung abweicht, den Host eindämmen."
)


def _other_high_alerts(evidence: Evidence, scope: Scope, agents: set[str]) -> bool:
    """Alerts of the same agent that are neither file changes nor package activity but severe."""
    covered = {id(g) for g in scope.groups}
    for group in evidence.groups:
        if id(group) in covered or group["max_level"] < SUSPICIOUS_LEVEL:
            continue
        kinds = {f["k"] for f in group.get("facts", [])}
        if kinds and kinds <= {fx.FACT_FIM, fx.FACT_PKG, fx.FACT_VULN}:
            continue
        if not agents or agents & set(group["agents"]):
            return True
    return False


def check_file_integrity(scope: Scope, evidence: Evidence) -> list[Adjustment]:
    """Scheduled changes after package activity are medium at most, and never rise by more
    than one step above the rule level without an indicator of tampering."""
    if not scope.only_kind(fx.FACT_FIM):
        return []
    facts = scope.facts(fx.FACT_FIM)
    if not facts or any("ind" in f for f in facts):
        return []
    agents = {f.get("agent", "") for f in facts}
    if scope.truncated:
        # The facts that were cut off may belong to other agents of the finding.
        agents |= set(scope.finding.affected_agents) or {
            a for g in scope.groups for a in g["agents"]
        }
    if _other_high_alerts(evidence, scope, agents):
        return []
    if scope.truncated and not all(evidence.has_package_activity(a) for a in agents):
        return []
    anchor = one_step_above(severity_for_level(max(g["max_level"] for g in scope.groups)))
    caps: list[Severity] = []
    explained = False
    for fact in facts:
        if evidence.has_package_activity(fact.get("agent", "")):
            caps.append("medium")
            explained = True
        elif (
            fact.get("mode", "") == "scheduled"
            and not scope.truncated  # a cut-off fact may be a system binary
            and not fx.is_system_binary_path(fact["path"])
        ):
            caps.append(anchor)
        else:
            # A change in a system directory without any package activity stays as rated.
            return []
    cap = min(caps, key=rank)  # the least restrictive one: the most severe cap
    if explained:
        return [
            Adjustment(
                "fim-package-activity",
                "Auf dem Agent gab es zeitnah Paketaktivität (dpkg-Log), und an den Änderungen"
                " ist nichts auffällig: weder sensible Pfade noch Pfade außerhalb der"
                " Paketverzeichnisse, noch geänderte Rechte oder Eigentümer, noch ein geänderter"
                " Hash bei gleicher Größe und Änderungszeit. Das spricht für ein Paket-Update;"
                " ein Beleg für Manipulation liegt nicht vor.",
                cap=cap,
                first_step=FIM_FIRST_STEP,
            )
        ]
    return [
        Adjustment(
            "fim-level-anchor",
            "Eine geplante Integritätsprüfung nennt nicht, wann die Änderung stattfand, und es"
            " gibt keinen weiteren Hinweis auf Manipulation. Die Einstufung steigt deshalb"
            f" höchstens eine Stufe über das Wazuh-Level der Regel (hier „{cap}“).",
            cap=cap,
            first_step=FIM_FIRST_STEP,
        )
    ]


# ── #80: records of a response and failed logins alone ───────────────────────
# The description of a log line of a blocking tool (fail2ban, CrowdSec, a firewall, a
# rate limiter) starts with the verb: "blocked <ip> for 4h", "Ban <ip>". The optional label
# in front is the tool or decoder name ("Fail2Ban: ...").
_BLOCK_RECORD = re.compile(
    r"^\W*(?:\[[\w .\-]{1,30}\]\s*|[\w .\-]{1,30}:\s*)?"
    r"(?:block(?:ed|ing)?|ban(?:ned|ning)?|drop(?:ped)?|reject(?:ed)?|deny|denied"
    r"|rate[- ]?limit(?:ed|ing)?|throttl(?:ed|ing))\b",
    re.IGNORECASE,
)
# Wazuh rules for failed authentication (sshd, PAM, syslog, Windows).
FAILED_LOGIN_RULES: Final = frozenset(
    {"2501", "2502", "5503", "5551", "5710", "5711", "5712", "5716", "5720", "5758", "5760"}
    | {"5763", "40111", "60122", "60204"}
)
_FAILED_LOGIN_TEXT = re.compile(
    r"\b(?:authentication (?:failure|failed)|failed (?:password|login|logon)|login failed"
    r"|logon failure|invalid user|illegal user|non-?existent user|missed the password)\b",
    re.IGNORECASE,
)
LOGIN_SUCCESS_RULES: Final = frozenset({"5501", "5715", "60106"})
_LOGIN_SUCCESS_TEXT = re.compile(
    r"\b(?:accepted (?:password|publickey)|login success|logon success|successful login"
    r"|session opened)\b",
    re.IGNORECASE,
)
FAILED_LOGIN_CAP: Final[Severity] = "medium"
BLOCK_RECORD_CAP: Final[Severity] = "low"


def is_block_record(group: AlertGroup) -> bool:
    """The alert is the log line of a blocking tool, not an event of the attack itself."""
    return _BLOCK_RECORD.match(group["description"]) is not None


def is_failed_login(group: AlertGroup) -> bool:
    return group["rule_id"] in FAILED_LOGIN_RULES or bool(
        _FAILED_LOGIN_TEXT.search(group["description"])
    )


def is_login_success(group: AlertGroup) -> bool:
    return group["rule_id"] in LOGIN_SUCCESS_RULES or bool(
        _LOGIN_SUCCESS_TEXT.search(group["description"])
    )


def check_block_record(scope: Scope, evidence: Evidence) -> list[Adjustment]:
    """A "blocked <ip>" line says the source was stopped: low, not a successful attack."""
    if not scope.groups or not all(is_block_record(g) for g in scope.groups):
        return []
    return [
        Adjustment(
            "block-record",
            "Die Alerts sind Protokolleinträge einer Sperre (Ban, Block oder Rate-Limit): die"
            " Quelle wurde bereits blockiert, ein erfolgreicher Angriff ist daraus nicht"
            " abzulesen. Der Angriff selbst steht in den Findings zu den Alerts davor.",
            cap=BLOCK_RECORD_CAP,
        )
    ]


def check_failed_logins(scope: Scope, evidence: Evidence) -> list[Adjustment]:
    """Failed logins alone are background noise at internet-facing hosts: medium at most.

    The cap is off when a successful login of the same agent is in the batch (the
    alerts then may describe a burst of failures that ended in access).
    """
    if not scope.groups or not all(
        is_failed_login(g) and not is_block_record(g) for g in scope.groups
    ):
        return []
    agents = set(scope.finding.affected_agents) or {a for g in scope.groups for a in g["agents"]}
    for group in evidence.groups:
        if is_login_success(group) and (not agents or agents & set(group["agents"])):
            return []
    return [
        Adjustment(
            "failed-logins",
            "Fehlgeschlagene Anmeldungen allein sind Hintergrundrauschen an erreichbaren Hosts;"
            " im Batch gibt es keine erfolgreiche Anmeldung desselben Agents, die auf einen"
            " Einbruch hindeutet.",
            cap=FAILED_LOGIN_CAP,
        )
    ]


CHECKS: Final[tuple[Callable[[Scope, Evidence], list[Adjustment]], ...]] = (
    check_vulnerability,
    check_transient_package_state,
    check_file_integrity,
    check_block_record,
    check_failed_logins,
)


# ── applying ─────────────────────────────────────────────────────────────────
def apply_adjustments(finding: NewFinding, adjustments: Sequence[Adjustment]) -> NewFinding:
    """`finding` with the lowest cap applied, the reasons in the description, the first
    steps in front of the recommendation and the change recorded in `decision`."""
    # A cap above the current rating changes nothing and needs no explanation.
    adjustments = [a for a in adjustments if a.cap is None or rank(finding.severity) < rank(a.cap)]
    if not adjustments:
        return finding
    severity: Severity = finding.severity
    for adjustment in adjustments:
        if adjustment.cap is not None:
            severity = lowered(severity, adjustment.cap)
    lines = [a.reason for a in adjustments]
    if severity != finding.severity:
        lines.insert(0, f"Einstufung von „{finding.severity}“ auf „{severity}“ herabgestuft.")
    note = f"\n\n{NOTE_TITLE}: " + " ".join(lines)
    description = clean_text(finding.description, TEXT_MAX - len(note), multiline=True) + note
    steps = [a.first_step for a in adjustments if a.first_step]
    recommendation = finding.recommendation
    if steps:
        prefix = " ".join(dict.fromkeys(steps)) + "\n\n"
        recommendation = prefix + clean_text(
            finding.recommendation, TEXT_MAX - len(prefix), multiline=True
        )
    decision = finding.decision
    if decision is not None and severity != finding.severity:
        entries = [
            {"rule": a.tag, "from": finding.severity, "to": severity}
            for a in adjustments
            if a.cap is not None
        ]
        decision = {**decision, "calibration": entries}
    return replace(
        finding,
        severity=severity,
        description=clean_text(description, TEXT_MAX, multiline=True),
        recommendation=clean_text(recommendation, TEXT_MAX, multiline=True),
        decision=decision,
    )


# ── #80: one finding per agent and rule set ──────────────────────────────────
MERGED_LIST_MAX: Final = 40
MERGED_TITLE_MAX: Final = 100


def merge_findings(findings: Sequence[NewFinding]) -> list[NewFinding]:
    """Findings of the same agents and the same rules become one, rated like the most severe.

    A burst of 35 CVE alerts for one agent is one situation, not 35. The merged finding
    keeps the most severe member's text and lists the titles of the others in the
    description. Findings without rule ids or agents are never merged (the key would
    say nothing).
    """
    keyed: dict[tuple[frozenset[str], frozenset[str]], list[int]] = {}
    for index, finding in enumerate(findings):
        if finding.rule_ids and finding.affected_agents:
            key = (frozenset(finding.rule_ids), frozenset(finding.affected_agents))
            keyed.setdefault(key, []).append(index)
    merged_into: dict[int, NewFinding] = {}
    absorbed: set[int] = set()
    for indexes in keyed.values():
        if len(indexes) < 2:
            continue
        members = sorted((findings[i] for i in indexes), key=lambda f: rank(f.severity))
        lead, rest = members[0], members[1:]  # the sort is stable: equal ones keep their order
        others = [clean_text(f.title, MERGED_TITLE_MAX) for f in rest]
        listed = others[:MERGED_LIST_MAX]
        more = len(others) - len(listed)
        lines = [f"- {title}" for title in listed]
        if more:
            lines.append(f"- ... und {more} weitere")
        note = (
            f"\n\nZusammengefasst: {len(members)} Findings mit gleichem Agent und gleichen"
            " Regeln, hier mit dem Titel des schwersten:\n" + "\n".join(lines)
        )
        suffix = f" (+{len(rest)} weitere)"
        recommendations = list(dict.fromkeys(f.recommendation for f in members if f.recommendation))
        decision = lead.decision
        if decision is not None:
            decision = {**decision, "merged": len(members)}
        merged_into[indexes[0]] = replace(
            lead,
            title=clean_text(lead.title, TITLE_MAX - len(suffix)) + suffix,
            description=clean_text(lead.description, TEXT_MAX - len(note), multiline=True) + note,
            recommendation=clean_text("\n\n".join(recommendations), TEXT_MAX, multiline=True),
            decision=decision,
        )
        absorbed.update(indexes[1:])
    return [merged_into.get(i, f) for i, f in enumerate(findings) if i not in absorbed]


def _highest(findings: Sequence[NewFinding]) -> Severity | None:
    return min((f.severity for f in findings), key=rank, default=None)


def _overall(result: AnalysisResult, findings: Sequence[NewFinding]) -> OverallRisk:
    """The batch risk follows the findings: it may not stay above the most severe one left."""
    if result.overall_risk == "unknown":
        return "unknown"
    highest = _highest(findings) or "info"
    return less_severe(result.overall_risk, highest)


def calibrate(
    result: AnalysisResult,
    groups: Sequence[AlertGroup],
    *,
    history: History | None = None,
    batch_id: int = 0,
) -> AnalysisResult:
    """`result` with the severities of its findings checked against the facts of the batch.

    `history` supplies the package activity of the last day (None: the batch alone).
    Returns `result` itself when nothing changed.
    """
    evidence = Evidence(groups, history, batch_id)
    findings: list[NewFinding] = []
    touched = False
    for finding in result.findings:
        scope = _scope(finding, groups)
        adjustments = [a for check in CHECKS for a in check(scope, evidence)]
        updated = apply_adjustments(finding, adjustments)
        if updated is not finding:
            touched = True
            log.info(
                "Calibration: %r %s -> %s (%s)",
                finding.title,
                finding.severity,
                updated.severity,
                ", ".join(a.tag for a in adjustments),
            )
        findings.append(updated)
    lowered_count = sum(
        1 for a, b in zip(result.findings, findings, strict=True) if a.severity != b.severity
    )
    merged = merge_findings(findings)
    merged_count = len(findings) - len(merged)
    if merged_count:
        log.info(
            "Calibration: %d findings merged into others of the same agent and rules", merged_count
        )
        # Most severe first, as the prompt asks of the model; equal ones keep their order.
        merged.sort(key=lambda f: rank(f.severity))
    if not touched and not merged_count:
        return result
    notes: list[str] = []
    if lowered_count:
        notes.append(
            f"{lowered_count} Finding(s) wurden automatisch herabgestuft; der Grund steht jeweils"
            " in der Beschreibung."
        )
    if merged_count:
        notes.append(
            f"{merged_count} Finding(s) mit gleichem Agent und gleichen Regeln wurden"
            " zusammengefasst."
        )
    summary = result.summary
    if notes:
        note = " " + " ".join(notes)
        summary = clean_text(summary, SUMMARY_MAX - len(note), multiline=True) + note
    return replace(
        result,
        summary=summary,
        overall_risk=_overall(result, merged) if lowered_count else result.overall_risk,
        findings=tuple(merged),
        calibrated=lowered_count,
    )
