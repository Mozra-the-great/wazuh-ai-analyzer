"""The German texts of the `decision` mode (#88).

Gemini Decision 1 returns probabilities and no text, so every title, description,
summary and placeholder of a finding is built here from facts: the sanitised alert
group, the answers and the thresholds. The recommendations are not here: they belong
to the versioned definitions (`decisions/v1.json`).

Functions return plain text; the caller bounds it with `clean_text`. Everything that
comes from an alert (rule description, agent names, addresses, user names) is already
cleaned by `ingest.sanitize` and is only ever inserted as data.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from ..ingest.sanitize import AlertGroup

PROVIDER: Final = "Gemini Decision 1"
COUNT_MARK: Final = "\N{MULTIPLICATION SIGN}"
AGENTS_SHOWN: Final = 5
SOURCES_SHOWN: Final = 3
RULES_SHOWN: Final = 5

BLOCKED_TITLE_PREFIX: Final = "Nicht analysierbar (vom Anbieter blockiert): "

RUBRIC_LABELS: Final[Mapping[str, str]] = {
    "needs_action_now": "Sofortiger Handlungsbedarf",
    "already_blocked": "Bereits blockiert",
    "known_benign": "Bekanntes harmloses Muster",
}


def percent(probability: float) -> str:
    return f"{round(probability * 100)} %"


def title_suffix(count: int) -> str:
    return f" ({count}{COUNT_MARK})" if count > 1 else ""


def title_base(group: AlertGroup) -> str:
    return group["description"] or f"Wazuh-Regel {group['rule_id']}"


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _listed(items: Sequence[str], shown: int) -> str:
    text = ", ".join(items[:shown])
    return f"{text} und {len(items) - shown} weitere" if len(items) > shown else text


def _facts(group: AlertGroup) -> list[str]:
    lines = [
        f"Wazuh-Regel {group['rule_id']} (Level {group['max_level']}):"
        f" {group['description'] or 'ohne Beschreibung'}.",
        f"{_plural(group['count'], 'Alert', 'Alerts')} auf"
        f" {_plural(len(group['agents']), 'Agent', 'Agents')}:"
        f" {_listed(group['agents'], AGENTS_SHOWN)}.",
    ]
    stamps = sorted(s["ts"] for s in group["samples"] if s["ts"])
    if stamps:
        span = stamps[0] if stamps[0] == stamps[-1] else f"{stamps[0]} bis {stamps[-1]}"
        lines.append(f"Beispiel-Zeitraum: {span}.")
    addresses = sorted({s["src_ip"] for s in group["samples"] if s["src_ip"]})
    users = sorted({s["dst_user"] for s in group["samples"] if s["dst_user"]})
    if addresses:
        lines.append(f"Quell-Adressen in den Beispielen: {_listed(addresses, SOURCES_SHOWN)}.")
    if users:
        lines.append(f"Benutzer in den Beispielen: {_listed(users, SOURCES_SHOWN)}.")
    return lines


def finding_description(
    group: AlertGroup,
    *,
    severity: str,
    relevance: float,
    confidence: float,
    rubric: Mapping[str, float],
    true_at: float,
) -> str:
    """The facts, then the rating, then every rubric answer in plain words."""
    lines = _facts(group)
    lines.append(
        f"Einstufung durch {PROVIDER}: {severity} (Konfidenz {percent(confidence)}),"
        f" Relevanz {percent(relevance)}."
    )
    for key, label in RUBRIC_LABELS.items():
        if key in rubric:
            verdict = "wahrscheinlich" if rubric[key] >= true_at else "unwahrscheinlich"
            lines.append(f"{label}: {verdict} ({percent(rubric[key])}).")
    return "\n".join(lines)


def blocked_description(group: AlertGroup, code: str) -> str:
    lines = _facts(group)
    lines.append(
        f"{PROVIDER} hat diese Gruppe nicht ausgewertet: der Anbieter hat die Anfrage"
        f" blockiert (Code {code}). Die Einstufung folgt deshalb nur dem Wazuh-Level."
    )
    return "\n".join(lines)


BLOCKED_RECOMMENDATION: Final = (
    "Die Alerts dieser Regel manuell prüfen: sie wurden vom Anbieter blockiert und"
    " nicht automatisch bewertet."
)


def batch_summary(
    *,
    groups: int,
    findings: int,
    highest: str | None,
    discarded: int,
    blocked: int,
    unrated_high_level: Sequence[str],
    overlooked: Sequence[str] = (),
    over_limit: int = 0,
) -> str:
    parts = [
        f"{_plural(groups, 'Alert-Gruppe', 'Alert-Gruppen')} mit {PROVIDER} bewertet:"
        f" {findings} als relevant eingestuft"
        + (f" (höchste Einstufung: {highest})" if highest else "")
        + f", {discarded} unter der Schwelle."
    ]
    if blocked:
        parts.append(f"{_plural(blocked, 'Gruppe', 'Gruppen')} vom Anbieter blockiert.")
    if over_limit:
        parts.append(
            f"{_plural(over_limit, 'weiteres Finding', 'weitere Findings')} über dem Limit"
            " nicht gespeichert (niedrigere Einstufung)."
        )
    if overlooked:
        rules = _listed([f"Regel {r}" for r in overlooked], RULES_SHOWN)
        parts.append(f"Unter der Schwelle trotz Wazuh-Level 7 oder höher: {rules}.")
    if unrated_high_level:
        rules = _listed([f"Regel {r}" for r in unrated_high_level], RULES_SHOWN)
        parts.append(
            "Achtung: Wazuh-Level 12 oder höher ohne Finding oder unter medium eingestuft: "
            f"{rules}."
        )
    return " ".join(parts)
