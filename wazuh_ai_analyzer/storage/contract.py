"""The frozen read interface of the database (R1, R2, C2).

External tools read `analyses.db` directly. The homelab metrics exporter
(`wazuh-ai-findings-metrics` in homelab-infra) counts findings per severity and
source, classifies error batches by the text of `last_error`, detects new
findings through `sqlite_sequence` and reads `batches.created_at` as an ISO 8601
timestamp. Everything in this module is therefore part of the public contract:
changing a value set, a prefix or a format breaks monitoring without any test of
the analyzer itself failing. Only additions are allowed.

`tests/v2/contract/` pins every item below, including the exporter's own SQL.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, Literal, get_args

Severity = Literal["critical", "high", "medium", "low", "info"]
OverallRisk = Literal["critical", "high", "medium", "low", "info", "unknown"]
Source = Literal["live", "history"]
Status = Literal["pending", "analyzing", "done", "error"]
AnalysisMode = Literal["llm", "decision"]

SEVERITIES: Final[tuple[str, ...]] = get_args(Severity)
OVERALL_RISKS: Final[tuple[str, ...]] = get_args(OverallRisk)
SOURCES: Final[tuple[str, ...]] = get_args(Source)
STATUSES: Final[tuple[str, ...]] = get_args(Status)
ANALYSIS_MODES: Final[tuple[str, ...]] = get_args(AnalysisMode)

# ── last_error ────────────────────────────────────────────────────────────────
# The exporter classifies batches in status 'error' with these LIKE patterns:
#   expired  : 'expired:%'  OR 'seit %h nicht analysierbar%'
#   dropped  : 'permanent:%' OR 'bad_response nach%'
#   other    : everything else, including NULL
# The texts are German and stay word for word the same as in analyzer.py.
LAST_ERROR_MESSAGE_MAX: Final = 300

ERROR_REASON_EXPIRED: Final = "expired"
ERROR_REASON_DROPPED: Final = "dropped"
ERROR_REASON_OTHER: Final = "other"


def error_queue_expired(max_age_hours: float) -> str:
    """A batch waited longer than QUEUE_MAX_AGE_HOURS in the queue."""
    return f"expired: laenger als {max_age_hours:g}h in der Warteschlange"


def error_unanalyzable(max_age_hours: float, kind: str, message: str) -> str:
    """A batch kept failing for RETRY_MAX_AGE_HOURS (kind: transient or config)."""
    return f"seit {max_age_hours:g}h nicht analysierbar ({kind}): {message}"


def error_permanent(message: str) -> str:
    """A batch was dropped because retrying the same payload cannot help."""
    return f"permanent: {message}"


def error_bad_response(attempts: int, message: str) -> str:
    """A batch was dropped after too many unusable answers."""
    return f"bad_response nach {attempts} Versuchen: {message}"


def classify_error(last_error: str | None) -> str:
    """Python twin of the exporter's CASE expression (see the contract test).

    SQLite's LIKE ignores the case of ASCII letters only, so the comparison does too.
    """
    text = _ascii_lower(last_error or "")
    if text.startswith("expired:") or _is_unanalyzable(text):
        return ERROR_REASON_EXPIRED
    if text.startswith(("permanent:", "bad_response nach")):
        return ERROR_REASON_DROPPED
    return ERROR_REASON_OTHER


def _ascii_lower(text: str) -> str:
    return "".join(ch.lower() if ch.isascii() else ch for ch in text)


def _is_unanalyzable(lowered: str) -> bool:
    # SQL: LIKE 'seit %h nicht analysierbar%'
    return lowered.startswith("seit ") and "h nicht analysierbar" in lowered[5:]


# ── created_at ────────────────────────────────────────────────────────────────
def iso_utc(timestamp: float) -> str:
    """`batches.created_at` format: ISO 8601, UTC, seconds, `+00:00` offset.

    Example: `2026-10-07T11:37:41+00:00`. It must sort like time (retention and
    expiry compare these strings) and parse with `datetime.fromisoformat`.
    """
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat(timespec="seconds")


# ── schema ────────────────────────────────────────────────────────────────────
# `sqlite_sequence` is maintained by SQLite for AUTOINCREMENT tables; the
# exporter reads the highest `findings` id from it and relies on ids never being
# reused. Both tables must therefore stay `INTEGER PRIMARY KEY AUTOINCREMENT`.
TABLE_BATCHES: Final = "batches"
TABLE_FINDINGS: Final = "findings"
