"""The `decision` analysis mode: Gemini Decision 1 over plain REST (#88).

`POST https://generativelanguage.googleapis.com/v1beta/decisions` answers typed
questions about one shared input with calibrated probabilities and no text
(docs: https://aistudio.google.com/docs/decisions-api, model page
https://aistudio.google.com/docs/models/gemini-decision-1).

Design:

* One request per alert group. The group is the shared `input`, serialised as a JSON
  document whose values are data; the questions (`decisions/v1.json`) hold every
  instruction, so log text can never sit in an instruction field (#38).
* The batch stays the retry unit. The validated answers of the groups that are done
  are kept in `batches.decision_partial` (through `BatchContext.partial`), so a retry
  after a 429 or an outage does not pay for them twice.
* Titles, descriptions and the batch summary are built from facts (`text_templates`),
  recommendations come from the definitions. The probabilities are stored in
  `findings.decision` and `findings.confidence`.
* A group is a finding when `relevant >= DECISION_THRESHOLDS[severity]`. A safety
  block (HTTP 400 with a safety `error.code`) is not an error of the batch: the group
  becomes a placeholder finding rated by its Wazuh level, so nothing disappears silently.

The API key goes only into the `x-goog-api-key` header; redirects are not followed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

import requests

from ..config import Config, DecisionThresholds
from ..ingest.sanitize import (
    FINDINGS_MAX,
    SUMMARY_MAX,
    TEXT_MAX,
    TITLE_MAX,
    AlertGroup,
    clean_text,
    sanitize_group,
)
from ..logging_setup import RedactSecrets
from ..secret import Secret
from ..storage.contract import SEVERITIES, AnalysisMode, OverallRisk, Severity
from . import text_templates as texts
from .backend import AnalysisResult, BackendFailure, BatchContext, Finding
from .decisions import (
    RELEVANT,
    RUBRIC_KEYS,
    SEVERITY,
    Definitions,
    Question,
    load_definitions,
)
from .llm import (
    HttpResponse,
    PostFunction,
    _default_post,
    is_config_error_body,
    quota_failure,
    retry_after_seconds,
)
from .prompt import SUSPICIOUS_LEVEL

log = logging.getLogger(__name__)

API_URL: Final = "https://generativelanguage.googleapis.com/v1beta/decisions"
# The model needs 50 to 100 ms; a request that takes longer than this is broken.
REQUEST_TIMEOUT: Final = 30.0
# `error.code` values of an HTTP 400 that mean "the provider refused this input".
SAFETY_CODES: Final = frozenset(
    {"safety", "prohibited_content", "blocklist", "image_safety", "content_blocked"}
)
ERROR_BODY_MAX: Final = 200
PARTIAL_VERSION_KEY: Final = "version"
PARTIAL_GROUPS_KEY: Final = "groups"

# A group below the thresholds is named in the summary from this Wazuh level on.
NOTABLE_LEVEL: Final = 7

# A group without a finding of its own still needs a rating when the provider blocked it:
# Wazuh's own level decides (0-3 info, 4-6 low, 7-11 medium, 12-14 high, 15 critical).
_LEVEL_SEVERITY: Final[tuple[tuple[int, Severity], ...]] = (
    (15, "critical"),
    (12, "high"),
    (7, "medium"),
    (4, "low"),
)

Answer = dict[str, object]


def severity_for_level(level: int) -> Severity:
    for minimum, severity in _LEVEL_SEVERITY:
        if level >= minimum:
            return severity
    return "info"


def severity_rank(severity: str) -> int:
    """0 for critical ... 4 for info: lower is more severe."""
    return SEVERITIES.index(severity)


# ── answer validation ────────────────────────────────────────────────────────
def _number(value: object, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise ValueError(f"{where}: Zahl erwartet")
    return float(value)


def _probability(value: object, where: str) -> float:
    number = _number(value, where)
    if not 0.0 <= number <= 1.0:
        raise ValueError(f"{where}: ausserhalb von 0..1")
    return number


def _probabilities(value: object, allowed: Sequence[str], where: str) -> dict[str, float]:
    if not isinstance(value, dict) or len(value) > len(allowed):
        raise ValueError(f"{where}: Objekt mit Wahrscheinlichkeiten erwartet")
    result: dict[str, float] = {}
    for key, probability in value.items():
        if key not in allowed:
            raise ValueError(f"{where}: unbekannte Option")
        result[key] = _probability(probability, f"{where}.{key}")
    return result


def validate_answer(question: Question, raw: object) -> Answer:
    """One answer, checked against its question; only the expected keys survive.

    The text of an answer (`choice`) must be one of the option keys of the definitions,
    so nothing but our own strings and numbers ever reaches storage.
    """
    where = f"Antwort {question.key!r}"
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: Objekt erwartet")
    if raw.get("type", question.type) != question.type:
        raise ValueError(f"{where}: Typ passt nicht zur Frage")
    answer: Answer = {"type": question.type}
    if question.type == "noul":
        answer["noul"] = _probability(raw.get("noul"), f"{where}.noul")
    elif question.type == "choice":
        choice = raw.get("choice")
        if not isinstance(choice, str) or choice not in question.options:
            raise ValueError(f"{where}.choice: keine bekannte Option")
        answer["choice"] = choice
        answer["probabilities"] = _probabilities(
            raw.get("probabilities"), question.options, f"{where}.probabilities"
        )
    else:
        score = _number(raw.get("score"), f"{where}.score")
        if not 0.0 <= score <= question.levels - 1:
            raise ValueError(f"{where}.score: ausserhalb der Stufen")
        answer["score"] = score
        levels = [str(n) for n in range(question.levels)]
        answer["probabilities"] = _probabilities(
            raw.get("probabilities"), levels, f"{where}.probabilities"
        )
    answer["confidence"] = _probability(raw.get("confidence"), f"{where}.confidence")
    return answer


def validate_answers(definitions: Definitions, data: object) -> dict[str, Answer]:
    """The `answers` object of a response: every question of the definitions is answered."""
    raw = data.get("answers") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        raise ValueError("'answers' fehlt")
    return {q.key: validate_answer(q, raw.get(q.key)) for q in definitions.questions}


# ── one group's outcome ──────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class GroupOutcome:
    """Either validated answers or the safety code the provider refused the group with."""

    answers: Mapping[str, Answer] | None = None
    blocked: str | None = None

    def to_json(self) -> dict[str, object]:
        if self.blocked is not None:
            return {"blocked": self.blocked}
        return {"answers": dict(self.answers or {})}

    @classmethod
    def from_json(cls, definitions: Definitions, raw: object) -> GroupOutcome:
        if not isinstance(raw, dict):
            raise ValueError("outcome is not an object")
        blocked = raw.get("blocked")
        if blocked is not None:
            if not isinstance(blocked, str) or blocked not in SAFETY_CODES:
                raise ValueError("unknown block code")
            return cls(blocked=blocked)
        return cls(answers=validate_answers(definitions, raw))


def group_key(group: AlertGroup) -> str:
    """A stable identity of a group inside a batch (the stored groups are deterministic)."""
    canonical = json.dumps(group, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class _Partial:
    """The answers a batch already has, as stored in `batches.decision_partial`."""

    def __init__(self, definitions: Definitions, context: BatchContext) -> None:
        self._definitions = definitions
        self._context = context
        self.outcomes: dict[str, GroupOutcome] = {}
        if context.partial is not None:
            self._load()

    def _load(self) -> None:
        store = self._context.partial
        assert store is not None  # noqa: S101 - narrowed by the caller
        try:
            document = store.load_decision_partial(self._context.batch_id)
            if document is None:
                return
            parsed = json.loads(document)
            if (
                not isinstance(parsed, dict)
                or parsed.get(PARTIAL_VERSION_KEY) != self._definitions.decision_version
                or not isinstance(parsed.get(PARTIAL_GROUPS_KEY), dict)
            ):
                log.info(
                    "Batch %d: stored answers belong to other definitions", self._context.batch_id
                )
                return
            for key, raw in parsed[PARTIAL_GROUPS_KEY].items():
                self.outcomes[str(key)] = GroupOutcome.from_json(self._definitions, raw)
        except Exception as exc:  # corrupt or unreadable scratch data only costs a request
            log.warning("Batch %d: stored answers ignored (%r)", self._context.batch_id, exc)
            self.outcomes.clear()

    def save(self) -> None:
        store = self._context.partial
        if store is None:
            return
        document = {
            PARTIAL_VERSION_KEY: self._definitions.decision_version,
            PARTIAL_GROUPS_KEY: {k: o.to_json() for k, o in self.outcomes.items()},
        }
        try:
            store.save_decision_partial(self._context.batch_id, json.dumps(document))
        except Exception:
            log.warning("Batch %d: answers so far could not be kept", self._context.batch_id)


# ── the backend ──────────────────────────────────────────────────────────────
class GeminiDecisionBackend:
    """Gemini Decision 1: one `decisions` request per alert group."""

    def __init__(
        self,
        *,
        api_key: Secret | None,
        model: str,
        infra_context: str,
        thresholds: DecisionThresholds,
        definitions: Definitions | None = None,
        post: PostFunction = _default_post,
        scrub: Callable[[str], str] | None = None,
    ) -> None:
        self._api_key = api_key
        if scrub is None:
            secrets = (api_key.reveal(),) if api_key is not None else ()
            scrub = RedactSecrets(secrets).scrub
        self._scrub = scrub
        self._model = model
        self._infra_context = infra_context
        self._thresholds = thresholds
        self.definitions = definitions if definitions is not None else load_definitions()
        self._post = post

    @classmethod
    def from_config(
        cls,
        config: Config,
        *,
        definitions: Definitions | None = None,
        post: PostFunction = _default_post,
    ) -> GeminiDecisionBackend:
        return cls(
            api_key=config.gemini.api_key,
            model=config.analysis.decision_model,
            infra_context=config.gemini.infra_context,
            thresholds=config.analysis.decision_thresholds,
            definitions=definitions,
            post=post,
        )

    @property
    def name(self) -> AnalysisMode:
        return "decision"

    @property
    def model(self) -> str:
        return self._model

    def scrub(self, text: str) -> str:
        """`text` without the API key (for output that is shown to the operator)."""
        return self._scrub(text)

    @property
    def decision_version(self) -> str:
        return self.definitions.decision_version

    # ── request ──────────────────────────────────────────────────────────────
    def _question_payload(self, question: Question) -> dict[str, object]:
        instructions = question.instructions
        if question.infra_context and self._infra_context:
            instructions += (
                f"\n\nInfrastructure context (set by the operator): {self._infra_context}"
            )
        payload: dict[str, object] = {"type": question.type, "instructions": instructions}
        if question.criteria is not None:
            payload["criteria"] = (
                list(question.criteria)
                if isinstance(question.criteria, tuple)
                else dict(question.criteria)
            )
        return payload

    def request_payload(self, group: AlertGroup) -> dict[str, object]:
        """The request body for one group. The group is data inside a JSON document."""
        document = {"kind": "wazuh_alert_group", "untrusted_log_data": sanitize_group(group)}
        return {
            "model": self._model,
            "input": json.dumps(document, ensure_ascii=False, separators=(",", ":")),
            "questions": {q.key: self._question_payload(q) for q in self.definitions.questions},
        }

    def exchange(self, payload: dict[str, object]) -> HttpResponse:
        """Send one request; transport errors become `BackendFailure("transient")`."""
        if self._api_key is None:
            log.error("GEMINI_API_KEY is not set")
            raise BackendFailure("config", "GEMINI_API_KEY nicht gesetzt")
        headers = {"x-goog-api-key": self._api_key.reveal()}
        try:
            return self._post(API_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.Timeout:
            log.error("Gemini Decision: timeout")
            raise BackendFailure("transient", "Gemini Decision: Timeout") from None
        except (requests.ConnectionError, requests.exceptions.ChunkedEncodingError) as exc:
            message = self._scrub(f"Gemini Decision: Verbindungsfehler: {exc}")
            log.error("%s", message)
            raise BackendFailure("transient", message) from None
        except Exception as exc:
            message = self._scrub(f"Gemini Decision: Fehler: {exc}")
            log.error("%s", message)
            raise BackendFailure("bad_response", message) from None

    # ── response ─────────────────────────────────────────────────────────────
    def interpret(self, resp: HttpResponse) -> GroupOutcome:
        """The answers of a response, a safety block, or one `BackendFailure`."""
        if resp.status_code == 429:
            raise quota_failure(resp, self._scrub)
        if not resp.ok:
            blocked = safety_block_code(resp) if resp.status_code == 400 else None
            if blocked is not None:
                log.warning("Gemini Decision: the provider blocked a group (%s)", blocked)
                return GroupOutcome(blocked=blocked)
            raise self._http_failure(resp)
        try:
            return GroupOutcome(answers=validate_answers(self.definitions, resp.json()))
        except (KeyError, IndexError, TypeError, ValueError) as exc:  # JSONDecodeError too
            message = self._scrub(f"Antwort nicht auswertbar: {exc}")
            log.error("Gemini Decision: %s", message)
            raise BackendFailure("bad_response", message) from None

    def _http_failure(self, resp: HttpResponse) -> BackendFailure:
        code = resp.status_code
        message = f"Gemini Decision HTTP {code}: {self._scrub(resp.text)[:ERROR_BODY_MAX]}"
        log.error("%s", message)
        if code >= 500 or code in (408, 425):
            return BackendFailure("transient", message, retry_after_seconds(resp))
        if code in (401, 403, 404):
            return BackendFailure("config", message)
        if code == 400 and is_config_error_body(resp):
            return BackendFailure("config", message)
        return BackendFailure("permanent", message)

    # ── analysis ─────────────────────────────────────────────────────────────
    def analyse(self, groups: Sequence[AlertGroup], context: BatchContext) -> AnalysisResult:
        if self._api_key is None:
            log.error("GEMINI_API_KEY is not set")
            raise BackendFailure("config", "GEMINI_API_KEY nicht gesetzt")
        clean = [sanitize_group(g) for g in groups]
        partial = _Partial(self.definitions, context)
        outcomes: list[GroupOutcome] = []
        for position, group in enumerate(clean):
            key = group_key(group)
            outcome = partial.outcomes.get(key)
            if outcome is None:
                outcome = self.interpret(self.exchange(self.request_payload(group)))
                partial.outcomes[key] = outcome
                if position < len(clean) - 1:  # the last answer completes the batch
                    partial.save()
            outcomes.append(outcome)
        return self.rate(clean, outcomes)

    # ── answers to findings ──────────────────────────────────────────────────
    def rate(
        self, groups: Sequence[AlertGroup], outcomes: Sequence[GroupOutcome]
    ) -> AnalysisResult:
        """Findings, summary and risk of a batch from the outcomes of its groups."""
        findings: list[tuple[int, Finding]] = []
        discarded = blocked = 0
        unrated: list[str] = []
        overlooked: list[str] = []
        for group, outcome in zip(groups, outcomes, strict=True):
            level = group["max_level"]
            if outcome.blocked is not None:
                blocked += 1
                findings.append((level, self._placeholder(group, outcome.blocked)))
                continue
            finding = self._finding(group, outcome.answers or {})
            if finding is None:
                discarded += 1
                if level >= NOTABLE_LEVEL:
                    overlooked.append(group["rule_id"])
            else:
                findings.append((level, finding))
            if level >= SUSPICIOUS_LEVEL and (
                finding is None or finding.severity in ("info", "low")
            ):
                unrated.append(group["rule_id"])
                log.warning(
                    "Rule %s (level %d) is not a finding of at least 'medium' in decision mode",
                    group["rule_id"],
                    level,
                )
        findings.sort(key=lambda item: (severity_rank(item[1].severity), -item[0]))
        kept = tuple(f for _, f in findings[:FINDINGS_MAX])
        cut = findings[FINDINGS_MAX:]
        for level, finding in cut:
            # Too many findings for one batch: what does not fit must still be visible.
            if level >= SUSPICIOUS_LEVEL:
                unrated.append(finding.rule_ids[0])
        if cut:
            log.warning(
                "Decision batch: %d findings over the limit of %d dropped", len(cut), FINDINGS_MAX
            )
        highest = kept[0].severity if kept else None
        risk: OverallRisk = highest if highest is not None else "info"
        summary = clean_text(
            texts.batch_summary(
                groups=len(groups),
                findings=len(kept),
                highest=highest,
                discarded=discarded,
                blocked=blocked,
                unrated_high_level=unrated,
                overlooked=overlooked,
                over_limit=len(cut),
            ),
            SUMMARY_MAX,
            multiline=True,
        )
        return AnalysisResult(
            summary=summary,
            overall_risk=risk,
            findings=kept,
            mode="decision",
            decision_version=self.definitions.decision_version,
            suspicious_downgrades=len(unrated),
            safety_blocked=blocked,
        )

    def _finding(self, group: AlertGroup, answers: Mapping[str, Answer]) -> Finding | None:
        relevance = cast(float, answers[RELEVANT]["noul"])
        severity_answer = answers[SEVERITY]
        severity = cast(Severity, severity_answer["choice"])
        confidence = cast(float, severity_answer["confidence"])
        threshold = self._thresholds.for_severity(severity)
        if threshold is None or relevance < threshold:
            return None
        true_at = self.definitions.rubric_true_at
        rubric = {key: cast(float, answers[key]["noul"]) for key in RUBRIC_KEYS}
        recommendation_key = next((key for key in RUBRIC_KEYS if rubric[key] >= true_at), "default")
        suffix = texts.title_suffix(group["count"])
        return Finding(
            title=clean_text(texts.title_base(group), TITLE_MAX - len(suffix)) + suffix,
            severity=severity,
            description=clean_text(
                texts.finding_description(
                    group,
                    severity=severity,
                    relevance=relevance,
                    confidence=confidence,
                    rubric=rubric,
                    true_at=true_at,
                ),
                TEXT_MAX,
                multiline=True,
            ),
            recommendation=self.definitions.recommendations[recommendation_key],
            affected_agents=tuple(group["agents"]),
            rule_ids=(group["rule_id"],),
            confidence=confidence,
            decision={
                "decision_version": self.definitions.decision_version,
                "wazuh_level": group["max_level"],
                "threshold": threshold,
                "answers": {key: dict(value) for key, value in answers.items()},
            },
        )

    def _placeholder(self, group: AlertGroup, code: str) -> Finding:
        suffix = texts.title_suffix(group["count"])
        room = TITLE_MAX - len(texts.BLOCKED_TITLE_PREFIX) - len(suffix)
        return Finding(
            title=texts.BLOCKED_TITLE_PREFIX + clean_text(texts.title_base(group), room) + suffix,
            severity=severity_for_level(group["max_level"]),
            description=clean_text(
                texts.blocked_description(group, code), TEXT_MAX, multiline=True
            ),
            recommendation=texts.BLOCKED_RECOMMENDATION,
            affected_agents=tuple(group["agents"]),
            rule_ids=(group["rule_id"],),
            confidence=None,
            decision={
                "decision_version": self.definitions.decision_version,
                "wazuh_level": group["max_level"],
                "blocked": code,
            },
        )


def safety_block_code(resp: HttpResponse) -> str | None:
    """The safety `error.code` of an HTTP 400, or None.

    The docs name `safety`, `prohibited_content`, `blocklist`, `image_safety` and
    `content_blocked`. Google's generic error body keeps a numeric `code` and puts a
    name in `status` or in `details[].reason`, so those are checked too.
    """
    try:
        error: Any = resp.json().get("error")
    except Exception:
        return None
    if not isinstance(error, dict):
        return None
    candidates: list[object] = [error.get("code"), error.get("status")]
    details = error.get("details")
    if isinstance(details, list):
        candidates += [d.get("reason") for d in details if isinstance(d, dict)]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.lower() in SAFETY_CODES:
            return candidate.lower()
    return None
