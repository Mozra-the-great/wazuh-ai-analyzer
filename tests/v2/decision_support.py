"""Fakes for the decision backend tests: response bodies in the shape of the Decisions API.

Shapes are those of https://aistudio.google.com/docs/decisions-api (read 2026-11-26):
`answers.<key>` is `{"type": "noul", "noul", "confidence"}` or
`{"type": "choice", "choice", "probabilities", "confidence"}`, `usage` counts input
tokens only. The 400 body of a safety block is `{"error": {"code": "<reason>", "message"}}`.
"""

from __future__ import annotations

from typing import Any

from v2.pipeline_support import KEY, FakeGemini, FakeResponse
from wazuh_ai_analyzer.analysis.backend import BatchContext, PartialStore
from wazuh_ai_analyzer.analysis.decision import GeminiDecisionBackend
from wazuh_ai_analyzer.config import DecisionThresholds
from wazuh_ai_analyzer.ingest.sanitize import AlertGroup, sanitize_group
from wazuh_ai_analyzer.secret import Secret

SEVERITY_OPTIONS = ("info", "low", "medium", "high", "critical")


def group(
    rule_id: str = "5710",
    *,
    level: int = 5,
    count: int = 14,
    description: str = "sshd: attempt to login using a non-existent user",
    agents: tuple[str, ...] = ("ct100",),
    log: str = "Failed password for invalid user admin from 203.0.113.7",
) -> AlertGroup:
    return sanitize_group(
        {
            "rule_id": rule_id,
            "description": description,
            "count": count,
            "max_level": level,
            "agents": list(agents),
            "locations": ["journald"],
            "samples": [
                {
                    "ts": "2026-11-26T10:00:00",
                    "log": log,
                    "src_ip": "203.0.113.7",
                    "dst_user": "admin",
                }
            ],
        }
    )


def answers(
    *,
    relevant: float = 0.9,
    severity: str = "high",
    confidence: float = 0.8,
    known_benign: float = 0.05,
    already_blocked: float = 0.1,
    needs_action_now: float = 0.2,
) -> dict[str, Any]:
    probabilities = dict.fromkeys(SEVERITY_OPTIONS, 0.01)
    probabilities[severity] = 1 - 0.01 * (len(SEVERITY_OPTIONS) - 1)

    def noul(value: float) -> dict[str, Any]:
        return {"type": "noul", "noul": value, "confidence": 0.7}

    return {
        "relevant": noul(relevant),
        "severity": {
            "type": "choice",
            "choice": severity,
            "probabilities": probabilities,
            "confidence": confidence,
        },
        "known_benign": noul(known_benign),
        "already_blocked": noul(already_blocked),
        "needs_action_now": noul(needs_action_now),
    }


def decision_ok(**kwargs: float | str) -> FakeResponse:
    body = {
        "answers": answers(**kwargs),  # type: ignore[arg-type]
        "usage": {
            "total_input_tokens": 812,
            "input_tokens_by_modality": [{"modality": "text", "tokens": 812}],
            "total_output_tokens": 0,
            "total_tokens": 812,
        },
    }
    return FakeResponse(200, body)


def blocked(code: str = "safety") -> FakeResponse:
    return FakeResponse(400, {"error": {"code": code, "message": "The input was blocked."}})


class MemoryPartial:
    """The scratch space of a batch, in memory (the repository does the same in SQL)."""

    def __init__(self, document: str | None = None) -> None:
        self.document = document
        self.saves = 0

    def load_decision_partial(self, batch_id: int) -> str | None:
        return self.document

    def save_decision_partial(self, batch_id: int, document: str) -> None:
        self.document = document
        self.saves += 1


def context(partial: PartialStore | None = None, batch_id: int = 1) -> BatchContext:
    return BatchContext(batch_id=batch_id, source="live", is_retry=False, partial=partial)


def backend(
    *outcomes: FakeResponse | BaseException,
    key: str | None = KEY,
    thresholds: DecisionThresholds | None = None,
    infra_context: str = "a small lab",
) -> GeminiDecisionBackend:
    return GeminiDecisionBackend(
        api_key=Secret(key) if key is not None else None,
        model="gemini-decision-1",
        infra_context=infra_context,
        thresholds=thresholds if thresholds is not None else DecisionThresholds(),
        post=FakeGemini(*outcomes),
    )


def calls(b: GeminiDecisionBackend) -> list[Any]:
    fake = b._post
    assert isinstance(fake, FakeGemini)
    return fake.calls
