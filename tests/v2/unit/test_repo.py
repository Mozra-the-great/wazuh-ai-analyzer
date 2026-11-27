"""Repository: batches and findings in every state."""

from __future__ import annotations

import json
from typing import Any

import pytest

from v2.helpers import FakeClock
from wazuh_ai_analyzer.storage import contract
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import NewFinding, Repository


def finding(**overrides: Any) -> NewFinding:
    values: dict[str, Any] = {
        "title": "SSH brute force",
        "severity": "high",
        "description": "many failed logins",
        "recommendation": "block the source",
        "affected_agents": ("ct100",),
        "rule_ids": ("5710",),
    }
    values.update(overrides)
    return NewFinding(**values)


def test_insert_batch_stores_it_as_analyzing_with_a_claim(
    repo: Repository, clock: FakeClock
) -> None:
    batch_id = repo.insert_batch(alert_count=3, raw_groups="[]", source="live")
    batch = repo.get_batch(batch_id)
    assert batch is not None
    assert (batch.status, batch.source, batch.mode, batch.alert_count) == (
        "analyzing",
        "live",
        "llm",
        3,
    )
    assert batch.created_at == "2026-11-25T12:00:00+00:00"
    assert batch.claimed_at == clock.now
    assert (batch.attempts, batch.bad_responses, batch.last_error) == (0, 0, None)


def test_insert_pending_history_batch_has_no_claim(repo: Repository) -> None:
    batch_id = repo.insert_batch(
        alert_count=1, raw_groups="[]", source="history", status="pending", mode="decision"
    )
    batch = repo.get_batch(batch_id)
    assert batch is not None
    assert (batch.status, batch.source, batch.mode, batch.claimed_at) == (
        "pending",
        "history",
        "decision",
        None,
    )


@pytest.mark.parametrize(
    "overrides",
    [{"source": "elsewhere"}, {"status": "weird"}, {"mode": "hybrid"}],
)
def test_insert_batch_rejects_values_outside_the_contract(
    repo: Repository, overrides: dict[str, str]
) -> None:
    args: dict[str, Any] = {"alert_count": 1, "raw_groups": "[]", "source": "live"}
    args.update(overrides)
    with pytest.raises(ValueError, match="invalid"):
        repo.insert_batch(**args)
    assert repo.count_batches_by_status() == {}


def test_complete_batch_stores_findings_and_clears_retry_state(repo: Repository) -> None:
    batch_id = repo.insert_batch(alert_count=2, raw_groups="[]", source="live")
    repo.set_pending(
        batch_id,
        next_attempt=1.0,
        message="Gemini HTTP 503",
        attempts=2,
        first_error_at="2026-11-25T11:00:00+00:00",
        bad_responses=0,
    )
    ids = repo.complete_batch(
        batch_id,
        summary="two groups",
        overall_risk="high",
        findings=[finding(), finding(title="Second", severity="info")],
    )
    assert len(ids) == 2
    batch = repo.get_batch(batch_id)
    assert batch is not None
    assert (batch.status, batch.summary, batch.overall_risk) == ("done", "two groups", "high")
    assert (batch.next_attempt, batch.last_error, batch.attempts) == (None, None, 2)
    stored = repo.findings_for_batch(batch_id)
    assert [f.title for f in stored] == ["SSH brute force", "Second"]
    assert stored[0].affected_agents == ["ct100"]
    assert stored[0].rule_ids == ["5710"]
    assert (stored[0].confidence, stored[0].decision) == (None, None)


def test_decision_mode_stores_confidence_and_raw_answers(repo: Repository) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live", mode="decision")
    answers = {"relevant": {"noul": 0.91, "confidence": 0.8}, "severity": {"choice": "high"}}
    repo.complete_batch(
        batch_id,
        summary="s",
        overall_risk="high",
        findings=[finding(confidence=0.8, decision=answers)],
        mode="decision",
        decision_version="v1",
    )
    batch = repo.get_batch(batch_id)
    assert batch is not None
    assert (batch.mode, batch.decision_version) == ("decision", "v1")
    [stored] = repo.findings_for_batch(batch_id)
    assert stored.confidence == 0.8
    assert stored.decision == answers


def test_findings_are_serialised_like_the_legacy_analyzer(
    repo: Repository, database: Database
) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    repo.complete_batch(
        batch_id,
        summary="s",
        overall_risk="low",
        findings=[finding(affected_agents=["a", "ä"], rule_ids=["1", "2"])],
    )
    with database.reader() as conn:
        row = conn.execute("SELECT affected_agents, rule_ids FROM findings").fetchone()
    assert row["affected_agents"] == json.dumps(["a", "ä"])  # ensure_ascii, as in analyzer.py
    assert row["rule_ids"] == '["1", "2"]'


def test_complete_batch_is_atomic(repo: Repository) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    bad = finding(severity="catastrophic")
    with pytest.raises(ValueError, match="severity"):
        repo.complete_batch(batch_id, summary="s", overall_risk="low", findings=[finding(), bad])
    batch = repo.get_batch(batch_id)
    assert batch is not None
    assert batch.status == "analyzing"
    assert repo.findings_for_batch(batch_id) == []


def test_complete_unknown_batch_fails_without_side_effects(repo: Repository) -> None:
    with pytest.raises(LookupError):
        repo.complete_batch(404, summary="s", overall_risk="low", findings=[finding()])
    assert repo.findings_for_batch(404) == []


def test_complete_batch_rejects_unknown_risk_and_mode(repo: Repository) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    with pytest.raises(ValueError, match="overall_risk"):
        repo.complete_batch(batch_id, summary="s", overall_risk="meh", findings=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="mode"):
        repo.complete_batch(
            batch_id,
            summary="s",
            overall_risk="low",
            findings=[],
            mode="hybrid",  # type: ignore[arg-type]
        )


def test_every_overall_risk_of_the_contract_is_accepted(repo: Repository) -> None:
    for risk in contract.OVERALL_RISKS:
        batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
        repo.complete_batch(batch_id, summary="s", overall_risk=risk, findings=[])  # type: ignore[arg-type]


def test_set_pending_and_fail_batch(repo: Repository) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    repo.set_pending(
        batch_id,
        next_attempt=123.5,
        message="Gemini: Timeout",
        attempts=1,
        first_error_at="2026-11-25T12:00:00+00:00",
        bad_responses=0,
    )
    pending = repo.get_batch(batch_id)
    assert pending is not None
    assert (pending.status, pending.next_attempt, pending.last_error) == (
        "pending",
        123.5,
        "Gemini: Timeout",
    )

    reason = contract.error_permanent("HTTP 400")
    repo.fail_batch(batch_id, reason=reason, attempts=4)
    failed = repo.get_batch(batch_id)
    assert failed is not None
    assert (failed.status, failed.next_attempt, failed.last_error, failed.attempts) == (
        "error",
        None,
        reason,
        4,
    )
    repo.fail_batch(batch_id, reason=reason, attempts=2)  # attempts never go down
    again = repo.get_batch(batch_id)
    assert again is not None
    assert again.attempts == 4


def test_get_unknown_batch_and_counts(repo: Repository) -> None:
    assert repo.get_batch(1) is None
    assert repo.count_batches_by_status() == {}
    repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    repo.insert_batch(alert_count=1, raw_groups="[]", source="live", status="pending")
    assert repo.count_batches_by_status() == {"analyzing": 1, "pending": 1}


# ── decision scratch space (#88) ─────────────────────────────────────────────
def test_decision_partial_round_trips_and_is_cleared_on_completion(repo: Repository) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live", mode="decision")
    assert repo.load_decision_partial(batch_id) is None
    repo.save_decision_partial(batch_id, '{"version": "1-x", "groups": {}}')
    assert repo.load_decision_partial(batch_id) == '{"version": "1-x", "groups": {}}'
    repo.save_decision_partial(batch_id, "{}")
    assert repo.load_decision_partial(batch_id) == "{}"
    repo.complete_batch(batch_id, summary="s", overall_risk="info", findings=[], mode="decision")
    assert repo.load_decision_partial(batch_id) is None


def test_decision_partial_of_an_unknown_batch_is_none(repo: Repository) -> None:
    assert repo.load_decision_partial(404) is None
    repo.save_decision_partial(404, "{}")  # updates no row, raises nothing
    assert repo.load_decision_partial(404) is None


def test_a_failed_batch_drops_its_scratch_data(
    repo: Repository,
) -> None:
    batch_id = repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
    repo.save_decision_partial(batch_id, "{}")
    repo.fail_batch(batch_id, reason="permanent: x")
    assert repo.load_decision_partial(batch_id) is None
