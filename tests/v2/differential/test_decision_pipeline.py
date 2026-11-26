"""Decision mode through the real pipeline and storage (#88).

The stored rows must satisfy the frozen read interface in decision mode exactly as
in llm mode: value sets, `last_error` prefixes, formats, and the homelab exporter's
own SQL. The HTTP layer is a fake; nothing talks to the network.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from v2.contract.exporter_sql import collect
from v2.decision_support import blocked, decision_ok
from v2.helpers import FakeClock
from v2.pipeline_support import ALERT, FakeGemini, FakeResponse, PipelineEnv, make_env
from wazuh_ai_analyzer.analysis.decision import GeminiDecisionBackend
from wazuh_ai_analyzer.analysis.decisions import load_definitions
from wazuh_ai_analyzer.ingest.batches import BatchWriter
from wazuh_ai_analyzer.metrics.runtime import runtime_counters
from wazuh_ai_analyzer.storage import contract

SECOND_RULE: dict[str, Any] = {
    "rule": {"id": "5712", "level": 12, "description": "sshd: brute force trying to get access"},
    "agent": {"name": "ct101"},
    "location": "journald",
    "timestamp": "2026-10-07T10:01:00.000+0000",
    "full_log": "Failed password for root from 203.0.113.9",
}
THIRD_RULE: dict[str, Any] = {
    "rule": {"id": "5402", "level": 3, "description": "sudo: command executed"},
    "agent": {"name": "ct100"},
    "location": "journald",
    "timestamp": "2026-10-07T10:02:00.000+0000",
    "full_log": "ct100 : TTY=pts/0 ; COMMAND=/usr/bin/apt update",
}


@pytest.fixture
def env(db_path: Path, clock: FakeClock) -> PipelineEnv:
    env = make_env(db_path, clock, ANALYSIS_MODE="decision")
    env.gemini = FakeGemini(decision_ok())
    env.pipeline._backend = GeminiDecisionBackend.from_config(env.config, post=env.gemini)
    return env


def store(env: PipelineEnv, source: str = "live", *alerts: dict[str, Any]) -> int:
    writer = BatchWriter(env.repo, mode="decision")
    return writer.store(list(alerts) or [ALERT, SECOND_RULE], source).batch_id  # type: ignore[arg-type]


def partial(env: PipelineEnv, batch_id: int) -> str | None:
    value = env.row(batch_id)["decision_partial"]
    return None if value is None else str(value)


def test_a_decision_batch_ends_done_with_contract_valid_rows(env: PipelineEnv) -> None:
    env.gemini.set(
        decision_ok(severity="medium", relevant=0.8),
        decision_ok(severity="high", relevant=0.9, confidence=0.77),
    )
    batch_id = store(env)  # groups come sorted by level: 5712 (12) first, then 5710 (5)
    env.run(batch_id)

    row = env.row(batch_id)
    assert row["status"] == "done"
    assert row["mode"] == "decision"
    assert row["decision_version"] == load_definitions().decision_version
    assert row["last_error"] is None
    assert row["next_attempt"] is None
    assert row["decision_partial"] is None
    assert row["overall_risk"] in contract.OVERALL_RISKS
    assert row["summary"]

    findings = env.findings(batch_id)
    assert len(findings) == 2
    for finding in findings:
        assert finding["severity"] in contract.SEVERITIES
        assert finding["title"]
        assert finding["description"]
        assert finding["recommendation"]
        assert 0 <= finding["confidence"] <= 1
        assert json.loads(finding["decision"])["decision_version"] == row["decision_version"]
        assert isinstance(json.loads(finding["affected_agents"]), list)
        assert isinstance(json.loads(finding["rule_ids"]), list)
    assert [f["severity"] for f in findings] == ["high", "medium"]
    assert findings[0]["confidence"] == 0.77


def test_the_homelab_exporter_reads_decision_rows(env: PipelineEnv) -> None:
    env.gemini.set(decision_ok(severity="critical", relevant=0.9))
    env.run(store(env, "live"))
    env.run(store(env, "history"))
    failed = store(env)
    env.gemini.set(FakeResponse(400, {"error": {"code": 400, "message": "bad field"}}))
    env.run(failed)

    result = collect(str(env.database.path), after_id=0)
    assert result["findings"][("critical", "live")] == 2
    assert result["findings"][("critical", "history")] == 2
    assert result["batches"]["done"] == 2
    assert result["batches"]["error"] == 1
    assert result["errors"] == {"expired": 0, "dropped": 1, "other": 0}
    assert result["sequence"] == 4
    assert result["new"] == [("history", "critical", 2), ("live", "critical", 2)]
    assert result["last_done"] is not None


def test_a_permanent_error_uses_the_contract_text(env: PipelineEnv) -> None:
    env.gemini.set(FakeResponse(400, {"error": {"code": 400, "message": "too many questions"}}))
    batch_id = store(env)
    env.run(batch_id)
    row = env.row(batch_id)
    assert row["status"] == "error"
    assert row["last_error"].startswith("permanent: Gemini Decision HTTP 400: ")
    assert contract.classify_error(row["last_error"]) == contract.ERROR_REASON_DROPPED
    assert env.stats()["dropped_permanent"] == 1


def test_an_unusable_answer_is_dropped_after_the_usual_attempts(env: PipelineEnv) -> None:
    env.gemini.set(FakeResponse(200, {"answers": {}}))
    batch_id = store(env)
    for attempt in range(3):
        env.run(batch_id, is_retry=attempt > 0)
    row = env.row(batch_id)
    assert row["status"] == "error"
    assert row["last_error"].startswith("bad_response nach 3 Versuchen: Antwort nicht auswertbar")
    assert contract.classify_error(row["last_error"]) == contract.ERROR_REASON_DROPPED


def test_a_rate_limit_keeps_the_answers_and_the_retry_pays_only_for_the_rest(
    env: PipelineEnv,
) -> None:
    quota = FakeResponse(429, {"error": {"message": "Resource has been exhausted (per minute)"}})
    env.gemini.set(decision_ok(severity="medium"), quota)
    batch_id = store(env)
    env.run(batch_id)

    row = env.row(batch_id)
    assert row["status"] == "pending"
    assert contract.classify_error(row["last_error"]) == contract.ERROR_REASON_OTHER
    assert len(env.gemini.calls) == 2
    kept = json.loads(partial(env, batch_id) or "")
    assert kept["version"] == load_definitions().decision_version
    assert len(kept["groups"]) == 1
    assert env.findings(batch_id) == []

    env.gemini.set(decision_ok(severity="high"))
    env.gemini.calls.clear()
    env.make_due(batch_id)
    assert env.pipeline.retry_once()
    assert len(env.gemini.calls) == 1  # the answered group is not asked again
    row = env.row(batch_id)
    assert row["status"] == "done"
    assert row["decision_partial"] is None
    assert len(env.findings(batch_id)) == 2
    assert env.stats()["retries_succeeded"] == 1


def test_scratch_answers_survive_a_restart_of_the_service(
    env: PipelineEnv, db_path: Path, clock: FakeClock
) -> None:
    env.gemini.set(decision_ok(), FakeResponse(503, text="down"))
    batch_id = store(env)
    env.run(batch_id)
    assert partial(env, batch_id) is not None

    again = make_env(db_path, clock, ANALYSIS_MODE="decision")
    fake = FakeGemini(decision_ok())
    again.pipeline._backend = GeminiDecisionBackend.from_config(again.config, post=fake)
    again.make_due(batch_id)
    assert again.pipeline.retry_once()
    assert len(fake.calls) == 1
    assert again.row(batch_id)["status"] == "done"


def test_a_safety_block_is_stored_counted_and_never_dropped(env: PipelineEnv) -> None:
    env.gemini.set(blocked("safety"), decision_ok(severity="low", relevant=0.9))
    batch_id = store(env)
    env.run(batch_id)

    row = env.row(batch_id)
    assert row["status"] == "done"
    assert row["last_error"] is None
    stored = env.findings(batch_id)
    placeholder = next(f for f in stored if f["title"].startswith("Nicht analysierbar"))
    assert placeholder["severity"] == "high"  # the rule had Wazuh level 12
    assert placeholder["confidence"] is None
    assert json.loads(placeholder["decision"])["blocked"] == "safety"
    assert len(stored) == 2
    stats = env.stats()
    assert stats["safety_blocked"] == 1
    assert stats["errors"] == 0
    snapshot = runtime_counters(_ingest_stats(), env.pipeline.counters.snapshot())
    assert snapshot["safety_blocked"] == 1


def test_a_level_12_rule_rated_low_is_counted_as_a_suspicious_downgrade(
    env: PipelineEnv,
) -> None:
    env.gemini.set(decision_ok(severity="low", relevant=0.9))
    batch_id = store(env, "live", SECOND_RULE)
    env.run(batch_id)
    assert env.stats()["suspicious_downgrades"] == 1
    assert "Achtung" in env.row(batch_id)["summary"]


def test_nothing_relevant_is_a_done_batch_without_findings(env: PipelineEnv) -> None:
    env.gemini.set(decision_ok(relevant=0.05))
    batch_id = store(env, "live", ALERT, THIRD_RULE)
    env.run(batch_id)
    row = env.row(batch_id)
    assert (row["status"], row["overall_risk"], row["mode"]) == ("done", "info", "decision")
    assert env.findings(batch_id) == []


def test_the_scratch_column_is_not_part_of_the_web_api(env: PipelineEnv) -> None:
    from wazuh_ai_analyzer.storage.repo import BATCH_API_COLUMNS

    assert "decision_partial" not in BATCH_API_COLUMNS
    env.gemini.set(decision_ok(), FakeResponse(503, text="down"))
    batch_id = store(env)
    env.run(batch_id)
    (listed,) = [b for b in env.repo.list_batches() if b["id"] == batch_id]
    assert "decision_partial" not in listed


def test_the_rollback_path_ignores_the_scratch_column(env: PipelineEnv) -> None:
    """The previous release writes batches without the column; rows stay valid."""
    conn = sqlite3.connect(env.database.path)
    try:
        conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status)"
            " VALUES ('2026-01-01T00:00:00+00:00', 1, '[]', 'pending')"
        )
        conn.commit()
        value = conn.execute(
            "SELECT decision_partial FROM batches ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    finally:
        conn.close()
    assert value is None


def _ingest_stats() -> Any:
    from wazuh_ai_analyzer.ingest.counters import IngestStats

    return IngestStats()
