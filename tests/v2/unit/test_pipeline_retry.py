"""Port of tests/test_retry_queue.py (#43): batches survive transient failures.

Same scenarios as the legacy suite, against `wazuh_ai_analyzer.pipeline`. The
classification of single responses lives in test_llm_backend.py.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import requests

from v2.helpers import FakeClock
from v2.pipeline_support import ALERT, KEY, FakeResponse, PipelineEnv, gemini_ok, make_env
from wazuh_ai_analyzer.analysis.backend import AnalysisResult, BackendFailure, BatchContext
from wazuh_ai_analyzer.ingest.sanitize import AlertGroup
from wazuh_ai_analyzer.pipeline import PERMANENT_STREAK_LIMIT
from wazuh_ai_analyzer.pipeline.gates import backoff_delay
from wazuh_ai_analyzer.storage import contract


@pytest.fixture
def env(db_path: Path, clock: FakeClock) -> PipelineEnv:
    return make_env(db_path, clock)


QUOTA_429 = FakeResponse(429, body={"error": {"message": "You exceeded your current quota"}})


# ── the regression from the issue: 503 / ConnectionError -> pending -> done ───


@pytest.mark.parametrize(
    "outage",
    [
        FakeResponse(503, text="The model is overloaded"),
        requests.ConnectionError("Temporary failure in name resolution"),
        requests.Timeout("read timed out"),
    ],
)
def test_transient_failure_ends_pending_then_done(
    env: PipelineEnv, outage: FakeResponse | Exception
) -> None:
    fake = env.install(outage, gemini_ok())
    batch_id = env.new_batch()

    env.run(batch_id)
    r = env.row(batch_id)
    assert r["status"] == "pending"
    assert r["attempts"] == 1
    assert r["next_attempt"] > env.clock()
    assert r["first_error_at"]
    assert r["last_error"]
    assert env.stats()["errors"] == 0

    env.make_due(batch_id)
    assert env.pipeline.retry_once() is True
    r = env.row(batch_id)
    assert r["status"] == "done"
    assert r["next_attempt"] is None
    assert r["last_error"] is None
    assert len(fake.calls) == 2
    assert env.stats()["retries_succeeded"] == 1
    assert len(env.findings(batch_id)) == 1


def test_retry_waits_for_next_attempt(env: PipelineEnv) -> None:
    fake = env.install(FakeResponse(503, text="x"), gemini_ok())
    batch_id = env.new_batch()
    env.run(batch_id)
    env.pipeline.upstream.next_ok_at = 0.0  # gate open, but the batch itself is not due
    assert env.pipeline.retry_once() is False
    assert len(fake.calls) == 1
    assert env.row(batch_id)["status"] == "pending"


def test_dead_internet_for_many_batches_is_one_probe_not_a_hammer(env: PipelineEnv) -> None:
    fake = env.install(requests.ConnectionError("down"))
    ids = [env.new_batch() for _ in range(5)]
    for batch_id in ids:
        env.run(batch_id)
    assert len(fake.calls) == 1  # the first failure closed the gate
    assert {env.row(b)["status"] for b in ids} == {"pending"}
    assert env.pipeline.retry_once() is False  # gate still closed
    assert len(fake.calls) == 1
    assert env.stats()["errors"] == 0


def test_gate_defer_does_not_use_up_an_attempt(env: PipelineEnv) -> None:
    fake = env.install(gemini_ok())
    env.pipeline.upstream.mark_failure("down")
    batch_id = env.new_batch()
    env.run(batch_id)
    r = env.row(batch_id)
    assert len(fake.calls) == 0
    assert r["status"] == "pending"
    assert r["attempts"] == 0
    assert r["next_attempt"] > env.clock()


# ── quota: parked, persistent, never expires, never hammered ─────────────────


def test_quota_parks_batch_until_reset_and_survives(env: PipelineEnv) -> None:
    fake = env.install(QUOTA_429, gemini_ok())
    batch_id = env.new_batch()
    env.run(batch_id)
    r = env.row(batch_id)
    quota = env.pipeline.quota
    assert r["status"] == "pending"
    assert r["first_error_at"] is None  # quota never starts the expiry clock
    assert quota.retry_at is not None
    assert r["next_attempt"] == pytest.approx(quota.retry_at, abs=1)
    assert quota.retry_at - env.clock() > 3000  # daily quota: ~1h, not seconds

    assert env.pipeline.retry_once() is False
    assert len(fake.calls) == 1
    env.make_due(batch_id)
    assert env.pipeline.retry_once() is True
    assert env.row(batch_id)["status"] == "done"


def test_quota_wait_never_expires_the_batch(env: PipelineEnv) -> None:
    env.install(FakeResponse(429, body={"error": {"message": "quota"}}))
    batch_id = env.new_batch()
    env.clock.now = 1e10  # far in the future
    env.run(batch_id)
    assert env.row(batch_id)["status"] == "pending"
    assert env.stats()["expired"] == 0


def test_quota_gate_blocks_live_batches_too(env: PipelineEnv) -> None:
    fake = env.install(gemini_ok())
    env.pipeline.quota.mark_exhausted("quota", 3600)
    batch_id = env.new_batch()
    env.run(batch_id)
    assert len(fake.calls) == 0
    assert env.row(batch_id)["status"] == "pending"


# ── permanent errors drop the batch - loudly ──────────────────────────────────


def test_permanent_4xx_drops_batch_and_counts_it(
    env: PipelineEnv, caplog: pytest.LogCaptureFixture
) -> None:
    fake = env.install(FakeResponse(400, text="Request contains an invalid argument"))
    batch_id = env.new_batch()
    with caplog.at_level(logging.ERROR):
        env.run(batch_id)
    r = env.row(batch_id)
    assert r["status"] == "error"
    assert r["last_error"] == contract.error_permanent(
        "Gemini HTTP 400: Request contains an invalid argument"
    )
    assert contract.classify_error(r["last_error"]) == "dropped"
    assert env.stats()["dropped_permanent"] == 1
    assert env.stats()["errors"] == 1
    assert any(
        "dropped" in rec.getMessage() and "dropped_permanent=1" in rec.getMessage()
        for rec in caplog.records
    )
    assert env.pipeline.retry_once() is False
    assert len(fake.calls) == 1


def test_revoked_key_keeps_batches_queued(env: PipelineEnv) -> None:
    env.install(FakeResponse(403, text="API key not valid"), gemini_ok())
    batch_id = env.new_batch()
    env.run(batch_id)
    assert env.row(batch_id)["status"] == "pending"
    assert env.stats()["errors"] == 0
    env.make_due(batch_id)  # the operator fixed the key
    env.pipeline.retry_once()
    assert env.row(batch_id)["status"] == "done"


def test_unparseable_answer_is_retried_a_few_times_only(env: PipelineEnv) -> None:
    env.install(FakeResponse(200, text="not json"))
    batch_id = env.new_batch()
    limit = env.config.retry.bad_response_max
    for _ in range(limit):
        env.make_due(batch_id)
        env.run(batch_id)
    r = env.row(batch_id)
    assert r["status"] == "error"
    assert r["attempts"] == limit
    assert r["last_error"].startswith(f"bad_response nach {limit} Versuchen: ")
    assert env.stats()["dropped_bad_response"] == 1


def test_a_blocked_batch_is_dropped_with_the_reason_in_last_error(env: PipelineEnv) -> None:
    env.install(FakeResponse(200, {"promptFeedback": {"blockReason": "SAFETY"}}))
    batch_id = env.new_batch()
    limit = env.config.retry.bad_response_max
    for _ in range(limit):
        env.make_due(batch_id)
        env.run(batch_id)
    r = env.row(batch_id)
    assert r["status"] == "error"
    assert r["last_error"] == (
        f"bad_response nach {limit} Versuchen: Gemini blockiert die Anfrage (blockReason=SAFETY)"
    )
    assert contract.classify_error(r["last_error"]) == contract.ERROR_REASON_DROPPED
    assert env.stats()["dropped_bad_response"] == 1


def test_transient_failures_expire_after_max_age(env: PipelineEnv) -> None:
    env.install(FakeResponse(503, text="x"))
    batch_id = env.new_batch()
    env.run(batch_id)
    assert env.row(batch_id)["status"] == "pending"
    env.clock.advance(env.config.retry.max_age_hours * 3600 + 60)
    env.run(batch_id)
    r = env.row(batch_id)
    assert r["status"] == "error"
    assert r["last_error"] == contract.error_unanalyzable(72, "transient", "Gemini HTTP 503: x")
    assert contract.classify_error(r["last_error"]) == "expired"
    assert env.stats()["expired"] == 1


def test_unexpected_exception_does_not_strand_the_batch(env: PipelineEnv) -> None:
    class Boom:
        name = "llm"

        def analyse(self, groups: list[AlertGroup], context: BatchContext) -> AnalysisResult:
            raise RuntimeError("kaputt")

    env.pipeline._backend = Boom()  # type: ignore[assignment]
    batch_id = env.new_batch()
    env.run(batch_id)
    r = env.row(batch_id)
    assert r["status"] == "pending"
    assert r["last_error"] == "interner Fehler: RuntimeError('kaputt')"
    assert batch_id not in env.pipeline.inflight()


def test_a_failing_database_write_leaves_no_half_written_batch(env: PipelineEnv) -> None:
    """A crash while the findings are written rolls the whole result back."""
    env.install(gemini_ok({**_two_findings(), "summary": "s"}))
    second = {**ALERT, "rule": {"id": "5712", "level": 5, "description": "other rule"}}
    batch_id = env.new_batch(alerts=[ALERT, second])
    original = env.repo.complete_batch
    calls: list[int] = []

    def broken(batch: int, **kwargs: Any) -> list[int]:
        calls.append(batch)
        first, second = kwargs.pop("findings")
        # NOT NULL fails on the second INSERT, after the UPDATE of the batch row.
        return original(batch, findings=(first, replace(second, title=None)), **kwargs)

    env.repo.complete_batch = broken  # type: ignore[method-assign,assignment]
    env.run(batch_id)
    assert calls == [batch_id]
    r = env.row(batch_id)
    assert r["status"] == "pending"
    assert r["summary"] is None
    assert env.findings(batch_id) == []  # nothing of the failed result is stored
    assert r["last_error"].startswith("interner Fehler: IntegrityError(")


def _two_findings() -> dict[str, object]:
    f = {
        "title": "t",
        "severity": "high",
        "description": "d",
        "recommendation": "r",
        "affected_agents": ["ct100"],
        "rule_ids": ["5710"],
    }
    return {
        "overall_risk": "high",
        "findings": [f, {**f, "title": "u", "rule_ids": ["5712"]}],
    }


# ── persistence across restarts ───────────────────────────────────────────────


def test_stale_analyzing_batches_are_requeued_on_startup(env: PipelineEnv) -> None:
    fake = env.install(gemini_ok())
    stuck = env.new_batch()  # the process died while this was in flight
    legacy = env.new_batch()  # a row written by the old schema: no claimed_at
    env.execute("UPDATE batches SET claimed_at=NULL WHERE id=?", (legacy,))
    assert env.pipeline.requeue_stale(0) == 2
    assert env.row(stuck)["status"] == "pending"
    assert env.row(legacy)["status"] == "pending"
    while env.pipeline.retry_once():
        pass
    assert env.row(stuck)["status"] == "done"
    assert env.row(legacy)["status"] == "done"
    assert len(fake.calls) == 2
    assert env.stats()["recovered_stale"] == 2


def test_runtime_sweep_spares_requests_in_flight(env: PipelineEnv) -> None:
    batch_id = env.new_batch()
    env.execute("UPDATE batches SET claimed_at=? WHERE id=?", (env.clock() - 7200, batch_id))
    stale = env.config.retry.stale_analyzing_seconds
    env.pipeline._mark_inflight(batch_id)
    assert env.pipeline.requeue_stale(stale) == 0
    env.pipeline._discard_inflight(batch_id)
    assert env.pipeline.requeue_stale(stale) == 1


def test_fresh_analyzing_batch_is_not_swept(env: PipelineEnv) -> None:
    env.new_batch()
    assert env.pipeline.requeue_stale(env.config.retry.stale_analyzing_seconds) == 0


# ── backoff maths ─────────────────────────────────────────────────────────────


def test_backoff_grows_exponentially_with_jitter_and_cap() -> None:
    base, cap = 60.0, 3600.0
    for attempt in range(1, 30):
        expected = min(cap, base * 2 ** (attempt - 1))
        for _ in range(20):
            delay = backoff_delay(attempt, base=base, maximum=cap)
            assert delay <= cap
            assert expected * 0.8 - 1e-6 <= delay <= expected * 1.2 + 1e-6 or delay == cap
    assert backoff_delay(1, base=base, maximum=cap) < backoff_delay(6, base=base, maximum=cap)


def test_backoff_survives_absurd_attempt_counts() -> None:
    assert backoff_delay(10**9, base=60, maximum=3600, jitter=lambda a, b: b) == 3600


def test_upstream_backoff_grows_with_consecutive_failures_and_resets(env: PipelineEnv) -> None:
    upstream = env.pipeline.upstream
    first = upstream.mark_failure("a")
    last = first
    for _ in range(4):
        last = upstream.mark_failure("a")
    assert last > first
    assert upstream.wait_seconds() > 0
    upstream.mark_success()
    assert upstream.wait_seconds() == 0
    assert upstream.consecutive_failures == 0


def test_retry_after_header_is_honoured_but_capped(env: PipelineEnv) -> None:
    env.install(FakeResponse(503, text="x", headers={"Retry-After": "7200"}))
    batch_id = env.new_batch()
    env.run(batch_id)
    assert env.pipeline.upstream.wait_seconds() <= env.config.retry.max_delay + 1


# ── secrets & observability ───────────────────────────────────────────────────


def test_stored_error_text_never_contains_the_api_key(env: PipelineEnv) -> None:
    env.install(requests.ConnectionError(f"HTTPSConnectionPool: url /x?key={KEY} failed"))
    batch_id = env.new_batch()
    env.run(batch_id)
    last_error = env.row(batch_id)["last_error"]
    assert KEY not in last_error
    assert "***" in last_error
    assert KEY not in env.pipeline.upstream.last_error


def test_quota_message_in_the_status_is_scrubbed(env: PipelineEnv) -> None:
    env.install(FakeResponse(429, body={"error": {"message": f"quota for key {KEY}"}}))
    env.run(env.new_batch())
    quota = env.pipeline.quota.as_dict()
    assert KEY not in str(quota)
    assert "***" in str(quota["last_error"])


def test_error_text_is_capped_for_the_database(env: PipelineEnv) -> None:
    env.install(FakeResponse(503, text="y" * 5000))
    batch_id = env.new_batch()
    env.run(batch_id)
    assert len(env.row(batch_id)["last_error"]) <= contract.LAST_ERROR_MESSAGE_MAX


# ── review follow-ups of the legacy suite ─────────────────────────────────────

INVALID_KEY_400 = {
    "error": {
        "code": 400,
        "status": "INVALID_ARGUMENT",
        "message": "API key not valid. Please pass a valid API key.",
        "details": [{"reason": "API_KEY_INVALID"}],
    }
}


def test_invalid_key_does_not_empty_the_queue(env: PipelineEnv) -> None:
    env.install(FakeResponse(400, body=INVALID_KEY_400))
    ids = [env.new_batch() for _ in range(4)]
    for batch_id in ids:
        env.make_due(batch_id)
        env.run(batch_id)
    assert {env.row(b)["status"] for b in ids} == {"pending"}
    assert env.stats()["errors"] == 0


def test_a_run_of_permanent_errors_stops_dropping_batches(env: PipelineEnv) -> None:
    env.install(FakeResponse(400, text="Request contains an invalid argument"))
    ids = [env.new_batch() for _ in range(5)]
    for batch_id in ids:
        env.make_due(batch_id)
        env.run(batch_id)
    statuses = [env.row(b)["status"] for b in ids]
    limit = PERMANENT_STREAK_LIMIT
    assert statuses[: limit - 1] == ["error"] * (limit - 1)
    assert "pending" in statuses[limit - 1 :]
    assert env.stats()["dropped_permanent"] == limit - 1


def test_success_resets_the_permanent_streak(env: PipelineEnv) -> None:
    env.install(
        FakeResponse(400, text="bad"),
        gemini_ok(),
        FakeResponse(400, text="bad"),
        FakeResponse(400, text="bad"),
    )
    ids = [env.new_batch() for _ in range(4)]
    for batch_id in ids:
        env.make_due(batch_id)
        env.run(batch_id)
    assert [env.row(b)["status"] for b in ids] == ["error", "done", "error", "error"]


def test_quota_wait_clears_the_expiry_clock(env: PipelineEnv) -> None:
    """503 on day 1, three days of waiting for quota, then one more 503: not expired."""
    env.install(
        FakeResponse(503, text="x"),
        FakeResponse(429, body={"error": {"message": "quota"}}),
        FakeResponse(503, text="x"),
    )
    batch_id = env.new_batch()
    env.run(batch_id)
    assert env.row(batch_id)["first_error_at"]
    env.make_due(batch_id)
    env.run(batch_id)  # 429
    assert env.row(batch_id)["first_error_at"] is None
    env.clock.advance(3 * 86400)
    env.make_due(batch_id)
    env.run(batch_id)  # 503 again
    assert env.row(batch_id)["status"] == "pending"
    assert env.stats()["expired"] == 0


def test_bad_response_budget_is_not_eaten_by_quota_waits(env: PipelineEnv) -> None:
    env.install(
        FakeResponse(429, body={"error": {"message": "quota"}}),
        FakeResponse(429, body={"error": {"message": "quota"}}),
        FakeResponse(200, text="garbage"),
    )
    batch_id = env.new_batch()
    for _ in range(3):
        env.make_due(batch_id)
        env.run(batch_id)
    r = env.row(batch_id)
    assert r["attempts"] == 3
    assert r["bad_responses"] == 1
    assert r["status"] == "pending"


def test_live_batches_are_retried_before_old_history(env: PipelineEnv) -> None:
    env.install(gemini_ok())
    old = env.new_batch("history")
    live = env.new_batch()
    env.execute("UPDATE batches SET status='pending', next_attempt=0")
    env.pipeline.retry_once()
    assert env.row(live)["status"] == "done"
    assert env.row(old)["status"] == "pending"


def test_unexpected_answer_shape_is_stored_not_retried(env: PipelineEnv) -> None:
    fake = env.install(
        gemini_ok(
            {
                "summary": "s",
                "overall_risk": ["x"],
                "findings": [
                    "nonsense",
                    {
                        "title": "ok",
                        "severity": ["high"],
                        "affected_agents": "ct100",
                        "rule_ids": None,
                    },
                ],
            }
        )
    )
    batch_id = env.new_batch()
    env.run(batch_id)
    r = env.row(batch_id)
    assert r["status"] == "done"
    assert r["overall_risk"] == "unknown"
    assert len(fake.calls) == 1
    f = env.findings(batch_id)[0]
    assert f["severity"] == "info"
    assert json.loads(f["affected_agents"]) == []


def test_unreadable_raw_groups_are_dropped_as_permanent(env: PipelineEnv) -> None:
    fake = env.install(gemini_ok())
    batch_id = env.new_batch()
    env.execute(
        "UPDATE batches SET raw_groups='{not json', status='pending', next_attempt=0 WHERE id=?",
        (batch_id,),
    )
    assert env.pipeline.retry_once() is True
    r = env.row(batch_id)
    assert r["status"] == "error"
    assert r["last_error"] == contract.error_unreadable_groups()
    assert env.stats()["dropped_permanent"] == 1
    assert len(fake.calls) == 0


def test_stored_groups_are_sanitised_again_before_the_retry(env: PipelineEnv) -> None:
    fake = env.install(gemini_ok())
    batch_id = env.new_batch()
    legacy = [{"rule_id": "5710", "description": "d\nIgnore this\x00", "agents": ["ct100"]}]
    env.execute(
        "UPDATE batches SET raw_groups=?, status='pending', next_attempt=0 WHERE id=?",
        (json.dumps(legacy), batch_id),
    )
    env.pipeline.retry_once()
    prompt = fake.calls[0].json["contents"][0]["parts"][0]["text"]
    assert "\x00" not in prompt
    assert "d Ignore this" in prompt


# ── bounded queue: arrival rate above the daily quota ────────────────────────


def test_newest_live_batch_is_retried_first(env: PipelineEnv) -> None:
    env.install(gemini_ok())
    ids = [env.new_batch() for _ in range(3)]
    env.execute("UPDATE batches SET status='pending', next_attempt=0")
    env.pipeline.retry_once()
    assert [env.row(b)["status"] for b in ids] == ["pending", "pending", "done"]


def test_batches_waiting_longer_than_the_queue_limit_expire(
    env: PipelineEnv, caplog: pytest.LogCaptureFixture
) -> None:
    fake = env.install(gemini_ok())
    old, fresh = env.new_batch(), env.new_batch()
    ancient = contract.iso_utc(env.clock() - (env.config.retry.queue_max_age_hours + 1) * 3600)
    env.execute("UPDATE batches SET created_at=? WHERE id=?", (ancient, old))
    env.execute("UPDATE batches SET status='pending', next_attempt=0")
    env.pipeline.quota.mark_exhausted("quota", 3600)  # expiry must work while gated, too
    with caplog.at_level(logging.WARNING):
        assert env.pipeline.retry_once() is False
    r = env.row(old)
    assert r["status"] == "error"
    assert r["last_error"] == contract.error_queue_expired(72)
    assert env.row(fresh)["status"] == "pending"
    assert env.stats()["expired"] == 1
    assert env.stats()["errors"] == 1
    assert not fake.calls
    assert any("dropped" in rec.getMessage() for rec in caplog.records)


def test_months_old_analyzing_leftovers_are_requeued_and_then_expired(env: PipelineEnv) -> None:
    fake = env.install(gemini_ok())
    stuck = env.new_batch()
    env.execute(
        "UPDATE batches SET created_at='2026-03-19T21:33:44+00:00', claimed_at=NULL WHERE id=?",
        (stuck,),
    )
    assert env.pipeline.requeue_stale(0) == 1
    env.pipeline.retry_once()
    assert env.row(stuck)["status"] == "error"
    assert not fake.calls


# ── the backend interface ─────────────────────────────────────────────────────


class ScriptedBackend:
    """A fake backend (no HTTP at all) that records the groups it was given."""

    name = "llm"

    def __init__(self, *outcomes: AnalysisResult | BackendFailure) -> None:
        self.outcomes = list(outcomes)
        self.seen: list[tuple[list[AlertGroup], BatchContext]] = []

    def analyse(self, groups: list[AlertGroup], context: BatchContext) -> AnalysisResult:
        self.seen.append((list(groups), context))
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BackendFailure):
            raise outcome
        return outcome


def test_any_backend_plugs_in_and_gets_the_batch_context(env: PipelineEnv) -> None:
    backend = ScriptedBackend(
        BackendFailure("transient", "down", retry_after=5),
        AnalysisResult(summary="s", overall_risk="info", findings=(), mode="llm"),
    )
    env.pipeline._backend = backend  # type: ignore[assignment]
    batch_id = env.new_batch("history")
    env.run(batch_id)
    env.make_due(batch_id)
    assert env.pipeline.retry_once()
    assert [(c.batch_id, c.source, c.is_retry) for _, c in backend.seen] == [
        (batch_id, "history", False),
        (batch_id, "history", True),
    ]
    # The pipeline hands the repository over as the scratch space of per-group backends.
    assert all(c.partial is env.repo for _, c in backend.seen)
    assert backend.seen[0][0][0]["rule_id"] == "5710"
    assert env.row(batch_id)["status"] == "done"


def test_quota_failure_of_any_backend_closes_the_quota_gate(env: PipelineEnv) -> None:
    env.pipeline._backend = ScriptedBackend(BackendFailure("quota", "empty", retry_after=120))  # type: ignore[assignment]
    batch_id = env.new_batch()
    env.run(batch_id)
    assert env.pipeline.gate_wait() == pytest.approx(120)
    assert env.row(batch_id)["next_attempt"] == pytest.approx(env.clock() + 120)


def test_unknown_failure_kind_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown failure kind"):
        BackendFailure("sometimes", "x")  # type: ignore[arg-type]


def test_suspicious_downgrades_are_counted(env: PipelineEnv) -> None:
    env.install(
        gemini_ok(
            {
                "overall_risk": "low",
                "findings": [{"title": "rootkit?", "severity": "info", "rule_ids": ["510"]}],
            }
        )
    )
    batch_id = env.new_batch(
        alerts=[{"rule": {"id": "510", "level": 12}, "agent": {"name": "wings"}}]
    )
    env.run(batch_id)
    assert env.stats()["suspicious_downgrades"] == 1
    assert env.findings(batch_id)[0]["severity"] == "info"  # flagged, never changed


def test_quota_message_in_the_stats_is_capped_like_the_upstream_one() -> None:
    from wazuh_ai_analyzer.pipeline.gates import UPSTREAM_ERROR_MAX, QuotaState

    quota = QuotaState()
    quota.mark_exhausted("q" * 5000, 60)
    last_error = quota.as_dict()["last_error"]
    assert isinstance(last_error, str)
    assert len(last_error) == UPSTREAM_ERROR_MAX
