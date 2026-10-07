"""Regression tests for #43: batches must survive transient Gemini failures."""
import json

import pytest
import requests

pytest.importorskip("flask")

ALERT = {"rule": {"id": "5710", "level": 7, "description": "sshd: attempt to login"},
         "agent": {"name": "ct100"}, "location": "journald", "timestamp": "2026-10-07T10:00:00.000+0000",
         "full_log": "Failed password for invalid user admin"}
GOOD_ANSWER = {"summary": "alles ruhig", "overall_risk": "low", "findings": [
    {"title": "SSH-Login-Versuche", "severity": "low", "description": "d",
     "recommendation": "r", "affected_agents": ["ct100"], "rule_ids": ["5710"]}]}


class FakeResponse:
    def __init__(self, status=200, body=None, text="", headers=None):
        self.status_code = status
        self.ok = status < 400
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            raise requests.exceptions.JSONDecodeError("no json", self.text, 0)
        return self._body


def gemini_ok(answer=None):
    return FakeResponse(200, {"candidates": [{"content": {"parts": [
        {"text": json.dumps(answer or GOOD_ANSWER)}]}}]})


class FakeGemini:
    """Stands in for requests.post: replays the given outcomes, one per call."""
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture
def gemini(az, monkeypatch):
    def install(*outcomes):
        fake = FakeGemini(*outcomes)
        monkeypatch.setattr(az.requests, "post", fake)
        return fake
    return install


def new_batch(az):
    batch_id, _ = az._store_batch([ALERT], "live")
    return batch_id


def row(az, batch_id):
    with az._db() as conn:
        return dict(conn.execute("SELECT * FROM batches WHERE id=?", (batch_id,)).fetchone())


def run_batch(az, batch_id, **kw):
    groups = json.loads(row(az, batch_id)["raw_groups"])
    az._do_gemini_and_save(batch_id, groups, **kw)


def make_due(az, batch_id):
    """Pretend the backoff has elapsed (for the batch and the shared gate)."""
    with az._db() as conn:
        conn.execute("UPDATE batches SET next_attempt=0 WHERE id=?", (batch_id,))
    az.upstream.next_ok_at = 0.0
    az.quota.retry_at = None


# ── classification ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("outcome, kind", [
    (FakeResponse(500, text="boom"), "transient"),
    (FakeResponse(502, text="bad gateway"), "transient"),
    (FakeResponse(503, text="overloaded"), "transient"),
    (FakeResponse(504, text="timeout"), "transient"),
    (FakeResponse(408, text="request timeout"), "transient"),
    (requests.Timeout("slow"), "transient"),
    (requests.ConnectionError("dns"), "transient"),
    (FakeResponse(429, body={"error": {"message": "Quota exceeded"}}), "quota"),
    (FakeResponse(400, text="invalid argument"), "permanent"),
    (FakeResponse(413, text="too large"), "permanent"),
    (FakeResponse(401, text="bad key"), "config"),
    (FakeResponse(403, text="forbidden"), "config"),
    (FakeResponse(404, text="no such model"), "config"),
    (FakeResponse(200, text="<html>"), "bad_response"),
    (FakeResponse(200, body={"candidates": []}), "bad_response"),
])
def test_call_gemini_classifies_failures(az, gemini, outcome, kind):
    gemini(outcome)
    result, failure = az.call_gemini([{"rule_id": "1"}])
    assert result is None and failure.kind == kind


def test_call_gemini_success(az, gemini):
    gemini(gemini_ok())
    result, failure = az.call_gemini([{"rule_id": "1"}])
    assert failure is None and result["overall_risk"] == "low"


def test_missing_api_key_is_config_not_permanent(az, monkeypatch):
    monkeypatch.setattr(az, "GEMINI_API_KEY", "")
    _, failure = az.call_gemini([])
    assert failure.kind == "config"


# ── the regression from the issue: 503 / ConnectionError -> pending -> done ───

@pytest.mark.parametrize("outage", [
    FakeResponse(503, text="The model is overloaded"),
    requests.ConnectionError("Temporary failure in name resolution"),
    requests.Timeout("read timed out"),
])
def test_transient_failure_ends_pending_then_done(az, gemini, outage):
    fake = gemini(outage, gemini_ok())
    batch_id = new_batch(az)

    run_batch(az, batch_id)
    r = row(az, batch_id)
    assert r["status"] == "pending"
    assert r["attempts"] == 1
    assert r["next_attempt"] > az._now()
    assert r["first_error_at"] and r["last_error"]
    assert az._stats["errors"] == 0

    make_due(az, batch_id)
    assert az._retry_once() is True
    r = row(az, batch_id)
    assert r["status"] == "done" and r["next_attempt"] is None and r["last_error"] is None
    assert fake.calls == 2
    assert az._stats["retries_succeeded"] == 1
    with az._db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE batch_id=?", (batch_id,)).fetchone()[0] == 1


def test_retry_waits_for_next_attempt(az, gemini):
    fake = gemini(FakeResponse(503, text="x"), gemini_ok())
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    az.upstream.next_ok_at = 0.0          # gate open, but the batch itself is not due
    assert az._retry_once() is False
    assert fake.calls == 1
    assert row(az, batch_id)["status"] == "pending"


def test_dead_internet_for_many_batches_is_one_probe_not_a_hammer(az, gemini):
    """68 batches during an uplink outage must not each probe the API."""
    fake = gemini(requests.ConnectionError("down"))
    ids = [new_batch(az) for _ in range(5)]
    for batch_id in ids:
        run_batch(az, batch_id)
    assert fake.calls == 1                      # first failure closed the gate
    assert {row(az, b)["status"] for b in ids} == {"pending"}
    assert az._retry_once() is False            # gate still closed
    assert fake.calls == 1
    assert az._stats["errors"] == 0


def test_gate_defer_does_not_use_up_an_attempt(az, gemini):
    fake = gemini(gemini_ok())
    az.upstream.mark_failure("down")
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    r = row(az, batch_id)
    assert fake.calls == 0
    assert r["status"] == "pending" and r["attempts"] == 0 and r["next_attempt"] > az._now()


# ── quota: parked, persistent, never expires, never hammered ─────────────────

def test_quota_parks_batch_until_reset_and_survives(az, gemini):
    fake = gemini(FakeResponse(429, body={"error": {"message": "You exceeded your current quota"}}),
                  gemini_ok())
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    r = row(az, batch_id)
    assert r["status"] == "pending"
    assert r["first_error_at"] is None                      # quota never starts the expiry clock
    assert r["next_attempt"] == pytest.approx(az.quota.retry_at, abs=1)
    assert az.quota.retry_at - az._now() > 3000             # daily quota: ~1h, not seconds

    assert az._retry_once() is False and fake.calls == 1    # quota gate holds
    make_due(az, batch_id)
    assert az._retry_once() is True and row(az, batch_id)["status"] == "done"


def test_quota_wait_never_expires_the_batch(az, gemini, monkeypatch):
    gemini(FakeResponse(429, body={"error": {"message": "quota"}}))
    batch_id = new_batch(az)
    monkeypatch.setattr(az, "_now", lambda: 1e10)           # far in the future
    run_batch(az, batch_id)
    assert row(az, batch_id)["status"] == "pending"
    assert az._stats["expired"] == 0


def test_quota_gate_blocks_live_batches_too(az, gemini):
    """While the quota is exhausted a new live batch must not be sent at all."""
    fake = gemini(gemini_ok())
    az.quota.mark_exhausted("quota", 3600)
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    assert fake.calls == 0 and row(az, batch_id)["status"] == "pending"


# ── permanent errors drop the batch - loudly ──────────────────────────────────

def test_permanent_4xx_drops_batch_and_counts_it(az, gemini, caplog):
    fake = gemini(FakeResponse(400, text="Request contains an invalid argument"))
    batch_id = new_batch(az)
    with caplog.at_level("ERROR"):
        run_batch(az, batch_id)
    r = row(az, batch_id)
    assert r["status"] == "error" and "permanent" in r["last_error"]
    assert az._stats["dropped_permanent"] == 1 and az._stats["errors"] == 1
    assert any("verworfen" in rec.getMessage() and "dropped_permanent=1" in rec.getMessage()
               for rec in caplog.records)
    assert az._retry_once() is False and fake.calls == 1    # not retried


def test_revoked_key_keeps_batches_queued(az, gemini):
    gemini(FakeResponse(403, text="API key not valid"), gemini_ok())
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    assert row(az, batch_id)["status"] == "pending"
    assert az._stats["errors"] == 0
    make_due(az, batch_id)                                  # operator fixed the key
    az._retry_once()
    assert row(az, batch_id)["status"] == "done"


def test_unparseable_answer_is_retried_a_few_times_only(az, gemini):
    gemini(FakeResponse(200, text="not json"))
    batch_id = new_batch(az)
    for _ in range(az.RETRY_BAD_RESPONSE_MAX):
        make_due(az, batch_id)
        run_batch(az, batch_id)
    r = row(az, batch_id)
    assert r["status"] == "error" and r["attempts"] == az.RETRY_BAD_RESPONSE_MAX
    assert az._stats["dropped_bad_response"] == 1


def test_transient_failures_expire_after_max_age(az, gemini, monkeypatch):
    gemini(FakeResponse(503, text="x"))
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    assert row(az, batch_id)["status"] == "pending"
    later = az._now() + az.RETRY_MAX_AGE_HOURS * 3600 + 60
    monkeypatch.setattr(az, "_now", lambda: later)
    run_batch(az, batch_id)
    assert row(az, batch_id)["status"] == "error"
    assert az._stats["expired"] == 1


def test_unexpected_exception_does_not_strand_the_batch(az, monkeypatch):
    def boom(groups):
        raise RuntimeError("kaputt")
    monkeypatch.setattr(az, "call_gemini", boom)
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    assert row(az, batch_id)["status"] == "pending"
    assert batch_id not in az._inflight


# ── persistence across restarts ───────────────────────────────────────────────

def test_stale_analyzing_batches_are_requeued_on_startup(az, gemini):
    fake = gemini(gemini_ok())
    stuck = new_batch(az)                  # process died while this was in flight
    legacy = new_batch(az)                 # row written by the old schema: no claimed_at
    with az._db() as conn:
        conn.execute("UPDATE batches SET claimed_at=NULL WHERE id=?", (legacy,))
    assert az._requeue_stale(0) == 2
    assert row(az, stuck)["status"] == "pending" and row(az, legacy)["status"] == "pending"
    while az._retry_once():
        pass
    assert row(az, stuck)["status"] == "done" and row(az, legacy)["status"] == "done"
    assert fake.calls == 2


def test_runtime_sweep_spares_requests_in_flight(az):
    batch_id = new_batch(az)
    with az._db() as conn:
        conn.execute("UPDATE batches SET claimed_at=? WHERE id=?", (az._now() - 7200, batch_id))
    az._inflight.add(batch_id)
    assert az._requeue_stale(az.STALE_ANALYZING_SECONDS) == 0
    az._inflight.discard(batch_id)
    assert az._requeue_stale(az.STALE_ANALYZING_SECONDS) == 1


def test_fresh_analyzing_batch_is_not_swept(az):
    new_batch(az)
    assert az._requeue_stale(az.STALE_ANALYZING_SECONDS) == 0


def test_old_database_is_migrated_in_place(az, tmp_path, monkeypatch):
    import sqlite3
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.executescript("""
        CREATE TABLE batches (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            alert_count INTEGER NOT NULL, raw_groups TEXT NOT NULL, summary TEXT,
            overall_risk TEXT DEFAULT 'unknown', status TEXT DEFAULT 'pending', source TEXT DEFAULT 'live');
        CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id INTEGER NOT NULL,
            title TEXT NOT NULL, severity TEXT NOT NULL, description TEXT NOT NULL,
            recommendation TEXT NOT NULL, affected_agents TEXT, rule_ids TEXT);
        INSERT INTO batches (created_at, alert_count, raw_groups, status) VALUES ('2026-03-19T00:00:00', 3, '[]', 'analyzing');
    """)
    con.commit()
    con.close()
    monkeypatch.setattr(az, "DB_PATH", str(old))
    az.init_db()
    az.init_db()                           # idempotent
    with az._db() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(batches)")}
        assert {"attempts", "next_attempt", "first_error_at", "last_error", "claimed_at"} <= cols
    assert az._requeue_stale(0) == 1       # the March batch that was stuck on 'analyzing'


# ── backoff maths ─────────────────────────────────────────────────────────────

def test_backoff_grows_exponentially_with_jitter_and_cap(az):
    base, cap = az.RETRY_BASE_DELAY, az.RETRY_MAX_DELAY
    for attempt in range(1, 30):
        expected = min(cap, base * 2 ** (attempt - 1))
        for _ in range(20):
            delay = az._backoff_delay(attempt)
            assert delay <= cap
            assert expected * 0.8 - 1e-6 <= delay <= expected * 1.2 + 1e-6 or delay == cap
    assert az._backoff_delay(1) < az._backoff_delay(6)


def test_upstream_backoff_grows_with_consecutive_failures_and_resets(az):
    first = az.upstream.mark_failure("a")
    for _ in range(4):
        last = az.upstream.mark_failure("a")
    assert last > first
    assert az.upstream.wait_seconds() > 0
    az.upstream.mark_success()
    assert az.upstream.wait_seconds() == 0 and az.upstream.consecutive_failures == 0


def test_retry_after_header_is_honoured_but_capped(az, gemini):
    gemini(FakeResponse(503, text="x", headers={"Retry-After": "7200"}))
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    assert az.upstream.wait_seconds() <= az.RETRY_MAX_DELAY + 1


# ── secrets & observability ───────────────────────────────────────────────────

def test_stored_error_text_never_contains_the_api_key(az, gemini):
    gemini(requests.ConnectionError(f"HTTPSConnectionPool: url /x?key={az.GEMINI_API_KEY} failed"))
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    last_error = row(az, batch_id)["last_error"]
    assert az.GEMINI_API_KEY not in last_error and "***" in last_error


def test_stats_endpoint_exposes_queue_and_counters(az, gemini, monkeypatch):
    gemini(FakeResponse(503, text="x"))
    done_id, pending_id, dropped_id = new_batch(az), new_batch(az), new_batch(az)
    with az._db() as conn:
        conn.execute("UPDATE batches SET status='done' WHERE id=?", (done_id,))
    run_batch(az, pending_id)
    az._drop_batch(dropped_id, "permanent: test", "dropped_permanent")

    monkeypatch.setattr(az, "DASHBOARD_PASSWORD_HASH", "x")
    client = az.app.test_client()
    with client.session_transaction() as sess:
        sess.update(authenticated=True, user=az.DASHBOARD_USER, expires_at=az._now() + 600)
    data = client.get("/api/stats").get_json()

    assert data["batches"] == {"done": 1, "error": 1, "pending": 1, "analyzing": 0}
    assert data["retry_queue_size"] == 1
    assert data["runtime"]["dropped_permanent"] == 1
    assert data["runtime"]["retries_scheduled"] == 1
    assert data["upstream"]["consecutive_failures"] == 1


# ── review follow-ups ─────────────────────────────────────────────────────────

INVALID_KEY_400 = {"error": {"code": 400, "status": "INVALID_ARGUMENT",
                             "message": "API key not valid. Please pass a valid API key.",
                             "details": [{"reason": "API_KEY_INVALID"}]}}


def test_invalid_key_answered_with_400_is_a_config_error(az, gemini):
    gemini(FakeResponse(400, body=INVALID_KEY_400))
    _, failure = az.call_gemini([{"rule_id": "1"}])
    assert failure.kind == "config"
    gemini(FakeResponse(400, body={"error": {"status": "FAILED_PRECONDITION",
                                             "message": "User location is not supported"}}))
    _, failure = az.call_gemini([{"rule_id": "1"}])
    assert failure.kind == "config"


def test_invalid_key_does_not_empty_the_queue(az, gemini):
    gemini(FakeResponse(400, body=INVALID_KEY_400))
    ids = [new_batch(az) for _ in range(4)]
    for batch_id in ids:
        make_due(az, batch_id)
        run_batch(az, batch_id)
    assert {row(az, b)["status"] for b in ids} == {"pending"}
    assert az._stats["errors"] == 0


def test_a_run_of_permanent_errors_stops_dropping_batches(az, gemini):
    """One poisoned batch is dropped; many in a row means the request is wrong."""
    gemini(FakeResponse(400, text="Request contains an invalid argument"))
    ids = [new_batch(az) for _ in range(5)]
    for batch_id in ids:
        make_due(az, batch_id)
        run_batch(az, batch_id)
    statuses = [row(az, b)["status"] for b in ids]
    assert statuses[:az.PERMANENT_STREAK_LIMIT - 1] == ["error"] * (az.PERMANENT_STREAK_LIMIT - 1)
    assert "pending" in statuses[az.PERMANENT_STREAK_LIMIT - 1:]
    assert az._stats["dropped_permanent"] == az.PERMANENT_STREAK_LIMIT - 1


def test_success_resets_the_permanent_streak(az, gemini):
    gemini(FakeResponse(400, text="bad"), gemini_ok(), FakeResponse(400, text="bad"),
           FakeResponse(400, text="bad"))
    ids = [new_batch(az) for _ in range(4)]
    for batch_id in ids:
        make_due(az, batch_id)
        run_batch(az, batch_id)
    assert [row(az, b)["status"] for b in ids] == ["error", "done", "error", "error"]


def test_quota_wait_clears_the_expiry_clock(az, gemini, monkeypatch):
    """503 on day 1, three days of waiting for quota, then one more 503: not expired."""
    gemini(FakeResponse(503, text="x"), FakeResponse(429, body={"error": {"message": "quota"}}),
           FakeResponse(503, text="x"))
    batch_id = new_batch(az)
    t0 = az._now()
    run_batch(az, batch_id)
    assert row(az, batch_id)["first_error_at"]
    make_due(az, batch_id)
    run_batch(az, batch_id)                                 # 429
    assert row(az, batch_id)["first_error_at"] is None
    monkeypatch.setattr(az, "_now", lambda: t0 + 3 * 86400)
    make_due(az, batch_id)
    run_batch(az, batch_id)                                 # 503 again
    assert row(az, batch_id)["status"] == "pending" and az._stats["expired"] == 0


def test_bad_response_budget_is_not_eaten_by_quota_waits(az, gemini):
    gemini(FakeResponse(429, body={"error": {"message": "quota"}}),
           FakeResponse(429, body={"error": {"message": "quota"}}),
           FakeResponse(200, text="garbage"))
    batch_id = new_batch(az)
    for _ in range(3):
        make_due(az, batch_id)
        run_batch(az, batch_id)
    r = row(az, batch_id)
    assert r["attempts"] == 3 and r["bad_responses"] == 1 and r["status"] == "pending"


def test_live_batches_are_retried_before_old_history(az, gemini):
    fake = gemini(gemini_ok())
    old = az._store_batch([ALERT], "history")[0]
    live = new_batch(az)
    for b in (old, live):
        with az._db() as conn:
            conn.execute("UPDATE batches SET status='pending', next_attempt=0 WHERE id=?", (b,))
    az._retry_once()
    assert row(az, live)["status"] == "done" and row(az, old)["status"] == "pending"


@pytest.mark.parametrize("header", ["inf", "nan", "-5", "1e12", "Wed, 21 Oct 2026 07:28:00 GMT"])
def test_hostile_retry_after_cannot_close_the_gate_forever(az, gemini, header):
    gemini(FakeResponse(429, body={"error": {"message": "quota"}}, headers={"Retry-After": header}))
    az.call_gemini([{"rule_id": "1"}])
    assert 0 < az.quota.wait_seconds() <= 86400 + 1


def test_unexpected_answer_shape_is_stored_not_retried(az, gemini):
    fake = gemini(gemini_ok({"summary": "s", "overall_risk": ["x"], "findings": [
        "nonsense", {"title": "ok", "severity": ["high"], "affected_agents": "ct100", "rule_ids": None}]}))
    batch_id = new_batch(az)
    run_batch(az, batch_id)
    r = row(az, batch_id)
    assert r["status"] == "done" and r["overall_risk"] == "unknown" and fake.calls == 1
    with az._db() as conn:
        f = conn.execute("SELECT * FROM findings WHERE batch_id=?", (batch_id,)).fetchone()
    assert f["severity"] == "info" and json.loads(f["affected_agents"]) == []
