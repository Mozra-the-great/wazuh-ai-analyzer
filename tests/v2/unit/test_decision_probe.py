"""`probe-decision`: the one real call to the Decisions API, with a fake HTTP layer here."""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest
import requests

from v2.decision_support import backend, blocked, decision_ok
from v2.pipeline_support import KEY, FakeResponse
from wazuh_ai_analyzer import __main__ as cli
from wazuh_ai_analyzer.analysis.probe import PROBE_GROUP, probe


def run(b: object, **kwargs: bool) -> tuple[int, str]:
    out = io.StringIO()
    code = probe(b, out, clock=iter([0.0, 0.25]).__next__, **kwargs)  # type: ignore[arg-type]
    return code, out.getvalue()


def test_a_successful_probe_prints_the_response_and_the_finding() -> None:
    code, text = run(backend(decision_ok(severity="medium", relevant=0.8)))
    assert code == 0
    assert "POST https://generativelanguage.googleapis.com/v1beta/decisions" in text
    assert "HTTP 200 in 250 ms" in text
    assert '"answers"' in text
    assert "finding [medium]" in text
    assert "decision_version: 1-" in text
    assert KEY not in text


def test_the_probe_group_is_made_up_data() -> None:
    assert PROBE_GROUP["agents"] == ["probe-host"]
    assert "203.0.113.7" in PROBE_GROUP["samples"][0]["src_ip"]  # documentation range


def test_a_probe_below_the_thresholds_says_so() -> None:
    code, text = run(backend(decision_ok(relevant=0.01)))
    assert code == 0
    assert "no finding" in text


@pytest.mark.parametrize(
    ("response", "kind"),
    [
        (
            FakeResponse(429, {"error": {"message": "quota"}}, headers={"Retry-After": "30"}),
            "quota",
        ),
        (FakeResponse(503, text="down"), "transient"),
        (FakeResponse(403, text="no"), "config"),
        (FakeResponse(200, text="<html>"), "bad_response"),
    ],
)
def test_a_failing_probe_shows_status_body_and_classification(
    response: FakeResponse, kind: str
) -> None:
    code, text = run(backend(response))
    assert code == 1
    assert f"HTTP {response.status_code}" in text
    assert f"classified as: {kind}" in text
    assert "last_error text:" in text


def test_a_429_probe_shows_the_retry_after_header() -> None:
    response = FakeResponse(429, {"error": {"message": "quota"}}, headers={"Retry-After": "30"})
    _, text = run(backend(response))
    assert "header retry-after: 30" in text
    assert "retry after 30 s" in text


def test_a_transport_error_is_reported() -> None:
    code, text = run(backend(requests.Timeout("slow")))
    assert code == 1
    assert "no response: transient: Gemini Decision: Timeout" in text


def test_a_blocked_probe_group_is_reported_as_a_finding() -> None:
    code, text = run(backend(blocked("safety")))
    assert code == 0
    assert "finding [low] Nicht analysierbar" in text


def test_invalid_mode_sends_no_questions_and_records_the_400() -> None:
    b = backend(FakeResponse(400, {"error": {"code": 400, "message": "questions is empty"}}))
    code, text = run(b, invalid=True)
    assert code == 0
    assert "0 questions" in text
    assert "questions is empty" in text
    assert b._post.calls[0].json["questions"] == {}  # type: ignore[attr-defined]


def test_invalid_mode_fails_if_the_api_accepts_the_request() -> None:
    code, text = run(backend(decision_ok()), invalid=True)
    assert code == 1
    assert "accepted an invalid request" in text


def test_the_key_never_appears_in_the_output() -> None:
    _, text = run(backend(FakeResponse(400, text=f"bad {KEY} key"), key=KEY))
    assert KEY not in text


def test_the_cli_needs_a_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(os, "environ", {"DB_PATH": str(tmp_path / "a.db")})
    assert cli.main(["probe-decision"]) == cli.EXIT_CONFIG


def test_the_cli_runs_the_probe_with_the_configured_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent: list[dict[str, object]] = []

    def fake_post(url: str, **kwargs: object) -> FakeResponse:
        sent.append({"url": url, **kwargs})
        return decision_ok()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(os, "environ", {"DB_PATH": str(tmp_path / "a.db"), "GEMINI_API_KEY": KEY})
    out = io.StringIO()
    assert cli.main(["probe-decision"], out=out) == cli.EXIT_OK
    assert "HTTP 200" in out.getvalue()
    (call,) = sent
    assert call["headers"] == {"x-goog-api-key": KEY}
    assert call["allow_redirects"] is False
    assert KEY not in out.getvalue()


def test_the_cli_exits_with_failure_when_the_probe_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(requests, "post", lambda url, **kw: FakeResponse(503, text="down"))
    monkeypatch.setattr(os, "environ", {"DB_PATH": str(tmp_path / "a.db"), "GEMINI_API_KEY": KEY})
    assert cli.main(["probe-decision"], out=io.StringIO()) == cli.EXIT_FAILURE
