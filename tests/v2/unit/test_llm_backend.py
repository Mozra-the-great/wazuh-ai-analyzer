"""The Gemini REST backend: request, error classification, key handling (#43, #41).

Ports the classification part of tests/test_retry_queue.py. No test talks to the
network: the HTTP POST is a `FakeGemini`.
"""

from __future__ import annotations

import logging

import pytest
import requests

from v2.pipeline_support import KEY, FakeGemini, FakeResponse, gemini_ok
from wazuh_ai_analyzer.analysis import create_backend
from wazuh_ai_analyzer.analysis.backend import BackendFailure, BatchContext
from wazuh_ai_analyzer.analysis.llm import (
    API_BASE,
    REQUEST_TIMEOUT,
    GeminiLlmBackend,
    _default_post,
    block_reason,
    strip_code_fence,
)
from wazuh_ai_analyzer.config import load_config
from wazuh_ai_analyzer.ingest.sanitize import AlertGroup, sanitize_group
from wazuh_ai_analyzer.logging_setup import RedactSecrets
from wazuh_ai_analyzer.secret import Secret

CONTEXT = BatchContext(batch_id=1, source="live", is_retry=False)
GROUPS: list[AlertGroup] = [sanitize_group({"rule_id": "1"})]


def backend(*outcomes: FakeResponse | Exception, key: str | None = KEY) -> GeminiLlmBackend:
    return GeminiLlmBackend(
        api_key=Secret(key) if key is not None else None,
        model="gemini-3.1-flash-lite",
        temperature=0.15,
        infra_context="a lab",
        post=FakeGemini(*outcomes),
    )


def failure_of(b: GeminiLlmBackend) -> BackendFailure:
    with pytest.raises(BackendFailure) as info:
        b.analyse(GROUPS, CONTEXT)
    return info.value


@pytest.mark.parametrize(
    ("outcome", "kind"),
    [
        (FakeResponse(500, text="boom"), "transient"),
        (FakeResponse(502, text="bad gateway"), "transient"),
        (FakeResponse(503, text="overloaded"), "transient"),
        (FakeResponse(504, text="timeout"), "transient"),
        (FakeResponse(408, text="request timeout"), "transient"),
        (FakeResponse(425, text="too early"), "transient"),
        (requests.Timeout("slow"), "transient"),
        (requests.ConnectionError("dns"), "transient"),
        (requests.exceptions.ChunkedEncodingError("cut"), "transient"),
        (FakeResponse(429, body={"error": {"message": "Quota exceeded"}}), "quota"),
        (FakeResponse(400, text="invalid argument"), "permanent"),
        (FakeResponse(413, text="too large"), "permanent"),
        (FakeResponse(401, text="bad key"), "config"),
        (FakeResponse(403, text="forbidden"), "config"),
        (FakeResponse(404, text="no such model"), "config"),
        (FakeResponse(200, text="<html>"), "bad_response"),
        (FakeResponse(200, body={"candidates": []}), "bad_response"),
        (FakeResponse(302, text="moved"), "bad_response"),
        (requests.TooManyRedirects("loop"), "bad_response"),
    ],
)
def test_failures_are_classified_like_the_legacy_code(
    outcome: FakeResponse | Exception, kind: str
) -> None:
    assert failure_of(backend(outcome)).kind == kind


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        (FakeResponse(503, text="overloaded"), "Gemini HTTP 503: overloaded"),
        (requests.Timeout("slow"), "Gemini: Timeout"),
        (requests.ConnectionError("dns"), "Gemini: Verbindungsfehler: dns"),
        (
            FakeResponse(200, body={"candidates": []}),
            "Antwort nicht auswertbar: IndexError('list index out of range')",
        ),
        (requests.TooManyRedirects("loop"), "Gemini: Fehler: loop"),
        (FakeResponse(429, body={"error": {"message": "Quota exceeded"}}), "Quota exceeded"),
    ],
)
def test_failure_messages_are_the_legacy_texts(
    outcome: FakeResponse | Exception, message: str
) -> None:
    assert failure_of(backend(outcome)).message == message


def test_success_returns_the_validated_result() -> None:
    result = backend(gemini_ok()).analyse(GROUPS, CONTEXT)
    assert result.overall_risk == "low"
    assert result.mode == "llm"
    assert result.findings[0].title == "SSH-Login-Versuche"


def test_a_code_fenced_answer_is_accepted() -> None:
    assert backend(gemini_ok(fenced=True)).analyse(GROUPS, CONTEXT).summary == "alles ruhig"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('{"a": 1}', '{"a": 1}'),
        ('```json\n{"a": 1}\n```', '{"a": 1}'),
        ('```JSON {"a": 1}```', '{"a": 1}'),
        ('```\n{"a": 1}\n```', '{"a": 1}'),
        ('  {"a": "```"}  ', '{"a": "```"}'),
    ],
)
def test_strip_code_fence(raw: str, expected: str) -> None:
    assert strip_code_fence(raw) == expected


def test_missing_api_key_is_config_and_sends_nothing() -> None:
    b = backend(gemini_ok(), key=None)
    assert failure_of(b).kind == "config"
    assert b._post.calls == []  # type: ignore[attr-defined]


def test_request_matches_the_legacy_request() -> None:
    fake = FakeGemini(gemini_ok())
    b = GeminiLlmBackend(
        api_key=Secret(KEY),
        model="gemini-3.1-flash-lite",
        temperature=0.4,
        infra_context="Proxmox lab",
        post=fake,
        nonce=lambda: "00" * 8,
    )
    b.analyse(GROUPS, CONTEXT)
    (call,) = fake.calls
    assert call.url == f"{API_BASE}/gemini-3.1-flash-lite:generateContent"
    assert call.headers == {"x-goog-api-key": KEY}
    assert call.kwargs == {"timeout": REQUEST_TIMEOUT}
    assert call.json["generationConfig"] == {
        "temperature": 0.4,
        "responseMimeType": "application/json",
    }
    assert "unvertrauenswuerdige" in call.json["systemInstruction"]["parts"][0]["text"]
    assert "Infrastruktur-Kontext: Proxmox lab." in call.json["contents"][0]["parts"][0]["text"]


def test_the_key_is_only_in_the_header() -> None:
    fake = FakeGemini(gemini_ok())
    b = GeminiLlmBackend(
        api_key=Secret(KEY), model="m", temperature=0, infra_context="x", post=fake
    )
    b.analyse(GROUPS, CONTEXT)
    (call,) = fake.calls
    assert KEY not in call.url
    assert KEY not in str(call.json)
    assert KEY not in repr(b.__dict__)


def test_the_real_post_does_not_follow_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_post(url: str, **kwargs: object) -> FakeResponse:
        seen.update(kwargs, url=url)
        return gemini_ok()

    monkeypatch.setattr(requests, "post", fake_post)
    _default_post("https://example.invalid/x", json={}, headers={}, timeout=1.0)
    assert seen["allow_redirects"] is False
    assert seen["timeout"] == 1.0


INVALID_KEY_400 = {
    "error": {
        "code": 400,
        "status": "INVALID_ARGUMENT",
        "message": "API key not valid. Please pass a valid API key.",
        "details": [{"reason": "API_KEY_INVALID"}],
    }
}


@pytest.mark.parametrize(
    "body",
    [
        INVALID_KEY_400,
        {"error": {"status": "FAILED_PRECONDITION", "message": "User location is not supported"}},
        {"error": {"message": "User location is not supported for the API use."}},
    ],
)
def test_setup_problems_answered_with_400_are_config_errors(body: object) -> None:
    assert failure_of(backend(FakeResponse(400, body=body))).kind == "config"


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(400, text="the api key is malformed"),  # not JSON: the text decides
        FakeResponse(400, body=["not", "an", "object"], text="plain"),
        FakeResponse(400, body={"error": "flat string"}, text="plain"),
    ],
)
def test_odd_400_bodies_do_not_crash_the_classification(response: FakeResponse) -> None:
    expected = "config" if "api key" in response.text else "permanent"
    assert failure_of(backend(response)).kind == expected


@pytest.mark.parametrize(
    ("message", "wait"),
    [("You exceeded your current quota", 3600), ("per day limit", 3600), ("slow down", 65)],
)
def test_quota_wait_without_retry_after(message: str, wait: float) -> None:
    f = failure_of(backend(FakeResponse(429, body={"error": {"message": message}})))
    assert (f.kind, f.retry_after) == ("quota", wait)


@pytest.mark.parametrize("header", ["inf", "nan", "-5", "1e12", "Wed, 21 Oct 2026 07:28:00 GMT"])
def test_hostile_retry_after_cannot_close_the_gate_forever(header: str) -> None:
    f = failure_of(
        backend(
            FakeResponse(429, body={"error": {"message": "q"}}, headers={"Retry-After": header})
        )
    )
    assert 0 < f.retry_after <= 86400


def test_retry_after_of_a_5xx_is_passed_on() -> None:
    f = failure_of(backend(FakeResponse(503, text="x", headers={"Retry-After": "120"})))
    assert (f.kind, f.retry_after) == ("transient", 120)


def test_429_with_an_odd_body_uses_the_text() -> None:
    f = failure_of(backend(FakeResponse(429, body=["x"], text="daily quota exhausted")))
    assert f.message == "daily quota exhausted"
    assert f.retry_after == 3600


def test_backend_log_lines_are_scrubbed_by_the_filter(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redactor = RedactSecrets([KEY])
    caplog.handler.addFilter(redactor)
    try:
        with caplog.at_level(logging.ERROR):
            failure_of(backend(requests.ConnectionError(f"https://x/?key={KEY}")))
    finally:
        caplog.handler.removeFilter(redactor)
    assert KEY not in caplog.text
    assert "***" in caplog.text


def test_create_backend_builds_the_backend_of_the_mode() -> None:
    assert create_backend(load_config({})).name == "llm"
    assert create_backend(load_config({"ANALYSIS_MODE": "decision"})).name == "decision"


def test_a_secret_is_scrubbed_before_the_error_text_is_cut() -> None:
    """The cut at 200 characters must not split the key into a form the redaction misses."""
    body = "x" * 190 + KEY + " trailing"
    failure = failure_of(backend(FakeResponse(400, text=body)))
    assert KEY not in failure.message
    assert KEY[:6] not in failure.message
    assert failure.message.startswith("Gemini HTTP 400: ")
    assert "***" in failure.message


def test_a_secret_in_a_quota_text_is_scrubbed_before_the_cut() -> None:
    failure = failure_of(backend(FakeResponse(429, text="y" * 140 + KEY)))
    assert failure.kind == "quota"
    assert KEY[:6] not in failure.message


# ── safety blocks (#97) ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            {"promptFeedback": {"blockReason": "SAFETY"}},
            "Gemini blockiert die Anfrage (blockReason=SAFETY)",
        ),
        (
            {"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}, "candidates": []},
            "Gemini blockiert die Anfrage (blockReason=PROHIBITED_CONTENT)",
        ),
        (
            {"candidates": [{"finishReason": "SAFETY"}]},
            "Gemini blockiert die Antwort (finishReason=SAFETY)",
        ),
        (
            {"candidates": [{"finishReason": "PROHIBITED_CONTENT", "content": {"parts": []}}]},
            "Gemini blockiert die Antwort (finishReason=PROHIBITED_CONTENT)",
        ),
        (
            {"candidates": [{"finishReason": "RECITATION", "content": {}}]},
            "Gemini blockiert die Antwort (finishReason=RECITATION)",
        ),
    ],
)
def test_a_blocked_answer_has_its_own_error_text(body: object, message: str) -> None:
    failure = failure_of(backend(FakeResponse(200, body)))
    assert failure.kind == "bad_response"
    assert failure.message == message


def test_a_hostile_block_reason_is_cleaned() -> None:
    body = {"promptFeedback": {"blockReason": "SAFETY‮\n" + "X" * 100}}
    message = failure_of(backend(FakeResponse(200, body))).message
    assert "‮" not in message
    assert "\n" not in message
    assert len(message) < 120


@pytest.mark.parametrize(
    "body",
    [
        {"candidates": [{"finishReason": "MAX_TOKENS"}]},  # not a block: stays a broken answer
        {"candidates": [{"finishReason": "SAFETY", "content": {"parts": [{"text": "{}"}]}}]},
        {"promptFeedback": {"blockReason": ""}, "candidates": []},
        {"promptFeedback": "x", "candidates": []},
    ],
)
def test_other_answers_without_text_are_not_reported_as_blocked(body: object) -> None:
    f = failure_of(backend(FakeResponse(200, body)))
    assert f.kind == "bad_response"
    assert "blockiert" not in f.message


def test_block_reason_only_reports_real_blocks() -> None:
    assert block_reason({"candidates": [{"finishReason": "SAFETY"}]}) is not None
    assert block_reason({"candidates": [{"finishReason": "STOP"}]}) is None
    assert block_reason([]) is None
