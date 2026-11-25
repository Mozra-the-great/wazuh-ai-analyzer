"""The `llm` analysis mode: Gemini `generateContent` over plain REST (#85).

Feature parity with `analyzer.py`: the same request (model, temperature, JSON
response mode, separate system instruction), the same answer validation and the
same error classification, including the German `last_error` texts.

The API key goes only into the `x-goog-api-key` header: never into the URL, a log
line or an exception text. Redirects are not followed, so the header cannot be
replayed to another host. The log redaction filter (#41) is the second line of
defence.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections.abc import Callable, Sequence
from typing import Any, Final, Protocol

import requests

from ..config import GeminiConfig
from ..ingest.sanitize import AlertGroup
from ..secret import Secret
from ..storage.contract import AnalysisMode
from .backend import AnalysisResult, BackendFailure, BatchContext
from .prompt import SYSTEM_INSTRUCTION, build_prompt, new_nonce, validate_result

log = logging.getLogger(__name__)

API_BASE: Final = "https://generativelanguage.googleapis.com/v1beta/models"
REQUEST_TIMEOUT: Final = 90.0  # seconds; STALE_ANALYZING_SECONDS must stay well above it
RETRY_AFTER_MAX: Final = 86400.0
# Without a Retry-After header: a daily quota waits an hour, a per-minute limit 65 s.
DAILY_QUOTA_WAIT: Final = 3600.0
MINUTE_QUOTA_WAIT: Final = 65.0
_DAILY_QUOTA_WORDS: Final = ("quota", "day", "exhausted")
_FENCE_START = re.compile(r"^```(?:json)?\s*", re.IGNORECASE)
_FENCE_END = re.compile(r"\s*```$")


class HttpResponse(Protocol):
    """The part of `requests.Response` the backend uses (tests pass fakes)."""

    @property
    def status_code(self) -> int: ...

    @property
    def ok(self) -> bool: ...

    @property
    def text(self) -> str: ...

    @property
    def headers(self) -> Any: ...

    def json(self) -> Any: ...


PostFunction = Callable[..., HttpResponse]


def _default_post(
    url: str, *, json: dict[str, object], headers: dict[str, str], timeout: float
) -> HttpResponse:
    return requests.post(url, json=json, headers=headers, timeout=timeout, allow_redirects=False)


def retry_after_seconds(resp: HttpResponse) -> float:
    """A numeric `Retry-After` header in seconds, capped at a day; 0 if absent or a date."""
    try:
        value = float(resp.headers.get("Retry-After", 0))
    except (TypeError, ValueError):
        return 0.0
    return min(value, RETRY_AFTER_MAX) if math.isfinite(value) and value > 0 else 0.0


def is_config_error_body(resp: HttpResponse) -> bool:
    """Gemini reports an invalid/expired key and unsupported regions as HTTP 400
    (API_KEY_INVALID / FAILED_PRECONDITION), not as 401/403. Those are problems of
    the setup, not of the batch."""
    try:
        err = resp.json().get("error", {})
        reasons = {d.get("reason") for d in err.get("details", []) if isinstance(d, dict)}
        text = str(err.get("message", "")).lower()
        status = err.get("status")
    except Exception:
        text = resp.text.lower()
        reasons, status = set(), None
    return (
        status == "FAILED_PRECONDITION"
        or "API_KEY_INVALID" in reasons
        or "api key" in text
        or "location is not supported" in text
    )


def _quota_message(resp: HttpResponse) -> str:
    try:
        message = resp.json().get("error", {}).get("message", "") or resp.text[:150]
    except Exception:
        message = resp.text[:150]
    return str(message)


def strip_code_fence(text: str) -> str:
    """Remove a Markdown code fence around a JSON answer (```json ... ```)."""
    text = text.strip()
    text = _FENCE_START.sub("", text, count=1)
    return _FENCE_END.sub("", text, count=1).strip()


class GeminiLlmBackend:
    """One `generateContent` request per batch."""

    def __init__(
        self,
        *,
        api_key: Secret | None,
        model: str,
        temperature: float,
        infra_context: str,
        post: PostFunction = _default_post,
        nonce: Callable[[], str] = new_nonce,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._infra_context = infra_context
        self._post = post
        self._nonce = nonce

    @classmethod
    def from_config(
        cls, gemini: GeminiConfig, *, post: PostFunction = _default_post
    ) -> GeminiLlmBackend:
        return cls(
            api_key=gemini.api_key,
            model=gemini.model,
            temperature=gemini.temperature,
            infra_context=gemini.infra_context,
            post=post,
        )

    @property
    def name(self) -> AnalysisMode:
        return "llm"

    @property
    def url(self) -> str:
        return f"{API_BASE}/{self._model}:generateContent"

    def request_payload(self, groups: Sequence[object]) -> dict[str, object]:
        prompt = build_prompt(groups, self._infra_context, self._nonce())
        return {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self._temperature,
                "responseMimeType": "application/json",
            },
            "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
        }

    def analyse(self, groups: Sequence[AlertGroup], context: BatchContext) -> AnalysisResult:
        if not self._api_key:
            log.error("GEMINI_API_KEY is not set")
            raise BackendFailure("config", "GEMINI_API_KEY nicht gesetzt")
        payload = self.request_payload(groups)
        headers = {"x-goog-api-key": self._api_key.reveal()}
        try:
            resp = self._post(self.url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 429:
                raise self._quota_failure(resp)
            if not resp.ok:
                raise self._http_failure(resp)
            data = resp.json()
            raw = data["candidates"][0]["content"]["parts"][0]["text"]
            answer = validate_result(json.loads(strip_code_fence(raw)), groups)
        except BackendFailure:
            raise
        except requests.Timeout:
            log.error("Gemini: timeout")
            raise BackendFailure("transient", "Gemini: Timeout") from None
        except (requests.ConnectionError, requests.exceptions.ChunkedEncodingError) as exc:
            log.error("Gemini: connection error: %s", exc)
            raise BackendFailure("transient", f"Gemini: Verbindungsfehler: {exc}") from None
        except (KeyError, IndexError, TypeError, ValueError) as exc:  # JSONDecodeError too
            log.error("Gemini: answer could not be parsed: %r", exc)
            raise BackendFailure("bad_response", f"Antwort nicht auswertbar: {exc!r}") from None
        except Exception as exc:
            log.error("Gemini: error: %s", exc)
            raise BackendFailure("bad_response", f"Gemini: Fehler: {exc}") from None
        return AnalysisResult(
            summary=answer.summary,
            overall_risk=answer.overall_risk,
            findings=answer.findings,
            mode="llm",
            suspicious_downgrades=answer.suspicious_downgrades,
        )

    @staticmethod
    def _quota_failure(resp: HttpResponse) -> BackendFailure:
        retry_after = retry_after_seconds(resp)
        message = _quota_message(resp)
        if retry_after <= 0:
            lowered = message.lower()
            daily = any(word in lowered for word in _DAILY_QUOTA_WORDS)
            retry_after = DAILY_QUOTA_WAIT if daily else MINUTE_QUOTA_WAIT
        return BackendFailure("quota", message, retry_after)

    @staticmethod
    def _http_failure(resp: HttpResponse) -> BackendFailure:
        code = resp.status_code
        message = f"Gemini HTTP {code}: {resp.text[:200]}"
        log.error("%s", message)
        if code >= 500 or code in (408, 425):
            return BackendFailure("transient", message, retry_after_seconds(resp))
        if code in (401, 403, 404):
            # Key revoked / wrong model: every batch fails alike and the operator can
            # fix it. The queue is kept meanwhile.
            return BackendFailure("config", message)
        if code == 400 and is_config_error_body(resp):
            return BackendFailure("config", message)
        return BackendFailure("permanent", message)
