"""Fakes and a harness for the pipeline and LLM backend tests (no network).

`FakeGemini` stands in for the HTTP POST, like the legacy tests' replacement of
`requests.post`: it replays the given outcomes, one per call (the last one
repeats), and records every call.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from v2.helpers import FakeClock
from wazuh_ai_analyzer.analysis.llm import GeminiLlmBackend
from wazuh_ai_analyzer.config import Config, load_config
from wazuh_ai_analyzer.ingest.batches import BatchWriter
from wazuh_ai_analyzer.logging_setup import RedactSecrets
from wazuh_ai_analyzer.pipeline import Pipeline
from wazuh_ai_analyzer.storage.contract import Source
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import Repository

# A dummy, low-entropy value: never a real key (gitleaks must not flag it).
KEY = "dummy-pipeline-secret-0005"

ALERT: dict[str, Any] = {
    "rule": {"id": "5710", "level": 7, "description": "sshd: attempt to login"},
    "agent": {"name": "ct100"},
    "location": "journald",
    "timestamp": "2026-10-07T10:00:00.000+0000",
    "full_log": "Failed password for invalid user admin",
}
GOOD_ANSWER: dict[str, Any] = {
    "summary": "alles ruhig",
    "overall_risk": "low",
    "findings": [
        {
            "title": "SSH-Login-Versuche",
            "severity": "low",
            "description": "d",
            "recommendation": "r",
            "affected_agents": ["ct100"],
            "rule_ids": ["5710"],
        }
    ],
}


class FakeResponse:
    def __init__(
        self,
        status: int = 200,
        body: object = None,
        text: str = "",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status_code = status
        self.ok = status < 400
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")
        self.headers: dict[str, str] = dict(headers or {})

    def json(self) -> Any:
        if self._body is None:
            raise requests.exceptions.JSONDecodeError("no json", self.text, 0)
        return self._body


def gemini_ok(answer: object = None, *, fenced: bool = False) -> FakeResponse:
    text = json.dumps(GOOD_ANSWER if answer is None else answer)
    if fenced:
        text = f"```json\n{text}\n```"
    return FakeResponse(200, {"candidates": [{"content": {"parts": [{"text": text}]}}]})


Outcome = FakeResponse | BaseException


@dataclass
class Call:
    url: str
    json: dict[str, Any]
    headers: dict[str, str]
    kwargs: dict[str, Any]


class FakeGemini:
    def __init__(self, *outcomes: Outcome) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[Call] = []
        self._lock = threading.Lock()

    def __call__(
        self, url: str, *, json: dict[str, Any], headers: dict[str, str], **kwargs: Any
    ) -> FakeResponse:
        with self._lock:
            self.calls.append(Call(url, json, dict(headers), kwargs))
            outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def set(self, *outcomes: Outcome) -> None:
        with self._lock:
            self.outcomes = list(outcomes)


def no_jitter(low: float, high: float) -> float:
    return 1.0


def config_for(db_path: Path, **env: str) -> Config:
    values = {"DB_PATH": str(db_path), "GEMINI_API_KEY": KEY, **env}
    return load_config(values)


@dataclass
class PipelineEnv:
    """A pipeline on a migrated database, a fake clock and a fake Gemini."""

    config: Config
    database: Database
    repo: Repository
    clock: FakeClock
    gemini: FakeGemini
    backend: GeminiLlmBackend
    pipeline: Pipeline
    stop: threading.Event = field(default_factory=threading.Event)

    def install(self, *outcomes: Outcome) -> FakeGemini:
        self.gemini.set(*outcomes)
        self.gemini.calls.clear()
        return self.gemini

    def new_batch(self, source: Source = "live", alerts: list[dict[str, Any]] | None = None) -> int:
        return BatchWriter(self.repo).store(alerts or [ALERT], source).batch_id

    def row(self, batch_id: int) -> dict[str, Any]:
        conn = self.database.connect()
        try:
            row = conn.execute("SELECT * FROM batches WHERE id=?", (batch_id,)).fetchone()
        finally:
            conn.close()
        assert row is not None
        return dict(row)

    def findings(self, batch_id: int) -> list[dict[str, Any]]:
        conn = self.database.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM findings WHERE batch_id=? ORDER BY id", (batch_id,)
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        conn = self.database.connect()
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def run(self, batch_id: int, *, is_retry: bool = False) -> None:
        r = self.row(batch_id)
        self.pipeline.run_attempt(
            batch_id, json.loads(r["raw_groups"]), r["source"], is_retry=is_retry
        )

    def make_due(self, batch_id: int) -> None:
        """Pretend the backoff has elapsed (for the batch and the shared gate)."""
        self.execute("UPDATE batches SET next_attempt=0 WHERE id=?", (batch_id,))
        self.pipeline.upstream.next_ok_at = 0.0
        self.pipeline.quota.retry_at = None

    def stats(self) -> dict[str, int]:
        return self.pipeline.counters.snapshot().as_dict()


def make_env(
    db_path: Path,
    clock: FakeClock,
    *,
    jitter: Any = no_jitter,
    **env: str,
) -> PipelineEnv:
    from wazuh_ai_analyzer.storage.schema import migrate

    db_path.parent.mkdir(parents=True, exist_ok=True)
    database = Database(db_path)
    migrate(database)
    config = config_for(db_path, **env)
    repo = Repository(database, clock=clock)
    gemini = FakeGemini(gemini_ok())
    backend = GeminiLlmBackend.from_config(config.gemini, post=gemini)
    stop = threading.Event()
    pipeline = Pipeline(
        config,
        repo,
        backend,
        stop=stop,
        scrub=RedactSecrets(config.secret_values()).scrub,
        clock=clock,
        monotonic=clock,
        jitter=jitter,
    )
    return PipelineEnv(config, database, repo, clock, gemini, backend, pipeline, stop)


def count(db_path: Path, sql: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute(sql).fetchone()[0])
    finally:
        conn.close()
