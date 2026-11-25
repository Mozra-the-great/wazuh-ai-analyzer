"""A web layer harness: the Flask app on a migrated temporary database, no network.

The client talks https (`SESSION_COOKIE_SECURE` is on by default, and a secure cookie is
only sent over https), and every helper that logs in goes through the real endpoints
(`/api/session` for the CSRF token, then `/api/login`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flask import Flask
from flask.testing import FlaskClient
from werkzeug.security import generate_password_hash
from werkzeug.test import TestResponse

from v2.helpers import FakeClock
from wazuh_ai_analyzer.config import Config, load_config
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import NewFinding, Repository
from wazuh_ai_analyzer.storage.schema import migrate
from wazuh_ai_analyzer.web.app import LiveState, create_app
from wazuh_ai_analyzer.web.auth import LoginLimiter
from wazuh_ai_analyzer.web.sessions import SessionStore

# Dummy values; the hash is generated at run time, so no hash literal sits in the repo.
USER = "admin"
PASSWORD = "dummy-web-password-0006"
HOST = "dashboard.test"
BASE = f"https://{HOST}"


class HttpsClient(FlaskClient):
    """A test client whose requests are https requests to `dashboard.test`."""

    def open(self, *args: Any, **kwargs: Any) -> TestResponse:
        kwargs.setdefault("base_url", BASE)
        return super().open(*args, **kwargs)


def password_hash(password: str = PASSWORD) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256:1000")


def web_config(tmp_path: Path, **env: str) -> Config:
    values = {
        "WAZUH_ALERTS_LOG": str(tmp_path / "alerts" / "alerts.json"),
        "DB_PATH": str(tmp_path / "data" / "analyses.db"),
        "DASHBOARD_USER": USER,
        "DASHBOARD_PASSWORD_HASH": password_hash(),
        "GEMINI_API_KEY": "dummy-web-key-0006",
        **env,
    }
    return load_config(values)


def fixed_runtime() -> dict[str, int | bool]:
    from wazuh_ai_analyzer.metrics.runtime import LEGACY_RUNTIME_KEYS, NEW_RUNTIME_KEYS

    values: dict[str, int | bool] = dict.fromkeys((*LEGACY_RUNTIME_KEYS, *NEW_RUNTIME_KEYS), 0)
    values["history_done"] = False
    values["processed"] = 7
    return values


@dataclass
class WebEnv:
    config: Config
    db: Database
    repo: Repository
    sessions: SessionStore
    app: Flask
    client: HttpsClient
    clock: FakeClock
    limiter: LoginLimiter
    key: bytes
    quota: dict[str, object] = field(default_factory=dict)
    upstream: dict[str, object] = field(default_factory=dict)
    buffered: list[int] = field(default_factory=lambda: [3])

    # ── data ─────────────────────────────────────────────────────────────────
    def add_finding(
        self,
        *,
        source: str = "live",
        severity: str = "high",
        title: str = "SSH brute force",
        description: str = "d",
        recommendation: str = "r",
        agents: tuple[str, ...] = ("ct100",),
        rules: tuple[str, ...] = ("5710",),
        confidence: float | None = None,
        summary: str = "summary",
    ) -> int:
        batch_id = self.repo.insert_batch(
            alert_count=3,
            raw_groups="[]",
            source="history" if source == "history" else "live",
            status="analyzing",
        )
        ids = self.repo.complete_batch(
            batch_id,
            summary=summary,
            overall_risk="low",
            findings=[
                NewFinding(
                    title=title,
                    severity=severity,  # type: ignore[arg-type]
                    description=description,
                    recommendation=recommendation,
                    affected_agents=agents,
                    rule_ids=rules,
                    confidence=confidence,
                )
            ],
        )
        return ids[0]

    # ── login ────────────────────────────────────────────────────────────────
    def login_token(self, client: HttpsClient | None = None) -> str:
        response = (client or self.client).get("/api/session")
        return str(response.get_json()["csrf_token"])

    def login(
        self,
        client: HttpsClient | None = None,
        *,
        password: str = PASSWORD,
        username: str = USER,
        next_path: str | None = None,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> TestResponse:
        target = client or self.client
        csrf = token if token is not None else self.login_token(target)
        body: dict[str, object] = {"username": username, "password": password}
        if next_path is not None:
            body["next"] = next_path
        merged = {"X-CSRF-Token": csrf, **(headers or {})}
        return target.post("/api/login", json=body, headers=merged, **kwargs)

    def logged_in(self, client: HttpsClient | None = None) -> str:
        """Log in and return the session CSRF token."""
        response = self.login(client)
        assert response.status_code == 200, response.get_data(as_text=True)
        return str(response.get_json()["csrf_token"])

    def new_client(self) -> HttpsClient:
        client = self.app.test_client()
        assert isinstance(client, HttpsClient)
        return client


def make_web(tmp_path: Path, clock: FakeClock | None = None, **env: str) -> WebEnv:
    config = web_config(tmp_path, **env)
    config.paths.db_path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(config.paths.db_path)
    migrate(db)
    the_clock = clock or FakeClock()
    repo = Repository(db, clock=the_clock)
    sessions = SessionStore(db, lifetime=config.web.session_lifetime, clock=the_clock)
    quota: dict[str, object] = {"exhausted": False, "last_error": ""}
    upstream: dict[str, object] = {"consecutive_failures": 0, "last_error": ""}
    buffered = [3]
    limiter = LoginLimiter(config.web.login_max_attempts, clock=the_clock)
    live = LiveState(
        runtime=fixed_runtime,
        buffered_alerts=lambda: buffered[0],
        quota=lambda: dict(quota),
        upstream=lambda: dict(upstream),
    )
    key = b"k" * 64
    ui_dir = Path(__file__).resolve().parents[2] / "wazuh_ai_analyzer" / "web" / "ui"
    app = create_app(
        config,
        repo,
        sessions,
        live,
        session_key=key,
        ui_dir=ui_dir,
        limiter=limiter,
        clock=the_clock,
    )
    app.test_client_class = HttpsClient
    client = app.test_client()
    assert isinstance(client, HttpsClient)
    return WebEnv(
        config=config,
        db=db,
        repo=repo,
        sessions=sessions,
        app=app,
        client=client,
        clock=the_clock,
        limiter=limiter,
        key=key,
        quota=quota,
        upstream=upstream,
        buffered=buffered,
    )


def body(response: TestResponse) -> Any:
    return json.loads(response.get_data(as_text=True))
