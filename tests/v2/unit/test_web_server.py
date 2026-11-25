"""The real waitress server: headers on the wire, proxy headers, shutdown, log redaction,
and the web layer inside `Service`."""

from __future__ import annotations

import logging
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests

from v2.helpers import free_port
from v2.pipeline_support import FakeGemini, gemini_ok
from v2.unit.test_service import llm_factory, make_config
from v2.web_support import PASSWORD, USER, WebEnv, make_web, password_hash
from wazuh_ai_analyzer.logging_setup import RedactSecrets
from wazuh_ai_analyzer.service import UI_DIR, Service
from wazuh_ai_analyzer.web.headers import build_csp
from wazuh_ai_analyzer.web.server import IDENT, WebServer, protect_server_loggers

SECRET = "dummy-server-secret-0007"


@pytest.fixture
def served(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[tuple[WebEnv, str]]:
    env_vars = getattr(request, "param", {})
    web = make_web(tmp_path, SESSION_COOKIE_SECURE="false", **env_vars)
    server = WebServer(
        web.app,
        host="127.0.0.1",
        port=0,
        trusted_proxy=web.config.web.trusted_proxy_hops > 0,
        redactor=RedactSecrets([SECRET]),
    )
    server.start()
    try:
        yield web, f"http://127.0.0.1:{server.port}"
    finally:
        server.close()


def login_session(base: str, password: str = PASSWORD, **headers: str) -> requests.Response:
    session = requests.Session()
    token = session.get(f"{base}/api/session", timeout=10).json()["csrf_token"]
    return session.post(
        f"{base}/api/login",
        json={"username": USER, "password": password},
        headers={"X-CSRF-Token": token, **headers},
        timeout=10,
    )


def test_the_security_headers_are_on_the_wire(served: tuple[WebEnv, str]) -> None:
    _, base = served
    response = requests.get(f"{base}/api/stats", timeout=10)
    assert response.status_code == 401
    assert response.headers["Content-Security-Policy"] == build_csp()
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Server"] == IDENT
    assert "Strict-Transport-Security" not in response.headers  # SESSION_COOKIE_SECURE=false
    page = requests.get(f"{base}/login", timeout=10)
    assert page.status_code == 200
    assert page.headers["Content-Security-Policy"] == build_csp()
    assert "Set-Cookie" not in page.headers


def test_full_login_and_dashboard_flow_over_http(served: tuple[WebEnv, str]) -> None:
    web, base = served
    web.add_finding()
    session = requests.Session()
    token = session.get(f"{base}/api/session", timeout=10).json()["csrf_token"]
    login = session.post(
        f"{base}/api/login",
        json={"username": USER, "password": PASSWORD},
        headers={"X-CSRF-Token": token},
        timeout=10,
    )
    assert login.status_code == 200
    cookie = session.cookies.get_dict()
    assert "wai_session" in cookie
    assert session.get(f"{base}/api/findings", timeout=10).json()["total"] == 1
    assert session.get(f"{base}/", timeout=10).status_code == 200
    csrf = login.json()["csrf_token"]
    out = session.post(f"{base}/api/logout", headers={"X-CSRF-Token": csrf}, timeout=10)
    assert out.status_code == 200
    assert session.get(f"{base}/api/findings", timeout=10).status_code == 401


def test_cross_origin_requests_are_refused_on_the_wire(served: tuple[WebEnv, str]) -> None:
    _, base = served
    response = login_session(base, Origin="https://evil.example")
    assert response.status_code == 403
    response = login_session(base, **{"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403


def test_raw_forwarded_for_cannot_reset_the_login_limit(served: tuple[WebEnv, str]) -> None:
    web, base = served
    limit = web.config.web.login_max_attempts
    for n in range(limit):
        response = login_session(base, "wrong", **{"X-Forwarded-For": f"198.51.100.{n}"})
        assert response.status_code == 401
    spoofed = login_session(base, "wrong", **{"X-Forwarded-For": "198.51.100.250"})
    assert spoofed.status_code == 429


@pytest.mark.parametrize("served", [{"TRUSTED_PROXY_HOPS": "1"}], indirect=True)
def test_with_a_trusted_proxy_the_forwarded_address_is_the_client(
    served: tuple[WebEnv, str],
) -> None:
    web, base = served
    limit = web.config.web.login_max_attempts
    for _ in range(limit):
        first = login_session(base, "wrong", **{"X-Forwarded-For": "198.51.100.7"})
        assert first.status_code == 401
    assert login_session(base, "wrong", **{"X-Forwarded-For": "198.51.100.7"}).status_code == 429
    assert login_session(base, "wrong", **{"X-Forwarded-For": "198.51.100.8"}).status_code == 401


def test_oversized_request_bodies_are_rejected_by_the_server(served: tuple[WebEnv, str]) -> None:
    _, base = served
    try:
        response = requests.post(
            f"{base}/api/login",
            data=b"x" * 200_000,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except requests.ConnectionError:
        return  # the server closed the connection before the body was sent: also a refusal
    assert response.status_code in (400, 413)


def test_close_stops_the_server_and_frees_the_port(tmp_path: Path) -> None:
    web = make_web(tmp_path)
    server = WebServer(
        web.app, host="127.0.0.1", port=0, trusted_proxy=False, redactor=RedactSecrets([])
    )
    thread = server.start()
    port = server.port
    assert thread.is_alive()
    assert requests.get(f"http://127.0.0.1:{port}/login", timeout=10).status_code == 200
    server.close()
    assert not thread.is_alive()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))  # the port can be used again
    server.close()  # idempotent


def test_a_taken_port_is_an_error_at_start(tmp_path: Path) -> None:
    web = make_web(tmp_path)
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        server = WebServer(
            web.app, host="127.0.0.1", port=port, trusted_proxy=False, redactor=RedactSecrets([])
        )
        with pytest.raises(OSError):  # noqa: PT011 - the exact errno differs per platform
            server.start()


# ── redaction of the server loggers ──────────────────────────────────────────
class Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.mark.parametrize("name", ["waitress", "waitress.queue", "werkzeug"])
def test_server_loggers_are_redacted_after_their_setup(name: str) -> None:
    logger = logging.getLogger(name)
    handler = Capture()
    redactor = RedactSecrets([SECRET])
    logger.addHandler(handler)  # a library adds its own handler during setup
    old_level = logger.level
    logger.setLevel(logging.INFO)
    try:
        protect_server_loggers(redactor)
        logger.info("request to /x?key=%s failed (%s)", SECRET, SECRET)
        try:
            raise RuntimeError(f"upstream said {SECRET}")
        except RuntimeError:
            logger.exception("crash")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        logger.removeFilter(redactor)
    text = "\n".join(handler.lines)
    assert SECRET not in text
    assert "***" in text


# ── inside the service ───────────────────────────────────────────────────────
def test_the_service_serves_the_dashboard_and_stops_it(tmp_path: Path) -> None:
    port = free_port()
    config = make_config(
        tmp_path,
        PORT=str(port),
        DASHBOARD_PASSWORD_HASH=password_hash(),
        DASHBOARD_USER=USER,
        SESSION_COOKIE_SECURE="false",
    )
    service = Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
    base = f"http://127.0.0.1:{port}"
    try:
        service.start()
        assert requests.get(f"{base}/login", timeout=10).status_code == 200
        login = login_session(base)
        assert login.status_code == 200
        # a second login from the same session object to read the stats
        session = requests.Session()
        token = session.get(f"{base}/api/session", timeout=10).json()["csrf_token"]
        session.post(
            f"{base}/api/login",
            json={"username": USER, "password": PASSWORD},
            headers={"X-CSRF-Token": token},
            timeout=10,
        )
        stats = session.get(f"{base}/api/stats", timeout=10).json()
        assert stats["gemini_ok"] is True
        assert stats["mode"] == "llm"
        assert stats["runtime"] == service.runtime()
        assert stats["quota"] == service.pipeline.quota.as_dict()
        assert stats["buffered_alerts"] == service.ingest.buffered_alerts()
        assert stats["upstream"]["consecutive_failures"] == 0
        assert [t.name for t in threading.enumerate()].count("web") == 1
    finally:
        assert service.shutdown(grace=10) is True
    with pytest.raises(requests.ConnectionError):
        requests.get(f"{base}/login", timeout=5)
    assert (config.paths.data_dir / "session.key").exists()


def test_a_taken_web_port_stops_the_start_before_anything_runs(tmp_path: Path) -> None:
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        config = make_config(tmp_path, PORT=str(blocker.getsockname()[1]))
        service = Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
        try:
            with pytest.raises(OSError):  # noqa: PT011
                service.start()
            assert not [t for t in threading.enumerate() if t.name in ("live", "history", "retry")]
        finally:
            service.shutdown(grace=5)


def test_a_static_dir_setting_is_ignored_with_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = make_config(tmp_path, STATIC_DIR=str(tmp_path / "legacy-static"))
    with caplog.at_level(logging.WARNING):
        service = Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
    try:
        assert "STATIC_DIR is set but ignored" in caplog.text
    finally:
        service.shutdown(grace=5)


def test_the_default_static_dir_needs_no_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = make_config(tmp_path)
    with caplog.at_level(logging.WARNING):
        service = Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
    try:
        assert "STATIC_DIR" not in caplog.text
        assert (UI_DIR / "index.html").is_file()
    finally:
        service.shutdown(grace=5)
