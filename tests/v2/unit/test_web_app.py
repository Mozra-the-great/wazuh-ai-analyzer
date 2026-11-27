"""The web layer end to end through Flask's test client (#86).

Covers: auth on every endpoint, login/logout, server-side sessions, session fixation,
CSRF, cookie flags, security headers on every route, the JSON API (parity and input
validation), static serving (traversal, no oracle) and strict-CSP compatibility of the
bundled UI.
"""

from __future__ import annotations

import base64
import hashlib
import re
import sqlite3
from html.parser import HTMLParser
from pathlib import Path

import pytest

from v2.web_support import (
    BASE,
    FIXTURE_UI_DIR,
    HOST,
    PASSWORD,
    USER,
    HttpsClient,
    WebEnv,
    body,
    make_web,
)
from wazuh_ai_analyzer.web.app import LiveState, create_app
from wazuh_ai_analyzer.web.headers import build_csp
from wazuh_ai_analyzer.web.sessions import hash_session_id
from wazuh_ai_analyzer.web.ui_manifest import load_ui_manifest

UI_DIR = FIXTURE_UI_DIR

API_GET_PATHS = (
    "/api/stats",
    "/api/findings",
    "/api/findings/1",
    "/api/batches",
    "/api/nonexistent",
)


@pytest.fixture
def web(tmp_path: Path) -> WebEnv:
    return make_web(tmp_path)


def session_cookie_value(web: WebEnv) -> str:
    cookie = web.client.get_cookie("__Host-wai_session", domain=HOST)
    assert cookie is not None
    return cookie.value


# ── auth on everything ───────────────────────────────────────────────────────
@pytest.mark.parametrize("path", API_GET_PATHS)
def test_every_api_endpoint_needs_a_session(web: WebEnv, path: str) -> None:
    web.add_finding()
    response = web.client.get(path)
    assert response.status_code == 401
    assert body(response) == {"error": "Unauthorized"}


@pytest.mark.parametrize("path", ["/", "/index.html", "/app.js", "/app.css", "/findings/3", "/x"])
def test_pages_and_files_redirect_to_the_login_without_a_session(web: WebEnv, path: str) -> None:
    response = web.client.get(path)
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login?next=")


def test_unknown_paths_do_not_reveal_whether_they_exist_before_login(web: WebEnv) -> None:
    existing = web.client.get("/app.js")
    missing = web.client.get("/no-such-file.js")
    assert existing.status_code == missing.status_code == 302


def test_login_assets_are_public(web: WebEnv) -> None:
    for path in ("/login", "/login.js", "/login.css", "/logout", "/logout.js"):
        assert web.client.get(path).status_code == 200, path


def test_without_a_password_hash_the_api_answers_503(tmp_path: Path) -> None:
    web = make_web(tmp_path, DASHBOARD_PASSWORD_HASH="")
    for path in ("/api/stats", "/api/session", "/api/findings"):
        response = web.client.get(path)
        assert response.status_code == 503
        assert body(response)["error"] == "No credentials configured"
    assert web.client.post("/api/login", json={}).status_code == 503
    # the login page itself is still served, so it can show the reason
    assert web.client.get("/login").status_code == 200


# ── login ────────────────────────────────────────────────────────────────────
def test_login_creates_a_session_that_opens_the_api(web: WebEnv) -> None:
    response = web.login()
    assert response.status_code == 200
    data = body(response)
    assert data["ok"] is True
    assert data["next"] == "/"
    assert web.client.get("/api/stats").status_code == 200
    session = body(web.client.get("/api/session"))
    assert session["authenticated"] is True
    assert session["user"] == USER
    assert session["csrf_token"] == data["csrf_token"]


def test_wrong_password_and_unknown_user_look_alike(web: WebEnv) -> None:
    wrong_password = web.login(password="nope")
    unknown_user = web.login(username="mallory")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert body(wrong_password)["error"] == body(unknown_user)["error"] == "Invalid credentials"
    assert "session" not in str(wrong_password.headers.get("Set-Cookie", ""))


def test_unknown_user_costs_a_password_hash_check(
    web: WebEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    from werkzeug.security import check_password_hash as real

    calls: list[str] = []

    def counting(stored: str, password: str) -> bool:
        calls.append(password)
        return real(stored, password)

    monkeypatch.setattr("wazuh_ai_analyzer.web.auth.check_password_hash", counting)
    web.login(username="mallory", password="whatever")
    assert calls == ["whatever"]


@pytest.mark.parametrize(
    "payload",
    [{"username": 1, "password": "x"}, {"username": "a"}, {"password": "x"}, []],
)
def test_malformed_login_bodies_are_400(web: WebEnv, payload: object) -> None:
    token = web.login_token()
    response = web.client.post("/api/login", json=payload, headers={"X-CSRF-Token": token})
    assert response.status_code == 400
    assert "error" in body(response)


def test_login_must_be_json(web: WebEnv) -> None:
    token = web.login_token()
    response = web.client.post(
        "/api/login",
        data={"username": USER, "password": PASSWORD},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 415


def test_oversized_bodies_are_413(web: WebEnv) -> None:
    token = web.login_token()
    response = web.client.post(
        "/api/login",
        data="x" * 100_000,
        content_type="application/json",
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 413


def test_login_of_an_over_long_password_is_refused_without_hashing(
    web: WebEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "wazuh_ai_analyzer.web.auth.check_password_hash", lambda *_: pytest.fail("hashed")
    )
    response = web.login(password="p" * 5000)
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        ("/findings/3", "/findings/3"),
        ("/?a=1", "/?a=1"),
        ("//evil.example", "/"),
        ("/\\evil.example", "/"),
        ("https://evil.example/", "/"),
        ("javascript:alert(1)", "/"),
        ("/ok\r\nSet-Cookie: x=y", "/"),
        ("evil", "/"),
        ("", "/"),
    ],
)
def test_next_is_only_ever_a_local_path(web: WebEnv, requested: str, expected: str) -> None:
    assert body(web.login(next_path=requested))["next"] == expected


def test_authenticated_visitors_of_the_login_page_go_to_the_dashboard(web: WebEnv) -> None:
    web.logged_in()
    response = web.client.get("/login")
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


# ── sessions on the server ───────────────────────────────────────────────────
def test_only_a_hash_of_the_session_id_is_stored(web: WebEnv) -> None:
    web.logged_in()
    cookie = session_cookie_value(web)
    conn = sqlite3.connect(web.config.paths.db_path)
    try:
        rows = conn.execute("SELECT id_hash, csrf_token FROM web_sessions").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0][0] == hashlib.sha256(cookie.encode()).hexdigest() == hash_session_id(cookie)
    assert cookie not in rows[0][0]
    assert cookie not in rows[0][1]


def test_logout_is_a_post_with_csrf_and_kills_the_session_on_the_server(web: WebEnv) -> None:
    csrf = web.logged_in()
    stolen = session_cookie_value(web)
    assert web.client.get("/api/logout").status_code == 404  # only POST exists
    assert web.client.post("/api/logout").status_code == 403  # no token
    assert web.client.get("/api/stats").status_code == 200  # still logged in
    response = web.client.post("/api/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert web.client.get("/api/stats").status_code == 401
    # the cookie value is dead on the server, not just removed from this client
    other = web.new_client()
    other.set_cookie("__Host-wai_session", stolen, domain=HOST)
    assert other.get("/api/stats").status_code == 401
    assert web.sessions.count() == 0


def test_get_logout_is_only_a_confirmation_page(web: WebEnv) -> None:
    csrf = web.logged_in()
    response = web.client.get("/logout")
    assert response.status_code == 200
    assert b"<button" in response.data
    assert web.client.get("/api/stats").status_code == 200
    assert csrf


def test_sessions_expire(web: WebEnv) -> None:
    web.logged_in()
    assert web.client.get("/api/stats").status_code == 200
    web.clock.advance(web.config.web.session_lifetime + 1)
    assert web.client.get("/api/stats").status_code == 401
    assert web.sessions.count() == 0  # the expired row is removed on use


def test_a_session_of_another_user_name_is_not_valid(web: WebEnv) -> None:
    web.logged_in()
    cookie = session_cookie_value(web)
    conn = sqlite3.connect(web.config.paths.db_path)
    try:
        conn.execute("UPDATE web_sessions SET username='someone-else'")
        conn.commit()
    finally:
        conn.close()
    assert cookie
    assert web.client.get("/api/stats").status_code == 401


@pytest.mark.parametrize("value", ["", "x", "A" * 43 + "=", "A" * 200, "../../etc", "a b"])
def test_garbage_session_cookies_are_just_unauthenticated(web: WebEnv, value: str) -> None:
    web.client.set_cookie("__Host-wai_session", value, domain=HOST)
    assert web.client.get("/api/stats").status_code == 401


def test_session_fixation_a_planted_cookie_is_never_adopted(web: WebEnv) -> None:
    planted = "A" * 43
    web.client.set_cookie("__Host-wai_session", planted, domain=HOST)
    response = web.login()
    assert response.status_code == 200
    issued = session_cookie_value(web)
    assert issued != planted
    attacker = web.new_client()
    attacker.set_cookie("__Host-wai_session", planted, domain=HOST)
    assert attacker.get("/api/stats").status_code == 401


def test_login_rotates_the_id_and_drops_the_old_session(web: WebEnv) -> None:
    web.logged_in()
    first = session_cookie_value(web)
    web.logged_in()  # logs in again with the first cookie still presented
    second = session_cookie_value(web)
    assert first != second
    assert web.sessions.lookup(first) is None
    assert web.sessions.lookup(second) is not None
    assert web.sessions.count() == 1


def test_a_session_id_from_one_login_does_not_work_in_a_second_browser(web: WebEnv) -> None:
    web.logged_in()
    other = web.new_client()
    assert other.get("/api/stats").status_code == 401


# ── cookies ──────────────────────────────────────────────────────────────────
def set_cookie_headers(response: object) -> list[str]:
    return list(response.headers.getlist("Set-Cookie"))  # type: ignore[attr-defined]


def test_session_cookie_flags(web: WebEnv) -> None:
    response = web.login()
    (cookie,) = [c for c in set_cookie_headers(response) if "wai_session" in c]
    assert cookie.startswith("__Host-wai_session=")
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert "Domain" not in cookie
    max_age = re.search(r"Max-Age=(\d+)", cookie)
    assert max_age is not None
    assert int(max_age.group(1)) == web.config.web.session_lifetime


def test_pre_session_cookie_flags_and_it_is_removed_by_login(web: WebEnv) -> None:
    first = web.client.get("/api/session")
    (cookie,) = set_cookie_headers(first)
    assert cookie.startswith("__Host-wai_pre=")
    for flag in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
        assert flag in cookie
    login = web.login()
    assert any(c.startswith("__Host-wai_pre=;") for c in set_cookie_headers(login))


def test_with_secure_cookies_off_the_flag_and_the_host_prefix_are_not_set(tmp_path: Path) -> None:
    web = make_web(tmp_path, SESSION_COOKIE_SECURE="false")
    response = web.login()
    (cookie,) = [c for c in set_cookie_headers(response) if "wai_session" in c]
    assert cookie.startswith("wai_session=")
    assert "Secure" not in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Strict-Transport-Security" not in response.headers


# ── CSRF ─────────────────────────────────────────────────────────────────────
def test_login_without_or_with_a_wrong_token_is_403(web: WebEnv) -> None:
    web.client.get("/api/session")  # a pre-session cookie exists
    payload = {"username": USER, "password": PASSWORD}
    assert web.client.post("/api/login", json=payload).status_code == 403
    bad = web.client.post("/api/login", json=payload, headers={"X-CSRF-Token": "nope"})
    assert bad.status_code == 403
    assert body(bad) == {"error": "Invalid CSRF token"}
    assert web.sessions.count() == 0


def test_login_token_is_bound_to_the_pre_session_cookie(web: WebEnv) -> None:
    victim_token = web.login_token()
    attacker = web.new_client()
    attacker.get("/api/session")  # the attacker has a cookie of their own, not the victim's
    response = web.login(attacker, token=victim_token)
    assert response.status_code == 403


def test_login_without_a_pre_session_cookie_is_403(web: WebEnv) -> None:
    token = web.login_token()
    web.client.delete_cookie("__Host-wai_pre", domain=HOST)
    assert web.login(token=token).status_code == 403


def test_session_csrf_token_is_per_session_and_required_for_state_changes(web: WebEnv) -> None:
    csrf = web.logged_in()
    assert web.client.post("/api/logout", headers={"X-CSRF-Token": "x" * 43}).status_code == 403
    assert web.client.post("/api/logout", headers={"X-CSRF-Token": ""}).status_code == 403
    # the login token of the pre-session phase is not a session token
    other = web.new_client()
    other_csrf = web.logged_in(other)
    assert other_csrf != csrf
    assert other.post("/api/logout", headers={"X-CSRF-Token": csrf}).status_code == 403
    assert web.client.post("/api/logout", headers={"X-CSRF-Token": csrf}).status_code == 200


def test_state_changes_without_a_session_are_401_not_csrf_hints(web: WebEnv) -> None:
    assert web.client.post("/api/logout").status_code == 401


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Origin": f"https://{HOST}.evil.example"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
        {"Origin": BASE, "Sec-Fetch-Site": "cross-site"},
    ],
)
def test_cross_origin_state_changes_are_refused_even_with_a_valid_token(
    web: WebEnv, headers: dict[str, str]
) -> None:
    csrf = web.logged_in()
    response = web.client.post("/api/logout", headers={"X-CSRF-Token": csrf, **headers})
    assert response.status_code == 403
    assert web.client.get("/api/stats").status_code == 200  # nothing happened


def test_cross_origin_login_is_refused(web: WebEnv) -> None:
    token = web.login_token()
    response = web.client.post(
        "/api/login",
        json={"username": USER, "password": PASSWORD},
        headers={"X-CSRF-Token": token, "Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert web.sessions.count() == 0


def test_same_origin_requests_pass_the_origin_check(web: WebEnv) -> None:
    token = web.login_token()
    response = web.client.post(
        "/api/login",
        json={"username": USER, "password": PASSWORD},
        headers={"X-CSRF-Token": token, "Origin": BASE, "Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 200


def test_other_methods_on_the_api_are_refused(web: WebEnv) -> None:
    csrf = web.logged_in()
    for method in ("put", "delete", "patch"):
        response = getattr(web.client, method)("/api/findings/1", headers={"X-CSRF-Token": csrf})
        assert response.status_code == 405, method
    assert web.client.post("/api/findings", headers={"X-CSRF-Token": csrf}).status_code == 405
    assert web.client.post("/", headers={"X-CSRF-Token": csrf}).status_code == 405


# ── login rate limit ─────────────────────────────────────────────────────────
def test_login_is_rate_limited_per_client_and_recovers(web: WebEnv) -> None:
    limit = web.config.web.login_max_attempts
    for _ in range(limit):
        assert web.login(password="nope").status_code == 401
    limited = web.login(password="nope")
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1
    assert body(limited)["retry_after"] >= 1
    # the right password does not get around the limit either
    assert web.login().status_code == 429
    # another client is not affected
    other = web.new_client()
    assert web.login(other, environ_overrides={"REMOTE_ADDR": "10.0.0.9"}).status_code == 200
    web.clock.advance(61)
    assert web.login().status_code == 200


def test_remaining_attempts_are_reported(web: WebEnv) -> None:
    limit = web.config.web.login_max_attempts
    assert body(web.login(password="nope"))["remaining_attempts"] == limit - 1


def test_a_successful_login_resets_the_counter(web: WebEnv) -> None:
    limit = web.config.web.login_max_attempts
    for _ in range(limit - 1):
        web.login(password="nope")
    assert web.login().status_code == 200
    assert body(web.login(password="nope"))["remaining_attempts"] == limit - 1


def test_forwarded_for_is_ignored_without_trusted_proxy_hops(web: WebEnv) -> None:
    limit = web.config.web.login_max_attempts
    for index in range(limit):
        web.login(password="nope", headers={"X-Forwarded-For": f"203.0.113.{index}"})
    response = web.login(password="nope", headers={"X-Forwarded-For": "203.0.113.200"})
    assert response.status_code == 429  # one client, whatever the header claims


def test_forwarded_for_is_used_with_trusted_proxy_hops(tmp_path: Path) -> None:
    web = make_web(tmp_path, TRUSTED_PROXY_HOPS="1")
    limit = web.config.web.login_max_attempts
    for _ in range(limit):
        web.login(password="nope", headers={"X-Forwarded-For": "203.0.113.1"})
    assert web.login(password="nope", headers={"X-Forwarded-For": "203.0.113.1"}).status_code == 429
    other = web.login(password="nope", headers={"X-Forwarded-For": "203.0.113.2"})
    assert other.status_code == 401


def proxied_web(tmp_path: Path) -> WebEnv:
    return make_web(
        tmp_path,
        TRUSTED_PROXY_HOPS="1",
        LISTEN_HOST="0.0.0.0",  # noqa: S104
        TRUSTED_PROXY_ADDRESSES="10.0.0.5, 192.168.1.0/24",
    )


def failed_login(web: WebEnv, peer: str, forwarded: str) -> int:
    response = web.login(
        password="nope",
        headers={"X-Forwarded-For": forwarded},
        environ_base={"REMOTE_ADDR": peer},
    )
    return response.status_code


@pytest.mark.parametrize("peer", ["10.0.0.5", "192.168.1.77", "::ffff:10.0.0.5"])
def test_forwarded_for_is_used_from_a_listed_proxy(tmp_path: Path, peer: str) -> None:
    web = proxied_web(tmp_path)
    for _ in range(web.config.web.login_max_attempts):
        failed_login(web, peer, "203.0.113.1")
    assert failed_login(web, peer, "203.0.113.1") == 429
    assert failed_login(web, peer, "203.0.113.2") == 401


@pytest.mark.parametrize("peer", ["203.0.113.9", "10.0.0.6", "2001:db8::5", "not-an-address"])
def test_forwarded_for_is_ignored_from_any_other_peer(tmp_path: Path, peer: str) -> None:
    web = proxied_web(tmp_path)
    for index in range(web.config.web.login_max_attempts):
        failed_login(web, peer, f"198.51.100.{index}")
    # one client, whatever the header claims
    assert failed_login(web, peer, "198.51.100.250") == 429


# ── headers on every route ───────────────────────────────────────────────────
EXPECTED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def assert_security_headers(response: object, *, hsts: bool = True) -> None:
    headers = response.headers  # type: ignore[attr-defined]
    for name, value in EXPECTED_HEADERS.items():
        assert headers.get(name) == value, name
    csp = headers["Content-Security-Policy"]
    assert csp == build_csp()
    for directive in ("default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"):
        assert directive in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert headers["Permissions-Policy"]
    assert ("Strict-Transport-Security" in headers) is hsts


def test_headers_are_on_every_kind_of_response(web: WebEnv) -> None:
    web.add_finding()
    csrf = web.logged_in()
    responses = [
        web.client.get("/"),
        web.client.get("/login"),
        web.client.get("/app.js"),
        web.client.get("/app.css"),
        web.client.get("/some/spa/route"),
        web.client.get("/missing.js"),  # 404
        web.client.get("/api/stats"),
        web.client.get("/api/findings"),
        web.client.get("/api/findings/1"),
        web.client.get("/api/findings/999"),  # 404 JSON
        web.client.get("/api/batches"),
        web.client.get("/api/nothing"),  # 404 JSON
        web.client.get("/api/findings?limit=abc"),  # 400
        web.client.post("/api/findings", headers={"X-CSRF-Token": csrf}),  # 405
        web.client.post("/api/logout"),  # 403
        web.new_client().get("/api/stats"),  # 401
        web.new_client().get("/"),  # 302
        web.new_client().get("/api/session"),
    ]
    codes = {r.status_code for r in responses}
    assert {200, 302, 400, 401, 403, 404, 405} <= codes
    for response in responses:
        assert_security_headers(response)
    for response in responses:
        if response.request.path.startswith("/api/"):
            assert response.headers["Cache-Control"] == "no-store"
    assert csrf


def test_unhandled_errors_are_500_json_without_details(
    web: WebEnv, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    web.logged_in()

    def boom() -> object:
        raise RuntimeError("secret internals /srv/db")

    monkeypatch.setattr(web.repo, "list_batches", boom)
    web.app.config["TESTING"] = False
    response = web.client.get("/api/batches")
    assert response.status_code == 500
    assert body(response) == {"error": "Internal server error"}
    assert "secret internals" not in response.get_data(as_text=True)
    assert_security_headers(response)
    assert "secret internals" in caplog.text  # in the log (redacted there), not to the client


def test_static_assets_are_not_html_sniffable(web: WebEnv) -> None:
    web.logged_in()
    response = web.client.get("/app.js")
    assert response.headers["Content-Type"].startswith("text/javascript")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    html = web.client.get("/")
    assert html.headers["Content-Type"].startswith("text/html")
    assert html.headers["Cache-Control"] == "no-store"


# ── JSON API ─────────────────────────────────────────────────────────────────
def test_findings_list_returns_the_legacy_keys_and_the_additive_ones(web: WebEnv) -> None:
    web.add_finding(confidence=0.8)
    web.logged_in()
    data = body(web.client.get("/api/findings"))
    assert data["total"] == 1
    assert data["limit"] == 50
    assert data["offset"] == 0
    finding = data["findings"][0]
    assert finding["title"] == "SSH brute force"
    assert finding["source"] == "live"
    assert finding["affected_agents"] == ["ct100"]
    assert finding["rule_ids"] == ["5710"]
    assert finding["confidence"] == 0.8
    assert finding["mode"] == "llm"
    assert set(finding) == {
        "id",
        "batch_id",
        "title",
        "severity",
        "description",
        "recommendation",
        "affected_agents",
        "rule_ids",
        "batch_time",
        "source",
        "confidence",
        "mode",
    }


def test_single_finding_adds_the_batch_fields(web: WebEnv) -> None:
    fid = web.add_finding(source="history", summary="a batch summary")
    web.logged_in()
    data = body(web.client.get(f"/api/findings/{fid}"))
    assert data["id"] == fid
    assert data["source"] == "history"
    assert data["alert_count"] == 3
    assert data["batch_summary"] == "a batch summary"


def test_unknown_and_absurd_finding_ids_are_404(web: WebEnv) -> None:
    web.logged_in()
    assert web.client.get("/api/findings/999").status_code == 404
    assert web.client.get(f"/api/findings/{10**30}").status_code == 404
    assert web.client.get("/api/findings/-1").status_code == 404
    assert web.client.get("/api/findings/abc").status_code == 404


def test_findings_filters(web: WebEnv) -> None:
    web.add_finding(source="live", severity="high")
    web.add_finding(source="history", severity="low")
    web.logged_in()
    assert body(web.client.get("/api/findings?source=history"))["total"] == 1
    assert body(web.client.get("/api/findings?severity=high"))["total"] == 1
    assert body(web.client.get("/api/findings?severity=high&source=history"))["total"] == 0
    assert body(web.client.get("/api/findings?severity=&source="))["total"] == 2  # empty = off


def test_null_batch_source_counts_as_live(web: WebEnv) -> None:
    fid = web.add_finding()
    conn = sqlite3.connect(web.config.paths.db_path)
    try:
        conn.execute("UPDATE batches SET source=NULL")
        conn.commit()
    finally:
        conn.close()
    web.logged_in()
    assert body(web.client.get(f"/api/findings/{fid}"))["source"] == "live"
    assert body(web.client.get("/api/findings?source=live"))["total"] == 1


def test_findings_are_newest_first_and_paged(web: WebEnv) -> None:
    ids = [web.add_finding(title=f"f{n}") for n in range(5)]
    web.logged_in()
    page = body(web.client.get("/api/findings?limit=2&offset=1"))
    assert [f["id"] for f in page["findings"]] == [ids[3], ids[2]]
    assert page["total"] == 5
    assert (page["limit"], page["offset"]) == (2, 1)


@pytest.mark.parametrize(
    "query",
    [
        "limit=-1",
        "limit=0",
        "limit=abc",
        "limit=1.5",
        "limit=%20",
        "limit=1e3",
        "limit=99999999999999999999999",
        "offset=-5",
        "offset=abc",
        "offset=-99999999999999999999",
        "severity=bogus",
        "severity=high'%20OR%201=1",
        "source=files",
    ],
)
def test_findings_query_values_are_validated_with_400_not_500(web: WebEnv, query: str) -> None:
    web.add_finding()
    web.logged_in()
    response = web.client.get(f"/api/findings?{query}")
    assert response.status_code == 400
    data = body(response)
    assert data["error"] == "Bad request"
    assert "detail" in data
    assert "OR" not in data["detail"]  # the input is never echoed


def test_limit_minus_one_never_returns_all_rows(web: WebEnv) -> None:
    for n in range(3):
        web.add_finding(title=f"f{n}")
    web.logged_in()
    assert web.client.get("/api/findings?limit=-1").status_code == 400


def test_limit_is_capped_at_200_and_a_huge_offset_is_empty(web: WebEnv) -> None:
    web.add_finding()
    web.logged_in()
    capped = body(web.client.get("/api/findings?limit=5000"))
    assert capped["limit"] == 200
    far = body(web.client.get(f"/api/findings?offset={10**17}"))
    assert far["findings"] == []
    assert far["total"] == 1


def test_batches_have_the_legacy_columns_and_the_additive_ones_only(web: WebEnv) -> None:
    web.add_finding()
    web.logged_in()
    (batch,) = body(web.client.get("/api/batches"))
    assert set(batch) == {
        "id",
        "created_at",
        "alert_count",
        "raw_groups",
        "summary",
        "overall_risk",
        "status",
        "source",
        "attempts",
        "next_attempt",
        "first_error_at",
        "last_error",
        "claimed_at",
        "bad_responses",
        "mode",
        "decision_version",
        "finding_count",
    }
    assert batch["finding_count"] == 1


def test_batches_are_limited_to_the_last_50(web: WebEnv) -> None:
    for _ in range(55):
        web.repo.insert_batch(alert_count=1, raw_groups="[]", source="live", status="pending")
    web.logged_in()
    batches = body(web.client.get("/api/batches"))
    assert len(batches) == 50
    assert batches[0]["id"] == 55


def test_stats_have_every_legacy_key_and_the_mode(web: WebEnv) -> None:
    web.add_finding(severity="critical")
    web.add_finding(severity="low", source="history")
    web.repo.insert_batch(alert_count=1, raw_groups="[]", source="live", status="pending")
    web.logged_in()
    stats = body(web.client.get("/api/stats"))
    legacy_keys = {
        "total_findings",
        "by_severity",
        "batch_count",
        "analyzing",
        "last_analysis",
        "buffered_alerts",
        "batch_max",
        "batch_timeout",
        "batch_timeout_quiet",
        "urgent_level",
        "runtime",
        "retention_days",
        "gemini_ok",
        "quota",
        "retry_queue_size",
        "batches",
        "upstream",
        "history",
    }
    assert legacy_keys <= set(stats)
    assert set(stats) - legacy_keys == {"mode"}
    assert stats["mode"] == "llm"
    assert stats["total_findings"] == 2
    assert stats["by_severity"] == {"critical": 1, "low": 1}
    assert stats["batch_count"] == 2
    assert stats["retry_queue_size"] == 1
    assert stats["batches"] == {"done": 2, "error": 0, "pending": 1, "analyzing": 0}
    assert stats["buffered_alerts"] == 3
    assert stats["gemini_ok"] is True
    assert stats["runtime"]["processed"] == 7
    assert set(stats["history"]) == {
        "done",
        "alerts_scanned",
        "files_total",
        "files_done",
        "batches_done",
    }
    assert stats["history"]["batches_done"] == 1
    assert stats["last_analysis"] is not None


def test_gemini_ok_follows_the_key(tmp_path: Path) -> None:
    web = make_web(tmp_path, GEMINI_API_KEY="")
    web.logged_in()
    assert body(web.client.get("/api/stats"))["gemini_ok"] is False


# ── attacker-influenced text is JSON data, never markup ──────────────────────
HOSTILE = '<img src=x onerror=alert(1)><script>alert(1)</script>"\'&'


def test_hostile_text_comes_back_as_json_strings_with_a_json_content_type(web: WebEnv) -> None:
    fid = web.add_finding(
        title=HOSTILE,
        description=HOSTILE,
        recommendation=HOSTILE,
        agents=(HOSTILE,),
        rules=(HOSTILE,),
        summary=HOSTILE,
    )
    web.quota["last_error"] = HOSTILE
    web.upstream["last_error"] = HOSTILE
    web.logged_in()
    for path in ("/api/findings", f"/api/findings/{fid}", "/api/batches", "/api/stats"):
        response = web.client.get(path)
        assert response.status_code == 200
        assert response.mimetype == "application/json"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "text/html" not in response.headers["Content-Type"]
    detail = body(web.client.get(f"/api/findings/{fid}"))
    assert detail["title"] == detail["description"] == detail["recommendation"] == HOSTILE
    assert detail["affected_agents"] == [HOSTILE]
    stats = body(web.client.get("/api/stats"))
    assert stats["quota"]["last_error"] == HOSTILE
    assert stats["upstream"]["last_error"] == HOSTILE


def test_error_responses_never_echo_the_input(web: WebEnv) -> None:
    web.logged_in()
    response = web.client.get("/api/findings?severity=%3Cscript%3E")
    assert response.status_code == 400
    assert "<script>" not in response.get_data(as_text=True)


# ── static files ─────────────────────────────────────────────────────────────
def test_the_dashboard_and_its_files_are_served_to_a_logged_in_user(web: WebEnv) -> None:
    web.logged_in()
    index = web.client.get("/")
    assert index.status_code == 200
    assert b"<title>Security Dashboard</title>" in index.data
    assert web.client.get("/index.html").data == index.data
    assert web.client.get("/app.js").data == (UI_DIR / "app.js").read_bytes()
    assert web.client.get("/app.css").data == (UI_DIR / "app.css").read_bytes()


def test_spa_routes_fall_back_to_index_and_unknown_files_are_404(web: WebEnv) -> None:
    web.logged_in()
    index = web.client.get("/").data
    assert web.client.get("/findings/12").data == index
    assert web.client.get("/some/deep/route").data == index
    assert web.client.get("/missing.js").status_code == 404
    assert web.client.get("/assets/missing.css").status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/../analyzer.py",
        "/..%2fanalyzer.py",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/....//....//etc/passwd",
        "/..\\..\\windows\\win.ini",
        "/%5c..%5c..%5cetc%5cpasswd",
        "//etc/passwd",
        "/etc/passwd%00.js",
        "/C:/Windows/win.ini",
        "/app.js/../../../etc/hosts",
        "/.git/config",
        "/.env",
        "/.hidden.js",
    ],
)
def test_traversal_attempts_never_leak_a_file(web: WebEnv, path: str) -> None:
    web.logged_in()
    response = web.client.get(path)
    assert response.status_code in (200, 301, 302, 308, 404)
    data = response.get_data()
    for needle in (b"root:", b"[fonts]", b"DB_PATH", b"import ", b"[core]"):
        assert needle not in data
    if response.status_code == 200:  # an app route: the index, never another file
        assert data == web.client.get("/").data


def test_there_is_no_file_existence_oracle_outside_the_root(web: WebEnv, tmp_path: Path) -> None:
    web.logged_in()
    outside = tmp_path / "outside-secret"
    outside.write_text("top secret")
    existing = web.client.get("/../outside-secret")
    missing = web.client.get("/../no-such-file-at-all")
    assert (existing.status_code, existing.data) == (missing.status_code, missing.data)
    assert b"top secret" not in existing.data


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlinks")
def test_a_symlink_that_leaves_the_root_is_not_served(tmp_path: Path) -> None:
    from wazuh_ai_analyzer.web.static_files import StaticSite

    root = tmp_path / "ui"
    root.mkdir()
    (root / "index.html").write_text("<html></html>")
    secret = tmp_path / "secret.js"
    secret.write_text("secret")
    try:
        (root / "link.js").symlink_to(secret)
    except OSError:
        pytest.skip("no symlink permission")
    site = StaticSite(root)
    assert site.lookup("link.js") is None
    resolved = site.resolve("link.js")
    assert resolved is None  # an unknown file with an extension


def test_the_file_types_and_names_that_are_served_are_limited(tmp_path: Path) -> None:
    from wazuh_ai_analyzer.web.static_files import StaticSite

    root = tmp_path / "ui"
    (root / "sub").mkdir(parents=True)
    (root / "index.html").write_text("<html></html>")
    (root / "notes.py").write_text("x")
    (root / ".hidden.js").write_text("x")
    (root / "sub" / "ok.css").write_text("a{}")
    site = StaticSite(root)
    assert site.lookup("notes.py") is None
    assert site.lookup(".hidden.js") is None
    assert site.lookup("sub") is None  # a directory
    assert site.lookup("sub/ok.css") is not None
    assert site.lookup("sub/../index.html") is None
    assert site.lookup("") is None
    assert site.resolve("sub/ok.css") is not None


# ── the dashboard build works under the strict CSP ──────────────────────────
# The dashboard is generated by `ui/` and not committed: these checks run on the build in
# `wazuh_ai_analyzer/web/ui` when it exists (the `ui` CI job builds it; the Playwright test
# there then loads it under the real CSP). The fixture pages above only exercise the server.
BUILT_UI = Path(__file__).resolve().parents[3] / "wazuh_ai_analyzer" / "web" / "ui"
needs_build = pytest.mark.skipif(
    not (BUILT_UI / "index.html").is_file(),
    reason="the dashboard is not built (cd ui && npm run build)",
)
BUILT_PAGES = ("index.html", "login.html", "logout.html")


class _InlineScripts(HTMLParser):
    """The text of every `<script>` without `src` (a real parser, not a regular expression)."""

    def __init__(self) -> None:
        super().__init__()
        self.found: list[str] = []
        self._open = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script" and all(name != "src" for name, _ in attrs):
            self._open = True
            self.found.append("")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._open = False

    def handle_data(self, data: str) -> None:
        if self._open:
            self.found[-1] += data


def _inline_scripts(text: str) -> list[str]:
    parser = _InlineScripts()
    parser.feed(text)
    return parser.found


@needs_build
@pytest.mark.parametrize("name", BUILT_PAGES)
def test_built_pages_have_only_the_hashed_theme_script_inline(name: str) -> None:
    text = (BUILT_UI / name).read_text(encoding="utf-8")
    manifest = load_ui_manifest(BUILT_UI)
    scripts = _inline_scripts(text)
    assert len(scripts) == 1
    digest = "sha256-" + base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
    assert digest in manifest.script_hashes
    assert "<style" not in text
    assert not re.search(r"\sstyle\s*=", text)
    assert not re.search(r"\son[a-z]+\s*=", text)
    assert "javascript:" not in text


@needs_build
def test_built_pages_reference_only_local_files() -> None:
    for name in BUILT_PAGES:
        text = (BUILT_UI / name).read_text(encoding="utf-8")
        for url in re.findall(r'(?:src|href)="([^"]+)"', text):
            assert url.startswith("/"), (name, url)
            assert not url.startswith("//"), (name, url)
    for css in BUILT_UI.rglob("*.css"):
        assert "data:" not in css.read_text(encoding="utf-8"), css.name


@needs_build
def test_built_login_files_are_served_without_a_session_and_the_app_is_not(tmp_path: Path) -> None:
    manifest = load_ui_manifest(BUILT_UI)
    web = make_web(tmp_path)
    app = create_app(
        web.config,
        web.repo,
        web.sessions,
        LiveState(
            runtime=lambda: {},
            buffered_alerts=lambda: 0,
            quota=dict,
            upstream=dict,
        ),
        session_key=web.key,
        ui_dir=BUILT_UI,
        script_hashes=manifest.script_hashes,
        public_files=manifest.public_files,
    )
    app.test_client_class = HttpsClient
    client = app.test_client()
    for name in manifest.public_files:
        response = client.get("/" + name, base_url=BASE)
        assert response.status_code == 200, name
    protected = client.get("/", base_url=BASE)
    assert protected.status_code == 302
    assert "/login" in protected.headers["Location"]
    csp = client.get("/login", base_url=BASE).headers["Content-Security-Policy"]
    assert all(f"'{digest}'" in csp for digest in manifest.script_hashes)
    assert "unsafe-inline" not in csp
