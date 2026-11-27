"""The Flask application: auth, sessions, CSRF, headers, the JSON API, static files.

Request flow (`gate`, a `before_request` hook that every request passes):

1. State-changing methods must come from this origin (`Origin` / `Sec-Fetch-Site`).
2. Without a configured password hash the API answers 503.
3. Every `/api/*` path except the two login endpoints needs a valid session (401
   otherwise, also for unknown paths, so nothing is learned without a login); a
   state-changing one also needs the session's CSRF token in `X-CSRF-Token`.
4. Pages and files need a session as well (a redirect to `/login`), except the few
   files the login page itself consists of.

Everything the model or the alert log influenced (finding texts, `raw_groups`,
`last_error`, `quota.last_error`, `upstream.last_error`, `summary`) leaves this module
as JSON strings with `Content-Type: application/json` and `nosniff`; none of it is ever
placed in HTML here. The UI must render it with `textContent` (see docs/web.md).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final
from urllib.parse import urlencode

from flask import Flask, Response, g, jsonify, redirect, request, send_file
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Response as BaseResponse

from ..config import Config, IPNetwork
from ..storage.contract import SEVERITIES, SOURCES
from ..storage.repo import Repository
from .auth import (
    LoginLimiter,
    client_key,
    is_pre_session_value,
    login_csrf_token,
    new_pre_session_value,
    origin_allowed,
    safe_next_path,
    tokens_match,
    verify_credentials,
)
from .headers import build_csp, security_headers
from .sessions import Session, SessionStore
from .static_files import StaticSite

if TYPE_CHECKING:
    from _typeshed.wsgi import StartResponse, WSGIApplication, WSGIEnvironment

log = logging.getLogger(__name__)

SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER: Final = "X-CSRF-Token"
MAX_BODY_BYTES: Final = 16 * 1024
PRE_SESSION_LIFETIME: Final = 3600

FINDINGS_DEFAULT_LIMIT: Final = 50
FINDINGS_MAX_LIMIT: Final = 200
OFFSET_MAX: Final = 10**9
_INT_RE: Final = re.compile(r"^[0-9]{1,18}$")

# The files the login and logout pages consist of; everything else needs a session.
PUBLIC_FILES: Final = frozenset(
    {"login.html", "login.css", "login.js", "logout.html", "logout.js"}
)
PAGE_ALIASES: Final = {"login": "login.html", "logout": "logout.html"}
PUBLIC_API: Final = frozenset({"/api/session", "/api/login"})


class _OnlyFromProxies:
    """Believe `X-Forwarded-*` only from the configured proxy addresses.

    A request from any other peer reaches the app without those headers, so it is
    counted under its socket address. `plain` is the app, `fixed` the same app behind
    `ProxyFix`.
    """

    def __init__(
        self,
        plain: WSGIApplication,
        fixed: WSGIApplication,
        proxies: tuple[IPNetwork, ...],
    ) -> None:
        self._plain = plain
        self._fixed = fixed
        self._proxies = proxies

    def _is_proxy(self, peer: str) -> bool:
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return any(
            address in network for network in self._proxies if network.version == address.version
        )

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
        if self._is_proxy(str(environ.get("REMOTE_ADDR", ""))):
            return self._fixed(environ, start_response)
        for name in [key for key in environ if key.startswith("HTTP_X_FORWARDED_")]:
            del environ[name]
        return self._plain(environ, start_response)


@dataclass(frozen=True, slots=True)
class LiveState:
    """What `/api/stats` reads from the running service (all callables are thread-safe)."""

    runtime: Callable[[], dict[str, int | bool]]
    buffered_alerts: Callable[[], int]
    quota: Callable[[], dict[str, object]]
    upstream: Callable[[], dict[str, object]]


class _BadRequest(Exception):
    """A query or body value is invalid; `detail` never echoes the input."""

    def __init__(self, detail: str, status: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status = status


def _parse_int(raw: str, name: str) -> int:
    if not _INT_RE.match(raw) and not (raw.startswith("-") and _INT_RE.match(raw[1:])):
        raise _BadRequest(f"{name} must be an integer")
    return int(raw)


def parse_findings_query(args: dict[str, str]) -> tuple[int, int, str | None, str | None]:
    """Validated `(limit, offset, severity, source)` of `/api/findings`.

    `limit` is 1..200 (above 200 is cut to 200, as before; below 1 is an error, so
    that `-1` can never reach SQLite, where it means "all rows"), `offset` is >= 0.
    `severity` and `source` are whitelisted; an empty value means "no filter".
    """
    limit = FINDINGS_DEFAULT_LIMIT
    if args.get("limit", "") != "":
        limit = _parse_int(args["limit"], "limit")
        if limit < 1:
            raise _BadRequest("limit must be at least 1")
        limit = min(limit, FINDINGS_MAX_LIMIT)
    offset = 0
    if args.get("offset", "") != "":
        offset = _parse_int(args["offset"], "offset")
        if offset < 0:
            raise _BadRequest("offset must not be negative")
        offset = min(offset, OFFSET_MAX)
    severity = args.get("severity") or None
    if severity is not None and severity not in SEVERITIES:
        raise _BadRequest("severity must be one of " + ", ".join(SEVERITIES))
    source = args.get("source") or None
    if source is not None and source not in SOURCES:
        raise _BadRequest("source must be one of " + ", ".join(SOURCES))
    return limit, offset, severity, source


def create_app(
    config: Config,
    repo: Repository,
    sessions: SessionStore,
    live: LiveState,
    *,
    session_key: bytes,
    ui_dir: Path,
    limiter: LoginLimiter | None = None,
    script_hashes: tuple[str, ...] = (),
    public_files: frozenset[str] = frozenset(),
    clock: Callable[[], float] = time.time,
) -> Flask:
    web = config.web
    secure = web.session_cookie_secure
    # `__Host-` pins a cookie to this exact host over https (no Domain, Path=/).
    session_cookie = "__Host-wai_session" if secure else "wai_session"
    pre_cookie = "__Host-wai_pre" if secure else "wai_pre"
    password_hash = (
        web.dashboard_password_hash.reveal() if web.dashboard_password_hash is not None else None
    )
    login_limiter = limiter if limiter is not None else LoginLimiter(web.login_max_attempts)
    site = StaticSite(ui_dir)
    # The login and logout pages and, from the UI build manifest, the hashed files they load.
    public_names = PUBLIC_FILES | public_files
    headers = security_headers(csp=build_csp(script_hashes), hsts=secure)

    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    app.config["PROPAGATE_EXCEPTIONS"] = False
    # Only trust X-Forwarded-For/-Proto/-Host when a reverse proxy is configured
    # (TRUSTED_PROXY_HOPS > 0); otherwise a client could spoof its address and escape
    # the login rate limit.
    if web.trusted_proxy_hops > 0:
        hops = web.trusted_proxy_hops
        # The Host header is passed on by the proxy as it is: not trusted from a header.
        fixed = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops)
        proxies = web.trusted_proxy_addresses
        # With TRUSTED_PROXY_ADDRESSES only those peers are believed; the headers of any
        # other peer are removed. Without it the service listens on loopback (config).
        app.wsgi_app = (  # type: ignore[method-assign]
            _OnlyFromProxies(app.wsgi_app, fixed, proxies) if proxies else fixed
        )

    # ── helpers ──────────────────────────────────────────────────────────────
    def error(status: int, message: str, **extra: object) -> Response:
        response = jsonify({"error": message, **extra})
        response.status_code = status
        return response

    def is_api() -> bool:
        return request.path.startswith("/api/") or request.path == "/api"

    def set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
        response.set_cookie(
            name, value, max_age=max_age, httponly=True, secure=secure, samesite="Strict", path="/"
        )

    def clear_cookie(response: Response, name: str) -> None:
        response.delete_cookie(name, httponly=True, secure=secure, samesite="Strict", path="/")

    def current_session() -> Session | None:
        found = sessions.lookup(request.cookies.get(session_cookie))
        if found is None or found.username != web.dashboard_user:
            return None
        return found

    def csrf_ok_for_session() -> bool:
        session: Session | None = g.session
        return session is not None and tokens_match(
            session.csrf_token, request.headers.get(CSRF_HEADER)
        )

    def json_body() -> dict[str, object]:
        if not request.is_json:
            raise _BadRequest("the body must be JSON (Content-Type: application/json)", 415)
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            raise _BadRequest("the body must be a JSON object")
        return body

    # ── the gate every request passes ────────────────────────────────────────
    @app.before_request
    def gate() -> BaseResponse | None:
        g.session = current_session()
        method = request.method
        if method not in SAFE_METHODS:
            if not origin_allowed(
                host=request.host,
                origin=request.headers.get("Origin"),
                sec_fetch_site=request.headers.get("Sec-Fetch-Site"),
            ):
                return error(403, "Cross-origin request refused")
            if not is_api():
                response = error(405, "Method Not Allowed")
                response.headers["Allow"] = "GET, HEAD"
                return response
        if is_api():
            if password_hash is None:
                return error(
                    503,
                    "No credentials configured",
                    hint="Set DASHBOARD_PASSWORD_HASH in the env file",
                )
            if request.path in PUBLIC_API:
                return None
            if g.session is None:
                return error(401, "Unauthorized")
            if method not in SAFE_METHODS and not csrf_ok_for_session():
                return error(403, "Invalid CSRF token")
            return None
        # A page or a file.
        if _public_page(request.path) is not None:
            return None
        if g.session is None:
            # `next` is a local path only (checked again when the login uses it).
            return redirect("/login?" + urlencode({"next": safe_next_path(request.path)}))
        return None

    def _public_page(path: str) -> str | None:
        name = path.lstrip("/")
        name = PAGE_ALIASES.get(name, name)
        return name if name in public_names else None

    @app.after_request
    def add_headers(response: Response) -> Response:
        for name, value in headers.items():
            response.headers[name] = value
        if is_api() or response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store"
        return response

    # ── errors: JSON for the API, short text for pages, never a traceback ────
    @app.errorhandler(_BadRequest)
    def bad_request(exc: _BadRequest) -> Response:
        return error(exc.status, "Bad request", detail=exc.detail)

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_: RequestEntityTooLarge) -> Response:
        return error(413, "Request too large")

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException) -> Response:
        status = exc.code or 500
        if is_api():
            response = error(status, exc.name)
        else:
            response = Response(exc.name + "\n", status=status, mimetype="text/plain")
        for key, value in exc.get_headers():
            if key.lower() == "allow":
                response.headers["Allow"] = value
        return response

    @app.errorhandler(Exception)
    def unexpected(exc: Exception) -> Response:
        # The message may carry attacker-influenced text; the redaction filter of the
        # log handlers scrubs it, and the client gets nothing.
        log.error("Unhandled error on %s %r", request.method, request.path, exc_info=exc)
        if is_api():
            return error(500, "Internal server error")
        return Response("Internal server error\n", status=500, mimetype="text/plain")

    # ── session and login ────────────────────────────────────────────────────
    @app.get("/api/session")
    def session_info() -> Response:
        session: Session | None = g.session
        if session is not None:
            return jsonify(
                {
                    "authenticated": True,
                    "user": session.username,
                    "csrf_token": session.csrf_token,
                    "expires_at": session.expires_at,
                }
            )
        existing = request.cookies.get(pre_cookie)
        if existing is not None and is_pre_session_value(existing):
            # Keep the cookie the client has; only its token is handed out again.
            return jsonify(
                {"authenticated": False, "csrf_token": login_csrf_token(session_key, existing)}
            )
        # A cookie value the server made up itself, never one the client sent.
        fresh = new_pre_session_value()
        response = jsonify(
            {"authenticated": False, "csrf_token": login_csrf_token(session_key, fresh)}
        )
        set_cookie(response, pre_cookie, fresh, PRE_SESSION_LIFETIME)
        return response

    @app.post("/api/login")
    def login() -> Response:
        if password_hash is None:  # the gate answered 503 already
            return error(503, "No credentials configured")
        # The token of the pre-session phase; a client that already has a session may
        # also present that session's token (logging in again).
        pre_value = request.cookies.get(pre_cookie)
        pre_session_ok = is_pre_session_value(pre_value) and tokens_match(
            login_csrf_token(session_key, pre_value or ""), request.headers.get(CSRF_HEADER)
        )
        if not pre_session_ok and not csrf_ok_for_session():
            return error(403, "Invalid CSRF token")
        body = json_body()
        username, password = body.get("username"), body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise _BadRequest("username and password must be strings")
        client = client_key(request.remote_addr)
        wait = login_limiter.try_acquire(client)  # counts this attempt
        if wait:
            log.warning("Login rate-limited for %s", client)
            response = error(429, "Too many failed attempts", retry_after=wait)
            response.headers["Retry-After"] = str(wait)
            return response
        # Over-long input cannot be right; it is not hashed, but it costs an attempt.
        if (
            len(username) <= 128
            and len(password) <= 1024
            and verify_credentials(
                username.strip(),
                password,
                expected_user=web.dashboard_user,
                password_hash=password_hash,
            )
        ):
            login_limiter.clear(client)
            # A new id for every login: a cookie the client brought along is dropped
            # on the server, so an id planted before the login is worthless.
            sessions.delete(request.cookies.get(session_cookie))
            issued = sessions.create(web.dashboard_user)
            log.info("Login successful from %s", client)
            response = jsonify(
                {
                    "ok": True,
                    "next": safe_next_path(_optional_str(body.get("next"))),
                    "csrf_token": issued.csrf_token,
                    "expires_at": issued.expires_at,
                }
            )
            set_cookie(
                response,
                session_cookie,
                issued.session_id,
                max(1, int(issued.expires_at - clock())),
            )
            clear_cookie(response, pre_cookie)
            return response
        log.warning("Failed login from %s", client)
        return error(
            401, "Invalid credentials", remaining_attempts=login_limiter.remaining(client)
        )

    @app.post("/api/logout")
    def logout() -> Response:
        sessions.delete(request.cookies.get(session_cookie))
        log.info("Logout from %s", client_key(request.remote_addr))
        response = jsonify({"ok": True})
        clear_cookie(response, session_cookie)
        return response

    # ── read API ─────────────────────────────────────────────────────────────
    @app.get("/api/stats")
    def stats() -> Response:
        snapshot = repo.stats_snapshot()
        runtime = live.runtime()
        batching = config.batching
        return jsonify(
            {
                "total_findings": snapshot.total_findings,
                "by_severity": snapshot.by_severity,
                "batch_count": snapshot.batch_count,
                "analyzing": snapshot.by_status.get("analyzing", 0),
                "last_analysis": snapshot.last_analysis,
                "buffered_alerts": live.buffered_alerts(),
                "batch_max": batching.batch_max,
                "batch_timeout": batching.batch_timeout,
                "batch_timeout_quiet": batching.effective_quiet_timeout,
                "urgent_level": batching.urgent_level,
                "runtime": runtime,
                "retention_days": config.retention.days,
                "gemini_ok": config.gemini.api_key is not None,
                "mode": config.analysis.mode,
                "quota": live.quota(),
                # Persistent queue: batches waiting for their next attempt.
                "retry_queue_size": snapshot.by_status.get("pending", 0),
                "batches": {
                    status: snapshot.by_status.get(status, 0)
                    for status in ("done", "error", "pending", "analyzing")
                },
                "upstream": live.upstream(),
                "history": {
                    "done": runtime["history_done"],
                    "alerts_scanned": runtime["history_alerts"],
                    "files_total": runtime["history_files_total"],
                    "files_done": runtime["history_files_done"],
                    "batches_done": snapshot.history_batches_done,
                },
            }
        )

    @app.get("/api/findings")
    def findings() -> Response:
        limit, offset, severity, source = parse_findings_query(request.args.to_dict())
        rows, total = repo.list_findings(
            limit=limit, offset=offset, severity=severity, source=source
        )
        return jsonify({"findings": rows, "total": total, "limit": limit, "offset": offset})

    @app.get("/api/findings/<int:finding_id>")
    def finding(finding_id: int) -> Response:
        detail = repo.get_finding(finding_id)
        if detail is None:
            return error(404, "Not Found")
        return jsonify(detail)

    @app.get("/api/batches")
    def batches() -> Response:
        return jsonify(repo.list_batches())

    # ── pages and files ──────────────────────────────────────────────────────
    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def page(path: str) -> BaseResponse:
        name = PAGE_ALIASES.get(path, path)
        if name == "login.html" and path == "login" and g.session is not None:
            return redirect("/")
        if is_api():  # an unknown /api/... path (the user is logged in): JSON 404
            return error(404, "Not Found")
        found = site.resolve(name)
        if found is None:
            return Response("Not Found\n", status=404, mimetype="text/plain")
        return send_file(
            found.path, mimetype=found.content_type, conditional=True, max_age=0, etag=True
        )

    return app


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None
