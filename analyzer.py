#!/usr/bin/env python3
"""
Wazuh AI Analyzer – powered by Aeterna™
Analysiert Wazuh-Alerts mit Google Gemini AI und zeigt sie im Web-Dashboard.
Erstellt mithilfe von KI (Claude by Anthropic)
"""

import html
import json
import math
import os
import random
import sqlite3
import threading
import time
import requests
import logging
import glob
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
import hashlib
import hmac
import secrets
from urllib.parse import urlparse
from flask import Flask, jsonify, request, abort, send_from_directory, session, redirect, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import NotFound
from werkzeug.middleware.proxy_fix import ProxyFix

# ─── Konfiguration ───────────────────────────────────────────────────────────
GEMINI_API_KEY  = os.environ.get("GEMINI_API_KEY", "")
ALERTS_LOG      = os.environ.get("WAZUH_ALERTS_LOG", "/var/ossec/logs/alerts/alerts.json")
DB_PATH         = os.environ.get("DB_PATH", "/opt/wazuh-ai-analyzer/data/analyses.db")
STATIC_DIR      = os.environ.get("STATIC_DIR", "/opt/wazuh-ai-analyzer/static")
BATCH_MAX       = int(os.environ.get("BATCH_MAX", "25"))
BATCH_TIMEOUT   = int(os.environ.get("BATCH_TIMEOUT", "300"))
MIN_LEVEL       = int(os.environ.get("MIN_LEVEL", "5"))
PORT            = int(os.environ.get("PORT", "8765"))
GEMINI_MODEL    = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
HISTORY_BATCH   = int(os.environ.get("HISTORY_BATCH", "50"))
HISTORY_PAUSE   = float(os.environ.get("HISTORY_PAUSE", "8.0"))
# Temperature for Gemini responses (0.0–1.0). Lower = more deterministic.
GEMINI_TEMPERATURE = float(os.environ.get("GEMINI_TEMPERATURE", "0.15"))

# ── Retry behaviour (#43) ─────────────────────────────────────────────────────
# Transient failures (HTTP 5xx/408, timeouts, connection errors) and Gemini
# quota errors (429) park the batch as status='pending' in the database; the
# retry worker picks it up again once its next_attempt is due. Delays grow
# exponentially from RETRY_BASE_DELAY to RETRY_MAX_DELAY (seconds, with jitter).
RETRY_BASE_DELAY       = float(os.environ.get("RETRY_BASE_DELAY", "60"))
RETRY_MAX_DELAY        = float(os.environ.get("RETRY_MAX_DELAY", "3600"))
# A batch that keeps failing for non-quota reasons for this long becomes
# status='error'. Quota waits never count - those batches just wait for reset.
RETRY_MAX_AGE_HOURS    = float(os.environ.get("RETRY_MAX_AGE_HOURS", "72"))
# Unparseable / empty Gemini answers are not an outage - give up after this many.
RETRY_BAD_RESPONSE_MAX = int(os.environ.get("RETRY_BAD_RESPONSE_MAX", "3"))
# Retry worker: poll interval when idle, pause between two retried batches
# (keeps the drain of a large backlog well below Gemini's per-minute limit).
RETRY_POLL             = float(os.environ.get("RETRY_POLL", "30"))
RETRY_PACE             = float(os.environ.get("RETRY_PACE", "10"))
# 'analyzing' rows nobody is working on for this long are re-queued (the
# request timeout is 90s, so 15 minutes means the worker thread is gone).
STALE_ANALYZING_SECONDS = float(os.environ.get("STALE_ANALYZING_SECONDS", "900"))
# Concurrent Gemini requests. The upstream backoff is only effective if a burst
# of live batches cannot all be in flight before the first failure closes it.
GEMINI_CONCURRENCY     = max(1, int(os.environ.get("GEMINI_CONCURRENCY", "2")))
# Describe your infrastructure so Gemini can give context-aware recommendations.
# Example: "Proxmox homelab with LXC containers, Oracle Cloud VPS, Tailscale VPN, fail2ban"
INFRA_CONTEXT   = os.environ.get("INFRA_CONTEXT", "a self-hosted Linux server environment")

# ── Security ──────────────────────────────────────────────────────────────────
# Default: bind only to localhost. Set to 0.0.0.0 only when behind a reverse
# proxy with authentication (e.g. Nginx Basic Auth, Cloudflare Access, VPN).
LISTEN_HOST          = os.environ.get("LISTEN_HOST", "127.0.0.1")
# Login credentials. Password is stored as a Werkzeug pbkdf2:sha256 hash –
# never the plaintext. Run: python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('yourpassword'))"
DASHBOARD_USER       = os.environ.get("DASHBOARD_USER", "admin").strip()
DASHBOARD_PASSWORD_HASH = os.environ.get("DASHBOARD_PASSWORD_HASH", "").strip()
# Session timeout in seconds (default: 8 hours)
SESSION_LIFETIME     = int(os.environ.get("SESSION_LIFETIME", str(8 * 3600)))
# Max failed login attempts before 60s cooldown
LOGIN_MAX_ATTEMPTS   = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
# Number of trusted reverse-proxy hops in front of this app (e.g. 1 for a single
# Nginx/Traefik in front). 0 (default) disables ProxyFix entirely - X-Forwarded-For
# is client-controlled and MUST NOT be trusted unless a real proxy is confirmed to
# be overwriting it before the request reaches this app, since the login
# rate-limiter is keyed on the resulting request.remote_addr.
TRUSTED_PROXY_HOPS   = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))
# Marks the session cookie Secure (HTTPS-only). Modern browsers treat
# 127.0.0.1/localhost as a secure context, so this stays safe with the
# documented SSH-tunnel default (LISTEN_HOST=127.0.0.1) - disable only if a
# specific browser/proxy setup needs the cookie over plain HTTP.
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").strip().lower() not in ("false", "0", "no")

WATERMARK_FILE       = Path(DB_PATH).parent / "watermark.json"
SESSION_KEY_FILE     = Path(DB_PATH).parent / "session.key"
# The data directory holds the analysis database (prioritised vulnerabilities,
# affected hostnames, source IPs), the alert watermark and the Flask session
# key. None of it is meant for other local accounts, so it is kept
# owner-only instead of inheriting the process umask (usually 0755/0644).
DATA_DIR_MODE        = 0o700
DATA_FILE_MODE       = 0o600
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("wazuh-ai")


class _RedactSecrets(logging.Filter):
    """Mask the Gemini key before a record is emitted (defense in depth).

    Sits on the root handlers, so it also covers library loggers (urllib3,
    werkzeug) whose messages can embed a full request URL or header dump."""
    _pattern = re.compile(
        r"""(key=|x-goog-api-key['"]?\s*[:=]\s*['"]?)[^&\s'"]+""", re.IGNORECASE)

    @classmethod
    def scrub(cls, text: str) -> str:
        """Return text with the key parameter / header value / literal key masked."""
        redacted = cls._pattern.sub(r"\1***", text)
        if GEMINI_API_KEY:
            redacted = redacted.replace(GEMINI_API_KEY, "***")
        return redacted

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        redacted = self.scrub(msg)
        if redacted != msg:
            record.msg, record.args = redacted, None
        return True


for _handler in logging.getLogger().handlers:
    _handler.addFilter(_RedactSecrets())

def _restrict(path: Path, mode: int) -> None:
    """Best-effort chmod on an existing path. A filesystem without POSIX modes
    must not take the whole service down, so failures are logged, not raised."""
    try:
        if path.exists():
            path.chmod(mode)
    except OSError as exc:
        log.warning("Konnte Rechte fuer %s nicht auf %o setzen: %s", path, mode, exc)

app = Flask(__name__, static_folder=STATIC_DIR)
# Only trust X-Forwarded-For/-Proto/-Host when a trusted reverse proxy is
# explicitly configured (TRUSTED_PROXY_HOPS > 0). Applying ProxyFix
# unconditionally let any client spoof request.remote_addr via a fake
# X-Forwarded-For header, bypassing the per-IP login lockout below.
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=TRUSTED_PROXY_HOPS, x_host=TRUSTED_PROXY_HOPS
    )
else:
    log.info("TRUSTED_PROXY_HOPS=0 – ProxyFix disabled, request.remote_addr is the raw socket peer.")
app.config["SESSION_COOKIE_SECURE"]   = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.after_request
def _set_security_headers(response):
    """SameSite=Lax on the session cookie doesn't stop the login form itself
    from being framed on another origin (clickjacking), so deny framing
    explicitly and block MIME-sniffing on every response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response

def _load_or_create_session_key() -> bytes:
    """Persistent secret key for Flask sessions. Generated once, stored on disk."""
    if SESSION_KEY_FILE.exists():
        try:
            key = SESSION_KEY_FILE.read_bytes()
            # Heal a key file left world-readable by an install predating the
            # explicit mode handling below.
            _restrict(SESSION_KEY_FILE, DATA_FILE_MODE)
            return key
        except Exception:
            pass
    key = secrets.token_bytes(64)
    SESSION_KEY_FILE.parent.mkdir(parents=True, exist_ok=True, mode=DATA_DIR_MODE)
    _restrict(SESSION_KEY_FILE.parent, DATA_DIR_MODE)
    SESSION_KEY_FILE.write_bytes(key)
    SESSION_KEY_FILE.chmod(DATA_FILE_MODE)
    return key

# Secret key placeholder – replaced at startup after init_db()
app.secret_key = b"placeholder"

# ─── Brute-force tracker ──────────────────────────────────────────────────────
_login_attempts: dict = {}   # ip -> [timestamp, ...]
_attempts_lock  = threading.Lock()

def _is_rate_limited(ip: str) -> tuple:
    """Returns (limited: bool, retry_in: int seconds)."""
    now = time.time()
    with _attempts_lock:
        # Sweep every IP's list here, not just the caller's. An attacker
        # rotating source addresses (trivial over IPv6) never revisits the
        # same IP, so pruning only the current key would leave a stale dict
        # entry behind for every address it ever used, growing the dict
        # without bound over the process lifetime.
        for stale_ip in [k for k, v in _login_attempts.items()
                          if not any(now - t < 60 for t in v)]:
            del _login_attempts[stale_ip]

        attempts = [t for t in _login_attempts.get(ip, []) if now - t < 60]
        if attempts:
            _login_attempts[ip] = attempts
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            retry_in = max(0, int(60 - (now - attempts[0])))
            return True, retry_in
        return False, 0

def _record_failed(ip: str):
    with _attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())

def _clear_attempts(ip: str):
    with _attempts_lock:
        _login_attempts.pop(ip, None)

# ─── Auth helpers ─────────────────────────────────────────────────────────────
_PUBLIC_PATHS = {"/login", "/logout"}

def _is_authenticated() -> bool:
    return (session.get("authenticated") is True and
            session.get("user") == DASHBOARD_USER and
            time.time() < session.get("expires_at", 0))

def _safe_next_path(next_url: str) -> str:
    """Only allow local, relative redirect targets (post-login `next` param).

    A leading "/" alone isn't enough: "//evil.com" and "/\\evil.com" are
    scheme-relative URLs that browsers resolve to an external host, and
    urlparse().netloc catches those plus any URL that smuggles in a scheme.
    """
    if not next_url.startswith("/") or next_url.startswith("//") or next_url.startswith("/\\"):
        return "/"
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return "/"
    return next_url

# ─── Auth middleware ──────────────────────────────────────────────────────────
@app.before_request
def require_login():
    """Block every request unless the session is authenticated."""
    if request.path in _PUBLIC_PATHS or request.path.startswith("/static/"):
        return

    if not DASHBOARD_PASSWORD_HASH:
        if request.path.startswith("/api/"):
            return jsonify({"error": "No credentials configured",
                            "hint":  "Set DASHBOARD_PASSWORD_HASH in the env file"}), 503
        return _login_html(
            error="Kein Passwort konfiguriert. Bitte DASHBOARD_PASSWORD_HASH in der env-Datei setzen."
        ), 503

    if not _is_authenticated():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect(f"/login?next={request.path}")

# ─── Login / Logout routes ────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login_route():
    if _is_authenticated():
        return redirect("/")

    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        limited, retry_in = _is_rate_limited(ip)
        if limited:
            error = f"Zu viele Fehlversuche. Bitte {retry_in}s warten."
            log.warning(f"Login rate-limited for {ip}")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if (username == DASHBOARD_USER and
                    DASHBOARD_PASSWORD_HASH and
                    check_password_hash(DASHBOARD_PASSWORD_HASH, password)):
                _clear_attempts(ip)
                session.clear()
                session["authenticated"] = True
                session["user"]          = username
                session["expires_at"]    = time.time() + SESSION_LIFETIME
                session.permanent        = True
                log.info(f"Login erfolgreich: {username} von {ip}")
                next_url = _safe_next_path(request.args.get("next", "/"))
                return redirect(next_url)
            else:
                _record_failed(ip)
                with _attempts_lock:
                    count = len(_login_attempts.get(ip, []))
                remaining = max(0, LOGIN_MAX_ATTEMPTS - count)
                error = f"Falscher Benutzername oder Passwort. ({remaining} Versuch(e) verbleibend)"
                log.warning(f"Fehlgeschlagener Login: user='{username}' ip={ip}")

    return _login_html(error=error, query_string=request.query_string.decode())

@app.route("/logout")
def logout_route():
    user = session.get("user", "unknown")
    ip   = request.remote_addr or "unknown"
    session.clear()
    log.info(f"Logout: {user} von {ip}")
    return redirect("/login")

# ─── Login page HTML ──────────────────────────────────────────────────────────
def _login_html(error: str = None, query_string: str = "") -> str:
    next_param = f"?{html.escape(query_string)}" if query_string else ""
    err_block  = (f'<div class="err">{error}</div>') if error else ""
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Anmelden</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #080c14; color: #e2e8f0;
      font-family: 'Segoe UI', system-ui, sans-serif;
      min-height: 100vh; display: flex;
      align-items: center; justify-content: center;
    }}
    .card {{
      background: #0f1623; border: 1px solid rgba(255,255,255,.08);
      border-radius: 18px; padding: 42px 44px 36px; width: 340px;
      box-shadow: 0 24px 64px rgba(0,0,0,.6);
    }}
    .logo {{ text-align: center; margin-bottom: 28px; }}
    .logo-icon {{ font-size: 36px; display: block; margin-bottom: 10px; }}
    .logo-title {{ font-size: 16px; font-weight: 600; letter-spacing: .3px; }}
    .logo-sub {{ font-size: 11px; color: rgba(255,255,255,.3); letter-spacing: 1px; text-transform: uppercase; margin-top: 3px; }}
    hr {{ border: none; border-top: 1px solid rgba(255,255,255,.07); margin: 0 0 24px; }}
    .field {{ margin-bottom: 14px; }}
    label {{ display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: rgba(255,255,255,.35); font-weight: 600; margin-bottom: 7px; }}
    input[type=text], input[type=password] {{
      width: 100%; padding: 11px 14px;
      background: rgba(255,255,255,.07); border: 1px solid rgba(255,255,255,.13);
      border-radius: 10px; color: #fff; font-size: 14px; outline: none;
      transition: border-color .2s;
    }}
    input:focus {{ border-color: rgba(99,102,241,.7); background: rgba(255,255,255,.09); }}
    .submit {{
      margin-top: 20px; width: 100%; padding: 12px;
      background: #6366f1; border: none; border-radius: 10px;
      color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;
      letter-spacing: .3px; transition: opacity .2s;
    }}
    .submit:hover {{ opacity: .85; }}
    .err {{
      background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3);
      border-radius: 8px; color: #fca5a5; font-size: 12px;
      padding: 10px 13px; margin-top: 14px; line-height: 1.5;
    }}
    .footer {{ text-align: center; font-size: 10px; color: rgba(255,255,255,.15); margin-top: 24px; letter-spacing: .5px; }}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="logo-icon">🛡️</span>
    <div class="logo-title">Wazuh AI Analyzer</div>
    <div class="logo-sub">powered by Aeterna™</div>
  </div>
  <hr>
  <form method="POST" action="/login{next_param}" autocomplete="on">
    <div class="field">
      <label for="username">Benutzername</label>
      <input type="text" id="username" name="username" autofocus autocomplete="username" placeholder="admin">
    </div>
    <div class="field">
      <label for="password">Passwort</label>
      <input type="password" id="password" name="password" autocomplete="current-password" placeholder="••••••••">
    </div>
    <button type="submit" class="submit">Anmelden</button>
    {err_block}
  </form>
  <div class="footer">Sicherheitssystem · Nur autorisierter Zugriff</div>
</div>
</body>
</html>"""


# ─── Quota / Rate-Limit State ─────────────────────────────────────────────────
class QuotaState:
    """Verwaltet Gemini-Quota-Erschöpfung und automatisches Retry."""
    def __init__(self):
        self._lock            = threading.Lock()
        self.exhausted        = False
        self.exhausted_since  = None
        self.retry_at         = None   # Unix-Timestamp
        self.retry_count      = 0
        self.last_error_msg   = ""
        self.last_success_at  = None

    def mark_exhausted(self, msg: str, retry_after_s: float):
        with self._lock:
            now = datetime.now(timezone.utc)
            if not self.exhausted:
                self.exhausted_since = now.isoformat(timespec="seconds")
            self.exhausted      = True
            self.retry_count   += 1
            self.retry_at       = time.time() + retry_after_s
            self.last_error_msg = msg
            retry_ts = datetime.fromtimestamp(self.retry_at, tz=timezone.utc).isoformat(timespec="seconds")
            log.warning(f"Quota erschoepft: {msg} | Naechster Versuch: {retry_ts}")

    def mark_success(self):
        with self._lock:
            if self.exhausted:
                log.info("Quota wiederhergestellt – Analyse laeuft wieder")
            self.exhausted       = False
            self.exhausted_since = None
            self.retry_at        = None
            self.retry_count     = 0
            self.last_error_msg  = ""
            self.last_success_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def can_send(self) -> bool:
        with self._lock:
            if not self.exhausted:
                return True
            return time.time() >= (self.retry_at or 0)

    def wait_seconds(self) -> float:
        """Seconds until the quota backoff allows the next request (0 = now)."""
        with self._lock:
            if not self.exhausted:
                return 0.0
            return max(0.0, (self.retry_at or 0) - time.time())

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "exhausted":        self.exhausted,
                "exhausted_since":  self.exhausted_since,
                "retry_at":         datetime.fromtimestamp(self.retry_at, tz=timezone.utc).isoformat(timespec="seconds")
                                    if self.retry_at else None,
                "retry_in_seconds": max(0, int((self.retry_at or 0) - time.time()))
                                    if self.exhausted else 0,
                "retry_count":      self.retry_count,
                "last_error":       self.last_error_msg,
                "last_success_at":  self.last_success_at,
            }

quota = QuotaState()

# ─── Retry-Steuerung ──────────────────────────────────────────────────────────
def _now() -> float:
    return time.time()

def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")

def _parse_iso(value) -> float:
    """ISO timestamp -> epoch seconds; 0.0 for anything unparseable."""
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return 0.0

def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter: RETRY_BASE_DELAY * 2**(attempt-1),
    never more than RETRY_MAX_DELAY."""
    exponent = max(0, min(attempt, 32) - 1)
    delay    = min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * (2 ** exponent))
    return min(RETRY_MAX_DELAY, delay * random.uniform(0.8, 1.2))

@dataclass(frozen=True)
class GeminiFailure:
    """Why a Gemini call produced no usable result.

    kind: 'quota'        HTTP 429 - wait for the quota backoff, never expires
          'transient'    5xx/408, timeout, connection error - retry with backoff
          'config'       401/403/404, missing key - retry slowly: the operator
                         can fix the key/model and the parked batches survive
          'bad_response' unparseable / empty answer - a few retries only
          'permanent'    any other 4xx - retrying the same payload cannot help"""
    kind:        str
    message:     str
    retry_after: float = 0.0

class UpstreamState:
    """Shared backoff for transient Gemini/network failures.

    Per-batch backoff alone is not enough: after a long outage every parked
    batch would probe the API on its own schedule, which on a 500 requests/day
    free tier burns quota while Gemini is still down. This gate closes for
    everybody after a failure and only grows while failures keep coming."""
    def __init__(self):
        self._lock                = threading.Lock()
        self.consecutive_failures = 0
        self.next_ok_at           = 0.0
        self.last_error           = ""

    def mark_failure(self, message: str, retry_after: float = 0.0) -> float:
        with self._lock:
            self.consecutive_failures += 1
            delay = max(min(retry_after, RETRY_MAX_DELAY),
                        _backoff_delay(self.consecutive_failures))
            self.next_ok_at = _now() + delay
            self.last_error = message[:200]
            count = self.consecutive_failures
        log.warning(f"Gemini nicht erreichbar/ueberlastet (Fehler #{count} in Folge) – "
                    f"naechster Versuch in {int(delay)}s")
        return delay

    def mark_success(self):
        with self._lock:
            recovered = self.consecutive_failures > 0
            self.consecutive_failures = 0
            self.next_ok_at           = 0.0
            self.last_error           = ""
        if recovered:
            log.info("Gemini wieder erreichbar – Retry-Sperre aufgehoben")

    def wait_seconds(self) -> float:
        with self._lock:
            return max(0.0, self.next_ok_at - _now())

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "consecutive_failures": self.consecutive_failures,
                "retry_in_seconds":     int(max(0.0, self.next_ok_at - _now())),
                "last_error":           self.last_error,
            }

upstream = UpstreamState()

def _gate_wait() -> float:
    """Seconds until Gemini may be contacted again: the longer of the quota
    backoff and the transient-failure backoff."""
    return max(quota.wait_seconds(), upstream.wait_seconds())

# Batch ids a thread in this process is working on right now. The stale
# sweeper must not requeue those, or a slow request would be sent twice.
_inflight      = set()
_inflight_lock = threading.Lock()
_gemini_slot   = threading.BoundedSemaphore(GEMINI_CONCURRENCY)

def _set_pending(batch_id: int, next_attempt: float, message: str,
                 attempts: int, first_error_at, bad_responses: int):
    with _db() as conn:
        conn.execute(
            """UPDATE batches
               SET status='pending', next_attempt=?, last_error=?, attempts=?,
                   first_error_at=?, bad_responses=?
               WHERE id=?""",
            (next_attempt, message, attempts, first_error_at, bad_responses, batch_id)
        )

def _defer_batch(batch_id: int, delay: float):
    """Park a batch without having sent anything (gate closed): no attempt used."""
    with _db() as conn:
        conn.execute(
            "UPDATE batches SET status='pending', next_attempt=? WHERE id=?",
            (_now() + delay, batch_id)
        )

def _drop_batch(batch_id: int, reason: str, counter: str, attempts: int = 0):
    """Final failure. Always logged and counted - dropping must never be silent."""
    with _db() as conn:
        conn.execute(
            "UPDATE batches SET status='error', next_attempt=NULL, last_error=?, "
            "attempts=MAX(attempts, ?) WHERE id=?",
            (reason, attempts, batch_id)
        )
    _inc("errors")
    _inc(counter)
    with stats_lock:
        total = _stats[counter]
    log.error(f"Batch {batch_id} verworfen ({counter}={total}): {reason}")

# Consecutive batches dropped as 'permanent'. A genuinely bad payload hits one
# batch; many in a row mean the request itself is wrong (key, region, model)
# and the queue must not be emptied into the error state.
_permanent_streak      = 0
PERMANENT_STREAK_LIMIT = 3

def _reset_permanent_streak():
    global _permanent_streak
    _permanent_streak = 0

def _handle_failure(batch_id: int, failure: GeminiFailure):
    global _permanent_streak
    now     = _now()
    message = _RedactSecrets.scrub(failure.message)[:300]
    with _db() as conn:
        row = conn.execute(
            "SELECT attempts, first_error_at, bad_responses FROM batches WHERE id=?", (batch_id,)
        ).fetchone()
    attempts       = (row["attempts"] if row else 0) + 1
    first_error_at = row["first_error_at"] if row else None
    bad_responses  = row["bad_responses"] if row else 0
    kind           = failure.kind

    if kind == "permanent":
        _permanent_streak += 1
        if _permanent_streak >= PERMANENT_STREAK_LIMIT:
            log.error(f"{_permanent_streak} Batches in Folge mit permanentem Fehler – "
                      f"vermutlich ist die Konfiguration falsch, Batch {batch_id} wird nicht verworfen")
            kind = "config"
        else:
            _drop_batch(batch_id, f"permanent: {message}", "dropped_permanent", attempts)
            return
    else:
        _permanent_streak = 0

    if kind == "quota":
        # Waiting for the quota reset is not a failure of the batch: it keeps
        # its place in the queue for as long as it takes, and the API answered,
        # so an earlier outage no longer counts towards the expiry.
        next_attempt = max(quota.retry_at or now, now)
        _set_pending(batch_id, next_attempt, message, attempts, None, bad_responses)
        _inc("retries_scheduled")
        log.warning(f"Batch {batch_id} pausiert wegen Quota-Erschoepfung "
                    f"(erneut in {int(next_attempt - now)}s)")
        return

    if kind == "bad_response":
        bad_responses += 1
        if bad_responses >= RETRY_BAD_RESPONSE_MAX:
            _drop_batch(batch_id, f"bad_response nach {bad_responses} Versuchen: {message}",
                        "dropped_bad_response", attempts)
            return
    else:   # transient / config
        started = _parse_iso(first_error_at) or now
        if now - started > RETRY_MAX_AGE_HOURS * 3600:
            _drop_batch(batch_id,
                        f"seit {RETRY_MAX_AGE_HOURS:g}h nicht analysierbar ({kind}): {message}",
                        "expired", attempts)
            return
        if first_error_at is None:
            first_error_at = _iso(now)
        upstream.mark_failure(message, failure.retry_after)

    next_attempt = now + max(_backoff_delay(attempts), upstream.wait_seconds())
    _set_pending(batch_id, next_attempt, message, attempts, first_error_at, bad_responses)
    _inc("retries_scheduled")
    log.warning(f"Batch {batch_id}: {kind} ({message}) – Versuch {attempts}, "
                f"erneut in {int(next_attempt - now)}s")

def _requeue_stale(older_than: float) -> int:
    """Put 'analyzing' batches nobody works on back into the queue. A restart
    kills every in-flight request, so at startup older_than is 0 and all of
    them qualify; at runtime the in-flight set protects live requests."""
    now = _now()
    with _inflight_lock:
        busy = set(_inflight)
    with _db() as conn:
        rows = conn.execute(
            "SELECT id FROM batches WHERE status='analyzing' "
            "AND (claimed_at IS NULL OR claimed_at <= ?)", (now - older_than,)
        ).fetchall()
        ids = [r["id"] for r in rows if r["id"] not in busy]
        for batch_id in ids:
            conn.execute(
                "UPDATE batches SET status='pending', next_attempt=? "
                "WHERE id=? AND status='analyzing'", (now, batch_id))
    if ids:
        _inc("recovered_stale", len(ids))
        log.warning(f"{len(ids)} haengende Batches (analyzing) wieder eingereiht: {ids[:10]}")
    return len(ids)

def _retry_once() -> bool:
    """Run at most one due batch. Returns True if a Gemini attempt was made."""
    _requeue_stale(STALE_ANALYZING_SECONDS)
    if _gate_wait() > 0:
        return False
    now = _now()
    with _db() as conn:
        row = conn.execute(
            "SELECT id, raw_groups, source FROM batches "
            "WHERE status='pending' AND COALESCE(next_attempt, 0) <= ? "
            "ORDER BY (source = 'live') DESC, COALESCE(next_attempt, 0), id LIMIT 1", (now,)
        ).fetchone()
        if row is None:
            return False
        claimed = conn.execute(
            "UPDATE batches SET status='analyzing', claimed_at=? "
            "WHERE id=? AND status='pending'", (now, row["id"])
        ).rowcount
    if claimed != 1:
        return False
    try:
        groups = json.loads(row["raw_groups"])
    except ValueError:
        _drop_batch(row["id"], "raw_groups nicht lesbar", "dropped_permanent")
        return True
    log.info(f"Retry-Worker: verarbeite Batch {row['id']} erneut (Quelle: {row['source']})")
    _do_gemini_and_save(row["id"], groups, source=row["source"], is_retry=True)
    return True

def retry_worker():
    """Runs forever: retries due batches from the database (survives restarts)."""
    while True:
        did_work = False
        try:
            did_work = _retry_once()
        except Exception:
            log.exception("Retry-Worker: unerwarteter Fehler")
        time.sleep(RETRY_PACE if did_work else RETRY_POLL)

# ─── Datenbank ────────────────────────────────────────────────────────────────
def get_db_conn():
    """Open a new SQLite connection. Caller MUST call conn.close() when done."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL mode: allows concurrent reads alongside a single writer, eliminates most
    # "database is locked" errors under multi-threaded load.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, faster than FULL
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

class _db:
    """Context manager that opens a connection, manages the transaction,
    and guarantees conn.close() even if an exception is raised."""
    def __enter__(self):
        self.conn = get_db_conn()
        return self.conn
    def __exit__(self, exc_type, *_):
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

# Retry bookkeeping added for #43. Databases created by earlier versions get
# the columns via ALTER TABLE (cheap: SQLite only touches the schema).
_BATCH_RETRY_COLUMNS = (
    ("attempts",       "INTEGER NOT NULL DEFAULT 0"),
    ("next_attempt",   "REAL"),
    ("first_error_at", "TEXT"),
    ("last_error",     "TEXT"),
    ("claimed_at",     "REAL"),
    ("bad_responses",  "INTEGER NOT NULL DEFAULT 0"),
)

def _migrate_schema(conn: sqlite3.Connection):
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(batches)")}
    for name, ddl in _BATCH_RETRY_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE batches ADD COLUMN {name} {ddl}")
            log.info(f"Datenbank migriert: batches.{name} angelegt")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_batches_retry ON batches(status, next_attempt)")

def init_db():
    data_dir = Path(DB_PATH).parent
    # mode= is only honoured when mkdir actually creates the directory, so an
    # existing (world-readable) data dir from an older install is fixed too.
    data_dir.mkdir(parents=True, exist_ok=True, mode=DATA_DIR_MODE)
    _restrict(data_dir, DATA_DIR_MODE)
    conn = get_db_conn()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS batches (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at    TEXT    NOT NULL,
                alert_count   INTEGER NOT NULL,
                raw_groups    TEXT    NOT NULL,
                summary       TEXT,
                overall_risk  TEXT    DEFAULT 'unknown',
                status        TEXT    DEFAULT 'pending',
                source        TEXT    DEFAULT 'live',
                attempts      INTEGER NOT NULL DEFAULT 0,
                next_attempt  REAL,
                first_error_at TEXT,
                last_error    TEXT,
                claimed_at    REAL,
                bad_responses INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id        INTEGER NOT NULL,
                title           TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                description     TEXT    NOT NULL,
                recommendation  TEXT    NOT NULL,
                affected_agents TEXT,
                rule_ids        TEXT,
                FOREIGN KEY (batch_id) REFERENCES batches(id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_batch    ON findings(batch_id);
            CREATE INDEX IF NOT EXISTS idx_batches_created   ON batches(created_at);
            CREATE INDEX IF NOT EXISTS idx_batches_source    ON batches(source);
        """)
        _migrate_schema(conn)
        conn.commit()
    finally:
        conn.close()
    # SQLite creates the database (and its WAL sidecars) with the process umask,
    # typically 0644 - the analysis data must not be readable by other local users.
    for suffix in ("", "-wal", "-shm"):
        _restrict(Path(f"{DB_PATH}{suffix}"), DATA_FILE_MODE)
    log.info("Datenbank initialisiert (WAL-Modus aktiv)")

# ─── Watermark ────────────────────────────────────────────────────────────────
def load_watermark() -> dict:
    if WATERMARK_FILE.exists():
        try:
            return json.loads(WATERMARK_FILE.read_text())
        except Exception:
            pass
    return {}

def save_watermark(data: dict):
    # os.open() applies the mode only when the file is created, so an existing
    # file from an earlier install still needs the explicit _restrict() below.
    fd = os.open(WATERMARK_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, DATA_FILE_MODE)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(data, indent=2))
    _restrict(WATERMARK_FILE, DATA_FILE_MODE)

# ─── Runtime-Statistiken ──────────────────────────────────────────────────────
stats_lock = threading.Lock()
_stats     = {
    "processed": 0, "skipped": 0,
    "batches_sent": 0, "errors": 0,
    "history_alerts": 0, "history_done": False,
    "history_files_total": 0, "history_files_done": 0,
    # Retry bookkeeping (#43): every final failure ends in exactly one of the
    # dropped_*/expired counters, so "errors" can always be explained.
    "retries_scheduled": 0, "retries_succeeded": 0, "recovered_stale": 0,
    "dropped_permanent": 0, "dropped_bad_response": 0, "expired": 0,
}

def _inc(key, n=1):
    with stats_lock:
        _stats[key] += n

def _set(key, val):
    with stats_lock:
        _stats[key] = val

# ─── Alert-Buffer (Live) ──────────────────────────────────────────────────────
alert_buffer  = []
buffer_lock   = threading.Lock()
last_flush_ts = time.time()

def _handle_line(line: str, source: str = "live") -> bool:
    if not line.strip():
        return False
    try:
        alert = json.loads(line)
        level = alert.get("rule", {}).get("level", 0)
        if level < MIN_LEVEL:
            _inc("skipped")
            return False
        _inc("processed")
        alert["_source"] = source
        with buffer_lock:
            alert_buffer.append(alert)
            if len(alert_buffer) >= BATCH_MAX:
                _flush(source=source)
        return True
    except Exception:
        return False

def _flush(source: str = "live"):
    global last_flush_ts, alert_buffer
    if not alert_buffer:
        return
    batch  = alert_buffer.copy()
    alert_buffer.clear()
    last_flush_ts = time.time()
    _inc("batches_sent")
    t = threading.Thread(
        target=analyze_batch, args=(batch, source),
        daemon=True, name=f"gemini-{source}"
    )
    t.start()

def _store_batch(alerts: list, source: str) -> tuple:
    """Persist a batch as 'analyzing' before Gemini is contacted. From here on
    the batch survives restarts: it is either finished or re-queued."""
    groups = group_alerts(alerts)
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status, source, claimed_at) "
            "VALUES (?, ?, ?, 'analyzing', ?, ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), len(alerts),
             json.dumps(groups), source, _now())
        )
        batch_id = cur.lastrowid
    return batch_id, groups

# ─── Historische Analyse ──────────────────────────────────────────────────────
def find_alert_files() -> list:
    base    = Path(ALERTS_LOG)
    pattern = str(base.parent / "alerts.json*")
    files   = sorted(glob.glob(pattern), key=lambda p: os.path.getmtime(p))
    if str(base) in files:
        files.remove(str(base))
        files.append(str(base))
    return files

def historical_scan():
    """
    Scannt alle vorhandenen Alert-Logs von Anfang an.
    Macht nahtlos weiter wo ein frueherer Lauf aufgehoert hat (Watermark).
    Pausiert automatisch bei Quota-Erschoepfung und macht danach weiter.
    """
    wm    = load_watermark()
    files = find_alert_files()
    _set("history_files_total", len(files))

    if not files:
        log.warning("Keine Alert-Log-Dateien gefunden – historische Analyse uebersprungen")
        _set("history_done", True)
        return

    log.info(f"Historische Analyse: {len(files)} Datei(en) gefunden")

    for filepath in files:
        wm_line = wm.get(filepath, 0)
        if not os.path.exists(filepath):
            _inc("history_files_done")
            continue

        log.info(f"Historisch: {filepath} (ab Zeile {wm_line})")
        local_buf = []
        line_num  = 0

        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    line_num += 1
                    if line_num <= wm_line:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        if alert.get("rule", {}).get("level", 0) < MIN_LEVEL:
                            continue
                        alert["_source"] = "history"
                        local_buf.append(alert)
                        _inc("history_alerts")
                    except Exception:
                        continue

                    if len(local_buf) >= HISTORY_BATCH:
                        _wait_for_gate()
                        _send_history_batch(local_buf[:])
                        local_buf.clear()
                        wm[filepath] = line_num
                        save_watermark(wm)
                        time.sleep(HISTORY_PAUSE)

        except Exception as e:
            log.error(f"Historisch: Fehler beim Lesen von {filepath}: {e}")
            _inc("history_files_done")
            continue

        if local_buf:
            _wait_for_gate()
            _send_history_batch(local_buf)

        wm[filepath] = line_num
        save_watermark(wm)
        _inc("history_files_done")
        log.info(f"Historisch: {filepath} fertig ({line_num} Zeilen)")

    _set("history_done", True)
    with stats_lock:
        done = _stats["history_alerts"]
    log.info(f"Historische Analyse abgeschlossen: {done} Alerts verarbeitet")

def _wait_for_gate():
    """Blockiert solange Quota erschoepft ist oder Gemini nach einem Fehler pausiert."""
    while True:
        remaining = _gate_wait()
        if remaining <= 0:
            return
        log.info(f"Historisch: warte auf Gemini-Freigabe ({int(remaining)}s verbleibend) …")
        time.sleep(min(remaining + 2, 120))

def _send_history_batch(alerts: list):
    batch_id, groups = _store_batch(alerts, "history")
    _do_gemini_and_save(batch_id, groups, source="history")

# ─── Live-Watcher ─────────────────────────────────────────────────────────────
def _get_inode(path: str) -> int:
    """Return inode number of a file, or -1 if it does not exist."""
    try:
        return os.stat(path).st_ino
    except OSError:
        return -1

def tail_alerts():
    """
    Follows alerts.json continuously.
    Detects log rotation (inode change or file shrink) and reopens automatically.
    """
    global last_flush_ts

    # Wait until the log file exists
    while not os.path.exists(ALERTS_LOG):
        log.warning(f"Alert-Log nicht gefunden: {ALERTS_LOG} – warte 15s …")
        time.sleep(15)

    log.info(f"Live-Ueberwachung: {ALERTS_LOG}")

    def _open_at_end(path: str):
        f = open(path, "r", errors="replace")
        f.seek(0, 2)
        return f, _get_inode(path)

    f, current_inode = _open_at_end(ALERTS_LOG)
    try:
        while True:
            line = f.readline()
            if line:
                _handle_line(line.strip(), source="live")
                continue

            # No new data – check for rotation before sleeping
            # Rotation detected when:
            #   a) The inode of ALERTS_LOG changed (rename+create)
            #   b) The file is smaller than our current position (truncate)
            try:
                disk_inode = _get_inode(ALERTS_LOG)
                disk_size  = os.path.getsize(ALERTS_LOG)
            except OSError:
                disk_inode = -1
                disk_size  = 0

            pos = f.tell()
            if disk_inode != current_inode or disk_size < pos:
                log.info(
                    f"Log-Rotation erkannt (inode {current_inode}→{disk_inode}, "
                    f"pos {pos}→size {disk_size}) – Datei wird neu geoeffnet"
                )
                f.close()
                # Brief pause so the new file has time to appear
                time.sleep(1.0)
                while not os.path.exists(ALERTS_LOG):
                    time.sleep(1.0)
                f, current_inode = _open_at_end(ALERTS_LOG)
                log.info(f"Live-Watcher neu geoeffnet (inode {current_inode})")
                continue

            # Truly no data – sleep and maybe flush buffer
            time.sleep(0.3)
            with buffer_lock:
                if alert_buffer and (time.time() - last_flush_ts) >= BATCH_TIMEOUT:
                    log.info(f"Timeout-Flush: {len(alert_buffer)} Alerts")
                    _flush(source="live")
    finally:
        f.close()

# ─── Alert-Gruppierung ────────────────────────────────────────────────────────
def group_alerts(alerts: list) -> list:
    groups: dict = defaultdict(lambda: {
        "description": "", "count": 0, "agents": set(),
        "levels": [], "locations": set(), "samples": []
    })
    for a in alerts:
        rule = a.get("rule", {})
        rid  = str(rule.get("id", "unknown"))
        g    = groups[rid]
        g["description"] = rule.get("description", "")
        g["count"]      += 1
        g["levels"].append(rule.get("level", 0))
        g["agents"].add(a.get("agent", {}).get("name", "unknown"))
        g["locations"].add(a.get("location", ""))
        if len(g["samples"]) < 3:
            g["samples"].append({
                "ts":       a.get("timestamp", "")[:19],
                "log":      (a.get("full_log", "") or "")[:250],
                "src_ip":   a.get("data", {}).get("srcip", ""),
                "dst_user": a.get("data", {}).get("dstuser", ""),
            })
    result = []
    for rid, g in groups.items():
        result.append({
            "rule_id":     rid,
            "description": g["description"],
            "count":       g["count"],
            "max_level":   max(g["levels"]) if g["levels"] else 0,
            "agents":      sorted(g["agents"]),
            "locations":   sorted(g["locations"])[:3],
            "samples":     g["samples"],
        })
    return sorted(result, key=lambda x: x["max_level"], reverse=True)

# ─── Gemini API ───────────────────────────────────────────────────────────────
_SYSTEM = (
    "Du bist ein erfahrener Cybersecurity-Analyst. "
    "Du analysierst Wazuh SIEM-Alerts und gibst praezise, umsetzbare Handlungsempfehlungen. "
    "Antworte ausschliesslich mit validem JSON – kein Markdown, keine Erklaerungen ausserhalb des JSON."
)

_PROMPT_TPL = """\
Analysiere diese Wazuh SIEM-Alert-Gruppen. Infrastruktur-Kontext: {infra}.

Alert-Gruppen:
{groups}

Gib AUSSCHLIESSLICH dieses JSON zurueck (keine anderen Zeichen, kein Markdown):
{{
  "summary": "Kurze Zusammenfassung der aktuellen Sicherheitslage (2-4 Saetze, auf Deutsch)",
  "overall_risk": "critical|high|medium|low|info",
  "findings": [
    {{
      "title": "Praegnanter Titel (max. 60 Zeichen)",
      "severity": "critical|high|medium|low|info",
      "description": "Was bedeutet dieser Alert? Warum ist er wichtig? (3-6 Saetze, Deutsch)",
      "recommendation": "Konkrete Schritte zur Behebung oder Ueberwachung. Nummeriert. Deutsch.",
      "affected_agents": ["agent-name"],
      "rule_ids": ["rule-id"]
    }}
  ]
}}
Sortiere findings nach Schwere (kritischstes zuerst).\
"""

def _retry_after_seconds(resp) -> float:
    """Numeric Retry-After header in seconds; 0 if absent or an HTTP date."""
    try:
        value = float(resp.headers.get("Retry-After", 0))
    except (TypeError, ValueError):
        return 0.0
    return min(value, 86400.0) if math.isfinite(value) and value > 0 else 0.0

def _is_config_error_body(resp) -> bool:
    """Gemini reports an invalid/expired key and unsupported regions as HTTP 400
    (API_KEY_INVALID / FAILED_PRECONDITION), not as 401/403 - but those are
    problems of the setup, not of the batch."""
    try:
        err = resp.json().get("error", {})
        reasons = {d.get("reason") for d in err.get("details", []) if isinstance(d, dict)}
        text = str(err.get("message", "")).lower()
    except Exception:
        text = resp.text.lower()
        reasons, err = set(), {}
    return (err.get("status") == "FAILED_PRECONDITION" or "API_KEY_INVALID" in reasons
            or "api key" in text or "location is not supported" in text)

def call_gemini(groups: list) -> tuple:
    """
    Gibt (result_dict, None) bei Erfolg zurueck, sonst (None, GeminiFailure).
    Die Art des Fehlers entscheidet, ob ein Batch wiederholt wird (siehe GeminiFailure).
    """
    if not GEMINI_API_KEY:
        log.error("GEMINI_API_KEY nicht gesetzt")
        return None, GeminiFailure("config", "GEMINI_API_KEY nicht gesetzt")

    prompt  = _PROMPT_TPL.format(infra=INFRA_CONTEXT, groups=json.dumps(groups, ensure_ascii=False, indent=2))
    url     = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    headers = {"x-goog-api-key": GEMINI_API_KEY}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": GEMINI_TEMPERATURE, "responseMimeType": "application/json"},
        "systemInstruction": {"parts": [{"text": _SYSTEM}]},
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=90)

        # ── 429: Rate-Limit oder Tages-Quota ─────────────────────────────
        if resp.status_code == 429:
            retry_after = _retry_after_seconds(resp)
            try:
                body = resp.json()
                msg  = body.get("error", {}).get("message", "") or resp.text[:150]
            except Exception:
                msg = resp.text[:150]
            if retry_after <= 0:
                # "quota" oder "day" im Fehlertext → taeglich → 1h warten
                # Sonst minutliches Limit → 65s warten
                if any(w in msg.lower() for w in ("quota", "day", "exhausted")):
                    retry_after = 3600
                else:
                    retry_after = 65
            quota.mark_exhausted(msg, retry_after)
            upstream.mark_success()   # the API answered, only the quota is empty
            return None, GeminiFailure("quota", msg, retry_after)

        # ── Andere HTTP-Fehler ────────────────────────────────────────────
        if not resp.ok:
            code = resp.status_code
            msg  = f"Gemini HTTP {code}: {resp.text[:200]}"
            log.error(msg)
            if code >= 500 or code in (408, 425):
                return None, GeminiFailure("transient", msg, _retry_after_seconds(resp))
            if code in (401, 403, 404):
                # Key revoked / wrong model: every batch fails alike, and the
                # operator can fix it. Do not throw the queue away meanwhile.
                return None, GeminiFailure("config", msg)
            if code == 400 and _is_config_error_body(resp):
                return None, GeminiFailure("config", msg)
            upstream.mark_success()   # reachable - this payload is the problem
            return None, GeminiFailure("permanent", msg)

        data   = resp.json()
        raw    = data["candidates"][0]["content"]["parts"][0]["text"]
        raw    = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError(f"JSON-Objekt erwartet, {type(result).__name__} erhalten")
        quota.mark_success()
        upstream.mark_success()
        return result, None

    except requests.Timeout:
        log.error("Gemini: Timeout")
        return None, GeminiFailure("transient", "Gemini: Timeout")
    except (requests.ConnectionError, requests.exceptions.ChunkedEncodingError) as e:
        log.error(f"Gemini: Verbindungsfehler: {e}")
        return None, GeminiFailure("transient", f"Gemini: Verbindungsfehler: {e}")
    except (KeyError, IndexError, TypeError, ValueError) as e:   # JSONDecodeError is a ValueError
        log.error(f"Gemini: Antwort parsen fehlgeschlagen: {e!r}")
        return None, GeminiFailure("bad_response", f"Antwort nicht auswertbar: {e!r}")
    except Exception as e:
        log.error(f"Gemini: Fehler: {e}")
        return None, GeminiFailure("bad_response", f"Gemini: Fehler: {e}")

# ─── Batch-Analyse ────────────────────────────────────────────────────────────
def analyze_batch(alerts: list, source: str = "live"):
    log.info(f"[{source}] Analysiere {len(alerts)} Alerts …")
    batch_id, groups = _store_batch(alerts, source)
    _do_gemini_and_save(batch_id, groups, source=source)

def _do_gemini_and_save(batch_id: int, groups: list, source: str = "live", is_retry: bool = False):
    """Run one Gemini attempt for an already stored batch. Whatever happens, the
    batch ends up 'done', 'pending' (queued for retry) or 'error' (counted)."""
    with _inflight_lock:
        _inflight.add(batch_id)
    try:
        with _gemini_slot:
            wait = _gate_wait()
            if wait > 0:
                # Another request just failed or the quota is empty: do not send,
                # park without using up an attempt.
                _defer_batch(batch_id, wait)
                log.info(f"Batch {batch_id} zurueckgestellt ({int(wait)}s): Gemini-Sperre aktiv")
                return
            result, failure = call_gemini(groups)
        if failure is not None:
            _handle_failure(batch_id, failure)
            return
        _save_result(batch_id, result, source, is_retry)
        global _permanent_streak
        _permanent_streak = 0
        if is_retry:
            _inc("retries_succeeded")
    except Exception as exc:
        log.exception(f"Batch {batch_id}: unerwarteter Fehler")
        try:
            _handle_failure(batch_id, GeminiFailure("bad_response", f"interner Fehler: {exc!r}"))
        except Exception:
            # The database itself is failing; the row is still 'analyzing' and
            # the stale sweeper re-queues it once the database is back.
            log.exception(f"Batch {batch_id}: konnte nicht eingereiht werden")
    finally:
        with _inflight_lock:
            _inflight.discard(batch_id)

def _save_result(batch_id: int, result: dict, source: str, is_retry: bool):
    # ── Whitelist-Validierung: LLM-Output sanitisieren ─────────────────────────
    _VALID_RISK = {"critical", "high", "medium", "low", "info", "unknown"}
    _VALID_SEV  = {"critical", "high", "medium", "low", "info"}

    raw_risk = result.get("overall_risk", "unknown")
    safe_risk = raw_risk if isinstance(raw_risk, str) and raw_risk in _VALID_RISK else "unknown"
    if safe_risk != raw_risk:
        log.warning(f"Ungueltiger overall_risk Wert vom LLM: {raw_risk!r} → 'unknown'")

    # The answer is valid JSON but not necessarily the schema we asked for.
    # Sending the same prompt again would not fix that, so store what is usable.
    findings = result.get("findings", [])
    findings = [f for f in findings if isinstance(f, dict)] if isinstance(findings, list) else []
    log.info(f"[{'retry' if is_retry else source}] Batch {batch_id}: "
             f"Risiko={safe_risk} | {len(findings)} Findings")

    def _list(value, limit):
        return value[:limit] if isinstance(value, list) else []

    with _db() as conn:
        conn.execute(
            "UPDATE batches SET summary=?, overall_risk=?, status='done', "
            "next_attempt=NULL, last_error=NULL WHERE id=?",
            (str(result.get("summary", ""))[:2000], safe_risk, batch_id)
        )
        for f in findings:
            raw_sev = f.get("severity", "info")
            safe_sev = raw_sev if isinstance(raw_sev, str) and raw_sev in _VALID_SEV else "info"
            conn.execute(
                """INSERT INTO findings
                   (batch_id, title, severity, description, recommendation, affected_agents, rule_ids)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    batch_id,
                    str(f.get("title", "Unbekanntes Finding"))[:200],
                    safe_sev,
                    str(f.get("description", ""))[:5000],
                    str(f.get("recommendation", ""))[:5000],
                    json.dumps(_list(f.get("affected_agents"), 20)),
                    json.dumps(_list(f.get("rule_ids"), 50)),
                )
            )

# ─── REST-API ─────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    with _db() as conn:
        total    = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        sev_map  = {}
        for row in conn.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity"):
            sev_map[row["severity"]] = row["c"]
        last_row     = conn.execute(
            "SELECT created_at FROM batches WHERE status='done' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        batch_count  = conn.execute("SELECT COUNT(*) FROM batches WHERE status='done'").fetchone()[0]
        by_status    = {row["status"]: row["c"] for row in
                        conn.execute("SELECT status, COUNT(*) c FROM batches GROUP BY status")}
        analyzing    = by_status.get("analyzing", 0)
        hist_done    = conn.execute("SELECT COUNT(*) FROM batches WHERE source='history' AND status='done'").fetchone()[0]

    with buffer_lock:
        buffered = len(alert_buffer)
    with stats_lock:
        s = dict(_stats)

    return jsonify({
        "total_findings":   total,
        "by_severity":      sev_map,
        "batch_count":      batch_count,
        "analyzing":        analyzing,
        "last_analysis":    last_row["created_at"] if last_row else None,
        "buffered_alerts":  buffered,
        "batch_max":        BATCH_MAX,
        "batch_timeout":    BATCH_TIMEOUT,
        "runtime":          s,
        "gemini_ok":        bool(GEMINI_API_KEY),
        "quota":            quota.as_dict(),
        # Persistent queue: batches waiting for their next attempt.
        "retry_queue_size": by_status.get("pending", 0),
        "batches": {status: by_status.get(status, 0)
                    for status in ("done", "error", "pending", "analyzing")},
        "upstream":         upstream.as_dict(),
        "history": {
            "done":            s["history_done"],
            "alerts_scanned":  s["history_alerts"],
            "files_total":     s["history_files_total"],
            "files_done":      s["history_files_done"],
            "batches_done":    hist_done,
        },
    })

@app.route("/api/findings")
def api_findings():
    limit    = min(int(request.args.get("limit", 50)), 200)
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    source   = request.args.get("source")

    conds, params = [], []
    if severity:
        conds.append("f.severity=?"); params.append(severity)
    if source:
        conds.append("b.source=?"); params.append(source)

    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    with _db() as conn:
        rows = conn.execute(
            f"""SELECT f.*, b.created_at batch_time, b.alert_count, b.source batch_source
                FROM findings f JOIN batches b ON f.batch_id=b.id
                {where} ORDER BY f.id DESC LIMIT ? OFFSET ?""",
            params + [limit, offset]
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) FROM findings f JOIN batches b ON f.batch_id=b.id {where}",
            params
        ).fetchone()[0]

    return jsonify({"findings": [_finding_dict(r) for r in rows], "total": total, "limit": limit, "offset": offset})

@app.route("/api/findings/<int:fid>")
def api_finding(fid):
    with _db() as conn:
        r = conn.execute(
            "SELECT f.*, b.created_at batch_time, b.alert_count, b.summary batch_summary, b.source batch_source "
            "FROM findings f JOIN batches b ON f.batch_id=b.id WHERE f.id=?",
            (fid,)
        ).fetchone()
    if not r:
        abort(404)
    d = _finding_dict(r)
    d["batch_summary"] = r["batch_summary"]
    d["alert_count"]   = r["alert_count"]
    return jsonify(d)

@app.route("/api/batches")
def api_batches():
    with _db() as conn:
        rows = conn.execute(
            "SELECT b.*, (SELECT COUNT(*) FROM findings WHERE batch_id=b.id) finding_count "
            "FROM batches b ORDER BY b.id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

def _finding_dict(r):
    return {
        "id":              r["id"],
        "batch_id":        r["batch_id"],
        "title":           r["title"],
        "severity":        r["severity"],
        "description":     r["description"],
        "recommendation":  r["recommendation"],
        "affected_agents": json.loads(r["affected_agents"] or "[]"),
        "rule_ids":        json.loads(r["rule_ids"] or "[]"),
        "batch_time":      r["batch_time"],
        "source":          r.get("batch_source", "live"),
    }

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def spa(path):
    """SPA catch-all: serve a real static file if there is one, else index.html.

    The existence check is left to send_from_directory (which resolves the path
    through Werkzeug's safe_join) rather than done up front with
    os.path.exists(os.path.join(...)). os.path.join is plain string
    concatenation - it happily resolves "../" segments, and discards its first
    argument entirely when the second looks absolute - so the old pre-check ran
    os.path.exists() on paths outside STATIC_DIR. safe_join then refused to
    serve them, but *which branch was taken* still differed, turning this route
    into a boolean "does this file exist on disk" oracle over arbitrary paths
    for any authenticated user (#30).
    """
    if path:
        try:
            return send_from_directory(STATIC_DIR, path)
        except NotFound:
            pass
    return send_from_directory(STATIC_DIR, "index.html")

# ─── Start ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  \033[1mpowered by Aeterna\033[0m")
    print("  \033[0;36mWazuh AI Analyzer – erstellt mithilfe von KI (Claude by Anthropic)\033[0m\n")

    if not GEMINI_API_KEY:
        log.warning("GEMINI_API_KEY nicht gesetzt!")

    init_db()

    # Load (or generate) persistent session secret key AFTER init_db so data dir exists
    app.secret_key = _load_or_create_session_key()

    if not DASHBOARD_PASSWORD_HASH:
        log.warning("DASHBOARD_PASSWORD_HASH nicht gesetzt – Dashboard nicht zugänglich!")
        log.warning("Installer erneut ausführen oder Passwort-Hash manuell setzen:")
        log.warning("  python3 -c \"from werkzeug.security import generate_password_hash; print(generate_password_hash('deinpasswort'))\"")
        log.warning("  Dann DASHBOARD_PASSWORD_HASH=<hash> in /etc/wazuh-ai-analyzer.env eintragen")
    else:
        log.info(f"Login:         User '{DASHBOARD_USER}' | Session-Lifetime: {SESSION_LIFETIME // 3600}h")

    # Whatever was in flight when the previous process died is gone for good:
    # re-queue it instead of leaving it on 'analyzing' forever.
    _requeue_stale(0)

    threading.Thread(target=historical_scan, daemon=True, name="history").start()
    threading.Thread(target=tail_alerts,     daemon=True, name="live").start()
    threading.Thread(target=retry_worker,    daemon=True, name="retry").start()

    log.info(f"Dashboard:     http://{LISTEN_HOST}:{PORT}/login")
    bind_note = "(localhost only – use SSH tunnel or reverse proxy)" if LISTEN_HOST == "127.0.0.1" else "(EXPOSED – ensure only accessible via trusted network/proxy)"
    log.info(f"Bind:          {LISTEN_HOST} {bind_note}")
    log.info(f"Batch:         {BATCH_MAX} Alerts / {BATCH_TIMEOUT}s Timeout | Min-Level: {MIN_LEVEL}")
    log.info(f"History:       {HISTORY_BATCH} Alerts/Batch | {HISTORY_PAUSE}s Pause")
    log.info(f"Infra-Kontext: {INFRA_CONTEXT}")

    if LISTEN_HOST != "127.0.0.1" and not DASHBOARD_PASSWORD_HASH:
        log.warning("SICHERHEIT: Dashboard auf " + LISTEN_HOST + " OHNE Passwort – Zugriff nicht möglich!")

    app.run(host=LISTEN_HOST, port=PORT, debug=False, threaded=True, use_reloader=False)

