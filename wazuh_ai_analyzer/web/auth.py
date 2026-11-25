"""Login checks: credentials, the bounded rate limiter, redirect targets, CSRF tokens.

* Credentials: one user from `DASHBOARD_USER` / `DASHBOARD_PASSWORD_HASH` (the
  Werkzeug hash format, so existing hashes keep working). The password hash is
  verified on *every* attempt, also for an unknown user name, so the response time
  does not tell a valid user name from an invalid one. Names are compared in
  constant time.
* `LoginLimiter`: failed attempts per client in a sliding window, with state that
  cannot grow without limit: at most `max_tracked` clients (least recently used
  ones are dropped first) and every entry expires with its window.
* `safe_next_path`: the post-login redirect target is a local path or `/`.
* CSRF: a per-session token (stored with the session) and, before a session exists,
  a login token bound to a random pre-session cookie by an HMAC with `session.key`.
  Both are compared in constant time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import logging
import math
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from typing import Final
from urllib.parse import urlsplit

from werkzeug.security import check_password_hash

log = logging.getLogger(__name__)

USERNAME_MAX: Final = 128
PASSWORD_MAX: Final = 1024
LOGIN_WINDOW_SECONDS: Final = 60.0
# Enough for any real client population; a spray of addresses just evicts the oldest.
MAX_TRACKED_CLIENTS: Final = 4096
UNKNOWN_CLIENT: Final = "unknown"


# ── credentials ──────────────────────────────────────────────────────────────
def verify_credentials(
    username: str, password: str, *, expected_user: str, password_hash: str
) -> bool:
    """True only for the configured user with the right password.

    The hash check always runs, so a wrong user name costs the same as a wrong password.
    """
    user_ok = hmac.compare_digest(
        username.encode("utf-8", "surrogatepass"), expected_user.encode("utf-8", "surrogatepass")
    )
    try:
        password_ok = check_password_hash(password_hash, password)
    except (ValueError, TypeError, OverflowError):
        # An unsupported hash method or a corrupt hash: nobody can log in.
        log.error("DASHBOARD_PASSWORD_HASH cannot be verified (unsupported or corrupt hash)")
        password_ok = False
    return user_ok and password_ok


# ── rate limit ───────────────────────────────────────────────────────────────
def client_key(remote_addr: str | None) -> str:
    """The rate limit bucket of a client address.

    An IPv6 address is reduced to its /64 (one subscriber owns a whole /64, so
    rotating inside it must not buy a fresh budget), an IPv4-mapped IPv6 address to
    its IPv4 address. Anything that is not an address shares one bucket.
    """
    if not remote_addr:
        return UNKNOWN_CLIENT
    try:
        address = ipaddress.ip_address(remote_addr)
    except ValueError:
        return UNKNOWN_CLIENT
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


class LoginLimiter:
    """At most `max_attempts` failed logins per client in a sliding window."""

    def __init__(
        self,
        max_attempts: int,
        *,
        window: float = LOGIN_WINDOW_SECONDS,
        max_tracked: int = MAX_TRACKED_CLIENTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_attempts < 1 or max_tracked < 1 or window <= 0:
            raise ValueError("max_attempts, max_tracked and window must be positive")
        self._max = max_attempts
        self._window = window
        self._max_tracked = max_tracked
        self._clock = clock
        self._lock = threading.Lock()
        # client -> failure times (at most `max_attempts`), least recently updated first
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()

    def __len__(self) -> int:
        with self._lock:
            return len(self._failures)

    def _expire(self, now: float) -> None:
        # Entries are ordered by their last update, so the oldest sit at the front
        # and the sweep stops at the first one that is still inside its window.
        while self._failures:
            oldest_key = next(iter(self._failures))
            if now - self._failures[oldest_key][-1] < self._window:
                break
            del self._failures[oldest_key]

    def retry_after(self, client: str) -> int:
        """0 if the client may try, else the whole seconds until it may."""
        now = self._clock()
        with self._lock:
            self._expire(now)
            attempts = self._failures.get(client)
            if attempts is None:
                return 0
            recent = [t for t in attempts if now - t < self._window]
            if len(recent) < self._max:
                return 0
            return max(1, math.ceil(self._window - (now - recent[0])))

    def try_acquire(self, client: str) -> int:
        """Atomically check the limit and count one attempt (0 = go ahead).

        The attempt is counted *before* the slow password check, so parallel requests of
        one client cannot all pass the check first. A successful login gives it back
        with `clear`.
        """
        now = self._clock()
        with self._lock:
            self._expire(now)
            attempts = self._failures.pop(client, None)
            if attempts is None:
                attempts = deque(maxlen=self._max)
            recent = [t for t in attempts if now - t < self._window]
            if len(recent) >= self._max:
                self._failures[client] = attempts
                return max(1, math.ceil(self._window - (now - recent[0])))
            attempts.append(now)
            self._failures[client] = attempts
            while len(self._failures) > self._max_tracked:
                self._failures.popitem(last=False)
            return 0

    def remaining(self, client: str) -> int:
        now = self._clock()
        with self._lock:
            attempts = self._failures.get(client)
            used = 0 if attempts is None else sum(1 for t in attempts if now - t < self._window)
        return max(0, self._max - used)

    def record_failure(self, client: str) -> None:
        now = self._clock()
        with self._lock:
            self._expire(now)
            attempts = self._failures.pop(client, None)
            if attempts is None:
                attempts = deque(maxlen=self._max)
            attempts.append(now)
            self._failures[client] = attempts
            while len(self._failures) > self._max_tracked:
                self._failures.popitem(last=False)

    def clear(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)


# ── redirect target ──────────────────────────────────────────────────────────
def safe_next_path(next_url: str | None) -> str:
    """Only a local, relative redirect target (the `next` of the login) is allowed.

    A leading "/" alone is not enough: "//evil.example" and "/\\evil.example" are
    scheme-relative URLs that browsers resolve to another host. Control characters
    (header and URL smuggling), backslashes and anything with a scheme or host fall
    back to "/".
    """
    if not next_url or len(next_url) > 2048:
        return "/"
    if not next_url.startswith("/") or next_url.startswith(("//", "/\\")):
        return "/"
    if "\\" in next_url or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in next_url):
        return "/"
    try:
        parsed = urlsplit(next_url)
    except ValueError:
        return "/"
    if parsed.scheme or parsed.netloc or parsed.path.startswith("//"):
        return "/"
    return next_url


# ── CSRF ─────────────────────────────────────────────────────────────────────
_PRE_SESSION_RE: Final = re.compile(r"^[A-Za-z0-9_-]{43}$")


def new_pre_session_value() -> str:
    return secrets.token_urlsafe(32)


def is_pre_session_value(value: str | None) -> bool:
    return value is not None and _PRE_SESSION_RE.match(value) is not None


def login_csrf_token(key: bytes, pre_session_value: str) -> str:
    """The login CSRF token that belongs to a pre-session cookie value."""
    mac = hmac.new(key, b"login-csrf:" + pre_session_value.encode("ascii"), hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).decode("ascii").rstrip("=")


def tokens_match(expected: str, presented: str | None) -> bool:
    """Constant-time comparison; a missing token never matches."""
    if not presented or not expected:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), presented.encode("utf-8", "replace"))


def origin_allowed(*, host: str, origin: str | None, sec_fetch_site: str | None) -> bool:
    """Same-origin check for state-changing requests.

    `Sec-Fetch-Site`, when the browser sends it, must say `same-origin` (or `none`:
    typed into the address bar). `Origin`, when present, must name this host (the
    scheme is not compared: behind a TLS-terminating proxy the app sees http while
    the browser says https). A request with neither header comes from a client that
    is not a browser; it still has to present the CSRF token.
    """
    if sec_fetch_site is not None and sec_fetch_site.lower() not in ("same-origin", "none"):
        return False
    if origin is None:
        return True
    if origin.lower() == "null":
        return False
    try:
        parts = urlsplit(origin)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.path not in ("", "/"):
        return False
    return parts.netloc.lower() == host.lower()
