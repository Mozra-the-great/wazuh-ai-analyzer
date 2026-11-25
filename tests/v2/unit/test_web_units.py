"""Units of the web layer: rate limiter, redirect targets, origin check, CSP, sessions, key file."""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest

from v2.helpers import FakeClock
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.web import sessions as sessions_module
from wazuh_ai_analyzer.web.app import (
    FINDINGS_MAX_LIMIT,
    OFFSET_MAX,
    _BadRequest,
    parse_findings_query,
)
from wazuh_ai_analyzer.web.auth import (
    LoginLimiter,
    client_key,
    login_csrf_token,
    new_pre_session_value,
    origin_allowed,
    safe_next_path,
    tokens_match,
    verify_credentials,
)
from wazuh_ai_analyzer.web.headers import build_csp, security_headers
from wazuh_ai_analyzer.web.sessions import (
    MAX_SESSIONS,
    SessionKeyError,
    SessionStore,
    load_or_create_session_key,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="owners, modes and symlinks are POSIX")


# ── rate limiter ─────────────────────────────────────────────────────────────
def test_limiter_blocks_after_max_attempts_and_releases_after_the_window() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(3, window=60, clock=clock)
    for _ in range(3):
        assert limiter.retry_after("a") == 0
        limiter.record_failure("a")
    assert 1 <= limiter.retry_after("a") <= 60
    assert limiter.remaining("a") == 0
    clock.advance(30)
    assert limiter.retry_after("a") > 0
    clock.advance(31)
    assert limiter.retry_after("a") == 0
    assert limiter.remaining("a") == 3


def test_limiter_window_slides_with_each_failure() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(2, window=60, clock=clock)
    limiter.record_failure("a")
    clock.advance(40)
    limiter.record_failure("a")
    assert limiter.retry_after("a") > 0
    clock.advance(21)  # the first failure is out of the window
    assert limiter.retry_after("a") == 0


def test_limiter_state_is_bounded_under_a_spray_of_addresses() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(5, max_tracked=100, clock=clock)
    for n in range(10_000):
        limiter.record_failure(f"10.{n // 256 % 256}.{n % 256}.{n // 65536}")
        assert len(limiter) <= 100
    assert len(limiter) == 100


def test_limiter_drops_the_least_recently_used_client_first() -> None:
    limiter = LoginLimiter(2, max_tracked=3, clock=FakeClock())
    for name in ("a", "b", "c"):
        limiter.record_failure(name)
    limiter.record_failure("a")  # a is now the most recent
    limiter.record_failure("d")  # evicts b, the oldest
    assert limiter.remaining("b") == 2
    assert limiter.remaining("a") == 0
    assert limiter.remaining("c") == 1
    assert len(limiter) == 3


def test_limiter_entries_expire_and_are_swept() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(5, window=60, clock=clock)
    for n in range(50):
        limiter.record_failure(f"client-{n}")
    clock.advance(61)
    limiter.record_failure("fresh")  # any call sweeps the expired entries
    assert len(limiter) == 1


def test_limiter_keeps_at_most_max_attempts_timestamps_per_client() -> None:
    limiter = LoginLimiter(3, clock=FakeClock())
    for _ in range(1000):
        limiter.record_failure("a")
    assert limiter.remaining("a") == 0
    assert len(limiter._failures["a"]) == 3


def test_limiter_clear_and_validation() -> None:
    limiter = LoginLimiter(1, clock=FakeClock())
    limiter.record_failure("a")
    limiter.clear("a")
    limiter.clear("never-seen")
    assert limiter.retry_after("a") == 0
    invalid = (
        {"max_attempts": 0},
        {"max_attempts": 1, "max_tracked": 0},
        {"max_attempts": 1, "window": 0},
    )
    for bad in invalid:
        with pytest.raises(ValueError, match="positive"):
            LoginLimiter(**bad)  # type: ignore[arg-type]


def test_limiter_is_thread_safe() -> None:
    limiter = LoginLimiter(10, max_tracked=50)

    def hammer(seed: int) -> None:
        for n in range(500):
            limiter.record_failure(f"{seed}-{n % 80}")
            limiter.retry_after(f"{seed}-{n % 80}")

    threads = [threading.Thread(target=hammer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(limiter) <= 50


@pytest.mark.parametrize(
    ("address", "key"),
    [
        ("203.0.113.9", "203.0.113.9"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
        ("not-an-address", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_client_key(address: str | None, key: str) -> None:
    assert client_key(address) == key


# ── credentials ──────────────────────────────────────────────────────────────
def test_verify_credentials_needs_both_and_survives_a_corrupt_hash() -> None:
    from v2.web_support import PASSWORD, USER, password_hash

    stored = password_hash()
    assert verify_credentials(USER, PASSWORD, expected_user=USER, password_hash=stored)
    assert not verify_credentials(USER, "x", expected_user=USER, password_hash=stored)
    assert not verify_credentials("x", PASSWORD, expected_user=USER, password_hash=stored)
    assert not verify_credentials(USER, PASSWORD, expected_user=USER, password_hash="bogus$a$b")
    assert not verify_credentials(USER, PASSWORD, expected_user=USER, password_hash="md5:1$a$b")
    # lone surrogates in a user name must not raise
    assert not verify_credentials("\ud800", PASSWORD, expected_user=USER, password_hash=stored)


# ── redirect targets ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "/"),
        ("/", "/"),
        ("/findings/12?severity=high", "/findings/12?severity=high"),
        ("//evil.example/x", "/"),
        ("/\\evil.example", "/"),
        ("/a\\b", "/"),
        ("http://evil.example", "/"),
        ("https:evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("evil.example", "/"),
        ("/\t/evil.example", "/"),
        ("/\n", "/"),
        ("/x\x00", "/"),
        ("/" + "a" * 3000, "/"),
    ],
)
def test_safe_next_path(value: str | None, expected: str) -> None:
    assert safe_next_path(value) == expected


# ── origin check ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("origin", "site", "allowed"),
    [
        (None, None, True),  # not a browser: the token still has to match
        ("https://dash.test", None, True),
        ("http://dash.test", None, True),  # scheme is not compared (TLS proxy)
        ("https://DASH.test", None, True),
        ("https://dash.test", "same-origin", True),
        (None, "none", True),
        ("https://evil.test", None, False),
        ("https://dash.test.evil.test", None, False),
        ("https://dash.test:8443", None, False),
        ("https://dash.test/path", None, False),
        ("null", None, False),
        ("ftp://dash.test", None, False),
        ("https://", None, False),
        ("https://[::1", None, False),
        (None, "cross-site", False),
        (None, "same-site", False),
        ("https://dash.test", "cross-site", False),
    ],
)
def test_origin_allowed(origin: str | None, site: str | None, allowed: bool) -> None:
    assert origin_allowed(host="dash.test", origin=origin, sec_fetch_site=site) is allowed


# ── csrf tokens ──────────────────────────────────────────────────────────────
def test_login_tokens_depend_on_the_key_and_the_cookie_value() -> None:
    value = new_pre_session_value()
    token = login_csrf_token(b"a" * 64, value)
    assert token == login_csrf_token(b"a" * 64, value)
    assert token != login_csrf_token(b"b" * 64, value)
    assert token != login_csrf_token(b"a" * 64, new_pre_session_value())


def test_tokens_match_is_strict() -> None:
    assert tokens_match("abc", "abc")
    assert not tokens_match("abc", "abd")
    assert not tokens_match("abc", None)
    assert not tokens_match("abc", "")
    assert not tokens_match("", "")
    assert not tokens_match("abc", "abc ")
    assert not tokens_match("abc", "\udcff")


# ── headers ──────────────────────────────────────────────────────────────────
def test_csp_is_strict_and_accepts_only_well_formed_script_hashes() -> None:
    csp = build_csp()
    assert csp.startswith("default-src 'self'; script-src 'self'; style-src 'self'")
    for directive in (
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
    ):
        assert directive in csp
    assert "unsafe" not in csp
    digest = "sha256-" + "A" * 43 + "="
    assert f"script-src 'self' '{digest}'" in build_csp([digest])
    for bad in ("sha256-short", "'unsafe-inline'", "sha256-" + "A" * 43 + "=; script-src *"):
        with pytest.raises(ValueError, match="sha256"):
            build_csp([bad])


def test_hsts_only_when_the_cookie_is_secure() -> None:
    assert "Strict-Transport-Security" in security_headers(csp="x", hsts=True)
    assert "Strict-Transport-Security" not in security_headers(csp="x", hsts=False)


# ── query validation ─────────────────────────────────────────────────────────
def test_parse_findings_query_defaults_and_clamps() -> None:
    assert parse_findings_query({}) == (50, 0, None, None)
    assert parse_findings_query({"limit": "", "offset": "", "severity": "", "source": ""}) == (
        50,
        0,
        None,
        None,
    )
    assert parse_findings_query({"limit": "1"})[0] == 1
    assert parse_findings_query({"limit": "9999"})[0] == FINDINGS_MAX_LIMIT
    assert parse_findings_query({"offset": str(10**17)})[1] == OFFSET_MAX
    filtered = parse_findings_query({"severity": "low", "source": "history"})
    assert filtered == (50, 0, "low", "history")


@pytest.mark.parametrize(
    "args",
    [
        {"limit": "-1"},
        {"limit": "0"},
        {"limit": "x"},
        {"limit": "1.0"},
        {"limit": "١٢"},  # non-ASCII digits
        {"limit": "9" * 19},
        {"offset": "-1"},
        {"offset": "0x10"},
        {"severity": "HIGH"},
        {"severity": "high "},
        {"source": "LIVE"},
    ],
)
def test_parse_findings_query_rejects(args: dict[str, str]) -> None:
    with pytest.raises(_BadRequest):
        parse_findings_query(args)


# ── session store ────────────────────────────────────────────────────────────
@pytest.fixture
def store(database: Database, clock: FakeClock) -> SessionStore:
    return SessionStore(database, lifetime=600, clock=clock)


def test_create_and_lookup(store: SessionStore, clock: FakeClock) -> None:
    issued = store.create("admin")
    found = store.lookup(issued.session_id)
    assert found is not None
    assert found.username == "admin"
    assert found.csrf_token == issued.csrf_token
    assert found.expires_at == clock() + 600
    assert issued.session_id != issued.csrf_token
    assert len(issued.session_id) == 43


def test_every_session_gets_a_new_id_and_token(store: SessionStore) -> None:
    first, second = store.create("admin"), store.create("admin")
    assert first.session_id != second.session_id
    assert first.csrf_token != second.csrf_token


def test_lookup_rejects_unknown_expired_and_malformed(
    store: SessionStore, clock: FakeClock
) -> None:
    issued = store.create("admin")
    assert store.lookup(None) is None
    assert store.lookup("") is None
    assert store.lookup("A" * 43) is None
    assert store.lookup(issued.session_id + "x") is None
    assert store.lookup(issued.session_id.replace(issued.session_id[0], "!", 1)) is None
    clock.advance(601)
    assert store.lookup(issued.session_id) is None
    assert store.count() == 0


def test_delete_is_idempotent_and_tolerates_junk(store: SessionStore) -> None:
    issued = store.create("admin")
    store.delete(issued.session_id)
    store.delete(issued.session_id)
    store.delete(None)
    store.delete("junk")
    assert store.lookup(issued.session_id) is None


def test_the_table_stays_small_and_expired_rows_are_pruned(
    store: SessionStore, clock: FakeClock
) -> None:
    first = store.create("admin")
    for _ in range(MAX_SESSIONS + 20):
        clock.advance(1)
        store.create("admin")
    assert store.count() == MAX_SESSIONS
    assert store.lookup(first.session_id) is None  # the oldest went first
    clock.advance(10_000)
    store.create("admin")
    assert store.count() == 1  # everything else had expired


# ── session.key ──────────────────────────────────────────────────────────────
def test_the_key_is_created_once_and_reused(tmp_path: Path) -> None:
    path = tmp_path / "data" / "session.key"
    key = load_or_create_session_key(path)
    assert len(key) == 64
    assert load_or_create_session_key(path) == key
    assert path.read_bytes() == key


@posix_only
def test_a_new_key_file_is_0600(tmp_path: Path) -> None:
    path = tmp_path / "session.key"
    load_or_create_session_key(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@posix_only
def test_an_existing_key_keeps_its_content_and_is_healed_to_0600(tmp_path: Path) -> None:
    path = tmp_path / "session.key"
    path.write_bytes(b"k" * 64)
    path.chmod(0o644)
    assert load_or_create_session_key(path) == b"k" * 64
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@posix_only
def test_a_symlink_in_place_of_the_key_is_never_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"t" * 64)
    path = tmp_path / "session.key"
    path.symlink_to(target)
    with pytest.raises(SessionKeyError):
        load_or_create_session_key(path)
    assert target.read_bytes() == b"t" * 64


@posix_only
def test_a_dangling_symlink_is_not_created_through(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    path = tmp_path / "session.key"
    path.symlink_to(victim)
    with pytest.raises(SessionKeyError):
        load_or_create_session_key(path)
    assert not victim.exists()


def test_an_unusable_key_file_is_replaced(tmp_path: Path) -> None:
    path = tmp_path / "session.key"
    path.write_bytes(b"short")
    key = load_or_create_session_key(path)
    assert len(key) == 64
    assert path.read_bytes() == key
    empty = tmp_path / "empty.key"
    empty.write_bytes(b"")
    assert len(load_or_create_session_key(empty)) == 64


def test_a_directory_is_not_a_key(tmp_path: Path) -> None:
    path = tmp_path / "session.key"
    path.mkdir()
    with pytest.raises(SessionKeyError):
        load_or_create_session_key(path)


def test_creation_is_exclusive_when_another_process_wins_the_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "session.key"
    real_read = sessions_module._read_key
    calls = {"n": 0}

    def racing_read(p: Path) -> bytes | None:
        calls["n"] += 1
        if calls["n"] == 1:
            p.write_bytes(b"w" * 64)  # the other process creates the file after our check
            return None
        return real_read(p)

    monkeypatch.setattr(sessions_module, "_read_key", racing_read)
    assert load_or_create_session_key(path) == b"w" * 64  # ours did not overwrite it
    assert path.read_bytes() == b"w" * 64


def test_try_acquire_lets_exactly_max_attempts_through_under_concurrency() -> None:
    limiter = LoginLimiter(5, clock=FakeClock())
    passed: list[int] = []
    lock = threading.Lock()

    def attempt() -> None:
        if limiter.try_acquire("same-client") == 0:
            with lock:
                passed.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(passed) == 5
    assert limiter.try_acquire("same-client") >= 1
    limiter.clear("same-client")
    assert limiter.try_acquire("same-client") == 0


def test_try_acquire_keeps_state_bounded() -> None:
    limiter = LoginLimiter(2, max_tracked=10, clock=FakeClock())
    for n in range(1000):
        limiter.try_acquire(f"c{n}")
    assert len(limiter) == 10
