"""Typed configuration: defaults, parsing, strict validation, secrets."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from v2.helpers import RecordingEnv
from wazuh_ai_analyzer.config import (
    Config,
    ConfigError,
    DecisionThresholds,
    load_config,
    parse_decision_thresholds,
)

ROOT = Path(__file__).resolve().parents[3]
posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX owners and modes")

Getter = Callable[[Config], Any]

# env name, accessor, default. `LEGACY_ATTR` is the attribute name in analyzer.py.
# The 34 variables of analyzer.py plus the four new ones. GEMINI_MODEL's default is the
# deliberate exception (Q6): the legacy default has been retired by Google.
TABLE: list[tuple[str, Getter, Any]] = [
    ("WAZUH_ALERTS_LOG", lambda c: c.paths.alerts_log, Path("/var/ossec/logs/alerts/alerts.json")),
    ("DB_PATH", lambda c: c.paths.db_path, Path("/opt/wazuh-ai-analyzer/data/analyses.db")),
    ("STATIC_DIR", lambda c: c.paths.static_dir, Path("/opt/wazuh-ai-analyzer/static")),
    ("BATCH_MAX", lambda c: c.batching.batch_max, 25),
    ("BATCH_TIMEOUT", lambda c: c.batching.batch_timeout, 300),
    ("BATCH_TIMEOUT_QUIET", lambda c: c.batching.batch_timeout_quiet, 0),
    ("URGENT_LEVEL", lambda c: c.batching.urgent_level, 10),
    ("MIN_LEVEL", lambda c: c.batching.min_level, 5),
    ("HISTORY_BATCH", lambda c: c.batching.history_batch, 50),
    ("HISTORY_PAUSE", lambda c: c.batching.history_pause, 8.0),
    ("GEMINI_API_KEY", lambda c: c.gemini.api_key, None),
    ("GEMINI_MODEL", lambda c: c.gemini.model, "gemini-3.1-flash-lite"),
    ("GEMINI_TEMPERATURE", lambda c: c.gemini.temperature, 0.15),
    ("GEMINI_CONCURRENCY", lambda c: c.gemini.concurrency, 2),
    ("INFRA_CONTEXT", lambda c: c.gemini.infra_context, "a self-hosted Linux server environment"),
    ("RETRY_BASE_DELAY", lambda c: c.retry.base_delay, 60.0),
    ("RETRY_MAX_DELAY", lambda c: c.retry.max_delay, 3600.0),
    ("RETRY_MAX_AGE_HOURS", lambda c: c.retry.max_age_hours, 72.0),
    ("QUEUE_MAX_AGE_HOURS", lambda c: c.retry.queue_max_age_hours, 72.0),
    ("RETRY_BAD_RESPONSE_MAX", lambda c: c.retry.bad_response_max, 3),
    ("RETRY_POLL", lambda c: c.retry.poll, 30.0),
    ("RETRY_PACE", lambda c: c.retry.pace, 10.0),
    ("STALE_ANALYZING_SECONDS", lambda c: c.retry.stale_analyzing_seconds, 900.0),
    ("RETENTION_DAYS", lambda c: c.retention.days, 0.0),
    ("RETENTION_INTERVAL", lambda c: c.retention.interval, 3600.0),
    ("RETENTION_CHUNK", lambda c: c.retention.chunk, 500),
    ("LISTEN_HOST", lambda c: c.web.listen_host, "127.0.0.1"),
    ("PORT", lambda c: c.web.port, 8765),
    ("DASHBOARD_USER", lambda c: c.web.dashboard_user, "admin"),
    ("DASHBOARD_PASSWORD_HASH", lambda c: c.web.dashboard_password_hash, None),
    ("SESSION_LIFETIME", lambda c: c.web.session_lifetime, 28800),
    ("LOGIN_MAX_ATTEMPTS", lambda c: c.web.login_max_attempts, 5),
    ("TRUSTED_PROXY_HOPS", lambda c: c.web.trusted_proxy_hops, 0),
    ("SESSION_COOKIE_SECURE", lambda c: c.web.session_cookie_secure, True),
    # new in the rewrite
    ("TRUSTED_PROXY_ADDRESSES", lambda c: c.web.trusted_proxy_addresses, ()),
    ("ANALYSIS_MODE", lambda c: c.analysis.mode, "llm"),
    ("DECISION_MODEL", lambda c: c.analysis.decision_model, "gemini-decision-1"),
    ("DECISION_THRESHOLDS", lambda c: c.analysis.decision_thresholds, DecisionThresholds()),
    ("GEMINI_API_KEY_FILE", lambda c: c.gemini.api_key, None),
]
NEW_VARIABLES = {
    "ANALYSIS_MODE",
    "DECISION_MODEL",
    "DECISION_THRESHOLDS",
    "GEMINI_API_KEY_FILE",
    "TRUSTED_PROXY_ADDRESSES",
}
LEGACY_VARIABLES = {name for name, _, _ in TABLE} - NEW_VARIABLES
# Variables that are read through another variable or the systemd credentials directory.
INDIRECT = {"CREDENTIALS_DIRECTORY"}
# analyzer.py names these attributes differently or tests set them before import.
LEGACY_ATTR = {"WAZUH_ALERTS_LOG": "ALERTS_LOG"}
NOT_COMPARABLE_WITH_LEGACY = {
    "WAZUH_ALERTS_LOG",  # tests/conftest.py points these at a scratch dir before importing
    "DB_PATH",
    "STATIC_DIR",
    "GEMINI_API_KEY",
    "GEMINI_MODEL",  # Q6
    "DASHBOARD_PASSWORD_HASH",  # "" in analyzer.py, None here
}


def test_every_variable_is_read_and_nothing_else() -> None:
    env = RecordingEnv()
    load_config(env)
    assert env.looked_up - INDIRECT == {name for name, _, _ in TABLE}


@pytest.mark.parametrize(("name", "getter", "default"), TABLE, ids=[row[0] for row in TABLE])
def test_defaults_without_environment(name: str, getter: Getter, default: Any) -> None:
    value = getter(load_config({}))
    assert value == default
    assert type(value) is type(default)


def test_empty_and_blank_values_mean_default() -> None:
    env = {name: "   " for name, _, _ in TABLE}
    config = load_config(env)
    for name, getter, default in TABLE:
        assert getter(config) == default, name


def test_legacy_variable_set_matches_analyzer_py() -> None:
    source = (ROOT / "analyzer.py").read_text(encoding="utf-8")
    in_analyzer = set(re.findall(r'os\.environ\.get\("([A-Z_]+)"', source))
    assert len(in_analyzer) == 34
    assert in_analyzer == LEGACY_VARIABLES


def test_defaults_equal_the_legacy_defaults() -> None:
    pytest.importorskip("flask")
    import analyzer  # the legacy module; tests/conftest.py isolates its paths

    config = load_config({})
    for name, getter, default in TABLE:
        if name in NEW_VARIABLES or name in NOT_COMPARABLE_WITH_LEGACY:
            continue
        legacy = getattr(analyzer, LEGACY_ATTR.get(name, name))
        assert legacy == default, name
        assert getter(config) == legacy, name


def test_legacy_quiet_timeout_semantics() -> None:
    config = load_config({"BATCH_TIMEOUT": "300", "BATCH_TIMEOUT_QUIET": "900"})
    assert config.batching.effective_quiet_timeout == 900
    assert load_config({"BATCH_TIMEOUT_QUIET": "10"}).batching.effective_quiet_timeout == 300


VALID: list[tuple[str, str, Getter, Any]] = [
    ("WAZUH_ALERTS_LOG", "/tmp/a.json", lambda c: c.paths.alerts_log, Path("/tmp/a.json")),
    ("DB_PATH", "/tmp/x/y.db", lambda c: c.paths.db_path, Path("/tmp/x/y.db")),
    ("BATCH_MAX", "100", lambda c: c.batching.batch_max, 100),
    ("BATCH_MAX", " 7 ", lambda c: c.batching.batch_max, 7),
    ("BATCH_TIMEOUT_QUIET", "900", lambda c: c.batching.batch_timeout_quiet, 900),
    ("MIN_LEVEL", "0", lambda c: c.batching.min_level, 0),
    ("URGENT_LEVEL", "15", lambda c: c.batching.urgent_level, 15),
    ("HISTORY_PAUSE", "0", lambda c: c.batching.history_pause, 0.0),
    ("HISTORY_PAUSE", "2.5", lambda c: c.batching.history_pause, 2.5),
    ("GEMINI_MODEL", "gemini-2.5-flash", lambda c: c.gemini.model, "gemini-2.5-flash"),
    ("GEMINI_TEMPERATURE", "1", lambda c: c.gemini.temperature, 1.0),
    ("GEMINI_CONCURRENCY", "4", lambda c: c.gemini.concurrency, 4),
    ("INFRA_CONTEXT", "Proxmox homelab", lambda c: c.gemini.infra_context, "Proxmox homelab"),
    ("RETRY_BASE_DELAY", "0.5", lambda c: c.retry.base_delay, 0.5),
    ("RETRY_MAX_AGE_HOURS", "1e1", lambda c: c.retry.max_age_hours, 10.0),
    ("RETENTION_DAYS", "180", lambda c: c.retention.days, 180.0),
    ("RETENTION_CHUNK", "1", lambda c: c.retention.chunk, 1),
    ("LISTEN_HOST", "0.0.0.0", lambda c: c.web.listen_host, "0.0.0.0"),  # noqa: S104
    ("LISTEN_HOST", "::1", lambda c: c.web.listen_host, "::1"),
    ("LISTEN_HOST", "dashboard.internal", lambda c: c.web.listen_host, "dashboard.internal"),
    ("PORT", "65535", lambda c: c.web.port, 65535),
    ("DASHBOARD_USER", "  alice  ", lambda c: c.web.dashboard_user, "alice"),
    ("TRUSTED_PROXY_HOPS", "1", lambda c: c.web.trusted_proxy_hops, 1),
    ("SESSION_COOKIE_SECURE", "false", lambda c: c.web.session_cookie_secure, False),
    ("SESSION_COOKIE_SECURE", " NO ", lambda c: c.web.session_cookie_secure, False),
    ("SESSION_COOKIE_SECURE", "0", lambda c: c.web.session_cookie_secure, False),
    ("SESSION_COOKIE_SECURE", "True", lambda c: c.web.session_cookie_secure, True),
    ("ANALYSIS_MODE", "decision", lambda c: c.analysis.mode, "decision"),
    ("ANALYSIS_MODE", "LLM", lambda c: c.analysis.mode, "llm"),
    (
        "DECISION_MODEL",
        "gemini-decision-2",
        lambda c: c.analysis.decision_model,
        "gemini-decision-2",
    ),
]


@pytest.mark.parametrize(("name", "raw", "getter", "expected"), VALID)
def test_valid_values(name: str, raw: str, getter: Getter, expected: Any) -> None:
    value = getter(load_config({name: raw}))
    assert value == expected
    assert type(value) is type(expected)


INVALID: list[tuple[str, str]] = [
    ("BATCH_MAX", "abc"),
    ("BATCH_MAX", "0"),
    ("BATCH_MAX", "-1"),
    ("BATCH_MAX", "1.5"),
    ("BATCH_MAX", "1_000"),
    ("BATCH_MAX", "10001"),
    ("BATCH_TIMEOUT", "0"),
    ("BATCH_TIMEOUT_QUIET", "-5"),
    ("URGENT_LEVEL", "16"),
    ("MIN_LEVEL", "-1"),
    ("HISTORY_BATCH", "0"),
    ("HISTORY_PAUSE", "-1"),
    ("HISTORY_PAUSE", "nan"),
    ("HISTORY_PAUSE", "inf"),
    ("HISTORY_PAUSE", "1_0"),
    ("GEMINI_MODEL", "models/gemini"),
    ("GEMINI_MODEL", "a b"),
    ("GEMINI_MODEL", "x?key=1"),
    ("GEMINI_TEMPERATURE", "2.5"),
    ("GEMINI_TEMPERATURE", "-0.1"),
    ("GEMINI_CONCURRENCY", "0"),
    ("INFRA_CONTEXT", "line one\nline two"),
    ("INFRA_CONTEXT", "x" * 2001),
    ("RETRY_BASE_DELAY", "0"),
    ("RETRY_POLL", "0"),
    ("RETRY_PACE", "-1"),
    ("RETRY_BAD_RESPONSE_MAX", "0"),
    ("STALE_ANALYZING_SECONDS", "0"),
    ("QUEUE_MAX_AGE_HOURS", "-1"),
    ("RETENTION_DAYS", "-1"),
    ("RETENTION_INTERVAL", "0"),
    ("RETENTION_CHUNK", "0"),
    ("LISTEN_HOST", "not a host"),
    ("LISTEN_HOST", "http://x"),
    ("PORT", "0"),
    ("PORT", "65536"),
    ("PORT", "http"),
    ("DASHBOARD_USER", "x" * 129),
    ("DASHBOARD_USER", "bad\x07user"),
    ("DASHBOARD_PASSWORD_HASH", "plaintext-password"),
    ("DASHBOARD_PASSWORD_HASH", "a$b"),
    ("SESSION_LIFETIME", "59"),
    ("LOGIN_MAX_ATTEMPTS", "0"),
    ("TRUSTED_PROXY_HOPS", "-1"),
    ("TRUSTED_PROXY_HOPS", "11"),
    ("SESSION_COOKIE_SECURE", "off"),  # the legacy parser read this as true
    ("SESSION_COOKIE_SECURE", "disabled"),
    ("ANALYSIS_MODE", "hybrid"),
    ("DECISION_MODEL", "../x"),
    ("DECISION_THRESHOLDS", "critical"),
    ("DECISION_THRESHOLDS", "bogus=0.5"),
    ("DECISION_THRESHOLDS", "high=2"),
    ("DECISION_THRESHOLDS", "high=0"),
    ("DECISION_THRESHOLDS", "high=0.5,high=0.6"),
    ("DECISION_THRESHOLDS", "high=abc"),
    ("WAZUH_ALERTS_LOG", "a\x00b"),
    ("GEMINI_API_KEY", "key with spaces"),
    ("GEMINI_API_KEY", "ключ"),
    ("GEMINI_API_KEY", "x" * 513),
]


@pytest.mark.parametrize(("name", "raw"), INVALID, ids=[f"{n}={r[:12]!r}" for n, r in INVALID])
def test_invalid_values_are_rejected_without_echoing_them(name: str, raw: str) -> None:
    with pytest.raises(ConfigError) as info:
        load_config({name: raw})
    message = str(info.value)
    assert any(p.startswith(f"{name}:") or p.startswith(f"{name} ") for p in info.value.problems)
    # Short values ("0") legitimately appear in the range text of the message.
    if len(raw) > 8:
        assert raw not in message


def test_all_problems_are_reported_at_once() -> None:
    with pytest.raises(ConfigError) as info:
        load_config({"BATCH_MAX": "x", "PORT": "0", "ANALYSIS_MODE": "nope"})
    assert len(info.value.problems) == 3


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost", "LocalHost"])
def test_a_proxy_in_front_is_fine_on_a_loopback_bind(host: str) -> None:
    config = load_config({"TRUSTED_PROXY_HOPS": "1", "LISTEN_HOST": host})
    assert config.web.trusted_proxy_hops == 1


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.0.10", "::", "dashboard.internal"])  # noqa: S104
def test_trusted_proxy_hops_need_a_loopback_bind_or_proxy_addresses(host: str) -> None:
    with pytest.raises(ConfigError, match="TRUSTED_PROXY_HOPS") as info:
        load_config({"TRUSTED_PROXY_HOPS": "1", "LISTEN_HOST": host})
    assert "TRUSTED_PROXY_ADDRESSES" in str(info.value)
    # without a proxy in front the bind address does not matter
    assert load_config({"LISTEN_HOST": host}).web.trusted_proxy_hops == 0


def test_trusted_proxy_addresses_allow_a_public_bind() -> None:
    config = load_config(
        {
            "TRUSTED_PROXY_HOPS": "1",
            "LISTEN_HOST": "192.168.0.10",
            "TRUSTED_PROXY_ADDRESSES": " 192.168.0.5 , 10.0.0.0/8,::1 ",
        }
    )
    assert [str(n) for n in config.web.trusted_proxy_addresses] == [
        "192.168.0.5/32",
        "10.0.0.0/8",
        "::1/128",
    ]


@pytest.mark.parametrize("raw", ["not-an-ip", "10.0.0.5, nope", "10.0.0.0/33"])
def test_invalid_trusted_proxy_addresses_are_rejected(raw: str) -> None:
    with pytest.raises(ConfigError, match="TRUSTED_PROXY_ADDRESSES"):
        load_config({"TRUSTED_PROXY_ADDRESSES": raw})


def test_retry_delay_order_is_checked() -> None:
    with pytest.raises(ConfigError, match="RETRY_MAX_DELAY"):
        load_config({"RETRY_BASE_DELAY": "100", "RETRY_MAX_DELAY": "10"})


def test_password_hash_is_a_secret() -> None:
    hashed = "scrypt:32768:8:1$salt1234$" + "ab" * 32
    config = load_config({"DASHBOARD_PASSWORD_HASH": hashed})
    assert config.web.dashboard_password_hash is not None
    assert config.web.dashboard_password_hash.reveal() == hashed
    assert hashed not in repr(config)
    assert hashed in config.secret_values()


def test_repr_never_contains_secrets() -> None:
    key = "dummy-config-secret-0001"
    hashed = "pbkdf2:sha256:600000$abcdefgh$" + "cd" * 32
    config = load_config({"GEMINI_API_KEY": key, "DASHBOARD_PASSWORD_HASH": hashed})
    for text in (repr(config), str(config), f"{config!r}", repr(config.gemini), repr(config.web)):
        assert key not in text
        assert hashed not in text
    assert "***" in repr(config)
    assert config.require_api_key().reveal() == key


def test_config_is_frozen() -> None:
    config = load_config({})
    with pytest.raises(AttributeError):
        config.paths = config.paths  # type: ignore[misc]


def test_derived_paths_sit_next_to_the_database() -> None:
    config = load_config({"DB_PATH": "/srv/data/analyses.db"})
    assert config.paths.data_dir == Path("/srv/data")
    assert config.paths.watermark_file == Path("/srv/data/watermark.json")
    assert config.paths.session_key_file == Path("/srv/data/session.key")


# ── API key sources ──────────────────────────────────────────────────────────
KEY = "dummy-file-secret-0002"


def _key_file(tmp_path: Path, content: str = KEY + "\n", mode: int = 0o600) -> Path:
    path = tmp_path / "gemini.key"
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return path


def test_no_key_is_allowed_but_can_be_required() -> None:
    config = load_config({})
    assert config.gemini.api_key is None
    with pytest.raises(ConfigError, match="no Gemini API key"):
        config.require_api_key()


def test_key_from_environment_is_stripped() -> None:
    config = load_config({"GEMINI_API_KEY": f"  {KEY}\n"})
    assert config.require_api_key().reveal() == KEY


@posix_only
def test_key_from_file(tmp_path: Path) -> None:
    config = load_config({"GEMINI_API_KEY_FILE": str(_key_file(tmp_path))})
    assert config.require_api_key().reveal() == KEY


@posix_only
def test_environment_key_wins_over_the_file(tmp_path: Path) -> None:
    config = load_config(
        {"GEMINI_API_KEY": "env-key", "GEMINI_API_KEY_FILE": str(_key_file(tmp_path))}
    )
    assert config.require_api_key().reveal() == "env-key"


@posix_only
def test_key_file_wins_over_the_credentials_directory(tmp_path: Path) -> None:
    creds = tmp_path / "creds"
    creds.mkdir(mode=0o700)
    (creds / "gemini").write_text("cred-key", encoding="utf-8")
    (creds / "gemini").chmod(0o400)
    env = {"GEMINI_API_KEY_FILE": str(_key_file(tmp_path)), "CREDENTIALS_DIRECTORY": str(creds)}
    assert load_config(env).require_api_key().reveal() == KEY


@posix_only
def test_key_from_systemd_credential(tmp_path: Path) -> None:
    creds = tmp_path / "creds"
    creds.mkdir(mode=0o700)
    (creds / "gemini").write_text("cred-key\n", encoding="utf-8")
    (creds / "gemini").chmod(0o400)
    config = load_config({"CREDENTIALS_DIRECTORY": str(creds)})
    assert config.require_api_key().reveal() == "cred-key"


@posix_only
def test_root_owned_systemd_credential_with_acl_mask_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # What systemd leaves behind when it cannot chown the credential (ACL fallback).
    creds = tmp_path / "creds"
    creds.mkdir(mode=0o700)
    (creds / "gemini").write_text("cred-key\n", encoding="utf-8")
    (creds / "gemini").chmod(0o400)
    real_fstat = os.fstat

    def fake(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        fields = list(info)
        if not stat.S_ISREG(info.st_mode):
            fields[stat.ST_UID] = 0  # the credentials directory: private, owned by root
            return os.stat_result(fields)
        fields[stat.ST_UID] = 0
        fields[stat.ST_MODE] = stat.S_IFREG | 0o440
        return os.stat_result(fields)

    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    monkeypatch.setattr(os, "fstat", fake)
    assert load_config({"CREDENTIALS_DIRECTORY": str(creds)}).require_api_key().reveal() == (
        "cred-key"
    )


def test_credentials_directory_without_gemini_credential_means_no_key(tmp_path: Path) -> None:
    assert load_config({"CREDENTIALS_DIRECTORY": str(tmp_path)}).gemini.api_key is None


@posix_only
def test_permissive_key_file_refuses_to_start(tmp_path: Path) -> None:
    path = _key_file(tmp_path, mode=0o644)
    with pytest.raises(ConfigError, match="too permissive") as info:
        load_config({"GEMINI_API_KEY_FILE": str(path)})
    assert KEY not in str(info.value)


def test_missing_and_empty_key_files_refuse_to_start(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        load_config({"GEMINI_API_KEY_FILE": str(tmp_path / "nope")})
    if os.name == "posix":
        with pytest.raises(ConfigError, match="empty"):
            load_config({"GEMINI_API_KEY_FILE": str(_key_file(tmp_path, content="\n"))})


@posix_only
def test_key_file_with_garbage_refuses_to_start(tmp_path: Path) -> None:
    path = _key_file(tmp_path, content="two words\n")
    with pytest.raises(ConfigError, match="not a valid API key") as info:
        load_config({"GEMINI_API_KEY_FILE": str(path)})
    assert "two words" not in str(info.value)


# ── decision thresholds ──────────────────────────────────────────────────────
def test_threshold_defaults_and_overrides() -> None:
    defaults = DecisionThresholds()
    assert (defaults.critical, defaults.high, defaults.medium, defaults.low, defaults.info) == (
        0.3,
        0.5,
        0.6,
        0.7,
        None,
    )
    parsed = parse_decision_thresholds("critical=0.1, high=0.4,info=0.9,low=never,")
    assert parsed.critical == 0.1
    assert parsed.high == 0.4
    assert parsed.medium == 0.6  # unlisted: default
    assert parsed.low is None
    assert parsed.info == 0.9
    assert parsed.for_severity("high") == 0.4
    with pytest.raises(ValueError, match="unknown severity"):
        parsed.for_severity("catastrophic")


def test_thresholds_from_environment() -> None:
    config = load_config({"DECISION_THRESHOLDS": "high=0.45"})
    assert config.analysis.decision_thresholds.high == 0.45
