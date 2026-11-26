"""Typed, strictly validated configuration.

One frozen `Config` is built from the environment once, at startup. Every
environment variable of the legacy `analyzer.py` keeps its name and default (C1),
so existing env files work unchanged. The exceptions are listed in
`docs/configuration.md`.

Rules:

* A wrong type, an out-of-range value, an unknown mode or an unusable key file is
  a `ConfigError` that names every offending variable (never its value, as it may
  be a secret put into the wrong variable). There is no silent fallback to a default.
* An unset or empty variable means "use the default".
* Secrets (API key, password hash) are held in `Secret`, whose `repr` is `***`.
* The API key comes from `GEMINI_API_KEY`, else `GEMINI_API_KEY_FILE`, else
  `$CREDENTIALS_DIRECTORY/gemini` (systemd `LoadCredential`), in that order. A key
  file must be a regular file owned by the service user with mode 0600 or 0400.
* A missing key is not an error here: the legacy service starts without one and the
  dashboard shows "no key". `Config.require_api_key()` is for callers that cannot
  run without it.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, cast

from .secret import Secret, SecretFileError, read_secret_file
from .storage.contract import ANALYSIS_MODES, SEVERITIES, AnalysisMode

# Variable names that are new in the rewrite (everything else exists in analyzer.py).
ENV_ANALYSIS_MODE: Final = "ANALYSIS_MODE"
ENV_DECISION_MODEL: Final = "DECISION_MODEL"
ENV_DECISION_THRESHOLDS: Final = "DECISION_THRESHOLDS"
ENV_TRUSTED_PROXY_ADDRESSES: Final = "TRUSTED_PROXY_ADDRESSES"
ENV_API_KEY_FILE: Final = "GEMINI_API_KEY_FILE"
ENV_CREDENTIALS_DIRECTORY: Final = "CREDENTIALS_DIRECTORY"
CREDENTIAL_NAME: Final = "gemini"

# Q6: the legacy default `gemini-1.5-flash` has been retired by Google.
DEFAULT_GEMINI_MODEL: Final = "gemini-3.1-flash-lite"
DEFAULT_DECISION_MODEL: Final = "gemini-decision-1"

_INT_RE = re.compile(r"^[+-]?[0-9]{1,18}$")
_FLOAT_RE = re.compile(r"^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?$")
# The model name becomes a URL path segment: no slash, no query, no whitespace.
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_KEY_RE = re.compile(r"^[\x21-\x7e]{1,512}$")  # printable ASCII, no whitespace
# werkzeug hashes: `<method>$<salt>$<hash>`, e.g. `scrypt:32768:8:1$salt$hex`.
_PASSWORD_HASH_RE = re.compile(r"^[A-Za-z0-9:_.+-]+\$[^$\s]+\$[^$\s]+$")
_TRUE: Final = frozenset({"true", "1", "yes"})
_FALSE: Final = frozenset({"false", "0", "no"})

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_PATH_LENGTH = 4096
MAX_INFRA_CONTEXT_LENGTH = 2000


class ConfigError(Exception):
    """The configuration is invalid. `problems` has one line per offending variable."""

    def __init__(self, problems: list[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems)
        super().__init__("invalid configuration:\n" + "\n".join(f"  - {p}" for p in problems))


# ── sections ─────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class PathsConfig:
    alerts_log: Path
    db_path: Path
    static_dir: Path

    @property
    def data_dir(self) -> Path:
        return self.db_path.parent

    @property
    def watermark_file(self) -> Path:
        return self.data_dir / "watermark.json"

    @property
    def session_key_file(self) -> Path:
        return self.data_dir / "session.key"


@dataclass(frozen=True, slots=True)
class BatchingConfig:
    batch_max: int
    batch_timeout: int
    batch_timeout_quiet: int  # 0 = same as batch_timeout
    urgent_level: int
    min_level: int
    history_batch: int
    history_pause: float

    @property
    def effective_quiet_timeout(self) -> int:
        """Wait before a part-filled batch of non-urgent alerts is sent."""
        return max(self.batch_timeout_quiet, self.batch_timeout)


@dataclass(frozen=True, slots=True)
class GeminiConfig:
    api_key: Secret | None
    model: str
    temperature: float
    concurrency: int
    infra_context: str


@dataclass(frozen=True, slots=True)
class RetryConfig:
    base_delay: float
    max_delay: float
    max_age_hours: float
    queue_max_age_hours: float
    bad_response_max: int
    poll: float
    pace: float
    stale_analyzing_seconds: float


@dataclass(frozen=True, slots=True)
class RetentionConfig:
    days: float  # 0 = keep everything
    interval: float
    chunk: int


@dataclass(frozen=True, slots=True)
class WebConfig:
    listen_host: str
    port: int
    dashboard_user: str
    dashboard_password_hash: Secret | None
    session_lifetime: int
    login_max_attempts: int
    trusted_proxy_hops: int
    # Peers whose X-Forwarded-* headers are believed; empty = every peer (loopback only).
    trusted_proxy_addresses: tuple[IPNetwork, ...]
    session_cookie_secure: bool


@dataclass(frozen=True, slots=True)
class DecisionThresholds:
    """Minimum `relevant` probability per severity for a finding to be created.

    `None` means never (no finding of that severity). Defaults are the starting
    values of #88; the evaluation (#89) tunes them.
    """

    critical: float | None = 0.3
    high: float | None = 0.5
    medium: float | None = 0.6
    low: float | None = 0.7
    info: float | None = None

    def for_severity(self, severity: str) -> float | None:
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity {severity!r}")
        return cast("float | None", getattr(self, severity))


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    mode: AnalysisMode
    decision_model: str
    decision_thresholds: DecisionThresholds = field(default_factory=DecisionThresholds)


@dataclass(frozen=True, slots=True)
class Config:
    paths: PathsConfig
    batching: BatchingConfig
    gemini: GeminiConfig
    retry: RetryConfig
    retention: RetentionConfig
    web: WebConfig
    analysis: AnalysisConfig

    def require_api_key(self) -> Secret:
        """The API key, or `ConfigError` when none is configured."""
        if self.gemini.api_key is None:
            raise ConfigError(
                [
                    "no Gemini API key: set GEMINI_API_KEY, GEMINI_API_KEY_FILE or a "
                    f"systemd credential named {CREDENTIAL_NAME!r}"
                ]
            )
        return self.gemini.api_key

    def secret_values(self) -> tuple[str, ...]:
        """Every secret value, for the log redaction filter."""
        found = (self.gemini.api_key, self.web.dashboard_password_hash)
        return tuple(secret.reveal() for secret in found if secret is not None)


# ── reading ──────────────────────────────────────────────────────────────────
class _Reader:
    """Reads and validates variables, collecting every problem instead of stopping."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self._env = env
        self.problems: list[str] = []

    def raw(self, name: str) -> str | None:
        value = self._env.get(name)
        if value is None:
            return None
        value = value.strip()
        return value or None

    def _fail(self, name: str, expectation: str) -> None:
        # The value is deliberately not part of the message (see module docstring).
        self.problems.append(f"{name}: {expectation}")

    def integer(self, name: str, default: int, *, minimum: int, maximum: int) -> int:
        raw = self.raw(name)
        if raw is None:
            return default
        if not _INT_RE.match(raw) or not minimum <= int(raw) <= maximum:
            self._fail(name, f"expected an integer from {minimum} to {maximum}")
            return default
        return int(raw)

    def number(
        self,
        name: str,
        default: float,
        *,
        minimum: float,
        maximum: float,
        exclusive_minimum: bool = False,
    ) -> float:
        raw = self.raw(name)
        if raw is None:
            return default
        if _FLOAT_RE.match(raw):
            value = float(raw)
            low_ok = value > minimum if exclusive_minimum else value >= minimum
            if math.isfinite(value) and low_ok and value <= maximum:
                return value
        relation = "greater than" if exclusive_minimum else "from"
        self._fail(name, f"expected a number {relation} {minimum:g} up to {maximum:g}")
        return default

    def boolean(self, name: str, default: bool) -> bool:
        raw = self.raw(name)
        if raw is None:
            return default
        lowered = raw.lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
        # The legacy parser treated every value except false/0/no as true. Guessing
        # for "off" or "disabled" could silently weaken a security setting.
        self._fail(name, "expected one of true, 1, yes, false, 0, no")
        return default

    def text(
        self, name: str, default: str, *, pattern: re.Pattern[str] | None = None, what: str
    ) -> str:
        raw = self.raw(name)
        if raw is None:
            return default
        if pattern is not None and not pattern.match(raw):
            self._fail(name, f"expected {what}")
            return default
        return raw

    def path(self, name: str, default: str) -> Path:
        raw = self.raw(name)
        if raw is None:
            return Path(default)
        if len(raw) > MAX_PATH_LENGTH or "\x00" in raw:
            self._fail(name, "expected a file system path")
            return Path(default)
        return Path(raw)

    def choice(self, name: str, default: str, choices: tuple[str, ...]) -> str:
        raw = self.raw(name)
        if raw is None:
            return default
        lowered = raw.lower()
        if lowered not in choices:
            self._fail(name, f"expected one of {', '.join(choices)}")
            return default
        return lowered


def _read_host(reader: _Reader) -> str:
    host = reader.raw("LISTEN_HOST")
    if host is None:
        return "127.0.0.1"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            reader.problems.append("LISTEN_HOST: expected an IP address or a host name")
            return "127.0.0.1"
    return host


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _read_proxy_addresses(reader: _Reader) -> tuple[IPNetwork, ...]:
    raw = reader.raw(ENV_TRUSTED_PROXY_ADDRESSES)
    if raw is None:
        return ()
    networks: list[IPNetwork] = []
    for item in raw.split(","):
        text = item.strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
            if network.prefixlen == 0:
                raise ValueError("every address")
            networks.append(network)
        except ValueError:
            reader.problems.append(
                f"{ENV_TRUSTED_PROXY_ADDRESSES}: expected a comma-separated list of IP addresses"
                " or networks, not 0.0.0.0/0 (10.0.0.5, 192.168.0.0/24, ::1)"
            )
            return ()
    return tuple(networks)


def _read_user(reader: _Reader) -> str:
    user = reader.raw("DASHBOARD_USER")
    if user is None:
        return "admin"
    if len(user) > 128 or not user.isprintable():
        reader.problems.append("DASHBOARD_USER: expected 1 to 128 printable characters")
        return "admin"
    return user


def _read_password_hash(reader: _Reader) -> Secret | None:
    raw = reader.raw("DASHBOARD_PASSWORD_HASH")
    if raw is None:
        return None
    if not _PASSWORD_HASH_RE.match(raw):
        reader.problems.append("DASHBOARD_PASSWORD_HASH: not a Werkzeug password hash")
        return None
    return Secret(raw)


def _read_infra_context(reader: _Reader) -> str:
    default = "a self-hosted Linux server environment"
    raw = reader.raw("INFRA_CONTEXT")
    if raw is None:
        return default
    if len(raw) > MAX_INFRA_CONTEXT_LENGTH or not raw.isprintable():
        reader.problems.append(
            f"INFRA_CONTEXT: expected printable text up to {MAX_INFRA_CONTEXT_LENGTH} characters"
        )
        return default
    return raw


def _validate_key(reader: _Reader, source: str, value: str) -> Secret | None:
    if not _KEY_RE.match(value):
        reader.problems.append(
            f"{source}: not a valid API key"
            " (expected 1 to 512 printable ASCII characters, no whitespace)"
        )
        return None
    return Secret(value)


def _read_api_key(reader: _Reader) -> Secret | None:
    inline = reader.raw("GEMINI_API_KEY")
    if inline is not None:
        return _validate_key(reader, "GEMINI_API_KEY", inline)
    key_file = reader.raw(ENV_API_KEY_FILE)
    if key_file is not None:
        return _key_from_file(reader, ENV_API_KEY_FILE, key_file)
    credentials = reader.raw(ENV_CREDENTIALS_DIRECTORY)
    if credentials is not None:
        candidate = Path(credentials) / CREDENTIAL_NAME
        if candidate.exists():
            return _key_from_file(
                reader, "systemd credential 'gemini'", str(candidate), systemd_credential=True
            )
    return None


def _key_from_file(
    reader: _Reader, source: str, path: str, *, systemd_credential: bool = False
) -> Secret | None:
    try:
        content = read_secret_file(path, systemd_credential=systemd_credential)
    except SecretFileError as exc:
        reader.problems.append(f"{source}: {exc}")
        return None
    if not content:
        reader.problems.append(f"{source}: {path}: file is empty")
        return None
    return _validate_key(reader, f"{source} ({path})", content)


def parse_decision_thresholds(raw: str) -> DecisionThresholds:
    """Parse `critical=0.3,high=0.5,info=never`; unlisted severities keep their default.

    Raises `ValueError` with a message that does not contain the input.
    """
    values: dict[str, float | None] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        severity, separator, value = (part.strip() for part in item.partition("="))
        if not separator or severity not in SEVERITIES:
            raise ValueError(
                f"expected <severity>=<value> with severity in {', '.join(SEVERITIES)}"
            )
        if severity in values:
            raise ValueError(f"severity {severity} given twice")
        if value.lower() == "never":
            values[severity] = None
            continue
        if not _FLOAT_RE.match(value) or not 0 < float(value) <= 1:
            raise ValueError("a threshold is a number above 0 up to 1, or 'never'")
        values[severity] = float(value)
    return DecisionThresholds(**values)


def _read_analysis(reader: _Reader) -> AnalysisConfig:
    mode = cast(
        AnalysisMode,
        reader.choice(ENV_ANALYSIS_MODE, "llm", ANALYSIS_MODES),
    )
    model = reader.text(
        ENV_DECISION_MODEL,
        DEFAULT_DECISION_MODEL,
        pattern=_MODEL_RE,
        what="a model name (letters, digits, '.', '_', '-')",
    )
    thresholds = DecisionThresholds()
    raw = reader.raw(ENV_DECISION_THRESHOLDS)
    if raw is not None:
        try:
            thresholds = parse_decision_thresholds(raw)
        except ValueError as exc:
            reader.problems.append(f"{ENV_DECISION_THRESHOLDS}: {exc}")
    return AnalysisConfig(mode=mode, decision_model=model, decision_thresholds=thresholds)


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Build the configuration from `env` (default: the process environment).

    Raises `ConfigError` listing every problem found.
    """
    source: Mapping[str, str] = os.environ if env is None else env
    r = _Reader(source)

    paths = PathsConfig(
        alerts_log=r.path("WAZUH_ALERTS_LOG", "/var/ossec/logs/alerts/alerts.json"),
        db_path=r.path("DB_PATH", "/opt/wazuh-ai-analyzer/data/analyses.db"),
        static_dir=r.path("STATIC_DIR", "/opt/wazuh-ai-analyzer/static"),
    )
    batching = BatchingConfig(
        batch_max=r.integer("BATCH_MAX", 25, minimum=1, maximum=10_000),
        batch_timeout=r.integer("BATCH_TIMEOUT", 300, minimum=1, maximum=604_800),
        batch_timeout_quiet=r.integer("BATCH_TIMEOUT_QUIET", 0, minimum=0, maximum=604_800),
        urgent_level=r.integer("URGENT_LEVEL", 10, minimum=0, maximum=15),
        min_level=r.integer("MIN_LEVEL", 5, minimum=0, maximum=15),
        history_batch=r.integer("HISTORY_BATCH", 50, minimum=1, maximum=10_000),
        history_pause=r.number("HISTORY_PAUSE", 8.0, minimum=0, maximum=3600),
    )
    gemini = GeminiConfig(
        api_key=_read_api_key(r),
        model=r.text(
            "GEMINI_MODEL",
            DEFAULT_GEMINI_MODEL,
            pattern=_MODEL_RE,
            what="a model name (letters, digits, '.', '_', '-')",
        ),
        temperature=r.number("GEMINI_TEMPERATURE", 0.15, minimum=0, maximum=2),
        concurrency=r.integer("GEMINI_CONCURRENCY", 2, minimum=1, maximum=64),
        infra_context=_read_infra_context(r),
    )
    retry = RetryConfig(
        base_delay=r.number(
            "RETRY_BASE_DELAY", 60.0, minimum=0, maximum=86_400, exclusive_minimum=True
        ),
        max_delay=r.number(
            "RETRY_MAX_DELAY", 3600.0, minimum=0, maximum=604_800, exclusive_minimum=True
        ),
        max_age_hours=r.number(
            "RETRY_MAX_AGE_HOURS", 72.0, minimum=0, maximum=8760, exclusive_minimum=True
        ),
        queue_max_age_hours=r.number(
            "QUEUE_MAX_AGE_HOURS", 72.0, minimum=0, maximum=8760, exclusive_minimum=True
        ),
        bad_response_max=r.integer("RETRY_BAD_RESPONSE_MAX", 3, minimum=1, maximum=100),
        poll=r.number("RETRY_POLL", 30.0, minimum=0, maximum=86_400, exclusive_minimum=True),
        pace=r.number("RETRY_PACE", 10.0, minimum=0, maximum=86_400),
        stale_analyzing_seconds=r.number(
            "STALE_ANALYZING_SECONDS", 900.0, minimum=0, maximum=604_800, exclusive_minimum=True
        ),
    )
    if retry.max_delay < retry.base_delay:
        r.problems.append("RETRY_MAX_DELAY: must not be smaller than RETRY_BASE_DELAY")
    retention = RetentionConfig(
        days=r.number("RETENTION_DAYS", 0.0, minimum=0, maximum=36_500),
        interval=r.number(
            "RETENTION_INTERVAL", 3600.0, minimum=0, maximum=604_800, exclusive_minimum=True
        ),
        chunk=r.integer("RETENTION_CHUNK", 500, minimum=1, maximum=100_000),
    )
    web = WebConfig(
        listen_host=_read_host(r),
        port=r.integer("PORT", 8765, minimum=1, maximum=65_535),
        dashboard_user=_read_user(r),
        dashboard_password_hash=_read_password_hash(r),
        session_lifetime=r.integer("SESSION_LIFETIME", 8 * 3600, minimum=60, maximum=30 * 86_400),
        login_max_attempts=r.integer("LOGIN_MAX_ATTEMPTS", 5, minimum=1, maximum=1000),
        trusted_proxy_hops=r.integer("TRUSTED_PROXY_HOPS", 0, minimum=0, maximum=10),
        trusted_proxy_addresses=_read_proxy_addresses(r),
        session_cookie_secure=r.boolean("SESSION_COOKIE_SECURE", True),
    )
    if (
        web.trusted_proxy_hops > 0
        and not web.trusted_proxy_addresses
        and not _is_loopback_host(web.listen_host)
    ):
        # Without a peer check any client that reaches the port sends its own
        # X-Forwarded-For and picks its address (login rate limit, logs).
        r.problems.append(
            "TRUSTED_PROXY_HOPS: above 0 needs LISTEN_HOST on loopback (the proxy on the same"
            f" host) or {ENV_TRUSTED_PROXY_ADDRESSES} naming the proxy"
        )
    analysis = _read_analysis(r)

    if r.problems:
        raise ConfigError(r.problems)
    return Config(
        paths=paths,
        batching=batching,
        gemini=gemini,
        retry=retry,
        retention=retention,
        web=web,
        analysis=analysis,
    )
