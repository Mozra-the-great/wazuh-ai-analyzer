"""Vocabulary and pure classification helpers of the alert facts (#118, #119, #120).

An alert group only carries the rule description and up to three truncated log
samples. That is not enough to tell a package upgrade from tampering, a fixed CVE
from a live one or a transient dpkg state from a broken package, so `sanitize`
adds a short list of *facts* to the groups of three alert families:

* `fim`   syscheck (file integrity) alerts: path, event, mode, changed attributes
* `pkg`   dpkg log alerts: package, state or action, version
* `vuln`  vulnerability-detector alerts: CVE, severity, status, package, condition

This module holds what both sides share: the closed vocabularies (every value of a
fact is whitelisted or cleaned, so a fact can never carry text that reads as an
instruction) and the classification that does not depend on any other alert: which
paths are sensitive, what a package manager can and cannot have changed. It has no
imports from the rest of the package, so `sanitize` (the only gate for alert
fields) and `analysis.calibration` (the consumer) can both use it.
"""

from __future__ import annotations

import posixpath
import re
from typing import Final

FACT_FIM: Final = "fim"
FACT_PKG: Final = "pkg"
FACT_VULN: Final = "vuln"
FACT_KINDS: Final = frozenset({FACT_FIM, FACT_PKG, FACT_VULN})

# ── package facts (dpkg log) ─────────────────────────────────────────────────
# `status <state> <package> <version>` lines of /var/log/dpkg.log.
PKG_TRANSIENT_STATES: Final = frozenset(
    {"half-configured", "half-installed", "unpacked", "triggers-pending", "triggers-awaited"}
)
# States after which dpkg is done with a package.
PKG_FINAL_STATES: Final = frozenset({"installed", "not-installed", "config-files"})
# Action lines (`install|upgrade|remove|purge <package> <old> <new>`).
PKG_ACTIONS: Final = frozenset({"install", "upgrade", "remove", "purge"})
PKG_STATES: Final = PKG_TRANSIENT_STATES | PKG_FINAL_STATES | PKG_ACTIONS
DPKG_LOG_BASENAME: Final = "dpkg.log"

_DPKG_LINE = re.compile(
    r"^(?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d )?(?P<verb>status|install|upgrade|remove|purge) "
    r"(?P<rest>[^\n]{1,300})$"
)
_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,100}(?::[a-z0-9\-]{1,20})?$")
_VERSION = re.compile(r"^[A-Za-z0-9.+~:_\-]{1,100}$")


def parse_dpkg_line(text: str) -> tuple[str, str, str] | None:
    """`(state or action, package, version)` of one dpkg.log line, or None.

    The package name and the version have to look like Debian ones; anything else
    (and every unknown state) is not a fact. The version of an action line is the
    new one.
    """
    first = text.strip().split("\n", 1)[0]
    match = _DPKG_LINE.match(first)
    if match is None:
        return None
    parts = match["rest"].split()
    if match["verb"] == "status":
        if len(parts) < 2 or parts[0] not in PKG_TRANSIENT_STATES | PKG_FINAL_STATES:
            return None
        state, package, version = parts[0], parts[1], (parts[2] if len(parts) > 2 else "")
    else:
        if not parts:
            return None
        state, package, version = match["verb"], parts[0], parts[-1] if len(parts) > 1 else ""
    if _PACKAGE_NAME.match(package) is None:
        return None
    return state, package, version if _VERSION.match(version) else ""


def package_base_name(package: str) -> str:
    """`libc-bin:amd64` -> `libc-bin`."""
    return package.split(":", 1)[0]


# ── vulnerability facts ──────────────────────────────────────────────────────
# `location` of the alerts the manager's vulnerability detector writes.
VULN_LOCATION: Final = "vulnerability-detector"
VULN_SEVERITIES: Final = ("critical", "high", "medium", "low")
VULN_STATUS_ACTIVE: Final = "active"
VULN_STATUS_SOLVED: Final = "solved"
# `data.vulnerability.package.condition` when the feed records no fixed version.
VULN_CONDITION_DEFAULT: Final = "package default status"
# Rules of the vulnerability detector and the highest severity each one stands for.
VULN_RULE_SEVERITY: Final = {"23504": "medium", "23505": "high", "23506": "critical"}


def vuln_severity(label: str) -> str:
    """`High` -> `high`; "" for labels that are no severity of ours (Unknown, Untriaged, ...)."""
    lowered = label.strip().lower()
    return lowered if lowered in VULN_SEVERITIES else ""


# ── file integrity facts ─────────────────────────────────────────────────────
FIM_EVENTS: Final = frozenset({"added", "modified", "deleted"})
FIM_MODES: Final = frozenset({"scheduled", "realtime", "whodata"})
# Wazuh rules of the syscheck group (files and the Windows registry).
FIM_RULES: Final = frozenset(
    {"550", "551", "552", "553", "554", "555", "594", "595", "596", "597", "598"}
    | {"750", "751", "752", "753", "754"}
)
# What a package manager rewrites: a new file has a new inode, content and mtime, and
# the size usually changes with it. Anything else (owner, permissions, attributes) is
# not an effect of an upgrade.
FIM_PACKAGE_ATTRIBUTES: Final = frozenset({"size", "mtime", "inode", "md5", "sha1", "sha256"})
_FIM_HASHES: Final = frozenset({"md5", "sha1", "sha256"})

IND_SENSITIVE: Final = "sensitive-path"
IND_OUTSIDE: Final = "outside-package-paths"
IND_ATTRIBUTES: Final = "perm-or-owner"
IND_HASH_ONLY: Final = "hash-only"
IND_UNKNOWN_CHANGE: Final = "unknown-change"
FIM_INDICATORS: Final = frozenset(
    {IND_SENSITIVE, IND_OUTSIDE, IND_ATTRIBUTES, IND_HASH_ONLY, IND_UNKNOWN_CHANGE}
)

# Files an attacker changes to get in or to stay in: a package upgrade does not
# explain a change here, so such a change is never downgraded.
_SENSITIVE_EXACT: Final = frozenset(
    {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/ld.so.preload",
        "/etc/crontab",
        "/etc/rc.local",
    }
)
_SENSITIVE_PREFIXES: Final = (
    "/etc/sudoers.d/",
    "/etc/ssh/",
    "/etc/pam.d/",
    "/etc/security/",
    "/etc/cron",
    "/etc/systemd/system/",
    "/etc/profile.d/",
    "/etc/ld.so.conf.d/",
    "/etc/apt/",
    "/var/spool/cron/",
)
# Directories a Debian/RPM package installs into. Everything else (/tmp, /home, /opt,
# /usr/local, the web root, Windows paths, ...) is not changed by an upgrade.
_PACKAGE_PREFIXES: Final = (
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/usr/share/",
    "/usr/include/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/etc/",
    "/boot/",
)
# Where programs and libraries live: a change here without any package activity is
# the case that must stay at the model's rating.
SYSTEM_BINARY_PREFIXES: Final = (
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/boot/",
)


def normalise_path(path: str) -> str:
    """`..` and `//` resolved, so a crafted path cannot slip past a prefix check."""
    return posixpath.normpath(path) if path.startswith("/") else path


def is_sensitive_path(path: str) -> bool:
    norm = normalise_path(path)
    return (
        norm in _SENSITIVE_EXACT
        or norm.startswith(_SENSITIVE_PREFIXES)
        or "/.ssh/" in norm
        or norm.endswith("/.ssh")
    )


def is_package_path(path: str) -> bool:
    return normalise_path(path).startswith(_PACKAGE_PREFIXES)


def is_system_binary_path(path: str) -> bool:
    return normalise_path(path).startswith(SYSTEM_BINARY_PREFIXES)


def fim_indicator(path: str, event: str, changed: frozenset[str]) -> str:
    """Why a file change is not explained by a package upgrade, or "" if nothing speaks against it.

    The first matching reason wins: a sensitive path, a path outside the package
    directories, a change of owner/permissions/attributes, a changed hash without a
    changed size or mtime, or a modification whose changed attributes are not known.
    """
    if is_sensitive_path(path):
        return IND_SENSITIVE
    if not is_package_path(path):
        return IND_OUTSIDE
    if event == "modified":
        if not changed:
            return IND_UNKNOWN_CHANGE
        if changed - FIM_PACKAGE_ATTRIBUTES:
            return IND_ATTRIBUTES
        if changed & _FIM_HASHES and not changed & {"size", "mtime"}:
            return IND_HASH_ONLY
    return ""
