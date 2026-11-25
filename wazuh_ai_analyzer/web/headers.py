"""Security headers of every response (#36) and the Content-Security-Policy.

The policy has no `unsafe-inline` and no `unsafe-eval`: scripts and styles come from
files of this origin only. A page that needs one inline script (kern's theme script,
P5) adds its sha256 through `build_csp(script_hashes=...)`; the hash is computed at
build time, never typed by hand.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

SCRIPT_HASH_RE: Final = re.compile(r"^sha256-[A-Za-z0-9+/]{43}=$")

# Features the dashboard never uses.
PERMISSIONS_POLICY: Final = (
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(),"
    " microphone=(), payment=(), usb=()"
)
HSTS: Final = "max-age=31536000"


def build_csp(script_hashes: Iterable[str] = ()) -> str:
    """`default-src 'self'` and explicit directives for everything the page uses."""
    scripts = ["'self'"]
    for digest in script_hashes:
        if not SCRIPT_HASH_RE.match(digest):
            raise ValueError("a script hash must look like sha256-<44 base64 characters>")
        scripts.append(f"'{digest}'")
    return "; ".join(
        (
            "default-src 'self'",
            f"script-src {' '.join(scripts)}",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "frame-src 'none'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
        )
    )


def security_headers(*, csp: str, hsts: bool) -> dict[str, str]:
    """The header set that goes on every response (errors and redirects included)."""
    headers = {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": PERMISSIONS_POLICY,
    }
    if hsts:
        headers["Strict-Transport-Security"] = HSTS
    return headers
