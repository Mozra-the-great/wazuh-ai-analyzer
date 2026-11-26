"""The manifest of the dashboard build (`ui-manifest.json`, written by `ui/` at build time).

The UI build has two facts the server needs and must not guess:

* the sha256 of kern's before-paint theme script, the only inline script of the pages
  (it goes into `build_csp(script_hashes=...)`; computed from the script text in the
  built pages, never typed by hand), and
* the files the login and logout pages consist of (hashed asset names change with every
  build), which are served without a session, like `PUBLIC_FILES` in `app.py`.

The manifest is read once at start-up and validated strictly: an entry that is not a plain
relative path of an existing, servable file refuses the start instead of widening what an
unauthenticated client can fetch. No manifest (a fixture directory, or a checkout that was
never built) means no extra hashes and no extra public files.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .headers import SCRIPT_HASH_RE
from .static_files import StaticSite

MANIFEST_NAME: Final = "ui-manifest.json"
MANIFEST_VERSION: Final = 1
MAX_MANIFEST_BYTES: Final = 64 * 1024
MAX_PUBLIC_FILES: Final = 64
MAX_SCRIPT_HASHES: Final = 4

_NAME_RE: Final = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$")


class UiManifestError(ValueError):
    """The manifest is present but wrong; the service must not start with it."""


@dataclass(frozen=True, slots=True)
class UiManifest:
    script_hashes: tuple[str, ...] = ()
    public_files: frozenset[str] = frozenset()


def load_ui_manifest(ui_dir: Path) -> UiManifest:
    """The validated manifest of `ui_dir`, or an empty one when there is none."""
    path = ui_dir / MANIFEST_NAME
    if not path.is_file():
        return UiManifest()
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise UiManifestError(f"{MANIFEST_NAME} is too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UiManifestError(f"{MANIFEST_NAME} is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("version") != MANIFEST_VERSION:
        raise UiManifestError(f"{MANIFEST_NAME} has an unknown format or version")

    hashes = data.get("script_hashes")
    if (
        not isinstance(hashes, list)
        or not 0 < len(hashes) <= MAX_SCRIPT_HASHES
        or not all(isinstance(item, str) and SCRIPT_HASH_RE.match(item) for item in hashes)
    ):
        raise UiManifestError("script_hashes must be 1 to 4 values like sha256-<44 base64 chars>")

    files = data.get("public_files")
    if not isinstance(files, list) or not 0 < len(files) <= MAX_PUBLIC_FILES:
        raise UiManifestError(f"public_files must list 1 to {MAX_PUBLIC_FILES} files")
    site = StaticSite(ui_dir)
    names: set[str] = set()
    for entry in files:
        if not isinstance(entry, str) or not _NAME_RE.match(entry) or ".." in entry:
            raise UiManifestError("public_files holds a name that is not a plain relative path")
        # The same lookup that serves the file: it must exist, stay inside the root and
        # have a type on the allowlist.
        if site.lookup(entry) is None:
            raise UiManifestError("public_files names a file the server would not serve")
        names.add(entry)
    return UiManifest(script_hashes=tuple(hashes), public_files=frozenset(names))
