"""Static files for the dashboard (#30).

Every file comes from `safe_join(root, ...)` (Werkzeug), which refuses `..`, absolute
paths and drive letters, and the result is checked again after symlinks are resolved:
a link inside the root that points out of it is never served. Dot-files, directories
and file types that are not on the allowlist are not served either.

No answer depends on what exists *outside* the root, so there is no file-existence
oracle: a path that is not a file of the root answers like any other unknown path.
Unknown paths without a file extension are routes of the single-page app and get
`index.html`; unknown paths with an extension are 404.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from werkzeug.security import safe_join

INDEX: Final = "index.html"

# Only these types are served; the content type is fixed here, never guessed from the
# operating system's registry. (`nosniff` is set on every response.)
CONTENT_TYPES: Final = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".css": "text/css",
    ".json": "application/json",
    ".txt": "text/plain",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


@dataclass(frozen=True, slots=True)
class StaticFile:
    path: Path
    content_type: str


def _has_extension(url_path: str) -> bool:
    return "." in url_path.rsplit("/", 1)[-1]


class StaticSite:
    def __init__(self, root: Path) -> None:
        self._root = os.path.realpath(root)

    @property
    def root(self) -> str:
        return self._root

    def lookup(self, url_path: str) -> StaticFile | None:
        """The file for a URL path (no leading slash), or None."""
        if not url_path or "\x00" in url_path or "\\" in url_path:
            return None
        parts = url_path.split("/")
        if any(part in ("", ".", "..") or part.startswith(".") for part in parts):
            return None
        content_type = CONTENT_TYPES.get(Path(parts[-1]).suffix.lower())
        if content_type is None:
            return None
        joined = safe_join(self._root, *parts)
        if joined is None:
            return None
        resolved = os.path.realpath(joined)
        try:
            if os.path.commonpath([self._root, resolved]) != self._root:
                return None
        except ValueError:  # another drive (Windows)
            return None
        file_path = Path(resolved)
        if not file_path.is_file():
            return None
        return StaticFile(path=file_path, content_type=content_type)

    def resolve(self, url_path: str) -> StaticFile | None:
        """What a GET for `url_path` serves: the file, or `index.html` for an app route.

        None means 404 (an unknown file with an extension, or no index at all).
        """
        found = self.lookup(url_path)
        if found is not None:
            return found
        stripped = url_path.strip("/")
        if stripped and (
            _has_extension(stripped) or "\\" in stripped or "\x00" in stripped or ".." in stripped
        ):
            return None
        return self.lookup(INDEX)
