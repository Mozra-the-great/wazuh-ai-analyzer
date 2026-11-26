#!/usr/bin/env python3
"""Build the reproducible release tarball of the rewrite (`wazuh-ai-analyzer-<version>.tar.gz`).

The tarball is what a deployment installs (see docs/install.md). It holds the Python
package with the built dashboard (`wazuh_ai_analyzer/web/ui/`, git-ignored, so it exists
only here), the hash-pinned `requirements.txt`, the systemd unit and installer under
`deploy/`, the licenses (own, and every npm package that ends up in the dashboard bundle,
including the SIL OFL texts of the two fonts), and the install notes.

Reproducible: the same commit and the same UI build give the same bytes. Entries are
sorted, every mtime is SOURCE_DATE_EPOCH, owner and group are root:root (numeric 0),
modes are 0644/0755, the gzip header has no name and mtime 0, and the tar format is fixed
(GNU). Nothing depends on the checkout path, the user, the umask or the time of day. The
gzip stream itself depends on the zlib of the Python that runs the build; for a
cross-machine comparison use the checksum of the uncompressed tar (`gzip -dc | sha256sum`),
which this script prints as well.

    python scripts/build_release.py --output dist
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python scripts/build_release.py --version 2.0.0

Only the standard library is used.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

NAME: Final = "wazuh-ai-analyzer"
PACKAGE_DIR: Final = "wazuh_ai_analyzer"
UI_BUILD_DIR: Final = "wazuh_ai_analyzer/web/ui"
UI_MANIFEST: Final = "ui-manifest.json"
VERSION_RE: Final = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$")
LICENSE_FILE_RE: Final = re.compile(r"^(licen[cs]e|notice|copying)(\..+)?$", re.IGNORECASE)

# Tracked files that are not part of the release: lint config of the package sources, the
# install notes (shipped once, as INSTALL.md) and the notes about building the release.
EXCLUDED: Final = frozenset({"wazuh_ai_analyzer/ruff.toml", "docs/install.md", "docs/release.md"})
# Tracked directories copied as they are.
TREE_DIRS: Final = ("wazuh_ai_analyzer", "decisions", "deploy", "docs")
# Single files, as `source -> path in the tarball`.
SINGLE_FILES: Final = {
    "requirements.txt": "requirements.txt",
    "LICENSE": "LICENSE",
    "docs/install.md": "INSTALL.md",
}
FILE_MODE: Final = 0o644
EXEC_MODE: Final = 0o755
DIR_MODE: Final = 0o755


class BuildError(Exception):
    """The release cannot be built; the message says what to fix."""


@dataclass(frozen=True, slots=True)
class Entry:
    """One file of the tarball (path relative to the top directory)."""

    path: str
    data: bytes
    executable: bool = False


def _git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(  # noqa: S603 - fixed argument vector, no shell
            ["git", "-C", str(root), *args],  # noqa: S607 - git from PATH is intended
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BuildError(f"git {' '.join(args)} failed: {exc}") from exc
    return result.stdout


def tracked_files(root: Path, directory: str) -> list[tuple[str, bool]]:
    """Tracked files under `directory` as (path, executable), from the git index."""
    raw = _git(root, "ls-files", "-s", "-z", "--", directory)
    found: list[tuple[str, bool]] = []
    for record in raw.decode("utf-8").split("\0"):
        if not record:
            continue
        meta, _, path = record.partition("\t")
        mode = meta.split(" ", 1)[0]
        if mode == "120000":
            raise BuildError(f"{path}: a symlink cannot go into the release")
        found.append((path, mode == "100755"))
    return found


def _read_text_setting(path: Path, pattern: str, label: str) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise BuildError(f"{label} not found in {path}")
    return match.group(1)


def package_version(root: Path) -> str:
    """`__version__` of the package, which must agree with pyproject.toml."""
    code = _read_text_setting(
        root / PACKAGE_DIR / "__init__.py", r'^__version__\s*=\s*"([^"]+)"', "__version__"
    )
    project = _read_text_setting(root / "pyproject.toml", r'^version\s*=\s*"([^"]+)"', "version")
    if code != project:
        raise BuildError(
            f"version mismatch: {PACKAGE_DIR}/__init__.py has {code!r}, pyproject.toml {project!r}"
        )
    return code


def resolve_version(root: Path, requested: str | None) -> str:
    version = package_version(root)
    if requested is not None and requested != version:
        raise BuildError(
            f"requested version {requested!r} is not the package version {version!r};"
            " bump __version__ and pyproject.toml in the release commit first"
        )
    if not VERSION_RE.match(version):
        raise BuildError(f"{version!r} is not a version like 2.0.0 or 2.0.0-rc.1")
    return version


def resolve_epoch(root: Path, explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    env = os.environ.get("SOURCE_DATE_EPOCH")
    if env:
        if not env.isdigit():
            raise BuildError("SOURCE_DATE_EPOCH must be a number of seconds")
        return int(env)
    out = _git(root, "log", "-1", "--format=%ct").decode("ascii").strip()
    if not out.isdigit():
        raise BuildError("cannot read the commit time; set SOURCE_DATE_EPOCH")
    return int(out)


def ui_entries(root: Path) -> list[Entry]:
    """The dashboard build, which is generated and not committed."""
    ui_dir = root / UI_BUILD_DIR
    manifest = ui_dir / UI_MANIFEST
    if not manifest.is_file():
        raise BuildError(
            f"{UI_BUILD_DIR}/{UI_MANIFEST} is missing: build the dashboard first"
            " (cd ui && npm ci && npm run build)"
        )
    entries: list[Entry] = []
    for path in sorted(ui_dir.rglob("*")):
        if path.is_symlink():
            raise BuildError(f"{path}: a symlink cannot go into the release")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            entries.append(Entry(relative, path.read_bytes()))
    try:
        listed = json.loads(manifest.read_text(encoding="utf-8"))["public_files"]
    except (ValueError, KeyError, TypeError) as exc:
        raise BuildError(f"{UI_MANIFEST} is not a valid manifest") from exc
    present = {entry.path for entry in entries}
    missing = sorted(name for name in listed if f"{UI_BUILD_DIR}/{name}" not in present)
    if missing or not (ui_dir / "index.html").is_file():
        raise BuildError(
            f"{UI_MANIFEST} does not match the build: missing {missing or 'index.html'}"
        )
    return entries


def _declared_license(name: str, version: str, license_id: str, directory: Path) -> Entry:
    """A notice for a package that ships no license file: what its package.json declares."""
    try:
        meta = json.loads((directory / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BuildError(f"cannot read the package.json of {name}@{version}") from exc
    repository = meta.get("repository")
    if isinstance(repository, dict):
        repository = repository.get("url")
    author = meta.get("author")
    if isinstance(author, dict):
        author = author.get("name")
    lines = [
        f"{name} {version}",
        f"Declared license (package.json): {license_id}",
        f"Author: {author or 'not stated'}",
        f"Repository: {repository or 'not stated'}",
        "",
        "This package ships no license file; the lines above are all that it declares.",
        "",
    ]
    return Entry(f"licenses/npm/{name}@{version}/DECLARED-LICENSE.txt", "\n".join(lines).encode())


def _npm_license_entries(root: Path) -> tuple[list[Entry], list[tuple[str, str, str]]]:
    """License texts of every npm package of the dashboard bundle (the lock's non-dev set)."""
    lock_path = root / "ui" / "package-lock.json"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        packages: dict[str, dict[str, object]] = lock["packages"]
    except (OSError, ValueError, KeyError) as exc:
        raise BuildError(f"cannot read {lock_path}") from exc
    entries: list[Entry] = []
    table: list[tuple[str, str, str]] = []
    for key in sorted(packages):
        info = packages[key]
        if not key or info.get("dev"):
            continue
        name = key.rsplit("node_modules/", 1)[1]
        version = str(info.get("version", ""))
        license_id = str(info.get("license", "UNKNOWN"))
        table.append((name, version, license_id))
        directory = root / "ui" / key
        found = (
            sorted(f for f in directory.iterdir() if f.is_file() and LICENSE_FILE_RE.match(f.name))
            if directory.is_dir()
            else []
        )
        if not found:
            entries.append(_declared_license(name, version, license_id, directory))
        for source in found:
            entries.append(
                Entry(f"licenses/npm/{name}@{version}/{source.name}", source.read_bytes())
            )
    return entries, table


def notices_text(table: Iterable[tuple[str, str, str]]) -> str:
    lines = [
        "# Third-party notices",
        "",
        "Wazuh AI Analyzer is licensed under the GNU GPL v3 (see LICENSE).",
        "",
        "## Dashboard (npm packages in the bundle under wazuh_ai_analyzer/web/ui/)",
        "",
        "The full license texts are in licenses/npm/<package>@<version>/. The two fonts in",
        "wazuh_ai_analyzer/web/ui/assets/ are Inter and JetBrains Mono (SIL Open Font License",
        "1.1): licenses/npm/@fontsource-variable/inter@*/LICENSE and",
        "licenses/npm/@fontsource-variable/jetbrains-mono@*/LICENSE.",
        "",
        "| Package | Version | License |",
        "| --- | --- | --- |",
    ]
    lines += [f"| {name} | {version} | {license_id} |" for name, version, license_id in table]
    lines += [
        "",
        "## Python dependencies",
        "",
        "They are installed from requirements.txt (pinned with hashes) into the venv and carry",
        "their own license files in their dist-info directories.",
        "",
    ]
    return "\n".join(lines)


def collect_entries(root: Path, version: str, epoch: int, commit: str) -> list[Entry]:
    """Everything that goes into the tarball, sorted by path."""
    by_path: dict[str, Entry] = {}

    def add(entry: Entry) -> None:
        if entry.path in by_path:
            raise BuildError(f"{entry.path} is listed twice")
        by_path[entry.path] = entry

    for directory in TREE_DIRS:
        for path, executable in tracked_files(root, directory):
            if path in EXCLUDED or path.endswith(".pyc") or "/__pycache__/" in path:
                continue
            add(Entry(path, (root / path).read_bytes(), executable))
    for source, target in SINGLE_FILES.items():
        add(Entry(target, (root / source).read_bytes()))
    for entry in ui_entries(root):
        add(entry)
    license_entries, table = _npm_license_entries(root)
    for entry in license_entries:
        add(entry)
    add(Entry("THIRD-PARTY-NOTICES.md", notices_text(table).encode("utf-8")))
    add(Entry("VERSION", f"{version}\n".encode("ascii")))
    info = {"commit": commit, "name": NAME, "source_date_epoch": epoch, "version": version}
    add(Entry("BUILD-INFO.json", (json.dumps(info, indent=2, sort_keys=True) + "\n").encode()))
    for required in ("deploy/install.sh", "deploy/wazuh-ai-analyzer.service", "requirements.txt"):
        if required not in by_path:
            raise BuildError(f"{required} is missing from the release")
    return [by_path[path] for path in sorted(by_path, key=lambda p: p.encode("utf-8"))]


def _info(
    name: str, mtime: int, mode: int, size: int = 0, directory: bool = False
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mtime = mtime
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.size = size
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    return info


def write_tar(entries: Sequence[Entry], top: str, epoch: int) -> bytes:
    """The uncompressed tar stream (GNU format, fixed metadata)."""
    directories = {top}
    for entry in entries:
        parts = entry.path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add(f"{top}/{'/'.join(parts[:index])}")
    members: list[tuple[str, Entry | None]] = [(name, None) for name in directories]
    members += [(f"{top}/{entry.path}", entry) for entry in entries]
    members.sort(key=lambda item: item[0].encode("utf-8"))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, member in members:
            if member is None:
                tar.addfile(_info(name + "/", epoch, DIR_MODE, directory=True))
            else:
                mode = EXEC_MODE if member.executable else FILE_MODE
                tar.addfile(_info(name, epoch, mode, len(member.data)), io.BytesIO(member.data))
    return buffer.getvalue()


def compress(tar_bytes: bytes) -> bytes:
    """gzip without a file name and with mtime 0."""
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as stream:
        stream.write(tar_bytes)
    return raw.getvalue()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(
    root: Path,
    output: Path,
    *,
    version: str | None = None,
    epoch: int | None = None,
    commit: str | None = None,
    allow_dirty: bool = False,
) -> tuple[Path, str, str]:
    """Build `<output>/wazuh-ai-analyzer-<version>.tar.gz` and `<output>/SHA256SUMS`.

    Returns the tarball path, its sha256 and the sha256 of the uncompressed tar.
    """
    if not allow_dirty and _git(root, "status", "--porcelain", "--untracked-files=no").strip():
        raise BuildError("the working tree has uncommitted changes to tracked files")
    resolved_version = resolve_version(root, version)
    resolved_epoch = resolve_epoch(root, epoch)
    resolved_commit = commit or _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", resolved_commit):
        raise BuildError("the commit must be a full 40-character sha1")
    entries = collect_entries(root, resolved_version, resolved_epoch, resolved_commit)
    tar_bytes = write_tar(entries, f"{NAME}-{resolved_version}", resolved_epoch)
    archive = compress(tar_bytes)
    output.mkdir(parents=True, exist_ok=True)
    name = f"{NAME}-{resolved_version}.tar.gz"
    path = output / name
    path.write_bytes(archive)
    digest = sha256_hex(archive)
    (output / "SHA256SUMS").write_text(f"{digest}  {name}\n", encoding="utf-8", newline="\n")
    return path, digest, sha256_hex(tar_bytes)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the reproducible release tarball.")
    parser.add_argument("--version", help="must equal __version__ (default: __version__)")
    parser.add_argument("--output", default="dist", type=Path, help="output directory")
    parser.add_argument("--root", default=Path(__file__).resolve().parent.parent, type=Path)
    parser.add_argument("--source-date-epoch", type=int, help="default: $SOURCE_DATE_EPOCH or HEAD")
    parser.add_argument("--commit", help="full commit sha for BUILD-INFO.json (default: HEAD)")
    parser.add_argument("--allow-dirty", action="store_true", help="for local experiments only")
    args = parser.parse_args(argv)
    try:
        path, digest, tar_digest = build(
            args.root,
            args.output,
            version=args.version,
            epoch=args.source_date_epoch,
            commit=args.commit,
            allow_dirty=args.allow_dirty,
        )
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"tarball:  {path}")
    print(f"sha256:   {digest}")
    print(f"tar-sha256 (uncompressed): {tar_digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
