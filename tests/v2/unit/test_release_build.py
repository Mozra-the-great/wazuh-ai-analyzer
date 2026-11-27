"""The release tarball build (scripts/build_release.py): reproducible and complete (N5)."""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]
EPOCH = 1_700_000_000
COMMIT = "0123456789abcdef0123456789abcdef01234567"
TOP = "wazuh-ai-analyzer-2.0.0"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "build_release", ROOT / "scripts" / "build_release.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


script = _load_script()


def _write(root: Path, name: str, content: str | bytes = "x\n") -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)  # noqa: S603, S607


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A small repository with everything the build needs, indexed but not committed."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, "wazuh_ai_analyzer/__init__.py", '__version__ = "2.0.0"\n')
    _write(root, "wazuh_ai_analyzer/__main__.py", "print('hi')\n")
    _write(root, "wazuh_ai_analyzer/ruff.toml", "line-length = 100\n")
    _write(root, "wazuh_ai_analyzer/py.typed", "")
    _write(root, "pyproject.toml", '[project]\nname = "x"\nversion = "2.0.0"\n')
    _write(root, "requirements.txt", "flask==1 \\\n    --hash=sha256:00\n")
    _write(root, "LICENSE", "GPL\n")
    _write(root, "docs/install.md", "# install\n")
    _write(root, "docs/configuration.md", "# config\n")
    _write(root, "docs/release.md", "# release\n")
    _write(root, "deploy/install.sh", "#!/bin/sh\n")
    _write(root, "deploy/wazuh-ai-analyzer.service", "[Service]\n")
    _write(root, "ui/package-lock.json", json.dumps(_lock()))
    _write(root, "ui/node_modules/svelte/LICENSE.md", "MIT svelte\n")
    _write(root, "ui/node_modules/@fontsource-variable/inter/LICENSE", "OFL inter\n")
    _write(root, "ui/node_modules/nolicense/package.json", json.dumps(_no_license_meta()))
    _write(root, "ui/node_modules/dev-only/package.json", "{}")
    _write_ui_build(root)
    _git(root, "add", "-A", "-f", ".")
    _git(root, "update-index", "--chmod=+x", "deploy/install.sh")
    # The dashboard build and node_modules are git-ignored in the real repository.
    _git(root, "rm", "-r", "-q", "--cached", "wazuh_ai_analyzer/web/ui", "ui/node_modules")
    return root


def _lock() -> dict[str, object]:
    return {
        "packages": {
            "": {"name": "ui"},
            "node_modules/svelte": {"version": "5.0.0", "license": "MIT"},
            "node_modules/@fontsource-variable/inter": {"version": "5.3.0", "license": "OFL-1.1"},
            "node_modules/nolicense": {"version": "1.0.0", "license": "MIT"},
            "node_modules/dev-only": {"version": "9.9.9", "license": "MIT", "dev": True},
        }
    }


def _no_license_meta() -> dict[str, object]:
    return {"license": "MIT", "author": "A. Author", "repository": {"url": "git+https://x/y.git"}}


def _write_ui_build(root: Path) -> None:
    ui = "wazuh_ai_analyzer/web/ui"
    _write(root, f"{ui}/index.html", "<html></html>")
    _write(root, f"{ui}/login.html", "<html>login</html>")
    _write(root, f"{ui}/assets/app-ABC.js", "console.log(1)")
    manifest = {"version": 1, "script_hashes": ["sha256-x"], "public_files": ["login.html"]}
    _write(root, f"{ui}/ui-manifest.json", json.dumps(manifest))


def _build(root: Path, out: Path, **kwargs: object) -> tuple[Path, str, str]:
    options: dict[str, object] = {"epoch": EPOCH, "commit": COMMIT, "allow_dirty": True}
    options.update(kwargs)
    path, digest, tar_digest = script.build(root, out, **options)
    assert isinstance(path, Path)
    return path, str(digest), str(tar_digest)


def _members(tarball: Path) -> list[tarfile.TarInfo]:
    with tarfile.open(tarball, "r:gz") as tar:
        return tar.getmembers()


def test_two_builds_are_byte_identical(repo: Path, tmp_path: Path) -> None:
    first, digest_first, tar_first = _build(repo, tmp_path / "a")
    second, digest_second, tar_second = _build(repo, tmp_path / "b")
    assert digest_first == digest_second
    assert tar_first == tar_second
    assert first.read_bytes() == second.read_bytes()
    sums = (tmp_path / "a" / "SHA256SUMS").read_text(encoding="utf-8")
    assert sums == f"{digest_first}  {TOP}.tar.gz\n"


def test_the_build_ignores_file_times_and_the_umask(repo: Path, tmp_path: Path) -> None:
    _, before, _ = _build(repo, tmp_path / "a")
    later = time.time() + 86_400
    for path in repo.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            os.utime(path, (later, later))
    _, after, _ = _build(repo, tmp_path / "b")
    assert before == after


def test_a_different_source_date_epoch_changes_the_archive(repo: Path, tmp_path: Path) -> None:
    _, one, _ = _build(repo, tmp_path / "a")
    _, other, _ = _build(repo, tmp_path / "b", epoch=EPOCH + 1)
    assert one != other


def test_metadata_is_fixed_and_entries_are_sorted(repo: Path, tmp_path: Path) -> None:
    path, _, _ = _build(repo, tmp_path / "a")
    members = _members(path)
    names = [member.name for member in members]
    assert names == sorted(names, key=lambda name: name.encode())
    assert names[0] == f"{TOP}"
    for member in members:
        assert (member.uid, member.gid) == (0, 0)
        assert (member.uname, member.gname) == ("root", "root")
        assert member.mtime == EPOCH
        assert member.mode in {0o644, 0o755}
        assert member.isfile() or member.isdir()
    modes = {member.name: member.mode for member in members}
    assert modes[f"{TOP}/deploy/install.sh"] == 0o755
    assert modes[f"{TOP}/deploy/wazuh-ai-analyzer.service"] == 0o644
    assert modes[f"{TOP}/wazuh_ai_analyzer"] == 0o755


def test_the_gzip_header_has_no_name_and_no_time(repo: Path, tmp_path: Path) -> None:
    path, _, _ = _build(repo, tmp_path / "a")
    header = path.read_bytes()[:10]
    assert header[:3] == b"\x1f\x8b\x08"
    assert header[3] == 0  # no FNAME flag
    assert header[4:8] == b"\x00\x00\x00\x00"  # mtime 0


def test_content_of_the_release(repo: Path, tmp_path: Path) -> None:
    path, _, _ = _build(repo, tmp_path / "a")
    names = {member.name.removeprefix(f"{TOP}/") for member in _members(path)}
    expected = {
        "VERSION",
        "BUILD-INFO.json",
        "INSTALL.md",
        "LICENSE",
        "THIRD-PARTY-NOTICES.md",
        "requirements.txt",
        "deploy/install.sh",
        "deploy/wazuh-ai-analyzer.service",
        "docs/configuration.md",
        "wazuh_ai_analyzer/__main__.py",
        "wazuh_ai_analyzer/py.typed",
        "wazuh_ai_analyzer/web/ui/index.html",
        "wazuh_ai_analyzer/web/ui/ui-manifest.json",
        "wazuh_ai_analyzer/web/ui/assets/app-ABC.js",
        "licenses/npm/svelte@5.0.0/LICENSE.md",
        "licenses/npm/@fontsource-variable/inter@5.3.0/LICENSE",
        "licenses/npm/nolicense@1.0.0/DECLARED-LICENSE.txt",
    }
    assert expected <= names
    # not part of the release
    assert "wazuh_ai_analyzer/ruff.toml" not in names
    assert "docs/install.md" not in names
    assert "docs/release.md" not in names
    assert not any("dev-only" in name for name in names)
    with tarfile.open(path, "r:gz") as tar:
        info = json.loads(_text(tar, "BUILD-INFO.json"))
        assert info == {
            "commit": COMMIT,
            "name": "wazuh-ai-analyzer",
            "source_date_epoch": EPOCH,
            "version": "2.0.0",
        }
        assert _text(tar, "VERSION") == "2.0.0\n"
        assert _text(tar, "INSTALL.md") == "# install\n"
        notices = _text(tar, "THIRD-PARTY-NOTICES.md")
        assert "| svelte | 5.0.0 | MIT |" in notices
        assert "dev-only" not in notices
        declared = _text(tar, "licenses/npm/nolicense@1.0.0/DECLARED-LICENSE.txt")
        assert "A. Author" in declared
        assert "git+https://x/y.git" in declared


def _text(tar: tarfile.TarFile, name: str) -> str:
    handle = tar.extractfile(f"{TOP}/{name}")
    assert handle is not None
    return handle.read().decode("utf-8")


def test_untracked_files_and_bytecode_stay_out(repo: Path, tmp_path: Path) -> None:
    _write(repo, "wazuh_ai_analyzer/stray.py", "untracked\n")
    _write(repo, "wazuh_ai_analyzer/__pycache__/x.cpython-312.pyc", b"\x00")
    path, _, _ = _build(repo, tmp_path / "a")
    names = {member.name for member in _members(path)}
    assert f"{TOP}/wazuh_ai_analyzer/stray.py" not in names
    assert not any("__pycache__" in name for name in names)


def test_the_archive_unpacks_to_one_top_directory(repo: Path, tmp_path: Path) -> None:
    path, _, tar_digest = _build(repo, tmp_path / "a")
    with gzip.open(path) as stream:
        raw = stream.read()
    assert script.sha256_hex(raw) == tar_digest
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        tops = {member.name.split("/", 1)[0] for member in tar.getmembers()}
    assert tops == {TOP}


def test_the_dashboard_build_is_required(repo: Path, tmp_path: Path) -> None:
    (repo / "wazuh_ai_analyzer/web/ui/ui-manifest.json").unlink()
    with pytest.raises(script.BuildError, match="build the dashboard first"):
        _build(repo, tmp_path / "a")


def test_the_manifest_must_match_the_build(repo: Path, tmp_path: Path) -> None:
    (repo / "wazuh_ai_analyzer/web/ui/login.html").unlink()
    with pytest.raises(script.BuildError, match="does not match the build"):
        _build(repo, tmp_path / "a")


def test_a_license_file_is_required_unless_the_package_declares_one(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "ui/node_modules/svelte/LICENSE.md").unlink()
    (repo / "ui/node_modules/svelte/package.json").write_text("{}", encoding="utf-8")
    path, _, _ = _build(repo, tmp_path / "a")
    names = {member.name for member in _members(path)}
    assert f"{TOP}/licenses/npm/svelte@5.0.0/DECLARED-LICENSE.txt" in names
    (repo / "ui/node_modules/svelte/package.json").unlink()
    with pytest.raises(script.BuildError, match=r"package\.json of svelte"):
        _build(repo, tmp_path / "b")


def test_the_requested_version_must_be_the_package_version(repo: Path, tmp_path: Path) -> None:
    _build(repo, tmp_path / "a", version="2.0.0")
    with pytest.raises(script.BuildError, match="is not the package version"):
        _build(repo, tmp_path / "b", version="2.0.1")


def test_package_and_pyproject_versions_must_agree(repo: Path, tmp_path: Path) -> None:
    _write(repo, "pyproject.toml", '[project]\nname = "x"\nversion = "2.0.1"\n')
    with pytest.raises(script.BuildError, match="version mismatch"):
        _build(repo, tmp_path / "a")


@pytest.mark.parametrize(
    "version", ["2.0", "v2.0.0", "2.0.0 x", "2.0.0/../x", "2.0.0rc", "2.0.0c1"]
)
def test_a_malformed_version_is_refused(repo: Path, tmp_path: Path, version: str) -> None:
    _write(repo, "wazuh_ai_analyzer/__init__.py", f'__version__ = "{version}"\n')
    _write(repo, "pyproject.toml", f'[project]\nname = "x"\nversion = "{version}"\n')
    with pytest.raises(script.BuildError, match="is not a version"):
        _build(repo, tmp_path / "a")


@pytest.mark.parametrize("version", ["2.0.0", "2.0.0.dev0", "2.0.0-rc.1", "10.20.30-beta"])
def test_release_and_prerelease_versions_are_accepted(
    repo: Path, tmp_path: Path, version: str
) -> None:
    _write(repo, "wazuh_ai_analyzer/__init__.py", f'__version__ = "{version}"\n')
    _write(repo, "pyproject.toml", f'[project]\nname = "x"\nversion = "{version}"\n')
    path, _, _ = _build(repo, tmp_path / "a")
    assert path.name == f"wazuh-ai-analyzer-{version}.tar.gz"


@pytest.mark.parametrize(
    ("package", "release"),
    [
        ("2.0.0rc1", "2.0.0-rc.1"),
        ("2.0.0a3", "2.0.0-a.3"),
        ("2.0.0b12", "2.0.0-b.12"),
        ("2.0.0", "2.0.0"),
        ("2.0.0-rc.1", "2.0.0-rc.1"),
        ("2.0.0.dev0", "2.0.0.dev0"),
    ],
)
def test_the_release_form_of_a_version(package: str, release: str) -> None:
    assert script.release_form(package) == release


@pytest.mark.parametrize("requested", ["2.0.0-rc.1", "2.0.0rc1"])
def test_a_pep440_prerelease_builds_under_its_tag_name(
    repo: Path, tmp_path: Path, requested: str
) -> None:
    _write(repo, "wazuh_ai_analyzer/__init__.py", '__version__ = "2.0.0rc1"\n')
    _write(repo, "pyproject.toml", '[project]\nname = "x"\nversion = "2.0.0rc1"\n')
    path, _, _ = _build(repo, tmp_path / "a", version=requested)
    assert path.name == "wazuh-ai-analyzer-2.0.0-rc.1.tar.gz"
    names = {member.name for member in _members(path)}
    assert "wazuh-ai-analyzer-2.0.0-rc.1/VERSION" in names
    with tarfile.open(path) as archive:
        member = archive.extractfile("wazuh-ai-analyzer-2.0.0-rc.1/VERSION")
        assert member is not None
        assert member.read() == b"2.0.0-rc.1\n"


@pytest.mark.parametrize("requested", ["2.0.0", "2.0.0-rc.2", "2.0.0rc2", "2.0.1-rc.1"])
def test_a_tag_that_is_not_the_prerelease_is_refused(
    repo: Path, tmp_path: Path, requested: str
) -> None:
    _write(repo, "wazuh_ai_analyzer/__init__.py", '__version__ = "2.0.0rc1"\n')
    _write(repo, "pyproject.toml", '[project]\nname = "x"\nversion = "2.0.0rc1"\n')
    with pytest.raises(script.BuildError, match="is not the package version"):
        _build(repo, tmp_path / "a", version=requested)


def test_a_dirty_tree_is_refused_without_the_flag(repo: Path, tmp_path: Path) -> None:
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x")
    _write(repo, "LICENSE", "changed\n")
    with pytest.raises(script.BuildError, match="uncommitted changes"):
        script.build(repo, tmp_path / "a", epoch=EPOCH, commit=COMMIT)


def test_source_date_epoch_comes_from_the_environment(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1234567890")
    path, _, _ = script.build(repo, tmp_path / "a", commit=COMMIT, allow_dirty=True)
    assert {member.mtime for member in _members(path)} == {1234567890}
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "yesterday")
    with pytest.raises(script.BuildError, match="SOURCE_DATE_EPOCH"):
        script.build(repo, tmp_path / "b", commit=COMMIT, allow_dirty=True)


def test_the_commit_must_be_a_full_sha(repo: Path, tmp_path: Path) -> None:
    with pytest.raises(script.BuildError, match="40-character"):
        _build(repo, tmp_path / "a", commit="abc123")


def test_the_real_repository_unit_and_installer_are_in_the_release_list() -> None:
    # The files the release depends on exist in the real checkout and are tracked.
    tracked = {path for path, _ in script.tracked_files(ROOT, "deploy")}
    assert {
        "deploy/install.sh",
        "deploy/wazuh-ai-analyzer.service",
        "deploy/unprivileged-lxc.conf",
        "deploy/wazuh-ai-analyzer.env.example",
    } <= tracked
    assert dict(script.tracked_files(ROOT, "deploy"))["deploy/install.sh"] is True
