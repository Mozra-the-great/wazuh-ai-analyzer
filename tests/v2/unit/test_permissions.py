"""Owner-only modes for the data directory and the database files (#31, S8)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from wazuh_ai_analyzer import permissions
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.schema import migrate

pytestmark = pytest.mark.skipif(os.name != "posix", reason="needs POSIX modes")


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_creates_a_private_data_dir(tmp_path: Path) -> None:
    target = tmp_path / "a" / "data"
    permissions.prepare_data_dir(target)
    assert mode(target) == 0o700


def test_tightens_an_existing_world_readable_dir(tmp_path: Path) -> None:
    target = tmp_path / "data"
    target.mkdir()
    target.chmod(0o755)
    permissions.prepare_data_dir(target)
    assert mode(target) == 0o700


def test_heals_database_and_wal_files(tmp_path: Path) -> None:
    db_path = tmp_path / "analyses.db"
    for suffix in ("", "-wal", "-shm"):
        file = Path(f"{db_path}{suffix}")
        file.write_text("x", encoding="utf-8")
        file.chmod(0o644)
    permissions.heal_database_files(db_path)
    for suffix in ("", "-wal", "-shm"):
        assert mode(Path(f"{db_path}{suffix}")) == 0o600


def test_missing_files_are_ignored(tmp_path: Path) -> None:
    permissions.heal_database_files(tmp_path / "absent.db")
    assert permissions.restrict(tmp_path / "absent", 0o600) is False


def test_chmod_failure_is_logged_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    file = tmp_path / "f"
    file.write_text("x", encoding="utf-8")

    def refuse(self: Path, mode: int) -> None:
        raise PermissionError("no")

    monkeypatch.setattr(Path, "chmod", refuse)
    with caplog.at_level("WARNING"):
        assert permissions.restrict(file, 0o600) is False
    assert "Could not set mode" in caplog.text


def test_database_created_by_the_migration_can_be_healed(tmp_path: Path) -> None:
    data = tmp_path / "data"
    permissions.prepare_data_dir(data)
    db_path = data / "analyses.db"
    migrate(Database(db_path))
    permissions.heal_database_files(db_path)
    assert mode(db_path) == 0o600
    assert mode(data) == 0o700
