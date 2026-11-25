"""Command line: `check-config` and `migrate`."""

from __future__ import annotations

import io
import logging
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from wazuh_ai_analyzer import __main__ as cli
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.schema import LATEST_VERSION, current_version

KEY = "AIzaSyCLI-0123456789-KEY"
HASH = "scrypt:32768:8:1$saltsalt$" + "ef" * 32


@pytest.fixture(autouse=True)
def _isolated_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for handler in list(root.handlers):
        root.removeHandler(handler)
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(level)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """A clean process environment pointing at a scratch data directory."""
    values = {"DB_PATH": str(tmp_path / "data" / "analyses.db")}
    monkeypatch.setattr(os, "environ", values)
    return values


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return cli.main(list(argv), out=out), out.getvalue()


def test_check_config_prints_settings_and_masks_secrets(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    env.update(GEMINI_API_KEY=KEY, DASHBOARD_PASSWORD_HASH=HASH, BATCH_MAX="40")
    code, out = run("check-config")
    assert code == 0
    assert "batching.batch_max = 40" in out
    assert "gemini.api_key = ***" in out
    assert "web.dashboard_password_hash = ***" in out
    assert KEY not in out + capsys.readouterr().err
    assert HASH not in out


def test_check_config_without_key_is_ok_unless_required(env: dict[str, str]) -> None:
    code, out = run("check-config")
    assert code == 0
    assert "no Gemini API key" in out
    code, _ = run("check-config", "--require-api-key")
    assert code == cli.EXIT_CONFIG


def test_invalid_configuration_exits_with_config_error(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    env.update(BATCH_MAX="many", PORT="0")
    code, out = run("check-config")
    assert code == cli.EXIT_CONFIG
    assert out == ""
    err = capsys.readouterr().err
    assert "BATCH_MAX" in err
    assert "PORT" in err


def test_migrate_creates_and_then_reuses_the_database(env: dict[str, str]) -> None:
    code, out = run("migrate")
    assert code == 0
    assert f"version 0 -> {LATEST_VERSION}" in out
    with Database(env["DB_PATH"]).reader() as conn:
        assert current_version(conn) == LATEST_VERSION
    code, out = run("migrate")
    assert code == 0
    assert f"already at version {LATEST_VERSION}" in out


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX modes")
def test_migrate_tightens_the_permissions(env: dict[str, str]) -> None:
    data = Path(env["DB_PATH"]).parent
    data.mkdir()
    data.chmod(0o755)
    run("migrate")
    assert stat.S_IMODE(data.stat().st_mode) == 0o700
    assert stat.S_IMODE(Path(env["DB_PATH"]).stat().st_mode) == 0o600


def test_migrate_refuses_a_database_from_a_newer_release(env: dict[str, str]) -> None:
    run("migrate")
    db = Database(env["DB_PATH"])
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO schema_version (version, name, applied_at) VALUES (99, 'future', 'x')"
        )
    code, _ = run("migrate")
    assert code == cli.EXIT_FAILURE


def test_migrate_reports_an_unwritable_location(env: dict[str, str], tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    env["DB_PATH"] = str(blocker / "sub" / "analyses.db")
    code, _ = run("migrate")
    assert code == cli.EXIT_FAILURE


def test_a_command_is_required(env: dict[str, str]) -> None:
    with pytest.raises(SystemExit) as info:
        run()
    assert info.value.code == 2
