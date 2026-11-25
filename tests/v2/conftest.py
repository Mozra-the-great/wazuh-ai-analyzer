"""Shared fixtures for the tests of the rewrite (`wazuh_ai_analyzer`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from v2.helpers import FakeClock
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import Repository
from wazuh_ai_analyzer.storage.schema import migrate


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "analyses.db"


@pytest.fixture
def database(db_path: Path) -> Database:
    """A database migrated to the latest schema."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(db_path)
    migrate(db)
    return db


@pytest.fixture
def repo(database: Database, clock: FakeClock) -> Repository:
    return Repository(database, clock=clock)
