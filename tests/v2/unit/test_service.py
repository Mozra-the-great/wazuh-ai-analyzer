"""The running service: ingest + pipeline end to end, clean stop, crash and restart.

The backend is the real `GeminiLlmBackend` with a fake HTTP POST, or a scripted
fake; nothing talks to the network.
"""

from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest

from v2.helpers import free_port
from v2.ingest_support import lines, wait_for, write
from v2.pipeline_support import KEY, FakeGemini, gemini_ok
from wazuh_ai_analyzer import __main__ as cli
from wazuh_ai_analyzer.analysis.backend import AnalysisBackend, AnalysisResult, BatchContext
from wazuh_ai_analyzer.analysis.llm import GeminiLlmBackend
from wazuh_ai_analyzer.config import Config, load_config
from wazuh_ai_analyzer.ingest.sanitize import AlertGroup
from wazuh_ai_analyzer.metrics.runtime import LEGACY_RUNTIME_KEYS
from wazuh_ai_analyzer.service import Service
from wazuh_ai_analyzer.storage.contract import AnalysisMode
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import Repository
from wazuh_ai_analyzer.storage.schema import migrate

REPO_ROOT = Path(__file__).resolve().parents[3]


def make_config(tmp_path: Path, **env: str) -> Config:
    values = {
        "WAZUH_ALERTS_LOG": str(tmp_path / "alerts" / "alerts.json"),
        "DB_PATH": str(tmp_path / "data" / "analyses.db"),
        "GEMINI_API_KEY": KEY,
        "BATCH_MAX": "2",
        "HISTORY_BATCH": "2",
        "HISTORY_PAUSE": "0",
        "RETRY_POLL": "0.05",
        "RETRY_PACE": "0.01",
        "GEMINI_CONCURRENCY": "1",
        "PORT": str(free_port()),
        **env,
    }
    return load_config(values)


def column(config: Config, name: str) -> list[str]:
    conn = sqlite3.connect(config.paths.db_path)
    try:
        return [str(r[0]) for r in conn.execute(f"SELECT {name} FROM batches ORDER BY id")]
    finally:
        conn.close()


def statuses(config: Config) -> list[str]:
    return column(config, "status")


def llm_factory(fake: FakeGemini) -> Callable[[Config], AnalysisBackend]:
    def factory(config: Config) -> AnalysisBackend:
        return GeminiLlmBackend.from_config(config.gemini, post=fake)

    return factory


@pytest.fixture
def running() -> Iterator[list[Service]]:
    services: list[Service] = []
    yield services
    for service in services:
        service.shutdown(grace=5)


def test_ingest_and_pipeline_run_end_to_end_and_stop_cleanly(
    tmp_path: Path, running: list[Service]
) -> None:
    config = make_config(tmp_path)
    write(config.paths.alerts_log, lines(1, 2, 3))  # history at first start
    fake = FakeGemini(gemini_ok())
    service = Service(config, backend_factory=llm_factory(fake))
    running.append(service)
    service.start()
    assert service.ingest.plan_ready.wait(10)
    write(config.paths.alerts_log, lines(4, 5), "ab")  # one full live batch

    assert wait_for(lambda: statuses(config) == ["done"] * 3)
    assert sorted(column(config, "source")) == ["history", "history", "live"]
    assert len(fake.calls) == 3
    runtime = service.runtime()
    assert tuple(runtime)[: len(LEGACY_RUNTIME_KEYS)] == LEGACY_RUNTIME_KEYS
    # batches_sent counts live batches only, as in analyzer.py
    assert runtime["batches_sent"] == 1
    assert runtime["errors"] == 0

    service.stop()
    assert service.shutdown(grace=10) is True
    assert not service.failed


def test_a_dead_worker_thread_stops_the_service(tmp_path: Path, running: list[Service]) -> None:
    service = Service(make_config(tmp_path), backend_factory=llm_factory(FakeGemini(gemini_ok())))
    running.append(service)
    service.pipeline.run_retry_worker = lambda: None  # type: ignore[method-assign]
    service.start()
    waiter = threading.Thread(target=service.wait, daemon=True)
    waiter.start()
    waiter.join(10)
    assert not waiter.is_alive()
    assert service.failed
    assert service.stop_event.is_set()


def test_restart_after_a_crash_requeues_and_finishes_the_batch_in_flight(
    tmp_path: Path, running: list[Service]
) -> None:
    config = make_config(tmp_path)
    config.paths.db_path.parent.mkdir(parents=True)
    db = Database(config.paths.db_path)
    migrate(db)
    # The previous process died while this batch was in flight.
    stuck = Repository(db).insert_batch(
        alert_count=1, raw_groups='[{"rule_id": "1"}]', source="live"
    )
    assert statuses(config) == ["analyzing"]

    fake = FakeGemini(gemini_ok())
    service = Service(config, backend_factory=llm_factory(fake))
    running.append(service)
    assert statuses(config) == ["pending"]  # re-queued before any worker runs
    service.start()
    assert wait_for(lambda: statuses(config) == ["done"])
    assert service.pipeline.counters.snapshot().recovered_stale == 1
    assert Repository(db).get_batch(stuck) is not None


class BlockingBackend:
    """Blocks in `analyse` until released, to stop the service mid-request."""

    name: AnalysisMode = "llm"

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def analyse(self, groups: Sequence[AlertGroup], context: BatchContext) -> AnalysisResult:
        self.calls += 1
        self.entered.set()
        assert self.release.wait(20)
        return AnalysisResult(summary="s", overall_risk="low", findings=())


def test_stop_mid_request_stores_the_result_and_requeues_the_waiting_batches(
    tmp_path: Path, running: list[Service]
) -> None:
    config = make_config(tmp_path)
    write(config.paths.alerts_log, b"")
    backend = BlockingBackend()
    service = Service(config, backend_factory=lambda c: backend)
    running.append(service)
    service.start()
    assert service.ingest.plan_ready.wait(10)
    write(config.paths.alerts_log, lines(1, 2, 3, 4, 5, 6), "ab")  # three live batches
    assert backend.entered.wait(10)
    assert wait_for(lambda: len(statuses(config)) == 3)

    service.stop()
    threading.Timer(0.5, backend.release.set).start()
    assert service.shutdown(grace=10) is True
    # The batch in flight is stored; the ones still waiting are queued, never lost.
    assert sorted(statuses(config)) == ["done", "pending", "pending"]
    assert backend.calls == 1


def test_a_request_that_outlives_the_grace_period_stays_analyzing(
    tmp_path: Path, running: list[Service]
) -> None:
    config = make_config(tmp_path)
    write(config.paths.alerts_log, b"")
    backend = BlockingBackend()
    service = Service(config, backend_factory=lambda c: backend)
    service.start()
    assert service.ingest.plan_ready.wait(10)
    write(config.paths.alerts_log, lines(1, 2), "ab")
    assert backend.entered.wait(10)
    assert service.shutdown(grace=0.2) is False
    assert statuses(config) == ["analyzing"]  # re-queued at the next start
    backend.release.set()
    assert wait_for(lambda: statuses(config) == ["done"])  # not half-written either way


def test_decision_mode_starts_with_the_decision_backend(tmp_path: Path) -> None:
    service = Service(make_config(tmp_path, ANALYSIS_MODE="decision"))
    try:
        assert service.backend.name == "decision"
    finally:
        service.shutdown(grace=0.2)


def test_a_broken_decision_definition_stops_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = tmp_path / "v1.json"
    broken.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("wazuh_ai_analyzer.analysis.decisions.DEFINITIONS_PATH", broken)
    monkeypatch.setattr(
        os,
        "environ",
        {"DB_PATH": str(tmp_path / "d" / "a.db"), "ANALYSIS_MODE": "decision"},
    )
    assert cli.main(["run"]) == cli.EXIT_CONFIG


def _service_env(tmp_path: Path) -> dict[str, str]:
    """A minimal environment: no inherited key, no credentials directory."""
    env = {
        "WAZUH_ALERTS_LOG": str(tmp_path / "alerts" / "alerts.json"),
        "DB_PATH": str(tmp_path / "data" / "analyses.db"),
        "BATCH_MAX": "2",
        "HISTORY_BATCH": "2",
        "HISTORY_PAUSE": "0",
        # The config failure closes the upstream gate; keep it short for the backlog.
        "RETRY_BASE_DELAY": "0.1",
        "RETRY_MAX_DELAY": "0.5",
        "PYTHONPATH": str(REPO_ROOT),
        "PORT": str(free_port()),
    }
    for name in ("PATH", "SYSTEMROOT", "LANG"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM delivery needs POSIX")
def test_sigterm_stops_the_service_cleanly(tmp_path: Path) -> None:
    env = _service_env(tmp_path)
    write(Path(env["WAZUH_ALERTS_LOG"]), lines(1, 2, 3, 4))
    proc = subprocess.Popen(
        [sys.executable, "-m", "wazuh_ai_analyzer", "run"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    db = Path(env["DB_PATH"])
    try:
        # No key: every batch is a config failure and stays queued (no network call).
        assert wait_for(lambda: db.exists() and _count(db, "1=1") == 2, 30)
        time.sleep(0.5)
        proc.send_signal(signal.SIGTERM)
        _, err = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    assert proc.returncode == 0, err
    assert "SIGTERM received" in err
    assert "Stopped cleanly" in err
    assert _count(db, "status='pending'") == 2  # queued, never half-written


def _count(db: Path, where: str) -> int:
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return int(conn.execute(f"SELECT COUNT(*) FROM batches WHERE {where}").fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return -1
