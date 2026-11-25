"""One service per data directory (pre-cutover fix 3)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from v2.pipeline_support import KEY, FakeGemini, gemini_ok
from v2.unit.test_service import llm_factory, make_config
from wazuh_ai_analyzer.instance_lock import LOCK_FILE_NAME, InstanceLock, InstanceLockError
from wazuh_ai_analyzer.service import Service

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_second_lock_on_the_same_directory_is_refused_until_the_first_is_released(
    tmp_path: Path,
) -> None:
    first, second = InstanceLock(tmp_path), InstanceLock(tmp_path)
    first.acquire()
    assert first.is_held()
    with pytest.raises(InstanceLockError, match="another instance is already running"):
        second.acquire()
    assert not second.is_held()
    first.release()
    second.acquire()
    assert second.is_held()
    second.release()


def test_lock_is_reentrant_for_its_owner_and_release_is_idempotent(tmp_path: Path) -> None:
    lock = InstanceLock(tmp_path)
    lock.acquire()
    lock.acquire()
    lock.release()
    lock.release()
    assert not lock.is_held()


def test_different_directories_do_not_collide(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with InstanceLock(tmp_path / "a"), InstanceLock(tmp_path / "b"):
        pass


@pytest.mark.skipif(os.name != "posix", reason="owner and modes are POSIX")
def test_lock_file_is_private_and_names_its_owner(tmp_path: Path) -> None:
    with InstanceLock(tmp_path) as lock:
        assert (lock.path.stat().st_mode & 0o777) == 0o600
        assert lock.path.read_text().strip() == str(os.getpid())
        with pytest.raises(InstanceLockError, match=f"pid {os.getpid()}"):
            InstanceLock(tmp_path).acquire()


@pytest.mark.skipif(os.name != "posix", reason="symlinks are POSIX here")
def test_a_symlink_in_place_of_the_lock_file_is_refused(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / LOCK_FILE_NAME).symlink_to(victim)
    with pytest.raises(InstanceLockError, match="cannot open the lock file"):
        InstanceLock(tmp_path).acquire()
    assert victim.read_text() == "keep"


def test_a_second_service_on_the_same_data_dir_does_not_start(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    first = Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
    try:
        with pytest.raises(InstanceLockError):
            Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
    finally:
        first.shutdown(grace=5)
    # the lock is gone with the first service
    again = Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
    again.shutdown(grace=5)


def test_a_second_service_does_not_touch_the_queue_of_the_first(tmp_path: Path) -> None:
    """The lock comes before `requeue_stale`: a batch in flight must stay in flight."""
    config = make_config(tmp_path)
    first = Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
    try:
        batch_id = first.repo.insert_batch(alert_count=1, raw_groups="[]", source="live")
        with pytest.raises(InstanceLockError):
            Service(config, backend_factory=llm_factory(FakeGemini(gemini_ok())))
        record = first.repo.get_batch(batch_id)
        assert record is not None
        assert record.status == "analyzing"
    finally:
        first.shutdown(grace=5)


def test_run_exits_1_with_a_clear_message_when_the_directory_is_locked(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    env = {
        **os.environ,
        "WAZUH_ALERTS_LOG": str(config.paths.alerts_log),
        "DB_PATH": str(config.paths.db_path),
        "GEMINI_API_KEY": KEY,
        "PYTHONPATH": str(REPO_ROOT),
    }
    config.paths.data_dir.mkdir(parents=True, exist_ok=True)
    with InstanceLock(config.paths.data_dir):
        done = subprocess.run(
            [sys.executable, "-m", "wazuh_ai_analyzer", "run"],
            env=env,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    assert done.returncode == 1
    assert "another instance is already running" in done.stderr
    assert KEY not in done.stderr
