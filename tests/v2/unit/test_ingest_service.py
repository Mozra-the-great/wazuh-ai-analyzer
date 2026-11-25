"""`Ingest`, the wiring the pipeline uses: both workers in threads, clean stop."""

from __future__ import annotations

import threading
from pathlib import Path

from v2.ingest_support import lines, wait_for, write
from wazuh_ai_analyzer.config import load_config
from wazuh_ai_analyzer.ingest import Ingest, StoredBatch
from wazuh_ai_analyzer.ingest.planner import plan_resume
from wazuh_ai_analyzer.storage.repo import Repository


def test_live_and_backlog_run_in_threads_and_stop_cleanly(
    tmp_path: Path, db_path: Path, repo: Repository
) -> None:
    alerts_log = tmp_path / "alerts" / "alerts.json"
    config = load_config(
        {
            "WAZUH_ALERTS_LOG": str(alerts_log),
            "DB_PATH": str(db_path),
            "BATCH_MAX": "2",
            "HISTORY_BATCH": "2",
            "HISTORY_PAUSE": "0",
        }
    )
    write(alerts_log, lines(1, 2, 3))  # history at first start
    dispatched: list[StoredBatch] = []
    analysed: list[StoredBatch] = []
    gate_calls: list[int] = []

    def gate() -> float:
        gate_calls.append(1)
        return 0.0

    stop = threading.Event()
    ingest = Ingest(
        config, repo, dispatch=dispatched.append, analyse=analysed.append, stop=stop, gate=gate
    )
    ingest.load()
    threads = [
        threading.Thread(target=ingest.live_watcher, daemon=True),
        threading.Thread(target=ingest.history_worker, daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        assert ingest.plan_ready.wait(10)
        assert wait_for(lambda: sum(b.alert_count for b in analysed) == 3)
        assert wait_for(lambda: ingest.stats().history_done)
        with alerts_log.open("ab") as fh:
            fh.write(lines(4, 5, 6))
        assert wait_for(lambda: len(dispatched) == 1)
        assert wait_for(lambda: ingest.buffered_alerts() == 1)
    finally:
        stop.set()
        for t in threads:
            t.join(10)
    assert not any(t.is_alive() for t in threads)

    assert [b.source for b in analysed] == ["history", "history"]
    assert [b.alert_count for b in analysed] == [2, 1]
    assert [(b.source, b.alert_count) for b in dispatched] == [("live", 2)]
    assert gate_calls  # every backlog batch waited for the upstream gate
    stats = ingest.stats().as_dict()
    assert stats["processed"] == 3
    assert stats["history_alerts"] == 3
    assert stats["batches_sent"] == 1
    assert stats["history_files_total"] == stats["history_files_done"] == 1
    assert repo.count_batches_by_status() == {"analyzing": 3}


def test_backlog_waits_for_a_closed_gate_and_stops_while_waiting(
    tmp_path: Path, db_path: Path, repo: Repository
) -> None:
    alerts_log = tmp_path / "alerts" / "alerts.json"
    config = load_config({"WAZUH_ALERTS_LOG": str(alerts_log), "DB_PATH": str(db_path)})
    write(alerts_log, lines(1))
    stop = threading.Event()
    asked = threading.Event()

    def closed_gate() -> float:
        asked.set()
        return 3600.0

    ingest = Ingest(
        config, repo, dispatch=lambda b: None, analyse=lambda b: None, stop=stop, gate=closed_gate
    )
    ingest.load()
    with alerts_log.open("rb") as f:
        plan_resume(f, files=ingest.files, watermark=ingest.watermark, counters=ingest.counters)
    ingest.plan_ready.set()
    worker = threading.Thread(target=ingest.history_worker, daemon=True)
    worker.start()
    assert asked.wait(10)
    stop.set()
    worker.join(10)
    assert not worker.is_alive()
    assert repo.count_batches_by_status() == {}  # nothing stored while the gate was closed
    assert ingest.watermark.first_segment() is not None  # and nothing given up
