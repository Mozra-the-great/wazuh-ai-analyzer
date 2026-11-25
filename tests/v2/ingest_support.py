"""A test harness around the ingest layer, shaped like the legacy test helpers.

The legacy tests (`tests/test_ingest_resume.py`) drive `analyzer.py` through
`start()`, `drain()`, `restart()` and a `seen` list of the alerts handed to the
analysis. `Harness` offers the same verbs for `wazuh_ai_analyzer.ingest`, so the
ported tests read like the originals.
"""

from __future__ import annotations

import gzip
import json
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

from wazuh_ai_analyzer.config import BatchingConfig
from wazuh_ai_analyzer.ingest.archives import MONTHS, AlertFiles
from wazuh_ai_analyzer.ingest.backlog import BacklogWorker
from wazuh_ai_analyzer.ingest.batches import BatchWriter, StoredBatch
from wazuh_ai_analyzer.ingest.counters import IngestCounters
from wazuh_ai_analyzer.ingest.live import LiveTailer
from wazuh_ai_analyzer.ingest.parse import Alert
from wazuh_ai_analyzer.ingest.planner import plan_resume
from wazuh_ai_analyzer.ingest.watermark import Cursor, WatermarkStore
from wazuh_ai_analyzer.storage.contract import Source
from wazuh_ai_analyzer.storage.repo import Repository

DEFAULT_BATCHING = BatchingConfig(
    batch_max=25,
    batch_timeout=300,
    batch_timeout_quiet=0,
    urgent_level=10,
    min_level=5,
    history_batch=50,
    history_pause=0.0,
)


def alert(n: int, level: int = 7) -> dict[str, Any]:
    return {
        "timestamp": "2026-10-07T10:00:00.000+0000",
        "id": f"evt-{n}",
        "rule": {"id": "5710", "level": level, "description": "sshd"},
        "agent": {"name": "ct100"},
        "location": "journald",
        "full_log": f"evt-{n}",
    }


def lines(*numbers: int, level: int = 7) -> bytes:
    return "".join(json.dumps(alert(n, level)) + "\n" for n in numbers).encode()


def ev(*numbers: int) -> list[str]:
    return [f"evt-{n}" for n in numbers]


def write(path: Path, data: bytes, mode: str = "wb") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(mode) as fh:
        fh.write(data)


def archive_path(alerts_log: Path, day: date, suffix: str = ".json.gz") -> Path:
    return (
        alerts_log.parent
        / f"{day.year}"
        / MONTHS[day.month - 1]
        / f"ossec-alerts-{day.day:02d}{suffix}"
    )


def write_gz(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb") as fh:
        fh.write(data)


def rotate(
    alerts_log: Path, day: date, final_content: bytes, new_content: bytes, *, compress: bool = True
) -> Path:
    """Wazuh's midnight rotation: the day's alerts become a dated archive and
    alerts.json starts over as a new file."""
    arch = archive_path(alerts_log, day, ".json.gz" if compress else ".json")
    if compress:
        write_gz(arch, final_content)
    else:
        write(arch, final_content)
    alerts_log.unlink()
    write(alerts_log, new_content)
    return arch


def wait_for(predicate: Callable[[], object], timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class RecordingWriter(BatchWriter):
    """Stores batches for real and records the `full_log` of every alert in them.

    `fail` may raise to simulate a database error or a crash before the insert.
    """

    def __init__(self, repo: Repository, batches: list[list[str]]) -> None:
        super().__init__(repo)
        self.batches = batches
        self.stored: list[StoredBatch] = []
        self.fail: Callable[[Sequence[Alert], Source], None] | None = None

    def store(self, alerts: Sequence[Alert], source: Source) -> StoredBatch:
        if self.fail is not None:
            self.fail(alerts, source)
        stored = super().store(alerts, source)
        self.batches.append([str(a.get("full_log")) for a in alerts])
        self.stored.append(stored)
        return stored


@dataclass
class Harness:
    alerts_log: Path
    watermark_path: Path
    repo: Repository
    batching: BatchingConfig = DEFAULT_BATCHING
    poll_interval: float = 0.05
    idle_commit: float = 0.0
    batches: list[list[str]] = field(default_factory=list)
    dispatched: list[StoredBatch] = field(default_factory=list)
    analysed: list[StoredBatch] = field(default_factory=list)
    counters: IngestCounters = field(default_factory=IngestCounters)
    plan_ready: threading.Event = field(default_factory=threading.Event)
    stop: threading.Event = field(default_factory=threading.Event)
    gate: Callable[[], float] = lambda: 0.0

    def __post_init__(self) -> None:
        self.files = AlertFiles(self.alerts_log)
        self.writer = RecordingWriter(self.repo, self.batches)
        self.watermark = WatermarkStore(self.watermark_path)
        self._build()

    def _build(self) -> None:
        self.tailer = LiveTailer(
            files=self.files,
            watermark=self.watermark,
            writer=self.writer,
            dispatch=self.dispatched.append,
            counters=self.counters,
            plan_ready=self.plan_ready,
            batching=self.batching,
            idle_commit=self.idle_commit,
            poll_interval=self.poll_interval,
            restart_delay=0.01,
            store_retry_base=0.02,
            store_retry_max=0.05,
        )
        self.worker = BacklogWorker(
            files=self.files,
            watermark=self.watermark,
            writer=self.writer,
            analyse=self.analysed.append,
            counters=self.counters,
            plan_ready=self.plan_ready,
            batching=self.batching,
            stop=self.stop,
            gate=self.gate,
            retry_delay=0.0,
        )

    def configure(self, **changes: Any) -> None:
        """Change batching settings (BATCH_MAX, HISTORY_BATCH ...) and rebuild."""
        self.batching = replace(self.batching, **changes)
        self._build()

    # ── the verbs of the legacy tests ────────────────────────────────────────
    def flat(self) -> list[str]:
        return [x for batch in self.batches for x in batch]

    def start(self) -> Cursor:
        """What the live thread does at startup, minus the endless loop."""
        self.watermark.load()
        with self.alerts_log.open("rb") as f:
            cursor = plan_resume(
                f, files=self.files, watermark=self.watermark, counters=self.counters
            )
        self.plan_ready.set()
        return cursor

    def drain(self) -> None:
        while self.worker.run_once():
            pass

    def restart(self) -> None:
        """A new process: nothing in memory, only watermark.json (and the DB) on disk."""
        self.watermark = WatermarkStore(self.watermark_path)
        self.stop = threading.Event()
        self._build()

    # ── the live tailer in a thread ──────────────────────────────────────────
    def run_tailer(self) -> TailerThread:
        return TailerThread(self)


class TailerThread:
    """Runs `LiveTailer.tail` in a thread; remembers an exception that ended it."""

    def __init__(self, harness: Harness) -> None:
        self.stop = threading.Event()
        self.error: BaseException | None = None
        self._tailer = harness.tailer
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            self._tailer.tail(self.stop)
        except BaseException as exc:  # the test inspects it
            self.error = exc

    def close(self) -> None:
        self.stop.set()
        self.thread.join(10)
        assert not self.thread.is_alive()
