"""The `runtime` block of `/api/stats`: ingest and pipeline counters under the legacy names.

There is no metrics endpoint in the app (that would be a new feature). External
monitoring reads the database (see `storage.contract`); the dashboard reads this
block. Its keys and their order are those of `analyzer.py`'s `_stats`, followed by
the counters that are new in the rewrite.
"""

from __future__ import annotations

from typing import Final

from ..ingest.counters import IngestStats
from ..pipeline.counters import PipelineStats

LEGACY_RUNTIME_KEYS: Final = (
    "processed",
    "skipped",
    "batches_sent",
    "errors",
    "history_alerts",
    "history_done",
    "history_files_total",
    "history_files_done",
    "retries_scheduled",
    "retries_succeeded",
    "recovered_stale",
    "dropped_permanent",
    "dropped_bad_response",
    "expired",
    "suspicious_downgrades",
    "purged_batches",
)
# New in the rewrite: lines the legacy code dropped silently, and groups the provider blocked.
NEW_RUNTIME_KEYS: Final = ("invalid_lines", "oversized_lines", "safety_blocked")


def runtime_counters(ingest: IngestStats, pipeline: PipelineStats) -> dict[str, int | bool]:
    values: dict[str, int | bool] = {**ingest.as_dict(), **pipeline.as_dict()}
    return {key: values[key] for key in (*LEGACY_RUNTIME_KEYS, *NEW_RUNTIME_KEYS)}
