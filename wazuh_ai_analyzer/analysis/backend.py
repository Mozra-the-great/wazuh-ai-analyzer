"""The one interface between the pipeline and an analysis backend (#85).

A backend turns the sanitised alert groups of one batch into an `AnalysisResult`,
or raises one `BackendFailure` that says what kind of failure it was. The pipeline
owns everything around the call: the retry queue, the backoff, the quota and
upstream gates, the concurrency limit and storing the result. A backend never
sleeps, never retries and never touches the quota state itself, so a new backend
(the `decision` mode of #88) only implements `analyse`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol, get_args

from ..ingest.sanitize import AlertGroup
from ..storage.contract import AnalysisMode, OverallRisk, Source
from ..storage.repo import NewFinding

FailureKind = Literal["transient", "quota", "permanent", "bad_response", "config"]
FAILURE_KINDS: Final[tuple[str, ...]] = get_args(FailureKind)

# The findings of a result have the shape storage takes (title, severity, description,
# recommendation, agents, rule ids, optional confidence, optional raw decision).
Finding = NewFinding


class BackendFailure(Exception):
    """Why a backend produced no usable result. The kind decides what the pipeline does.

    * `quota`        the provider's quota is used up: wait `retry_after` seconds; the
                     batch keeps its place in the queue (the queue age limit still applies)
    * `transient`    5xx/408/425, timeout, connection error: retry with backoff
    * `config`       missing/invalid key, wrong model, unsupported region: retry slowly,
                     the operator can fix it and the parked batches survive
    * `bad_response` an answer that cannot be used: a few retries only
    * `permanent`    any other client error: retrying the same payload cannot help

    `message` ends up in `batches.last_error` (scrubbed and capped by the pipeline) and
    must never contain a secret.
    """

    def __init__(self, kind: FailureKind, message: str, retry_after: float = 0.0) -> None:
        if kind not in FAILURE_KINDS:
            raise ValueError(f"unknown failure kind {kind!r}")
        super().__init__(message)
        self.kind: FailureKind = kind
        self.message = message
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"BackendFailure({self.kind!r}, {self.message!r}, retry_after={self.retry_after!r})"


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """A validated answer, ready to be stored with `Repository.complete_batch`."""

    summary: str
    overall_risk: OverallRisk
    findings: tuple[Finding, ...]
    mode: AnalysisMode = "llm"
    decision_version: str | None = None
    # Findings that rate a rule of a high Wazuh level as info/low (#38). Counted by
    # the pipeline, never changed.
    suspicious_downgrades: int = 0
    # Groups the provider refused to look at (safety block), stored as placeholder findings.
    safety_blocked: int = 0
    # Findings whose severity `calibration` lowered after the backend had rated them.
    calibrated: int = 0


class PartialStore(Protocol):
    """Where a backend that answers per group keeps the answers of a batch it has so far.

    The document is opaque to storage. `Repository` implements this, and clears it when
    the batch is completed.
    """

    def load_decision_partial(self, batch_id: int) -> str | None: ...

    def save_decision_partial(self, batch_id: int, document: str) -> None: ...


@dataclass(frozen=True, slots=True)
class BatchContext:
    """Which batch an analysis belongs to.

    The LLM backend does not need it. A backend that answers per group (decision
    mode) uses `batch_id` and `partial` to keep the answers it already has across
    retries: the batch is the retry unit, but a group that was answered is not paid
    for twice.
    """

    batch_id: int
    source: Source
    is_retry: bool
    partial: PartialStore | None = None


class AnalysisBackend(Protocol):
    """An analysis mode. Implementations must be safe to call from several threads."""

    @property
    def name(self) -> AnalysisMode: ...

    def analyse(self, groups: Sequence[AlertGroup], context: BatchContext) -> AnalysisResult:
        """Analyse one batch; raise `BackendFailure` for every expected failure."""
        ...
