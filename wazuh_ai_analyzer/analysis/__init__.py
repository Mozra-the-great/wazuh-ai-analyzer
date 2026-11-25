"""Analysis backends behind one interface: `llm` (#85) and `decision` (#88).

* `backend` the `AnalysisBackend` protocol, `AnalysisResult`, `BackendFailure`
* `prompt`  the LLM prompt (data isolation) and the strict answer validation
* `llm`     Gemini `generateContent` over plain REST
"""

from __future__ import annotations

from ..config import Config, ConfigError
from .backend import (
    AnalysisBackend,
    AnalysisResult,
    BackendFailure,
    BatchContext,
    FailureKind,
    Finding,
)
from .llm import GeminiLlmBackend

__all__ = [
    "AnalysisBackend",
    "AnalysisResult",
    "BackendFailure",
    "BatchContext",
    "FailureKind",
    "Finding",
    "GeminiLlmBackend",
    "create_backend",
]


def create_backend(config: Config) -> AnalysisBackend:
    """The backend of `ANALYSIS_MODE`.

    `decision` is accepted by the configuration but implemented in #88; until then
    a service started in that mode refuses to run instead of silently using `llm`.
    """
    if config.analysis.mode == "llm":
        return GeminiLlmBackend.from_config(config.gemini)
    raise ConfigError(
        [f"ANALYSIS_MODE: mode {config.analysis.mode!r} is not available in this version, use llm"]
    )
