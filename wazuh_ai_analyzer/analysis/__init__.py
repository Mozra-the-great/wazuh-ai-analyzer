"""Analysis backends behind one interface: `llm` (#85) and `decision` (#88).

* `backend`   the `AnalysisBackend` protocol, `AnalysisResult`, `BackendFailure`
* `prompt`    the LLM prompt (data isolation) and the strict answer validation
* `llm`       Gemini `generateContent` over plain REST
* `decision`  Gemini Decision 1 (`decisions` endpoint): probabilities per alert group
* `decisions` the versioned question definitions (`v1.json`) of the decision mode
* `text_templates` the German texts of the decision mode
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
from .decision import GeminiDecisionBackend
from .decisions import DefinitionsError
from .llm import GeminiLlmBackend

__all__ = [
    "AnalysisBackend",
    "AnalysisResult",
    "BackendFailure",
    "BatchContext",
    "FailureKind",
    "Finding",
    "GeminiDecisionBackend",
    "GeminiLlmBackend",
    "create_backend",
]


def create_backend(config: Config) -> AnalysisBackend:
    """The backend of `ANALYSIS_MODE`.

    The decision definitions are validated here, so a broken file stops the start
    (exit code 78) instead of failing on the first batch.
    """
    if config.analysis.mode == "decision":
        try:
            return GeminiDecisionBackend.from_config(config)
        except DefinitionsError as exc:
            raise ConfigError(
                [f"ANALYSIS_MODE=decision: unusable decision definitions: {exc}"]
            ) from None
    return GeminiLlmBackend.from_config(config.gemini)
