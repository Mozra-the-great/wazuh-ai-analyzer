"""Versioned decision definitions for the `decision` analysis mode (#88).

The questions asked of Gemini Decision 1, the written definition of every severity
option and the recommendation texts live in `v1.json`, next to the code, so a change
is reviewed like code and every stored finding says which definitions produced it.

`decision_version` is `<version>-<hash>`: the `version` field of the file and the
first 12 hex digits of the SHA-256 of its canonical JSON. Editing a definition
without bumping `version` still changes the hash, so two different sets of
definitions can never share a `decision_version`.

The file is validated when the service starts (`load_definitions`): unknown keys,
a missing required question, fewer than two options, a malformed key or an empty text
refuse the start (`DefinitionsError`) instead of failing on the first real batch.

Rules of the Decisions API that are checked here (docs: aistudio.google.com/docs/decisions-api):
a question key matches `[A-Za-z0-9_-]{1,64}`, there are 1 to 1000 questions, a `choice`
has 2 to 255 options, a `score` has 2 to 255 levels. Option keys are held to 128 bytes here
(the API allows up to 512), which is plenty for severities.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from ...storage.contract import SEVERITIES

QuestionType = Literal["noul", "choice", "score"]
QUESTION_TYPES: Final[tuple[str, ...]] = ("noul", "choice", "score")

DEFINITIONS_PATH: Final = Path(__file__).with_name("v1.json")
MAX_DEFINITIONS_BYTES: Final = 256 * 1024

QUESTION_KEY_RE: Final = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_QUESTIONS: Final = 1000
MIN_OPTIONS: Final = 2
MAX_OPTIONS: Final = 255
MAX_OPTION_KEY: Final = 128
HASH_LENGTH: Final = 12

# What the mapping to findings needs. v1 has no more questions than these.
RELEVANT: Final = "relevant"
SEVERITY: Final = "severity"
RUBRIC_KEYS: Final[tuple[str, ...]] = ("needs_action_now", "already_blocked", "known_benign")
REQUIRED_QUESTIONS: Final[Mapping[str, QuestionType]] = {
    RELEVANT: "noul",
    SEVERITY: "choice",
    "needs_action_now": "noul",
    "already_blocked": "noul",
    "known_benign": "noul",
}
RECOMMENDATION_KEYS: Final[tuple[str, ...]] = (*RUBRIC_KEYS, "default")

_TOP_LEVEL_KEYS = frozenset({"version", "rubric_true_at", "questions", "recommendations"})
_QUESTION_KEYS = frozenset({"type", "instructions", "criteria", "infra_context"})
_NOUL_CRITERIA = frozenset({"true_description", "false_description"})


class DefinitionsError(ValueError):
    """The decision definitions are unusable. Raised at startup, never at request time."""


@dataclass(frozen=True, slots=True)
class Question:
    key: str
    type: QuestionType
    instructions: str
    # noul: optional {"true_description", "false_description"}; choice: option -> description;
    # score: ordered level descriptions; None when the question has no criteria.
    criteria: Mapping[str, str] | tuple[str, ...] | None
    # The operator's INFRA_CONTEXT is appended to the instructions of this question.
    infra_context: bool = False

    @property
    def options(self) -> tuple[str, ...]:
        """The option keys of a `choice` question (empty for the other types)."""
        return tuple(self.criteria) if isinstance(self.criteria, Mapping) else ()

    @property
    def levels(self) -> int:
        """The number of levels of a `score` question (0 for the other types)."""
        return len(self.criteria) if isinstance(self.criteria, tuple) else 0


@dataclass(frozen=True, slots=True)
class Definitions:
    version: int
    decision_version: str
    questions: tuple[Question, ...]
    rubric_true_at: float
    recommendations: Mapping[str, str]

    def question(self, key: str) -> Question:
        for question in self.questions:
            if question.key == key:
                return question
        raise KeyError(key)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DefinitionsError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DefinitionsError(f"{where}: a non-empty text is required")
    return value


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise DefinitionsError(f"{where}: an object is required")
    return cast("Mapping[str, object]", value)


def _parse_criteria(
    key: str, kind: QuestionType, raw: object
) -> Mapping[str, str] | tuple[str, ...] | None:
    where = f"question {key!r}: criteria"
    if kind == "noul":
        if raw is None:
            return None
        criteria = _mapping(raw, where)
        unknown = set(criteria) - _NOUL_CRITERIA
        if unknown:
            raise DefinitionsError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
        return {name: _text(value, f"{where}.{name}") for name, value in criteria.items()}
    if kind == "choice":
        options = _mapping(raw, where)
        if not MIN_OPTIONS <= len(options) <= MAX_OPTIONS:
            raise DefinitionsError(f"{where}: {MIN_OPTIONS} to {MAX_OPTIONS} options are required")
        for name in options:
            if not 1 <= len(name.encode("utf-8")) <= MAX_OPTION_KEY:
                raise DefinitionsError(f"{where}: option keys are 1 to {MAX_OPTION_KEY} bytes")
        return {name: _text(value, f"{where}.{name}") for name, value in options.items()}
    if not isinstance(raw, list) or not MIN_OPTIONS <= len(raw) <= MAX_OPTIONS:
        raise DefinitionsError(f"{where}: a list of {MIN_OPTIONS} to {MAX_OPTIONS} levels")
    return tuple(_text(level, f"{where}[{n}]") for n, level in enumerate(raw))


def _parse_question(key: str, raw: object) -> Question:
    if not QUESTION_KEY_RE.match(key):
        raise DefinitionsError(f"question key {key!r} must match {QUESTION_KEY_RE.pattern}")
    data = _mapping(raw, f"question {key!r}")
    unknown = set(data) - _QUESTION_KEYS
    if unknown:
        raise DefinitionsError(f"question {key!r}: unknown key(s) {', '.join(sorted(unknown))}")
    kind = data.get("type")
    if kind not in QUESTION_TYPES:
        raise DefinitionsError(f"question {key!r}: type must be one of {', '.join(QUESTION_TYPES)}")
    infra = data.get("infra_context", False)
    if not isinstance(infra, bool):
        raise DefinitionsError(f"question {key!r}: infra_context must be true or false")
    question_type = cast(QuestionType, kind)
    return Question(
        key=key,
        type=question_type,
        instructions=_text(data.get("instructions"), f"question {key!r}: instructions"),
        criteria=_parse_criteria(key, question_type, data.get("criteria")),
        infra_context=infra,
    )


def parse_definitions(raw: bytes) -> Definitions:
    """Validate the bytes of a definitions file. Raises `DefinitionsError`."""
    if len(raw) > MAX_DEFINITIONS_BYTES:
        raise DefinitionsError("the definitions file is too large")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except DefinitionsError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise DefinitionsError(f"not valid UTF-8 JSON: {exc}") from None
    top = _mapping(document, "definitions")
    unknown = set(top) - _TOP_LEVEL_KEYS
    missing = _TOP_LEVEL_KEYS - set(top)
    if unknown or missing:
        problems = [f"unknown key(s) {', '.join(sorted(unknown))}"] if unknown else []
        problems += [f"missing key(s) {', '.join(sorted(missing))}"] if missing else []
        raise DefinitionsError("; ".join(problems))
    version = top["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise DefinitionsError("version must be a whole number of at least 1")
    true_at = top["rubric_true_at"]
    if isinstance(true_at, bool) or not isinstance(true_at, int | float) or not 0 < true_at < 1:
        raise DefinitionsError("rubric_true_at must be a number above 0 and below 1")

    raw_questions = _mapping(top["questions"], "questions")
    if not 1 <= len(raw_questions) <= MAX_QUESTIONS:
        raise DefinitionsError(f"1 to {MAX_QUESTIONS} questions are required")
    questions = tuple(_parse_question(key, value) for key, value in raw_questions.items())
    by_key = {question.key: question for question in questions}
    for key, kind in REQUIRED_QUESTIONS.items():
        question = by_key.get(key)
        if question is None:
            raise DefinitionsError(f"the question {key!r} is required")
        if question.type != kind:
            raise DefinitionsError(f"the question {key!r} must be of type {kind}")
    if set(by_key[SEVERITY].options) != set(SEVERITIES):
        raise DefinitionsError(
            f"the options of {SEVERITY!r} must be exactly {', '.join(SEVERITIES)}"
        )

    raw_recommendations = _mapping(top["recommendations"], "recommendations")
    if set(raw_recommendations) != set(RECOMMENDATION_KEYS):
        raise DefinitionsError(f"recommendations must be exactly {', '.join(RECOMMENDATION_KEYS)}")
    recommendations = {
        key: _text(raw_recommendations[key], f"recommendations.{key}")
        for key in RECOMMENDATION_KEYS
    }
    return Definitions(
        version=version,
        decision_version=f"{version}-{_digest(top)}",
        questions=questions,
        rubric_true_at=float(true_at),
        recommendations=recommendations,
    )


def _digest(document: Mapping[str, object]) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:HASH_LENGTH]


def load_definitions(path: Path | None = None) -> Definitions:
    """Read and validate a definitions file (default: the shipped `v1.json`)."""
    path = DEFINITIONS_PATH if path is None else path
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_DEFINITIONS_BYTES + 1)
    except OSError as exc:
        raise DefinitionsError(f"cannot read {path.name}: {exc.strerror or exc}") from None
    return parse_definitions(raw)
