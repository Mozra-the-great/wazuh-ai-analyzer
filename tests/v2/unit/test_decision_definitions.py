"""The versioned decision definitions (#88): shipped file, validation, version hash."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from wazuh_ai_analyzer.analysis.decisions import (
    DEFINITIONS_PATH,
    MAX_DEFINITIONS_BYTES,
    DefinitionsError,
    load_definitions,
    parse_definitions,
)
from wazuh_ai_analyzer.storage.contract import SEVERITIES


def shipped() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(DEFINITIONS_PATH.read_text(encoding="utf-8"))
    return document


def parse(document: dict[str, Any]) -> Any:
    return parse_definitions(json.dumps(document).encode("utf-8"))


def mutated(change: Any) -> dict[str, Any]:
    document = copy.deepcopy(shipped())
    change(document)
    return document


def test_the_shipped_definitions_load_and_have_the_v1_questions() -> None:
    definitions = load_definitions()
    assert [q.key for q in definitions.questions] == [
        "relevant",
        "severity",
        "known_benign",
        "already_blocked",
        "needs_action_now",
    ]
    assert [q.type for q in definitions.questions] == ["noul", "choice", "noul", "noul", "noul"]
    assert set(definitions.question("severity").options) == set(SEVERITIES)
    assert definitions.version == 1
    assert 0 < definitions.rubric_true_at < 1


def test_the_file_is_utf8_with_lf_line_endings() -> None:
    raw = DEFINITIONS_PATH.read_bytes()
    assert b"\r" not in raw
    raw.decode("utf-8")


def test_decision_version_is_the_version_and_a_hash_of_the_content() -> None:
    definitions = load_definitions()
    assert definitions.decision_version.startswith("1-")
    assert len(definitions.decision_version) == len("1-") + 12
    assert load_definitions().decision_version == definitions.decision_version


def test_editing_a_text_changes_the_version_even_without_bumping_it() -> None:
    before = parse(shipped()).decision_version

    def edit(document: dict[str, Any]) -> None:
        document["questions"]["relevant"]["instructions"] += " Extra."

    after = parse(mutated(edit)).decision_version
    assert after != before
    assert after.split("-")[0] == before.split("-")[0] == "1"


def test_the_hash_ignores_key_order_and_whitespace() -> None:
    document = shipped()
    reordered = json.dumps(dict(reversed(list(document.items()))), indent=4).encode("utf-8")
    assert parse_definitions(reordered).decision_version == parse(document).decision_version


def test_a_noul_question_may_have_no_criteria() -> None:
    def edit(document: dict[str, Any]) -> None:
        del document["questions"]["already_blocked"]["criteria"]

    assert parse(mutated(edit)).question("already_blocked").criteria is None


def test_a_score_question_is_supported() -> None:
    def edit(document: dict[str, Any]) -> None:
        document["questions"]["urgency"] = {
            "type": "score",
            "instructions": "How urgent is it?",
            "criteria": ["Low: later", "Medium: soon", "High: now"],
        }

    question = parse(mutated(edit)).question("urgency")
    assert question.type == "score"
    assert question.levels == 3


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d.update(extra=1), "unknown key"),
        (lambda d: d.pop("recommendations"), "missing key"),
        (lambda d: d.update(version=0), "version"),
        (lambda d: d.update(version=True), "version"),
        (lambda d: d.update(version="1"), "version"),
        (lambda d: d.update(rubric_true_at=0), "rubric_true_at"),
        (lambda d: d.update(rubric_true_at=1), "rubric_true_at"),
        (lambda d: d.update(rubric_true_at="half"), "rubric_true_at"),
        (lambda d: d.update(questions={}), "questions"),
        (lambda d: d["questions"].pop("relevant"), "'relevant' is required"),
        (lambda d: d["questions"].pop("severity"), "'severity' is required"),
        (lambda d: d["questions"].pop("known_benign"), "'known_benign' is required"),
        (lambda d: d["questions"]["relevant"].update(type="choice"), "must be of type noul"),
        (lambda d: d["questions"]["severity"].update(type="noul"), "unknown key"),
        (lambda d: d["questions"]["relevant"].update(type="bogus"), "type must be one of"),
        (lambda d: d["questions"]["relevant"].update(extra=1), "unknown key"),
        (lambda d: d["questions"]["relevant"].update(instructions=" "), "instructions"),
        (lambda d: d["questions"]["relevant"].update(infra_context="yes"), "infra_context"),
        (lambda d: d["questions"]["relevant"]["criteria"].update(maybe="x"), "unknown key"),
        (lambda d: d["questions"]["relevant"]["criteria"].update(true_description=""), "text"),
        (
            lambda d: d["questions"].update({"bad key": copy.deepcopy(d["questions"]["relevant"])}),
            "match",
        ),
        (
            lambda d: d["questions"].update({"x" * 65: copy.deepcopy(d["questions"]["relevant"])}),
            "match",
        ),
        (lambda d: d["questions"]["severity"].update(criteria={"info": "only one"}), "options"),
        (lambda d: d["questions"]["severity"]["criteria"].pop("critical"), "must be exactly"),
        (lambda d: d["questions"]["severity"]["criteria"].update(urgent="x"), "must be exactly"),
        (lambda d: d["questions"]["severity"]["criteria"].update(info=""), "text"),
        (lambda d: d["questions"]["severity"]["criteria"].update({"k" * 129: "x"}), "bytes"),
        (lambda d: d["recommendations"].pop("default"), "recommendations must be exactly"),
        (lambda d: d["recommendations"].update(extra="x"), "recommendations must be exactly"),
        (lambda d: d["recommendations"].update(default=""), "text"),
    ],
)
def test_broken_definitions_are_refused(change: Any, message: str) -> None:
    with pytest.raises(DefinitionsError, match=message):
        parse(mutated(change))


@pytest.mark.parametrize(
    "criteria",
    [["only one"], "text", [""], ["a"] * 256, None],
)
def test_a_score_question_needs_2_to_255_non_empty_levels(criteria: Any) -> None:
    def edit(document: dict[str, Any]) -> None:
        document["questions"]["urgency"] = {
            "type": "score",
            "instructions": "x",
            "criteria": criteria,
        }

    with pytest.raises(DefinitionsError):
        parse(mutated(edit))


def test_a_choice_question_may_not_have_more_than_255_options() -> None:
    def edit(document: dict[str, Any]) -> None:
        document["questions"]["pick"] = {
            "type": "choice",
            "instructions": "x",
            "criteria": {f"o{n}": "text" for n in range(256)},
        }

    with pytest.raises(DefinitionsError, match="options"):
        parse(mutated(edit))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'"text"',
        b"\xff\xfe",
        b'{"version": 1, "version": 2}',
        b"[" * 10000,
    ],
)
def test_garbage_is_refused_with_a_definitions_error(raw: bytes) -> None:
    with pytest.raises(DefinitionsError):
        parse_definitions(raw)


def test_an_oversized_file_is_refused() -> None:
    with pytest.raises(DefinitionsError, match="too large"):
        parse_definitions(b" " * (MAX_DEFINITIONS_BYTES + 1))


def test_load_reports_a_missing_file_without_a_path_traversal_detail(tmp_path: Path) -> None:
    with pytest.raises(DefinitionsError, match=r"cannot read nope\.json"):
        load_definitions(tmp_path / "nope.json")


def test_load_reads_a_custom_file(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    path.write_text(json.dumps(shipped()), encoding="utf-8")
    assert load_definitions(path).decision_version == load_definitions().decision_version


def test_every_severity_option_has_a_written_definition() -> None:
    options = load_definitions().question("severity").criteria
    assert isinstance(options, dict)
    assert all(len(text) > 20 for text in options.values())
