"""The log redaction filter (S7, #41)."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

from wazuh_ai_analyzer.logging_setup import RedactSecrets, configure_logging

KEY = "AIzaSyREDACT-ME-0123456789"


@pytest.fixture
def restore_root_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for handler in list(root.handlers):
        root.removeHandler(handler)
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(level)


def make_record(msg: str, *args: object, exc: bool = False) -> logging.LogRecord:
    exc_info = None
    if exc:
        try:
            raise RuntimeError(f"upstream said {KEY}")
        except RuntimeError as error:
            exc_info = (type(error), error, error.__traceback__)
    return logging.LogRecord("t", logging.ERROR, __file__, 1, msg, args or None, exc_info)


def test_known_secret_values_are_masked_in_message_and_args() -> None:
    redactor = RedactSecrets([KEY])
    record = make_record("request with %s failed", KEY)
    assert redactor.filter(record) is True
    assert record.getMessage() == "request with *** failed"


@pytest.mark.parametrize(
    "text",
    [
        f"GET https://example.test/x?key={KEY}&alt=json",
        f"headers: x-goog-api-key: {KEY}",
        f"headers: {{'x-goog-api-key': '{KEY}'}}",
    ],
)
def test_key_patterns_are_masked_even_when_the_value_is_unknown(text: str) -> None:
    redacted = RedactSecrets().scrub(text)
    assert KEY not in redacted
    assert "***" in redacted


def test_tracebacks_are_scrubbed() -> None:
    redactor = RedactSecrets([KEY])
    record = make_record("call failed", exc=True)
    redactor.filter(record)
    assert record.exc_text is not None
    assert KEY not in record.exc_text
    assert "RuntimeError" in record.exc_text


def test_formatted_output_has_no_secret_after_the_filter() -> None:
    redactor = RedactSecrets([KEY])
    record = make_record("call failed", exc=True)
    redactor.filter(record)
    assert KEY not in logging.Formatter("%(message)s").format(record)


def test_longest_secret_is_masked_first_and_tiny_values_are_ignored() -> None:
    redactor = RedactSecrets(["abcd", "abcdefgh", "ab", ""])
    assert redactor.scrub("x abcdefgh y ab z") == "x *** y ab z"


def test_clean_records_are_untouched() -> None:
    redactor = RedactSecrets([KEY])
    record = make_record("batch %d done", 3)
    redactor.filter(record)
    assert record.getMessage() == "batch 3 done"


@pytest.mark.usefixtures("restore_root_logging")
def test_configure_logging_protects_every_root_handler(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging([KEY])
    logging.getLogger("urllib3").error("POST /x?key=%s", KEY)
    logging.getLogger("wazuh-ai").error("raw %s", KEY)
    captured = capsys.readouterr().err
    assert KEY not in captured
    assert captured.count("***") == 2
