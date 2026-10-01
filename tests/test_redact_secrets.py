import logging
import os
import sys

import pytest

pytest.importorskip("flask")
os.environ["GEMINI_API_KEY"] = "SECRET-KEY-123"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import analyzer  # noqa: E402


def _emit(msg, *args):
    rec = logging.LogRecord("t", logging.ERROR, __file__, 1, msg, args, None)
    analyzer._RedactSecrets().filter(rec)
    return rec.getMessage()


def test_masks_key_query_parameter():
    out = _emit("GET https://x/generateContent?key=abc123&alt=json failed")
    assert "abc123" not in out and "key=***&alt=json" in out


def test_masks_header_dump():
    out = _emit("headers {'x-goog-api-key': 'abc123'}")
    assert "abc123" not in out and "***" in out


def test_masks_literal_key_in_exception_text():
    out = _emit("boom: %s", RuntimeError("token SECRET-KEY-123 rejected"))
    assert "SECRET-KEY-123" not in out and "***" in out


def test_clean_message_untouched():
    assert _emit("all fine %d", 3) == "all fine 3"


def test_filter_installed_on_root_handlers():
    # pytest adds its own capture handlers, so check that the one basicConfig
    # installed carries the filter rather than demanding it of every handler.
    assert any(any(isinstance(f, analyzer._RedactSecrets) for f in h.filters)
               for h in logging.getLogger().handlers)
