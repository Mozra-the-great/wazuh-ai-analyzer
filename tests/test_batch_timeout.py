"""Tiered flush window: quiet (low-level) buffers wait longer, urgent ones do not."""
import importlib
import sys

import pytest

pytest.importorskip("flask")


def a(level):
    return {"rule": {"id": "1", "level": level}}


def test_default_keeps_single_timeout(az):
    assert az.BATCH_TIMEOUT_QUIET == az.BATCH_TIMEOUT
    assert az._flush_timeout([a(5), a(12)]) == az.BATCH_TIMEOUT


def test_quiet_buffer_waits_longer_but_urgent_does_not(az, monkeypatch):
    monkeypatch.setattr(az, "BATCH_TIMEOUT", 300)
    monkeypatch.setattr(az, "BATCH_TIMEOUT_QUIET", 900)
    monkeypatch.setattr(az, "URGENT_LEVEL", 10)
    assert az._flush_timeout([a(5), a(7), a(9)]) == 900
    assert az._flush_timeout([a(5), a(10)]) == 300
    assert az._flush_timeout([a(15)]) == 300


def test_malformed_alerts_do_not_break_the_decision(az, monkeypatch):
    monkeypatch.setattr(az, "BATCH_TIMEOUT_QUIET", 900)
    assert az._flush_timeout([{}, {"rule": "x"}, {"rule": {"level": "n/a"}}]) == 900


def test_quiet_window_is_never_shorter_than_the_normal_timeout(monkeypatch):
    monkeypatch.setenv("BATCH_TIMEOUT", "300")
    monkeypatch.setenv("BATCH_TIMEOUT_QUIET", "60")
    sys.modules.pop("analyzer", None)
    mod = importlib.import_module("analyzer")
    try:
        assert mod.BATCH_TIMEOUT_QUIET == 300
    finally:
        sys.modules.pop("analyzer", None)
