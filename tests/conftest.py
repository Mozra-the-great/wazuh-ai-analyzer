import os
import sys
import tempfile
import threading

import pytest

# analyzer.py reads its configuration at import time. Point every path at a
# throw-away directory *before* the first import so a test run can never touch
# /opt/wazuh-ai-analyzer or /var/ossec.
_SCRATCH = tempfile.mkdtemp(prefix="wazuh-ai-tests-")
os.environ["GEMINI_API_KEY"] = "SECRET-KEY-123"
os.environ["DB_PATH"] = os.path.join(_SCRATCH, "data", "analyses.db")
os.environ["WAZUH_ALERTS_LOG"] = os.path.join(_SCRATCH, "alerts", "alerts.json")
os.environ["STATIC_DIR"] = os.path.join(_SCRATCH, "static")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture
def az(tmp_path, monkeypatch):
    """The analyzer module with an empty database, empty alert directory and
    pristine in-memory state (quota, upstream backoff, counters, buffer)."""
    pytest.importorskip("flask")
    import analyzer

    data = tmp_path / "data"
    alerts = tmp_path / "alerts"
    data.mkdir()
    alerts.mkdir()
    monkeypatch.setattr(analyzer, "DB_PATH", str(data / "analyses.db"))
    monkeypatch.setattr(analyzer, "WATERMARK_FILE", data / "watermark.json")
    monkeypatch.setattr(analyzer, "ALERTS_LOG", str(alerts / "alerts.json"))
    monkeypatch.setattr(analyzer, "quota", analyzer.QuotaState())
    monkeypatch.setattr(analyzer, "upstream", analyzer.UpstreamState())
    monkeypatch.setattr(analyzer, "_stats", dict(analyzer._stats))
    for key in analyzer._stats:
        analyzer._stats[key] = False if key == "history_done" else 0
    monkeypatch.setattr(analyzer, "alert_buffer", [])
    monkeypatch.setattr(analyzer, "_inflight", set())
    monkeypatch.setattr(analyzer, "_permanent_streak", 0)
    monkeypatch.setattr(analyzer, "watermark", analyzer.WatermarkStore(data / "watermark.json"))
    monkeypatch.setattr(analyzer, "live_cursor", analyzer._LiveCursor())
    monkeypatch.setattr(analyzer, "plan_ready", threading.Event())
    monkeypatch.setattr(analyzer, "_segment_failures", {})
    monkeypatch.setattr(analyzer, "HISTORY_PAUSE", 0)
    analyzer.init_db()
    return analyzer


@pytest.fixture
def client(az, monkeypatch):
    """Flask test client with a valid dashboard session."""
    monkeypatch.setattr(az, "DASHBOARD_PASSWORD_HASH", "x")
    c = az.app.test_client()
    with c.session_transaction() as sess:
        sess.update(authenticated=True, user=az.DASHBOARD_USER, expires_at=az._now() + 600)
    return c
