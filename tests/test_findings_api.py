"""Regression tests for #47: /api/findings crashed on sqlite3.Row.get()."""
import json

import pytest

pytest.importorskip("flask")


def add_finding(az, source="live", **kw):
    with az._db() as conn:
        cur = conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status, source) "
            "VALUES (?, ?, ?, 'done', ?)", ("2026-10-07T10:00:00Z", 3, "[]", source))
        batch_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO findings (batch_id, title, severity, description, recommendation, "
            "affected_agents, rule_ids) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (batch_id, kw.get("title", "SSH brute force"), kw.get("severity", "high"), "d", "r",
             json.dumps(["ct100"]), json.dumps(["5710"])))
        return cur.lastrowid


def test_findings_list_returns_200_with_rows(az, client):
    add_finding(az)
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    finding = data["findings"][0]
    assert finding["title"] == "SSH brute force"
    assert finding["source"] == "live"
    assert finding["affected_agents"] == ["ct100"]


def test_single_finding_returns_200(az, client):
    fid = add_finding(az, source="history")
    resp = client.get(f"/api/findings/{fid}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == fid
    assert data["source"] == "history"
    assert data["alert_count"] == 3


def test_findings_filters_by_source_and_severity(az, client):
    add_finding(az, source="live", severity="high")
    add_finding(az, source="history", severity="low")
    assert client.get("/api/findings?source=history").get_json()["total"] == 1
    assert client.get("/api/findings?severity=high").get_json()["total"] == 1


def test_findings_empty_list_and_unknown_id(az, client):
    assert client.get("/api/findings").get_json()["findings"] == []
    assert client.get("/api/findings/999").status_code == 404


def test_null_batch_source_falls_back_to_live(az, client):
    fid = add_finding(az)
    with az._db() as conn:
        conn.execute("UPDATE batches SET source=NULL")
    assert client.get(f"/api/findings/{fid}").get_json()["source"] == "live"
