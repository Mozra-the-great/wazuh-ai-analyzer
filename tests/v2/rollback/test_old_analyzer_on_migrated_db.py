"""Rollback proof (C3): the legacy `analyzer.py` keeps working on a migrated database.

If the rewrite has to be rolled back after its migrations ran, the old release is
started against the same `analyses.db`. These tests run the legacy code against
databases that the new package created or migrated, and read what the legacy code
wrote with the new package again.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from v2.contract.exporter_sql import collect
from wazuh_ai_analyzer.storage import contract
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import NewFinding, Repository
from wazuh_ai_analyzer.storage.schema import LATEST_VERSION, current_version, migrate

ROOT = Path(__file__).resolve().parents[3]

RESULT = {
    "summary": "legacy summary",
    "overall_risk": "high",
    "findings": [
        {
            "title": "SSH brute force",
            "severity": "high",
            "description": "d",
            "recommendation": "r",
            "affected_agents": ["ct100"],
            "rule_ids": ["5710"],
        }
    ],
}


def legacy_batch(az: Any, status: str = "analyzing", **columns: Any) -> int:
    values = {
        "created_at": az._iso(az._now()),
        "alert_count": 3,
        "raw_groups": "[]",
        "status": status,
        **columns,
    }
    with az._db() as conn:
        cur = conn.execute(
            f"INSERT INTO batches ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})",
            list(values.values()),
        )
        return int(cur.lastrowid)


def test_legacy_code_runs_on_a_database_migrated_in_place(az: Any, client: Any) -> None:
    # 1. data written by the legacy code
    first = legacy_batch(az)
    az._save_result(first, RESULT, "live", False)

    # 2. the rewrite migrates the same file
    db = Database(az.DB_PATH)
    assert migrate(db).applied == (1, 2)

    # 3. the legacy code starts again: init_db and every API endpoint
    az.init_db()
    with db.reader() as conn:
        assert current_version(conn) == LATEST_VERSION
    stats = client.get("/api/stats").get_json()
    assert (stats["total_findings"], stats["batch_count"]) == (1, 1)
    listing = client.get("/api/findings").get_json()
    assert listing["total"] == 1
    finding_id = listing["findings"][0]["id"]
    assert client.get(f"/api/findings/{finding_id}").get_json()["title"] == "SSH brute force"
    batches = client.get("/api/batches").get_json()
    assert batches[0]["finding_count"] == 1
    # additive only: every legacy key is still there, the new ones are extra
    assert {"id", "created_at", "raw_groups", "last_error", "bad_responses"} <= set(batches[0])
    assert batches[0]["mode"] == "llm"

    # 4. the legacy code writes, retries, expires and purges
    second = legacy_batch(az, source="history")
    az._save_result(second, RESULT, "history", False)
    stale = legacy_batch(az, claimed_at=1.0)
    assert az._requeue_stale(0) >= 1
    old = az._iso(az._now() - (az.QUEUE_MAX_AGE_HOURS + 1) * 3600)
    expiring = legacy_batch(az, status="pending", created_at=old)
    assert az._expire_old_pending() == 1
    purgeable = legacy_batch(az, status="done", created_at=az._iso(az._now() - 400 * 86400))
    assert az.purge_old_batches(30) == 1

    # 5. the rewrite reads everything the legacy code wrote
    repo = Repository(db)
    assert repo.get_batch(purgeable) is None
    assert repo.get_batch(first) is not None
    assert repo.get_batch(stale) is not None
    expired = repo.get_batch(expiring)
    assert expired is not None
    assert expired.last_error == contract.error_queue_expired(az.QUEUE_MAX_AGE_HOURS)
    done = repo.get_batch(second)
    assert done is not None
    assert (done.status, done.mode, done.source) == ("done", "llm", "history")
    assert [f.title for f in repo.findings_for_batch(second)] == ["SSH brute force"]
    assert repo.findings_for_batch(second)[0].confidence is None
    assert migrate(db).applied == ()

    # 6. and so does the exporter
    result = collect(az.DB_PATH)
    assert result["errors"]["expired"] == 1
    assert result["sequence"] == 2


def test_legacy_code_runs_on_a_database_created_by_the_new_code(
    az: Any, client: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "new" / "analyses.db"
    path.parent.mkdir()
    db = Database(path)
    migrate(db)
    repo = Repository(db)
    for mode in ("llm", "decision"):
        batch_id = repo.insert_batch(alert_count=2, raw_groups="[]", source="live", mode=mode)
        repo.complete_batch(
            batch_id,
            summary=f"{mode} batch",
            overall_risk="medium",
            findings=[
                NewFinding(
                    title=f"{mode} finding",
                    severity="medium",
                    description="d",
                    recommendation="r",
                    affected_agents=["ct1"],
                    rule_ids=["100"],
                    confidence=0.7 if mode == "decision" else None,
                    decision={"relevant": {"noul": 0.8}} if mode == "decision" else None,
                )
            ],
            mode=mode,
            decision_version="v1" if mode == "decision" else None,
        )

    monkeypatch.setattr(az, "DB_PATH", str(path))
    az.init_db()

    listing = client.get("/api/findings").get_json()
    assert listing["total"] == 2
    assert {f["title"] for f in listing["findings"]} == {"llm finding", "decision finding"}
    batches = {b["summary"]: b for b in client.get("/api/batches").get_json()}
    assert batches["decision batch"]["mode"] == "decision"
    assert batches["decision batch"]["decision_version"] == "v1"

    fresh = legacy_batch(az)
    az._save_result(fresh, RESULT, "live", False)
    assert client.get("/api/findings").get_json()["total"] == 3

    # the legacy retention deletes rows that carry the new columns, with their findings
    with az._db() as conn:
        conn.execute("UPDATE batches SET created_at=?", (az._iso(az._now() - 500 * 86400),))
    assert az.purge_old_batches(30) == 3
    assert client.get("/api/stats").get_json()["total_findings"] == 0


def test_new_finding_columns_do_not_break_legacy_inserts(az: Any) -> None:
    """The legacy INSERT lists its columns, so the new nullable columns stay NULL."""
    migrate(Database(az.DB_PATH))
    batch_id = legacy_batch(az)
    az._save_result(batch_id, RESULT, "live", False)
    with az._db() as conn:
        row = conn.execute("SELECT confidence, decision FROM findings").fetchone()
    assert (row["confidence"], row["decision"]) == (None, None)


def test_the_whole_legacy_suite_passes_on_a_migrated_database() -> None:
    """Acceptance of P1: the old analyzer passes its own suite on a P1-migrated DB.

    tests/conftest.py migrates the scratch database with the rewrite's migrations before
    the legacy init_db() when LEGACY_SUITE_ON_MIGRATED_DB=1.
    """
    env = {**os.environ, "LEGACY_SUITE_ON_MIGRATED_DB": "1"}
    legacy_tests = sorted(str(p) for p in (ROOT / "tests").glob("test_*.py"))
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *legacy_tests],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-1000:]
    match = re.search(r"(\d+) passed", done.stdout)
    assert match is not None
    assert int(match.group(1)) >= 100
