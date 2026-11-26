"""Differential tests: the legacy `analyzer.py` API and the new web layer, same database.

Both read the same `analyses.db` (the legacy one is migrated additively first, like
an upgrade). Wherever parity matters the answers must be the same: every key the
legacy API returned is still returned with the same value, and the only new keys are
the additive ones of #86 (`confidence` and `mode` per finding, `mode` in the stats).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from flask.testing import FlaskClient

from v2.web_support import HttpsClient, WebEnv, body, fixed_runtime, web_config
from wazuh_ai_analyzer.storage.db import Database
from wazuh_ai_analyzer.storage.repo import Repository
from wazuh_ai_analyzer.storage.schema import migrate
from wazuh_ai_analyzer.web.app import LiveState, create_app
from wazuh_ai_analyzer.web.auth import LoginLimiter
from wazuh_ai_analyzer.web.sessions import SessionStore

UI_DIR = Path(__file__).resolve().parents[3] / "wazuh_ai_analyzer" / "web" / "ui"


def seed(az: ModuleType) -> list[int]:
    """Batches and findings written by the legacy code's own SQL, in several shapes."""
    ids: list[int] = []
    with az._db() as conn:
        for n, (source, severity, status) in enumerate(
            [
                ("live", "critical", "done"),
                ("history", "high", "done"),
                ("live", "medium", "done"),
                (None, "low", "done"),
                ("history", "info", "done"),
                ("live", "high", "error"),
                ("live", "high", "pending"),
            ]
        ):
            cur = conn.execute(
                "INSERT INTO batches (created_at, alert_count, raw_groups, summary, overall_risk,"
                " status, source, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"2026-10-07T10:{n:02d}:00+00:00",
                    n + 1,
                    json.dumps([{"rule_id": str(n)}]),
                    f"summary {n}" if status == "done" else None,
                    "high" if status == "done" else None,
                    status,
                    source,
                    "expired: laenger als 72h in der Warteschlange" if status == "error" else None,
                ),
            )
            if status != "done":
                continue
            fcur = conn.execute(
                "INSERT INTO findings (batch_id, title, severity, description, recommendation,"
                " affected_agents, rule_ids) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    cur.lastrowid,
                    f"finding {n} <b>x</b>",
                    severity,
                    f"d{n}",
                    f"r{n}",
                    json.dumps([f"agent-{n}", "ct100"]) if n % 2 else None,
                    json.dumps([str(5700 + n)]),
                ),
            )
            assert fcur.lastrowid is not None
            ids.append(fcur.lastrowid)
    return ids


@pytest.fixture
def both(az: ModuleType, client: FlaskClient, tmp_path: Path) -> tuple[FlaskClient, WebEnv]:
    """The legacy test client (logged in) and a new web app over the same database."""
    seed(az)
    db_path = Path(az.DB_PATH)
    db = Database(db_path)
    migrate(db)  # the additive upgrade the cutover performs
    config = web_config(tmp_path, DB_PATH=str(db_path), WAZUH_ALERTS_LOG=str(db_path.parent / "a"))
    repo = Repository(db)
    sessions = SessionStore(db, lifetime=config.web.session_lifetime)
    live = LiveState(
        runtime=fixed_runtime,
        buffered_alerts=lambda: 0,
        quota=lambda: {},
        upstream=lambda: {},
    )
    app = create_app(
        config,
        repo,
        sessions,
        live,
        session_key=b"k" * 64,
        ui_dir=UI_DIR,
        limiter=LoginLimiter(5),
    )
    app.test_client_class = HttpsClient
    new_client = app.test_client()
    assert isinstance(new_client, HttpsClient)
    env = WebEnv(
        config=config,
        db=db,
        repo=repo,
        sessions=sessions,
        app=app,
        client=new_client,
        clock=None,  # type: ignore[arg-type]
        limiter=LoginLimiter(5),
        key=b"k" * 64,
    )
    env.logged_in()
    return client, env


def same_values(legacy: dict[str, Any], new: dict[str, Any]) -> None:
    """Every legacy key is present in `new` with the same value."""
    missing = set(legacy) - set(new)
    assert not missing, missing
    assert {key: new[key] for key in legacy} == legacy


FINDING_ADDITIONS = {"confidence", "mode"}


def test_findings_list_is_the_same_plus_the_additive_keys(
    both: tuple[FlaskClient, WebEnv],
) -> None:
    legacy_client, web = both
    for query in (
        "",
        "?limit=3",
        "?limit=2&offset=2",
        "?severity=high",
        "?source=history",
        "?source=live",
        "?severity=high&source=live",
        "?severity=critical&source=history",
        "?limit=200&offset=0",
    ):
        old = legacy_client.get(f"/api/findings{query}").get_json()
        new = body(web.client.get(f"/api/findings{query}"))
        # A batch without a source counts as 'live' in the new layer (in the response
        # the legacy code already did; its filter skipped such rows). The legacy
        # schema gives every batch a source, so this only matters for corrupt rows.
        null_source_live = 1 if "source=live" in query and "severity" not in query else 0
        assert new["total"] == old["total"] + null_source_live, query
        assert (new["limit"], new["offset"]) == (old["limit"], old["offset"]), query
        if null_source_live:
            continue
        assert len(new["findings"]) == len(old["findings"]), query
        for old_finding, new_finding in zip(old["findings"], new["findings"], strict=True):
            same_values(old_finding, new_finding)
            assert set(new_finding) - set(old_finding) == FINDING_ADDITIONS


def test_a_null_source_is_live_in_both(both: tuple[FlaskClient, WebEnv]) -> None:
    legacy_client, web = both
    old = legacy_client.get("/api/findings?limit=200").get_json()["findings"]
    new = body(web.client.get("/api/findings?limit=200"))["findings"]
    assert {f["source"] for f in old} == {f["source"] for f in new} == {"live", "history"}


def test_single_finding_is_the_same_plus_the_additive_keys(
    both: tuple[FlaskClient, WebEnv],
) -> None:
    legacy_client, web = both
    listing = legacy_client.get("/api/findings?limit=200").get_json()["findings"]
    for finding in listing:
        old = legacy_client.get(f"/api/findings/{finding['id']}").get_json()
        new = body(web.client.get(f"/api/findings/{finding['id']}"))
        same_values(old, new)
        assert set(new) - set(old) == FINDING_ADDITIONS
    assert legacy_client.get("/api/findings/9999").status_code == 404
    assert web.client.get("/api/findings/9999").status_code == 404


def test_batches_are_the_same_with_the_same_columns(both: tuple[FlaskClient, WebEnv]) -> None:
    legacy_client, web = both
    old = legacy_client.get("/api/batches").get_json()
    new = body(web.client.get("/api/batches"))
    assert len(old) == len(new) == 7
    for old_batch, new_batch in zip(old, new, strict=True):
        # The legacy `SELECT b.*` on the migrated database returns exactly our columns,
        # plus the scratch column of the decision backend, which our API leaves out.
        assert {k: v for k, v in old_batch.items() if k != "decision_partial"} == new_batch
        assert old_batch["decision_partial"] is None


def test_stats_keep_every_legacy_key_and_the_database_values(
    both: tuple[FlaskClient, WebEnv],
) -> None:
    legacy_client, web = both
    old = legacy_client.get("/api/stats").get_json()
    new = body(web.client.get("/api/stats"))
    assert set(old) <= set(new)
    assert set(new) - set(old) == {"mode"}
    for key in (
        "total_findings",
        "by_severity",
        "batch_count",
        "analyzing",
        "last_analysis",
        "batch_max",
        "batch_timeout",
        "batch_timeout_quiet",
        "urgent_level",
        "retention_days",
        "retry_queue_size",
        "batches",
    ):
        assert new[key] == old[key], key
    assert new["history"]["batches_done"] == old["history"]["batches_done"]
    assert set(old["history"]) == set(new["history"])
    # the runtime block: every legacy counter is still there
    assert set(old["runtime"]) <= set(new["runtime"])


def test_the_new_layer_fixes_the_input_bugs_the_legacy_code_has(
    both: tuple[FlaskClient, WebEnv],
) -> None:
    legacy_client, web = both
    # legacy: limit=-1 means "all rows" in SQLite; non-numeric values crash (500)
    assert legacy_client.get("/api/findings?limit=-1").get_json()["findings"]
    assert web.client.get("/api/findings?limit=-1").status_code == 400
    assert legacy_client.get("/api/findings?limit=abc").status_code == 500
    assert web.client.get("/api/findings?limit=abc").status_code == 400
