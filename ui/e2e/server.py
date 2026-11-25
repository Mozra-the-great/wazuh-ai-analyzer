"""The real backend for the UI tests: waitress + Flask + the real CSP, on a fixture database.

Playwright starts this script (see playwright.config.ts). It serves the dashboard build in
`wazuh_ai_analyzer/web/ui` exactly as the service does: the same `create_app`, the same
security headers, the CSP hash and the public login files from `ui-manifest.json`. Only the
data is made up: findings (with hostile texts on purpose), batches, and the live state the
service would report (quota, history, buffer), which a test can change at run time by
writing `state.json` in the run directory.

    python ui/e2e/server.py --port 8799 --run-dir ui/e2e/.run

Nothing here is secret: the password is a dummy that exists only for the test run.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from werkzeug.security import generate_password_hash  # noqa: E402

from wazuh_ai_analyzer.config import load_config  # noqa: E402
from wazuh_ai_analyzer.logging_setup import RedactSecrets  # noqa: E402
from wazuh_ai_analyzer.metrics.runtime import LEGACY_RUNTIME_KEYS, NEW_RUNTIME_KEYS  # noqa: E402
from wazuh_ai_analyzer.storage.db import Database  # noqa: E402
from wazuh_ai_analyzer.storage.repo import NewFinding, Repository  # noqa: E402
from wazuh_ai_analyzer.storage.schema import migrate  # noqa: E402
from wazuh_ai_analyzer.web.app import LiveState, create_app  # noqa: E402
from wazuh_ai_analyzer.web.server import WebServer  # noqa: E402
from wazuh_ai_analyzer.web.sessions import SessionStore  # noqa: E402
from wazuh_ai_analyzer.web.ui_manifest import load_ui_manifest  # noqa: E402

UI_DIR = ROOT / "wazuh_ai_analyzer" / "web" / "ui"
USER = "admin"
PASSWORD = "e2e-dummy-password-not-a-secret"  # noqa: S105

HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>"\'&amp;'
LONG_WORD = "A" * 180

DEFAULT_STATE: dict[str, object] = {
    "buffered": 4,
    "quota": {
        "exhausted": False,
        "exhausted_since": None,
        "retry_at": None,
        "retry_in_seconds": 0,
        "retry_count": 0,
        "last_error": "",
        "last_success_at": None,
    },
    "runtime": {
        "history_done": True,
        "history_alerts": 0,
        "history_files_total": 0,
        "history_files_done": 0,
    },
}


def seed(repo: Repository) -> None:
    """Findings and batches for every view: five levels, both sources, long and hostile text."""
    levels = ("critical", "high", "medium", "low", "info")
    # 66 findings: three pages of 30 (the last one with 6 rows).
    for number in range(1, 67):
        severity = levels[number % 5]
        source = "history" if number % 4 == 0 else "live"
        mode = "decision" if number % 7 == 0 else "llm"
        title = f"SSH brute force against ct{100 + number % 9} (#{number})"
        description = (
            f"Repeated failed logins for user root from 203.0.113.{number % 250}. "
            "Several attempts per minute over a long period."
        )
        recommendation = "Block the source address, disable password logins and review auth.log."
        agents: tuple[str, ...] = (f"ct{100 + number % 9}", "pve1")
        rules: tuple[str, ...] = ("5710", "5712")
        if number == 3:
            title, description, recommendation = HOSTILE, HOSTILE + "\nsecond line", HOSTILE
            agents, rules = (HOSTILE, LONG_WORD), (HOSTILE,)
        if number == 5:
            title = "Long unbroken value " + LONG_WORD + LONG_WORD
            description = LONG_WORD * 3
        batch_id = repo.insert_batch(
            alert_count=12 + number,
            raw_groups="[]",
            source="history" if source == "history" else "live",
            status="analyzing",
            mode="decision" if mode == "decision" else "llm",
        )
        repo.complete_batch(
            batch_id,
            summary="Brute-force noise from one network; no successful login seen.",
            overall_risk="medium",
            findings=[
                NewFinding(
                    title=title,
                    severity=severity,  # type: ignore[arg-type]
                    description=description,
                    recommendation=recommendation,
                    affected_agents=agents,
                    rule_ids=rules,
                    confidence=0.5 + (number % 5) / 10 if mode == "decision" else None,
                )
            ],
            mode="decision" if mode == "decision" else "llm",
        )
    # The newest done batch is the one the summary banner shows: hostile on purpose.
    latest = repo.insert_batch(alert_count=9, raw_groups="[]", source="live", status="analyzing")
    repo.complete_batch(
        latest,
        summary=HOSTILE + "\nA second line of the summary.",
        overall_risk="high",
        findings=[
            NewFinding(
                title="Web shell found",
                severity="critical",
                description="A PHP file with eval() appeared in /var/www.",
                recommendation="Isolate the host and restore from backup.",
                affected_agents=("web01",),
                rule_ids=("550",),
                confidence=None,
            )
        ],
    )
    for _ in range(2):  # two batches wait in the retry queue
        repo.insert_batch(alert_count=5, raw_groups="[]", source="live", status="pending")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--empty", action="store_true", help="no findings at all")
    args = parser.parse_args()

    run_dir: Path = args.run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    state_file = run_dir / "state.json"
    state_file.write_text(json.dumps(DEFAULT_STATE), encoding="utf-8")

    config = load_config(
        {
            "WAZUH_ALERTS_LOG": str(run_dir / "alerts.json"),
            "DB_PATH": str(run_dir / "data" / "analyses.db"),
            "DASHBOARD_USER": USER,
            "DASHBOARD_PASSWORD_HASH": generate_password_hash(PASSWORD, method="pbkdf2:sha256:1000"),
            "GEMINI_API_KEY": "dummy-e2e-key-not-a-secret",
            "SESSION_COOKIE_SECURE": "false",  # plain http on 127.0.0.1
            "LISTEN_HOST": "127.0.0.1",
            "PORT": str(args.port),
            "LOGIN_MAX_ATTEMPTS": "200",
        }
    )
    config.paths.db_path.parent.mkdir(parents=True, exist_ok=True)
    for stale in config.paths.db_path.parent.glob("analyses.db*"):
        stale.unlink()
    db = Database(config.paths.db_path)
    migrate(db)
    repo = Repository(db)
    if not args.empty:
        seed(repo)

    def current() -> dict[str, object]:
        try:
            loaded = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return DEFAULT_STATE
        return loaded if isinstance(loaded, dict) else DEFAULT_STATE

    def section(name: str) -> dict[str, object]:
        value = current().get(name)
        return value if isinstance(value, dict) else {}

    def runtime() -> dict[str, int | bool]:
        values: dict[str, int | bool] = dict.fromkeys((*LEGACY_RUNTIME_KEYS, *NEW_RUNTIME_KEYS), 0)
        for key, value in section("runtime").items():
            if isinstance(value, bool | int):
                values[key] = value
        return values

    def buffered() -> int:
        value = current().get("buffered")
        return value if isinstance(value, int) else 0

    manifest = load_ui_manifest(UI_DIR)
    app = create_app(
        config,
        repo,
        SessionStore(db, lifetime=config.web.session_lifetime),
        LiveState(runtime=runtime, buffered_alerts=buffered, quota=lambda: section("quota"), upstream=dict),
        session_key=b"e2e-session-key-not-a-secret".ljust(64, b"."),
        ui_dir=UI_DIR,
        script_hashes=manifest.script_hashes,
        public_files=manifest.public_files,
    )
    server = WebServer(
        app,
        host="127.0.0.1",
        port=args.port,
        trusted_proxy=False,
        redactor=RedactSecrets(config.secret_values()),
    )
    server.start()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print(f"READY http://127.0.0.1:{server.port}/", flush=True)
    stop.wait()
    server.close()


if __name__ == "__main__":
    main()
