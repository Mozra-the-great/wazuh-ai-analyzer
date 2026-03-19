#!/usr/bin/env python3
"""
Wazuh AI Analyzer – powered by Aeterna™
Analysiert Wazuh-Alerts mit Google Gemini AI und zeigt sie im Web-Dashboard.
Erstellt mithilfe von KI (Claude by Anthropic)
"""

import json
import os
import sqlite3
import threading
import time
import requests
import logging
import glob
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
import hashlib
import hmac
import secrets
from flask import Flask, jsonify, request, abort, send_from_directory, session, redirect, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ─── Konfiguration ───────────────────────────────────────────────────────────
GEMINI_API_KEY  = os.environ.get("GEMINI_API_KEY", "")
ALERTS_LOG      = os.environ.get("WAZUH_ALERTS_LOG", "/var/ossec/logs/alerts/alerts.json")
DB_PATH         = os.environ.get("DB_PATH", "/opt/wazuh-ai-analyzer/data/analyses.db")
STATIC_DIR      = os.environ.get("STATIC_DIR", "/opt/wazuh-ai-analyzer/static")
BATCH_MAX       = int(os.environ.get("BATCH_MAX", "25"))
BATCH_TIMEOUT   = int(os.environ.get("BATCH_TIMEOUT", "300"))
MIN_LEVEL       = int(os.environ.get("MIN_LEVEL", "5"))
PORT            = int(os.environ.get("PORT", "8765"))
GEMINI_MODEL    = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
HISTORY_BATCH   = int(os.environ.get("HISTORY_BATCH", "50"))
HISTORY_PAUSE   = float(os.environ.get("HISTORY_PAUSE", "8.0"))
# Temperature for Gemini responses (0.0–1.0). Lower = more deterministic.
GEMINI_TEMPERATURE = float(os.environ.get("GEMINI_TEMPERATURE", "0.15"))
# Describe your infrastructure so Gemini can give context-aware recommendations.
# Example: "Proxmox homelab with LXC containers, Oracle Cloud VPS, Tailscale VPN, fail2ban"
INFRA_CONTEXT   = os.environ.get("INFRA_CONTEXT", "a self-hosted Linux server environment")

# ── Security ──────────────────────────────────────────────────────────────────
# Default: bind only to localhost. Set to 0.0.0.0 only when behind a reverse
# proxy with authentication (e.g. Nginx Basic Auth, Cloudflare Access, VPN).
LISTEN_HOST          = os.environ.get("LISTEN_HOST", "127.0.0.1")
# Login credentials. Password is stored as a Werkzeug pbkdf2:sha256 hash –
# never the plaintext. Run: python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('yourpassword'))"
DASHBOARD_USER       = os.environ.get("DASHBOARD_USER", "admin").strip()
DASHBOARD_PASSWORD_HASH = os.environ.get("DASHBOARD_PASSWORD_HASH", "").strip()
# Session timeout in seconds (default: 8 hours)
SESSION_LIFETIME     = int(os.environ.get("SESSION_LIFETIME", str(8 * 3600)))
# Max failed login attempts before 60s cooldown
LOGIN_MAX_ATTEMPTS   = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))

WATERMARK_FILE       = Path(DB_PATH).parent / "watermark.json"
SESSION_KEY_FILE     = Path(DB_PATH).parent / "session.key"
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("wazuh-ai")

app = Flask(__name__, static_folder=STATIC_DIR)
# Trust X-Forwarded-For from up to 1 upstream proxy (e.g. Nginx).
# Increase x_for if multiple proxies are chained.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

def _load_or_create_session_key() -> bytes:
    """Persistent secret key for Flask sessions. Generated once, stored on disk."""
    if SESSION_KEY_FILE.exists():
        try:
            return SESSION_KEY_FILE.read_bytes()
        except Exception:
            pass
    key = secrets.token_bytes(64)
    SESSION_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_KEY_FILE.write_bytes(key)
    SESSION_KEY_FILE.chmod(0o600)
    return key

# Secret key placeholder – replaced at startup after init_db()
app.secret_key = b"placeholder"

# ─── Brute-force tracker ──────────────────────────────────────────────────────
_login_attempts: dict = {}   # ip -> [timestamp, ...]
_attempts_lock  = threading.Lock()

def _is_rate_limited(ip: str) -> tuple:
    """Returns (limited: bool, retry_in: int seconds)."""
    now = time.time()
    with _attempts_lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < 60]
        _login_attempts[ip] = attempts
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            retry_in = max(0, int(60 - (now - attempts[0])))
            return True, retry_in
        return False, 0

def _record_failed(ip: str):
    with _attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())

def _clear_attempts(ip: str):
    with _attempts_lock:
        _login_attempts.pop(ip, None)

# ─── Auth helpers ─────────────────────────────────────────────────────────────
_PUBLIC_PATHS = {"/login", "/logout"}

def _is_authenticated() -> bool:
    return (session.get("authenticated") is True and
            session.get("user") == DASHBOARD_USER and
            time.time() < session.get("expires_at", 0))

# ─── Auth middleware ──────────────────────────────────────────────────────────
@app.before_request
def require_login():
    """Block every request unless the session is authenticated."""
    if request.path in _PUBLIC_PATHS or request.path.startswith("/static/"):
        return

    if not DASHBOARD_PASSWORD_HASH:
        if request.path.startswith("/api/"):
            return jsonify({"error": "No credentials configured",
                            "hint":  "Set DASHBOARD_PASSWORD_HASH in the env file"}), 503
        return _login_html(
            error="Kein Passwort konfiguriert. Bitte DASHBOARD_PASSWORD_HASH in der env-Datei setzen."
        ), 503

    if not _is_authenticated():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect(f"/login?next={request.path}")

# ─── Login / Logout routes ────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login_route():
    if _is_authenticated():
        return redirect("/")

    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        limited, retry_in = _is_rate_limited(ip)
        if limited:
            error = f"Zu viele Fehlversuche. Bitte {retry_in}s warten."
            log.warning(f"Login rate-limited for {ip}")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if (username == DASHBOARD_USER and
                    DASHBOARD_PASSWORD_HASH and
                    check_password_hash(DASHBOARD_PASSWORD_HASH, password)):
                _clear_attempts(ip)
                session.clear()
                session["authenticated"] = True
                session["user"]          = username
                session["expires_at"]    = time.time() + SESSION_LIFETIME
                session.permanent        = True
                log.info(f"Login erfolgreich: {username} von {ip}")
                next_url = request.args.get("next", "/")
                if not next_url.startswith("/"):
                    next_url = "/"
                return redirect(next_url)
            else:
                _record_failed(ip)
                with _attempts_lock:
                    count = len(_login_attempts.get(ip, []))
                remaining = max(0, LOGIN_MAX_ATTEMPTS - count)
                error = f"Falscher Benutzername oder Passwort. ({remaining} Versuch(e) verbleibend)"
                log.warning(f"Fehlgeschlagener Login: user='{username}' ip={ip}")

    return _login_html(error=error, query_string=request.query_string.decode())

@app.route("/logout")
def logout_route():
    user = session.get("user", "unknown")
    ip   = request.remote_addr or "unknown"
    session.clear()
    log.info(f"Logout: {user} von {ip}")
    return redirect("/login")

# ─── Login page HTML ──────────────────────────────────────────────────────────
def _login_html(error: str = None, query_string: str = "") -> str:
    next_param = f"?{query_string}" if query_string else ""
    err_block  = (f'<div class="err">{error}</div>') if error else ""
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Anmelden</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #080c14; color: #e2e8f0;
      font-family: 'Segoe UI', system-ui, sans-serif;
      min-height: 100vh; display: flex;
      align-items: center; justify-content: center;
    }}
    .card {{
      background: #0f1623; border: 1px solid rgba(255,255,255,.08);
      border-radius: 18px; padding: 42px 44px 36px; width: 340px;
      box-shadow: 0 24px 64px rgba(0,0,0,.6);
    }}
    .logo {{ text-align: center; margin-bottom: 28px; }}
    .logo-icon {{ font-size: 36px; display: block; margin-bottom: 10px; }}
    .logo-title {{ font-size: 16px; font-weight: 600; letter-spacing: .3px; }}
    .logo-sub {{ font-size: 11px; color: rgba(255,255,255,.3); letter-spacing: 1px; text-transform: uppercase; margin-top: 3px; }}
    hr {{ border: none; border-top: 1px solid rgba(255,255,255,.07); margin: 0 0 24px; }}
    .field {{ margin-bottom: 14px; }}
    label {{ display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: rgba(255,255,255,.35); font-weight: 600; margin-bottom: 7px; }}
    input[type=text], input[type=password] {{
      width: 100%; padding: 11px 14px;
      background: rgba(255,255,255,.07); border: 1px solid rgba(255,255,255,.13);
      border-radius: 10px; color: #fff; font-size: 14px; outline: none;
      transition: border-color .2s;
    }}
    input:focus {{ border-color: rgba(99,102,241,.7); background: rgba(255,255,255,.09); }}
    .submit {{
      margin-top: 20px; width: 100%; padding: 12px;
      background: #6366f1; border: none; border-radius: 10px;
      color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;
      letter-spacing: .3px; transition: opacity .2s;
    }}
    .submit:hover {{ opacity: .85; }}
    .err {{
      background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3);
      border-radius: 8px; color: #fca5a5; font-size: 12px;
      padding: 10px 13px; margin-top: 14px; line-height: 1.5;
    }}
    .footer {{ text-align: center; font-size: 10px; color: rgba(255,255,255,.15); margin-top: 24px; letter-spacing: .5px; }}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="logo-icon">🛡️</span>
    <div class="logo-title">Wazuh AI Analyzer</div>
    <div class="logo-sub">powered by Aeterna™</div>
  </div>
  <hr>
  <form method="POST" action="/login{next_param}" autocomplete="on">
    <div class="field">
      <label for="username">Benutzername</label>
      <input type="text" id="username" name="username" autofocus autocomplete="username" placeholder="admin">
    </div>
    <div class="field">
      <label for="password">Passwort</label>
      <input type="password" id="password" name="password" autocomplete="current-password" placeholder="••••••••">
    </div>
    <button type="submit" class="submit">Anmelden</button>
    {err_block}
  </form>
  <div class="footer">Sicherheitssystem · Nur autorisierter Zugriff</div>
</div>
</body>
</html>"""


# ─── Quota / Rate-Limit State ─────────────────────────────────────────────────
class QuotaState:
    """Verwaltet Gemini-Quota-Erschöpfung und automatisches Retry."""
    def __init__(self):
        self._lock            = threading.Lock()
        self.exhausted        = False
        self.exhausted_since  = None
        self.retry_at         = None   # Unix-Timestamp
        self.retry_count      = 0
        self.last_error_msg   = ""
        self.last_success_at  = None

    def mark_exhausted(self, msg: str, retry_after_s: float):
        with self._lock:
            now = datetime.now(timezone.utc)
            if not self.exhausted:
                self.exhausted_since = now.isoformat(timespec="seconds")
            self.exhausted      = True
            self.retry_count   += 1
            self.retry_at       = time.time() + retry_after_s
            self.last_error_msg = msg
            retry_ts = datetime.fromtimestamp(self.retry_at, tz=timezone.utc).isoformat(timespec="seconds")
            log.warning(f"Quota erschoepft: {msg} | Naechster Versuch: {retry_ts}")

    def mark_success(self):
        with self._lock:
            if self.exhausted:
                log.info("Quota wiederhergestellt – Analyse laeuft wieder")
            self.exhausted       = False
            self.exhausted_since = None
            self.retry_at        = None
            self.retry_count     = 0
            self.last_error_msg  = ""
            self.last_success_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def can_send(self) -> bool:
        with self._lock:
            if not self.exhausted:
                return True
            return time.time() >= (self.retry_at or 0)

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "exhausted":        self.exhausted,
                "exhausted_since":  self.exhausted_since,
                "retry_at":         datetime.fromtimestamp(self.retry_at, tz=timezone.utc).isoformat(timespec="seconds")
                                    if self.retry_at else None,
                "retry_in_seconds": max(0, int((self.retry_at or 0) - time.time()))
                                    if self.exhausted else 0,
                "retry_count":      self.retry_count,
                "last_error":       self.last_error_msg,
                "last_success_at":  self.last_success_at,
            }

quota = QuotaState()

# ─── Retry-Queue ──────────────────────────────────────────────────────────────
retry_queue      = []
retry_queue_lock = threading.Lock()

def enqueue_retry(batch_id: int, groups: list, source: str = "live"):
    with retry_queue_lock:
        retry_queue.append((batch_id, groups, source))
    log.info(f"Batch {batch_id} in Retry-Queue ({len(retry_queue)} ausstehend)")

def retry_worker():
    """Laeuft dauerhaft, verarbeitet Retry-Queue sobald Quota wieder frei."""
    while True:
        time.sleep(30)
        if not retry_queue:
            continue
        if not quota.can_send():
            log.debug(f"Retry-Worker: Quota gesperrt, {quota.as_dict()['retry_in_seconds']}s warten")
            continue
        with retry_queue_lock:
            if not retry_queue:
                continue
            batch_id, groups, source = retry_queue.pop(0)
        log.info(f"Retry-Worker: verarbeite Batch {batch_id} erneut (Quelle: {source})")
        _do_gemini_and_save(batch_id, groups, source=source, is_retry=True)

# ─── Datenbank ────────────────────────────────────────────────────────────────
def get_db_conn():
    """Open a new SQLite connection. Caller MUST call conn.close() when done."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL mode: allows concurrent reads alongside a single writer, eliminates most
    # "database is locked" errors under multi-threaded load.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, faster than FULL
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

class _db:
    """Context manager that opens a connection, manages the transaction,
    and guarantees conn.close() even if an exception is raised."""
    def __enter__(self):
        self.conn = get_db_conn()
        return self.conn
    def __exit__(self, exc_type, *_):
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_conn()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS batches (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at    TEXT    NOT NULL,
                alert_count   INTEGER NOT NULL,
                raw_groups    TEXT    NOT NULL,
                summary       TEXT,
                overall_risk  TEXT    DEFAULT 'unknown',
                status        TEXT    DEFAULT 'pending',
                source        TEXT    DEFAULT 'live'
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id        INTEGER NOT NULL,
                title           TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                description     TEXT    NOT NULL,
                recommendation  TEXT    NOT NULL,
                affected_agents TEXT,
                rule_ids        TEXT,
                FOREIGN KEY (batch_id) REFERENCES batches(id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_batch    ON findings(batch_id);
            CREATE INDEX IF NOT EXISTS idx_batches_created   ON batches(created_at);
            CREATE INDEX IF NOT EXISTS idx_batches_source    ON batches(source);
        """)
        conn.commit()
    finally:
        conn.close()
    log.info("Datenbank initialisiert (WAL-Modus aktiv)")

# ─── Watermark ────────────────────────────────────────────────────────────────
def load_watermark() -> dict:
    if WATERMARK_FILE.exists():
        try:
            return json.loads(WATERMARK_FILE.read_text())
        except Exception:
            pass
    return {}

def save_watermark(data: dict):
    WATERMARK_FILE.write_text(json.dumps(data, indent=2))

# ─── Runtime-Statistiken ──────────────────────────────────────────────────────
stats_lock = threading.Lock()
_stats     = {
    "processed": 0, "skipped": 0,
    "batches_sent": 0, "errors": 0,
    "history_alerts": 0, "history_done": False,
    "history_files_total": 0, "history_files_done": 0,
}

def _inc(key, n=1):
    with stats_lock:
        _stats[key] += n

def _set(key, val):
    with stats_lock:
        _stats[key] = val

# ─── Alert-Buffer (Live) ──────────────────────────────────────────────────────
alert_buffer  = []
buffer_lock   = threading.Lock()
last_flush_ts = time.time()

def _handle_line(line: str, source: str = "live") -> bool:
    if not line.strip():
        return False
    try:
        alert = json.loads(line)
        level = alert.get("rule", {}).get("level", 0)
        if level < MIN_LEVEL:
            _inc("skipped")
            return False
        _inc("processed")
        alert["_source"] = source
        with buffer_lock:
            alert_buffer.append(alert)
            if len(alert_buffer) >= BATCH_MAX:
                _flush(source=source)
        return True
    except Exception:
        return False

def _flush(source: str = "live"):
    global last_flush_ts, alert_buffer
    if not alert_buffer:
        return
    batch  = alert_buffer.copy()
    alert_buffer.clear()
    last_flush_ts = time.time()
    _inc("batches_sent")
    t = threading.Thread(
        target=analyze_batch, args=(batch, source),
        daemon=True, name=f"gemini-{source}"
    )
    t.start()

# ─── Historische Analyse ──────────────────────────────────────────────────────
def find_alert_files() -> list:
    base    = Path(ALERTS_LOG)
    pattern = str(base.parent / "alerts.json*")
    files   = sorted(glob.glob(pattern), key=lambda p: os.path.getmtime(p))
    if str(base) in files:
        files.remove(str(base))
        files.append(str(base))
    return files

def historical_scan():
    """
    Scannt alle vorhandenen Alert-Logs von Anfang an.
    Macht nahtlos weiter wo ein frueherer Lauf aufgehoert hat (Watermark).
    Pausiert automatisch bei Quota-Erschoepfung und macht danach weiter.
    """
    wm    = load_watermark()
    files = find_alert_files()
    _set("history_files_total", len(files))

    if not files:
        log.warning("Keine Alert-Log-Dateien gefunden – historische Analyse uebersprungen")
        _set("history_done", True)
        return

    log.info(f"Historische Analyse: {len(files)} Datei(en) gefunden")

    for filepath in files:
        wm_line = wm.get(filepath, 0)
        if not os.path.exists(filepath):
            _inc("history_files_done")
            continue

        log.info(f"Historisch: {filepath} (ab Zeile {wm_line})")
        local_buf = []
        line_num  = 0

        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    line_num += 1
                    if line_num <= wm_line:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        if alert.get("rule", {}).get("level", 0) < MIN_LEVEL:
                            continue
                        alert["_source"] = "history"
                        local_buf.append(alert)
                        _inc("history_alerts")
                    except Exception:
                        continue

                    if len(local_buf) >= HISTORY_BATCH:
                        _wait_for_quota()
                        _send_history_batch(local_buf[:])
                        local_buf.clear()
                        wm[filepath] = line_num
                        save_watermark(wm)
                        time.sleep(HISTORY_PAUSE)

        except Exception as e:
            log.error(f"Historisch: Fehler beim Lesen von {filepath}: {e}")
            _inc("history_files_done")
            continue

        if local_buf:
            _wait_for_quota()
            _send_history_batch(local_buf)

        wm[filepath] = line_num
        save_watermark(wm)
        _inc("history_files_done")
        log.info(f"Historisch: {filepath} fertig ({line_num} Zeilen)")

    _set("history_done", True)
    with stats_lock:
        done = _stats["history_alerts"]
    log.info(f"Historische Analyse abgeschlossen: {done} Alerts verarbeitet")

def _wait_for_quota():
    """Blockiert solange Quota erschoepft ist."""
    while not quota.can_send():
        remaining = quota.as_dict()["retry_in_seconds"]
        log.info(f"Historisch: warte auf Quota-Reset ({remaining}s verbleibend) …")
        time.sleep(min(remaining + 2, 120))

def _send_history_batch(alerts: list):
    groups = group_alerts(alerts)
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status, source) VALUES (?, ?, ?, 'analyzing', 'history')",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), len(alerts), json.dumps(groups))
        )
        batch_id = cur.lastrowid
        conn.commit()
    _do_gemini_and_save(batch_id, groups, source="history")

# ─── Live-Watcher ─────────────────────────────────────────────────────────────
def _get_inode(path: str) -> int:
    """Return inode number of a file, or -1 if it does not exist."""
    try:
        return os.stat(path).st_ino
    except OSError:
        return -1

def tail_alerts():
    """
    Follows alerts.json continuously.
    Detects log rotation (inode change or file shrink) and reopens automatically.
    """
    global last_flush_ts

    # Wait until the log file exists
    while not os.path.exists(ALERTS_LOG):
        log.warning(f"Alert-Log nicht gefunden: {ALERTS_LOG} – warte 15s …")
        time.sleep(15)

    log.info(f"Live-Ueberwachung: {ALERTS_LOG}")

    def _open_at_end(path: str):
        f = open(path, "r", errors="replace")
        f.seek(0, 2)
        return f, _get_inode(path)

    f, current_inode = _open_at_end(ALERTS_LOG)
    try:
        while True:
            line = f.readline()
            if line:
                _handle_line(line.strip(), source="live")
                continue

            # No new data – check for rotation before sleeping
            # Rotation detected when:
            #   a) The inode of ALERTS_LOG changed (rename+create)
            #   b) The file is smaller than our current position (truncate)
            try:
                disk_inode = _get_inode(ALERTS_LOG)
                disk_size  = os.path.getsize(ALERTS_LOG)
            except OSError:
                disk_inode = -1
                disk_size  = 0

            pos = f.tell()
            if disk_inode != current_inode or disk_size < pos:
                log.info(
                    f"Log-Rotation erkannt (inode {current_inode}→{disk_inode}, "
                    f"pos {pos}→size {disk_size}) – Datei wird neu geoeffnet"
                )
                f.close()
                # Brief pause so the new file has time to appear
                time.sleep(1.0)
                while not os.path.exists(ALERTS_LOG):
                    time.sleep(1.0)
                f, current_inode = _open_at_end(ALERTS_LOG)
                log.info(f"Live-Watcher neu geoeffnet (inode {current_inode})")
                continue

            # Truly no data – sleep and maybe flush buffer
            time.sleep(0.3)
            with buffer_lock:
                if alert_buffer and (time.time() - last_flush_ts) >= BATCH_TIMEOUT:
                    log.info(f"Timeout-Flush: {len(alert_buffer)} Alerts")
                    _flush(source="live")
    finally:
        f.close()

# ─── Alert-Gruppierung ────────────────────────────────────────────────────────
def group_alerts(alerts: list) -> list:
    groups: dict = defaultdict(lambda: {
        "description": "", "count": 0, "agents": set(),
        "levels": [], "locations": set(), "samples": []
    })
    for a in alerts:
        rule = a.get("rule", {})
        rid  = str(rule.get("id", "unknown"))
        g    = groups[rid]
        g["description"] = rule.get("description", "")
        g["count"]      += 1
        g["levels"].append(rule.get("level", 0))
        g["agents"].add(a.get("agent", {}).get("name", "unknown"))
        g["locations"].add(a.get("location", ""))
        if len(g["samples"]) < 3:
            g["samples"].append({
                "ts":       a.get("timestamp", "")[:19],
                "log":      (a.get("full_log", "") or "")[:250],
                "src_ip":   a.get("data", {}).get("srcip", ""),
                "dst_user": a.get("data", {}).get("dstuser", ""),
            })
    result = []
    for rid, g in groups.items():
        result.append({
            "rule_id":     rid,
            "description": g["description"],
            "count":       g["count"],
            "max_level":   max(g["levels"]) if g["levels"] else 0,
            "agents":      sorted(g["agents"]),
            "locations":   sorted(g["locations"])[:3],
            "samples":     g["samples"],
        })
    return sorted(result, key=lambda x: x["max_level"], reverse=True)

# ─── Gemini API ───────────────────────────────────────────────────────────────
_SYSTEM = (
    "Du bist ein erfahrener Cybersecurity-Analyst. "
    "Du analysierst Wazuh SIEM-Alerts und gibst praezise, umsetzbare Handlungsempfehlungen. "
    "Antworte ausschliesslich mit validem JSON – kein Markdown, keine Erklaerungen ausserhalb des JSON."
)

_PROMPT_TPL = """\
Analysiere diese Wazuh SIEM-Alert-Gruppen. Infrastruktur-Kontext: {infra}.

Alert-Gruppen:
{groups}

Gib AUSSCHLIESSLICH dieses JSON zurueck (keine anderen Zeichen, kein Markdown):
{{
  "summary": "Kurze Zusammenfassung der aktuellen Sicherheitslage (2-4 Saetze, auf Deutsch)",
  "overall_risk": "critical|high|medium|low|info",
  "findings": [
    {{
      "title": "Praegnanter Titel (max. 60 Zeichen)",
      "severity": "critical|high|medium|low|info",
      "description": "Was bedeutet dieser Alert? Warum ist er wichtig? (3-6 Saetze, Deutsch)",
      "recommendation": "Konkrete Schritte zur Behebung oder Ueberwachung. Nummeriert. Deutsch.",
      "affected_agents": ["agent-name"],
      "rule_ids": ["rule-id"]
    }}
  ]
}}
Sortiere findings nach Schwere (kritischstes zuerst).\
"""

def call_gemini(groups: list) -> tuple:
    """
    Gibt (result_dict, None) bei Erfolg zurueck.
    Gibt (None, 'quota') bei Rate-Limit/Quota zurueck.
    Gibt (None, 'error') bei anderen Fehlern zurueck.
    """
    if not GEMINI_API_KEY:
        log.error("GEMINI_API_KEY nicht gesetzt")
        return None, "error"

    prompt  = _PROMPT_TPL.format(infra=INFRA_CONTEXT, groups=json.dumps(groups, ensure_ascii=False, indent=2))
    url     = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": GEMINI_TEMPERATURE, "responseMimeType": "application/json"},
        "systemInstruction": {"parts": [{"text": _SYSTEM}]},
    }

    try:
        resp = requests.post(url, json=payload, timeout=90)

        # ── 429: Rate-Limit oder Tages-Quota ─────────────────────────────
        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", 0))
            try:
                body = resp.json()
                msg  = body.get("error", {}).get("message", "") or resp.text[:150]
            except Exception:
                msg = resp.text[:150]
            if retry_after <= 0:
                # "quota" oder "day" im Fehlertext → taeglich → 1h warten
                # Sonst minutliches Limit → 65s warten
                if any(w in msg.lower() for w in ("quota", "day", "exhausted")):
                    retry_after = 3600
                else:
                    retry_after = 65
            quota.mark_exhausted(msg, retry_after)
            return None, "quota"

        # ── Andere HTTP-Fehler ────────────────────────────────────────────
        if not resp.ok:
            log.error(f"Gemini HTTP {resp.status_code}: {resp.text[:200]}")
            return None, "error"

        data   = resp.json()
        raw    = data["candidates"][0]["content"]["parts"][0]["text"]
        raw    = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        result = json.loads(raw)
        quota.mark_success()
        return result, None

    except requests.Timeout:
        log.error("Gemini: Timeout")
        return None, "error"
    except requests.ConnectionError as e:
        log.error(f"Gemini: Verbindungsfehler: {e}")
        return None, "error"
    except (KeyError, json.JSONDecodeError) as e:
        log.error(f"Gemini: Antwort parsen fehlgeschlagen: {e}")
        return None, "error"
    except Exception as e:
        log.error(f"Gemini: Fehler: {e}")
        return None, "error"

# ─── Batch-Analyse ────────────────────────────────────────────────────────────
def analyze_batch(alerts: list, source: str = "live"):
    groups = group_alerts(alerts)
    log.info(f"[{source}] Analysiere {len(alerts)} Alerts in {len(groups)} Gruppen …")
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO batches (created_at, alert_count, raw_groups, status, source) VALUES (?, ?, ?, 'analyzing', ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), len(alerts), json.dumps(groups), source)
        )
        batch_id = cur.lastrowid
        conn.commit()
    _do_gemini_and_save(batch_id, groups, source=source)

def _do_gemini_and_save(batch_id: int, groups: list, source: str = "live", is_retry: bool = False):
    result, err_type = call_gemini(groups)

    if err_type == "quota":
        # Nicht als 'error' markieren – bleibt auf 'analyzing' fuer spaeteres Retry
        log.warning(f"Batch {batch_id} pausiert wegen Quota-Erschoepfung")
        enqueue_retry(batch_id, groups, source=source)
        return

    if result is None:
        _inc("errors")
        with _db() as conn:
            conn.execute("UPDATE batches SET status='error' WHERE id=?", (batch_id,))
            conn.commit()
        return

    # ── Whitelist-Validierung: LLM-Output sanitisieren ─────────────────────────
    _VALID_RISK = {"critical", "high", "medium", "low", "info", "unknown"}
    _VALID_SEV  = {"critical", "high", "medium", "low", "info"}

    raw_risk = result.get("overall_risk", "unknown")
    safe_risk = raw_risk if raw_risk in _VALID_RISK else "unknown"
    if safe_risk != raw_risk:
        log.warning(f"Ungueltiger overall_risk Wert vom LLM: {raw_risk!r} → 'unknown'")

    findings = result.get("findings", [])
    log.info(f"[{'retry' if is_retry else source}] Batch {batch_id}: "
             f"Risiko={safe_risk} | {len(findings)} Findings")

    with _db() as conn:
        conn.execute(
            "UPDATE batches SET summary=?, overall_risk=?, status='done' WHERE id=?",
            (result.get("summary", "")[:2000], safe_risk, batch_id)
        )
        for f in findings:
            raw_sev = f.get("severity", "info")
            safe_sev = raw_sev if raw_sev in _VALID_SEV else "info"
            conn.execute(
                """INSERT INTO findings
                   (batch_id, title, severity, description, recommendation, affected_agents, rule_ids)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    batch_id,
                    str(f.get("title", "Unbekanntes Finding"))[:200],
                    safe_sev,
                    str(f.get("description", ""))[:5000],
                    str(f.get("recommendation", ""))[:5000],
                    json.dumps(f.get("affected_agents", [])[:20]),
                    json.dumps(f.get("rule_ids", [])[:50]),
                )
            )

# ─── REST-API ─────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    with _db() as conn:
        total    = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        sev_map  = {}
        for row in conn.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity"):
            sev_map[row["severity"]] = row["c"]
        last_row     = conn.execute(
            "SELECT created_at FROM batches WHERE status='done' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        batch_count  = conn.execute("SELECT COUNT(*) FROM batches WHERE status='done'").fetchone()[0]
        analyzing    = conn.execute("SELECT COUNT(*) FROM batches WHERE status='analyzing'").fetchone()[0]
        hist_done    = conn.execute("SELECT COUNT(*) FROM batches WHERE source='history' AND status='done'").fetchone()[0]

    with buffer_lock:
        buffered = len(alert_buffer)
    with stats_lock:
        s = dict(_stats)
    with retry_queue_lock:
        rq = len(retry_queue)

    return jsonify({
        "total_findings":   total,
        "by_severity":      sev_map,
        "batch_count":      batch_count,
        "analyzing":        analyzing,
        "last_analysis":    last_row["created_at"] if last_row else None,
        "buffered_alerts":  buffered,
        "batch_max":        BATCH_MAX,
        "batch_timeout":    BATCH_TIMEOUT,
        "runtime":          s,
        "gemini_ok":        bool(GEMINI_API_KEY),
        "quota":            quota.as_dict(),
        "retry_queue_size": rq,
        "history": {
            "done":            s["history_done"],
            "alerts_scanned":  s["history_alerts"],
            "files_total":     s["history_files_total"],
            "files_done":      s["history_files_done"],
            "batches_done":    hist_done,
        },
    })

@app.route("/api/findings")
def api_findings():
    limit    = min(int(request.args.get("limit", 50)), 200)
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    source   = request.args.get("source")

    conds, params = [], []
    if severity:
        conds.append("f.severity=?"); params.append(severity)
    if source:
        conds.append("b.source=?"); params.append(source)

    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    with _db() as conn:
        rows = conn.execute(
            f"""SELECT f.*, b.created_at batch_time, b.alert_count, b.source batch_source
                FROM findings f JOIN batches b ON f.batch_id=b.id
                {where} ORDER BY f.id DESC LIMIT ? OFFSET ?""",
            params + [limit, offset]
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) FROM findings f JOIN batches b ON f.batch_id=b.id {where}",
            params
        ).fetchone()[0]

    return jsonify({"findings": [_finding_dict(r) for r in rows], "total": total, "limit": limit, "offset": offset})

@app.route("/api/findings/<int:fid>")
def api_finding(fid):
    with _db() as conn:
        r = conn.execute(
            "SELECT f.*, b.created_at batch_time, b.alert_count, b.summary batch_summary, b.source batch_source "
            "FROM findings f JOIN batches b ON f.batch_id=b.id WHERE f.id=?",
            (fid,)
        ).fetchone()
    if not r:
        abort(404)
    d = _finding_dict(r)
    d["batch_summary"] = r["batch_summary"]
    d["alert_count"]   = r["alert_count"]
    return jsonify(d)

@app.route("/api/batches")
def api_batches():
    with _db() as conn:
        rows = conn.execute(
            "SELECT b.*, (SELECT COUNT(*) FROM findings WHERE batch_id=b.id) finding_count "
            "FROM batches b ORDER BY b.id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

def _finding_dict(r):
    return {
        "id":              r["id"],
        "batch_id":        r["batch_id"],
        "title":           r["title"],
        "severity":        r["severity"],
        "description":     r["description"],
        "recommendation":  r["recommendation"],
        "affected_agents": json.loads(r["affected_agents"] or "[]"),
        "rule_ids":        json.loads(r["rule_ids"] or "[]"),
        "batch_time":      r["batch_time"],
        "source":          r.get("batch_source", "live"),
    }

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def spa(path):
    full = os.path.join(STATIC_DIR, path)
    if path and os.path.exists(full):
        return send_from_directory(STATIC_DIR, path)
    return send_from_directory(STATIC_DIR, "index.html")

# ─── Start ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  \033[1mpowered by Aeterna\033[0m")
    print("  \033[0;36mWazuh AI Analyzer – erstellt mithilfe von KI (Claude by Anthropic)\033[0m\n")

    if not GEMINI_API_KEY:
        log.warning("GEMINI_API_KEY nicht gesetzt!")

    init_db()

    # Load (or generate) persistent session secret key AFTER init_db so data dir exists
    app.secret_key = _load_or_create_session_key()

    if not DASHBOARD_PASSWORD_HASH:
        log.warning("DASHBOARD_PASSWORD_HASH nicht gesetzt – Dashboard nicht zugänglich!")
        log.warning("Installer erneut ausführen oder Passwort-Hash manuell setzen:")
        log.warning("  python3 -c \"from werkzeug.security import generate_password_hash; print(generate_password_hash('deinpasswort'))\"")
        log.warning("  Dann DASHBOARD_PASSWORD_HASH=<hash> in /etc/wazuh-ai-analyzer.env eintragen")
    else:
        log.info(f"Login:         User '{DASHBOARD_USER}' | Session-Lifetime: {SESSION_LIFETIME // 3600}h")

    threading.Thread(target=historical_scan, daemon=True, name="history").start()
    threading.Thread(target=tail_alerts,     daemon=True, name="live").start()
    threading.Thread(target=retry_worker,    daemon=True, name="retry").start()

    log.info(f"Dashboard:     http://{LISTEN_HOST}:{PORT}/login")
    bind_note = "(localhost only – use SSH tunnel or reverse proxy)" if LISTEN_HOST == "127.0.0.1" else "(EXPOSED – ensure only accessible via trusted network/proxy)"
    log.info(f"Bind:          {LISTEN_HOST} {bind_note}")
    log.info(f"Batch:         {BATCH_MAX} Alerts / {BATCH_TIMEOUT}s Timeout | Min-Level: {MIN_LEVEL}")
    log.info(f"History:       {HISTORY_BATCH} Alerts/Batch | {HISTORY_PAUSE}s Pause")
    log.info(f"Infra-Kontext: {INFRA_CONTEXT}")

    if LISTEN_HOST != "127.0.0.1" and not DASHBOARD_PASSWORD_HASH:
        log.warning("SICHERHEIT: Dashboard auf " + LISTEN_HOST + " OHNE Passwort – Zugriff nicht möglich!")

    app.run(host=LISTEN_HOST, port=PORT, debug=False, threaded=True, use_reloader=False)

