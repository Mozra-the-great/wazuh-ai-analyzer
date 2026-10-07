# 🛡️ Wazuh AI Analyzer

**powered by Aeterna™** · Erstellt mithilfe von KI (Claude by Anthropic)

> ⚠️ **Sicherheitshinweis:** Das Dashboard zeigt eine priorisierte Liste deiner Sicherheitsschwachstellen inklusive betroffener Systeme. Exponiere es **niemals direkt ins Internet** ohne Authentifizierung.
> Betreibe es hinter einem SSH-Tunnel, VPN oder einem Reverse Proxy mit HTTPS.
> Das integrierte Login (Benutzername + Passwort) schützt den Zugriff – stelle trotzdem sicher, dass der Port nicht öffentlich erreichbar ist.

Analysiert Wazuh SIEM-Alerts automatisch mit **Google Gemini AI** und stellt sie in einem Web-Dashboard dar – mit KI-Erklärung, Schweregrad-Einstufung und konkreten Handlungsempfehlungen auf Deutsch.

Kostenlos nutzbar mit dem Google AI Studio Free Tier (Tageskontingent je Modell, aktuell 500 Anfragen/Tag für `gemini-3.1-flash-lite`; siehe [Anfragen sparen](#anfragen-sparen-gemini-free-tier)).

---

## Features

- 🔐 **Login-Schutz** – Benutzername + Passwort (pbkdf2:sha256), Session-basiert, Brute-Force-Schutz
- 📂 **Historische Analyse** – scannt beim ersten Start alle vorhandenen Alert-Logs, nicht nur neue; holt nach einem Neustart oder Ausfall alles nach, was in der Zwischenzeit geschrieben wurde
- 🔄 **Log-Rotation-Support** – erkennt Wazuh-Log-Rotation (`alerts.json` → `YYYY/Mon/ossec-alerts-DD.json.gz`), liest die alte Datei zu Ende und macht mit der neuen bei Byte 0 weiter; auch über Neustarts und mehrtägige Ausfälle hinweg, ohne doppelte oder fehlende Alerts
- 🔴 **Live-Überwachung** – verfolgt `alerts.json` kontinuierlich und analysiert neue Alerts automatisch
- ⏳ **Intelligentes Batching** – sammelt Alerts und sendet sie gebündelt, um API-Tokens zu sparen
- ⚠️ **Quota-Handling** – pausiert bei erschöpftem Gemini-Kontingent, zeigt Countdown im Dashboard und macht automatisch weiter
- 🔁 **Persistente Retry-Queue** – bei Quota-Erschöpfung, HTTP 5xx, Timeouts und Verbindungsfehlern werden Batches in der Datenbank geparkt und mit exponentiellem Backoff erneut gesendet; ein Neustart verliert nichts
- 🌐 **Web-Dashboard** – Severity-Filter, Live/Historisch-Tabs, Klick-Detail mit Erklärung und Handlungsempfehlung
- 🧠 **Infra-Kontext** – beschreibe deine Infrastruktur einmalig beim Setup, Gemini gibt passendere Empfehlungen
- 🛡️ **Gehärtete Architektur** – dedizierter unprivilegierter Service-User, WAL-Modus für SQLite, ProxyFix für korrekte IPs hinter Reverse Proxies, LLM-Output-Whitelist gegen Prompt Injection

---

## Wie es funktioniert

```
Wazuh alerts.json
      ↓  (tail -f, Lesestelle = Datei-Identität + Byte-Offset, siehe unten)
  Alert-Buffer
      ↓  (nach N Alerts ODER X Sekunden)
  Gruppierung nach Rule-ID  →  spart Gemini-Tokens
      ↓
  LLM-Output-Whitelist (severity/risk Enum-Prüfung)
      ↓
  Google Gemini 1.5 Flash API
      ↓
  SQLite (WAL-Modus)  →  REST-API  →  Web-Dashboard
```

Bei Fehlern (429, 5xx, Timeout, Verbindungsfehler):
```
  Gemini-Fehler
      ↓
  Batch → status='pending' + next_attempt   (in SQLite, übersteht Neustarts)
      ↓  (Retry-Worker prüft alle 30s, ein Batch alle 10s)
  Backoff + Quota abgelaufen → automatische Wiederholung → 'done'
```

| Fehler | Verhalten |
|---|---|
| 429 (Quota/Rate-Limit) | Batch wartet bis zum Quota-Reset (höchstens `QUEUE_MAX_AGE_HOURS` insgesamt) |
| HTTP 5xx / 408, Timeout, Verbindungsfehler | Backoff 1 min → 1 h (mit Jitter); nach `RETRY_MAX_AGE_HOURS` ohne Erfolg → `error` |
| HTTP 401 / 403 / 404, 400 mit `API_KEY_INVALID` / `FAILED_PRECONDITION` (Key, Region oder Modell falsch) | wie oben, die Batches bleiben für den Betreiber erhalten, bis der Key korrigiert ist |
| Unlesbare Gemini-Antwort | max. `RETRY_BAD_RESPONSE_MAX` Versuche, dann `error` |
| anderer 4xx (z. B. 400) | sofort `error` – Wiederholen ändert nichts. Wird geloggt (`verworfen (dropped_permanent=N)`) und gezählt. Ab dem 3. Batch in Folge wird nicht mehr verworfen, sondern wie ein Konfigurationsfehler geparkt |

Nach einem Fehler sperrt ein gemeinsames Backoff **alle** Gemini-Aufrufe (nicht nur den
betroffenen Batch), damit ein Ausfall das Tageskontingent nicht mit Proben verbrennt.
Beim Start werden Batches, die noch auf `analyzing` standen, wieder eingereiht.
`/api/stats` liefert dazu `batches` (Anzahl je Status), `retry_queue_size`, `upstream` und die
Zähler `runtime.retries_scheduled`, `retries_succeeded`, `dropped_permanent`,
`dropped_bad_response`, `expired`, `recovered_stale`.

---

## Voraussetzungen

- Debian 11/12 oder Ubuntu 22.04/24.04
- Wazuh Manager installiert und aktiv
- Internetzugang für die Gemini API
- Google AI Studio API Key (kostenlos): [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

---

## Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mozra-the-great/wazuh-ai-analyzer/v1.0.0/install.sh)
```

Der Installer fragt interaktiv nach:

| Parameter | Default | Beschreibung |
|---|---|---|
| Gemini API Key | – | Von Google AI Studio |
| Port | `8765` | Web-Dashboard Port |
| Min. Alert-Level | `5` | Wazuh-Levels unter diesem Wert ignorieren |
| Batch-Größe | `25` | Alerts pro Gemini-Anfrage |
| Batch-Timeout | `300s` | Flush auch bei weniger Alerts nach X Sekunden |
| Infra-Kontext | generisch | Beschreibung deiner Infrastruktur für bessere KI-Empfehlungen |
| Benutzername | `admin` | Login-Benutzername |
| Passwort | – | Min. 8 Zeichen, wird als Hash gespeichert |
| Bind-Adresse | `127.0.0.1` | `0.0.0.0` nur hinter HTTPS-Proxy |

Der Installer legt außerdem einen dedizierten, unprivilegierten System-User
(`wazuh-ai-analyzer`) an, unter dem der Service läuft (siehe
[Sicherheit & Hardening](#sicherheit--hardening)).

Nach der Installation ist das Dashboard erreichbar unter:
```
http://<SERVER-IP>:8765/login
```

---

## Konfiguration anpassen

Alle Einstellungen liegen in `/etc/wazuh-ai-analyzer.env`:

```bash
nano /etc/wazuh-ai-analyzer.env
systemctl restart wazuh-ai-analyzer
```

| Variable | Default | Beschreibung |
|---|---|---|
| `GEMINI_API_KEY` | – | Google AI Studio API Key |
| `WAZUH_ALERTS_LOG` | `/var/ossec/logs/alerts/alerts.json` | Pfad zur Wazuh Alert-Log-Datei |
| `MIN_LEVEL` | `5` | Minimales Wazuh-Alert-Level (1–15) |
| `BATCH_MAX` | `25` | Alerts pro Gemini-Anfrage |
| `BATCH_TIMEOUT` | `300` | Sekunden bis Flush (auch bei weniger als BATCH_MAX Alerts) |
| `BATCH_TIMEOUT_QUIET` | = `BATCH_TIMEOUT` | Wartezeit für einen nicht vollen Batch, solange er **nur** Alerts unter `URGENT_LEVEL` enthält (mindestens `BATCH_TIMEOUT`). Größer gesetzt (z. B. `900`) werden aus vielen Mini-Batches wenige volle – das spart Free-Tier-Anfragen, siehe [Anfragen sparen](#anfragen-sparen-gemini-free-tier) |
| `URGENT_LEVEL` | `10` | Ab diesem Wazuh-Level gilt der kurze `BATCH_TIMEOUT` weiter |
| `HISTORY_BATCH` | `50` | Alerts pro Anfrage beim historischen Scan |
| `HISTORY_PAUSE` | `8` | Sekunden Pause zwischen historischen Batches |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Gemini Modell |
| `GEMINI_TEMPERATURE` | `0.15` | Kreativität der KI-Antworten (0.0–1.0, niedriger = deterministischer) |
| `RETRY_BASE_DELAY` | `60` | Start-Backoff in Sekunden nach einem Fehler (verdoppelt sich pro Versuch) |
| `RETRY_MAX_DELAY` | `3600` | Obergrenze des Backoffs in Sekunden |
| `RETRY_MAX_AGE_HOURS` | `72` | Nach dieser Zeit ununterbrochener 5xx-/Netzfehler wird ein Batch `error` (Quota-Wartezeit zählt nicht) |
| `QUEUE_MAX_AGE_HOURS` | `72` | Höchstalter eines wartenden Batches (inkl. Quota-Wartezeit); ältere werden `error` (`runtime.expired`). Die Queue wird neueste zuerst abgearbeitet, damit frische Alerts bei knapper Quota nicht hinter altem Rückstand warten |
| `RETRY_BAD_RESPONSE_MAX` | `3` | Versuche bei unlesbarer Gemini-Antwort |
| `RETRY_POLL` / `RETRY_PACE` | `30` / `10` | Retry-Worker: Prüfintervall im Leerlauf / Pause zwischen zwei Wiederholungen (Sekunden) |
| `STALE_ANALYZING_SECONDS` | `900` | Batches, die so lange unbearbeitet auf `analyzing` stehen, werden wieder eingereiht |
| `GEMINI_CONCURRENCY` | `2` | Gleichzeitige Gemini-Anfragen |
| `INFRA_CONTEXT` | `a self-hosted Linux server environment` | Infrastruktur-Beschreibung für Gemini |
| `PORT` | `8765` | Web-Dashboard Port |
| `LISTEN_HOST` | `127.0.0.1` | Bind-Adresse (`0.0.0.0` nur hinter HTTPS-Proxy) |
| `DASHBOARD_USER` | `admin` | Login-Benutzername |
| `DASHBOARD_PASSWORD_HASH` | – | pbkdf2:sha256 Hash (kein Klartext!) |
| `SESSION_LIFETIME` | `28800` | Session-Dauer in Sekunden (8 Stunden) |
| `LOGIN_MAX_ATTEMPTS` | `5` | Max. Fehlversuche vor 60s Sperre |
| `TRUSTED_PROXY_HOPS` | `0` | Anzahl vertrauenswürdiger Reverse-Proxy-Hops vor der App. `0` = ProxyFix deaktiviert, `request.remote_addr` ist die rohe Socket-Peer-IP. Nur auf `1` setzen, wenn wirklich ein Reverse Proxy (z. B. Nginx, siehe unten) `X-Forwarded-For` korrekt überschreibt – sonst kann jeder Client die IP fürs Login-Rate-Limiting fälschen. |
| `SESSION_COOKIE_SECURE` | `true` | Session-Cookie nur über HTTPS senden (`false` nur falls ein spezielles Setup den Cookie über reines HTTP benötigt) |

### Infra-Kontext Beispiele

```bash
# Homelab mit Proxmox und VPN:
INFRA_CONTEXT="Proxmox homelab with LXC containers, Oracle Cloud VPS, Tailscale VPN, Nginx reverse proxy, fail2ban"

# Einfacher VPS:
INFRA_CONTEXT="Ubuntu VPS with Docker, Nginx, and UFW firewall"

# Firmen-Umgebung:
INFRA_CONTEXT="On-premise Linux servers with Active Directory, Samba, and iptables"
```

---

## Passwort ändern

```bash
# 1. Neuen Hash generieren
python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('neues_passwort'))"

# 2. Hash in Konfiguration eintragen
nano /etc/wazuh-ai-analyzer.env
# → DASHBOARD_PASSWORD_HASH=<ausgabe von oben> ersetzen

# 3. Service neu starten
systemctl restart wazuh-ai-analyzer
```

---

## Optional: Als Subdomain verfügbar machen

Mit Nginx Proxy Manager oder direkt mit Nginx. Wichtig:
1. `proxy_set_header X-Forwarded-For` setzen, damit das integrierte Brute-Force-Tracking die echte Client-IP sieht.
2. `TRUSTED_PROXY_HOPS=1` in der Konfiguration setzen, damit die App diesen Header auch tatsächlich auswertet (ProxyFix ist standardmäßig deaktiviert, siehe Sicherheitshinweis oben).

```nginx
server {
    listen 443 ssl;
    server_name wazuh-ai.deine-domain.de;

    # SSL-Zertifikat hier einbinden (Let's Encrypt empfohlen)

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

---

## Dashboard

Das Dashboard aktualisiert sich automatisch alle 20 Sekunden.

**Statusanzeigen im Header:**
- 🟢 **Gemini OK** – Analyse läuft normal
- 🔴 **Quota leer** – roter Banner mit Countdown und automatischem Resume
- ⏳ **N gepuffert** – Alerts im Puffer, noch nicht gesendet
- 🔁 **N warten** – Batches in der Retry-Queue (nach Quota- oder Verbindungsfehler)
- **Abmelden** – Button oben rechts

**Quota-Banner (erscheint automatisch bei 429):**

Zeigt Fehlermeldung von Google, Uhrzeit seit wann die Quota erschöpft ist, Countdown bis zum nächsten Versuch und Anzahl wartender Batches. Verschwindet automatisch sobald die Analyse wieder läuft.

**Historischer Scan / Nachholen (erscheint beim ersten Start und wenn nach einem Neustart etwas nachzuholen ist):**

Blauer Fortschrittsbalken mit Datei-Fortschritt und Anzahl verarbeiteter Alerts. Macht nach einem Neustart nahtlos weiter (Watermark-Datei).

---

## Lesestelle (Watermark)

`data/watermark.json` (Format v2) merkt sich, wie weit die Alerts gelesen sind:

- **`live`** – die Datei, die der Live-Watcher gerade liest: Device/Inode, Byte-Offset (im
  unkomprimierten Strom) und ein Hash der ersten Zeile. Der Hash erkennt dieselbe Datei auch
  nach Umbenennen, Hardlink und `gzip` (neuer Inode). Der Offset wird erst fortgeschrieben,
  **nachdem** der Batch mit den gelesenen Alerts in der Datenbank steht – ein Absturz liest
  höchstens ein paar Zeilen erneut, verliert aber keine.
- **`backlog`** – Abschnitte, die noch nachgeholt werden (gedrosselt mit `HISTORY_BATCH` /
  `HISTORY_PAUSE`, Quota-bewusst).

Beim Start wird das mit dem Dateisystem abgeglichen:

| Befund | Verhalten |
|---|---|
| gleiche Datei, Offset kleiner als Dateiende | der Rest kommt als Nachhol-Abschnitt, Live startet am Ende |
| Datei rotiert | die Vortagsdatei (`ossec-alerts-DD.json(.gz)`, per Hash gefunden) ab Offset zu Ende lesen, danach alle neueren Tagesarchive, danach die neue `alerts.json` ab Byte 0 |
| Datei gekürzt | von vorn lesen |
| Vorgängerdatei nicht mehr auffindbar | Warnung im Log; nur neuere Archive und die aktuelle Datei |
| kein Watermark (Erstinstallation) | vorhandene Alert-Logs neben `alerts.json` und die aktuelle Datei historisch analysieren; Tagesarchive älterer Tage werden **nicht** automatisch aufgerollt (Quota) |
| altes Format (`{pfad: zeilennummer}`) | Migration ohne erneutes Analysieren: Live startet am aktuellen Dateiende, Kopie als `watermark.json.v1.bak` |
| unlesbare Datei | wie altes Format, Kopie als `watermark.json.corrupt` |

---

## Anfragen sparen (Gemini-Free-Tier)

Das Free-Tier begrenzt die Anfragen pro Tag (Stand 2026-10: 500 für `gemini-3.1-flash-lite`, 15/min;
Reset 00:00 Pacific). Jeder Batch ist genau eine Anfrage, also zählt die **Anzahl der Batches**, nicht
die der Alerts. Gemessen an einer echten Installation: ruhige Tage hatten ~200–270 Batches mit
durchschnittlich 6–10 Alerts, nach dem Herunterstufen von Rauschquellen sogar nur 2,4 Alerts pro Batch,
weil der 5-Minuten-Timeout immer wieder fast leere Batches sendet. Ein Rauschbursts (hier eine Regel
mit 26 000 Alerts/Tag) füllt dagegen Batches zu 25 Alerts und verbraucht das Kontingent in Stunden;
das löst man an der Quelle (Wazuh-Regel herunterstufen) bzw. mit `MIN_LEVEL`, nicht im Analyzer.

Stellschraube im Analyzer: `BATCH_TIMEOUT_QUIET` (siehe oben). Replay der Batches vom 24.09.–07.10.
(Level-≥10-Alerts weiter nach 300 s): `900` halbiert die Batches ruhiger Tage (242 → 116/Tag, −52 %),
`1800` → 87/Tag (−64 %); die Zahl der Alert-Gruppen sinkt dabei mit (−31 % / −38 %), weil gleiche
Regeln in einem größeren Batch zu einer Gruppe zusammenfallen. Der Preis ist Latenz: Alerts unter
`URGENT_LEVEL` können bis zu `BATCH_TIMEOUT_QUIET` warten.

---

## Abhängigkeiten (Hash-Pinning)

`requirements.txt` ist mit `pip-compile --generate-hashes` aus `requirements.in` erzeugt und
enthält für jedes Paket (auch transitive) einen SHA256. Der Installer und die CI installieren mit
`pip install --require-hashes -r requirements.txt`; ein manipuliertes PyPI-Release wird abgelehnt.
Version anheben: Pin in `requirements.in` ändern, dann

```bash
pip install pip-tools
pip-compile --generate-hashes --strip-extras --output-file=requirements.txt requirements.in
```

---

## Nützliche Befehle

```bash
# Service-Status
systemctl status wazuh-ai-analyzer

# Live-Logs
journalctl -u wazuh-ai-analyzer -f

# Konfiguration bearbeiten
nano /etc/wazuh-ai-analyzer.env
systemctl restart wazuh-ai-analyzer

# Historischen Scan neu starten (Watermark löschen; analysiert die aktuelle alerts.json erneut ab Anfang)
rm /opt/wazuh-ai-analyzer/data/watermark.json
systemctl restart wazuh-ai-analyzer

# Alle Daten zurücksetzen
systemctl stop wazuh-ai-analyzer
rm /opt/wazuh-ai-analyzer/data/analyses.db
rm /opt/wazuh-ai-analyzer/data/watermark.json
systemctl start wazuh-ai-analyzer
```

---

## Update

Denselben Installer-Befehl erneut ausführen – bestehende Datenbank, Session-Key und Konfiguration bleiben erhalten:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mozra-the-great/wazuh-ai-analyzer/v1.0.0/install.sh)
```

---

## Integritätsprüfung des Installers

Der Installer lädt `analyzer.py` und `static/index.html` nicht mehr vom
floating `main`-Branch, sondern von einem gepinnten Release-Tag (aktuell
`v1.0.0`), und prüft beide Dateien nach dem Download gegen SHA-256-Hashes aus
`checksums.sha256` (ebenfalls vom selben Tag geladen). Weicht ein Hash ab oder
fehlt ein Eintrag komplett, bricht die Installation ab und löscht die
betroffene Datei – das schützt gegen einen kompromittierten Mirror, einen
manipulierten Download oder einen unbemerkt geänderten `main`-Branch.

Umgebungsvariablen dafür:

| Variable | Zweck |
|---|---|
| `WAZUH_AI_REF` | Anderer Tag statt des Default-Releases (z. B. `WAZUH_AI_REF=v1.1.0`) |
| `WAZUH_AI_REPO` | Eigener Fork/Mirror (muss mit `https://` beginnen). Die Prüfung bleibt aktiv, schützt dann aber nur gegen Übertragungsfehler – ein bösartiger Mirror kann `checksums.sha256` gleich mit manipulieren |
| `WAZUH_AI_ALLOW_UNVERIFIED=1` | Prüfung bewusst überspringen (nicht empfohlen, nur für Debugging) |

Ein neuer Release-Tag wird mit `scripts/release.sh <version>` vorbereitet:
das Skript regeneriert `checksums.sha256`, setzt den `WAZUH_AI_REF`-Default in
`install.sh` und zeigt die nötigen `git commit`/`git tag`/`git push`-Schritte
an.

---

## Datenspeicherung

```
/opt/wazuh-ai-analyzer/            # gehört dem Service-User "wazuh-ai-analyzer"
├── analyzer.py              # Backend
├── static/
│   └── index.html           # Dashboard
├── venv/                    # Python-Umgebung
└── data/
    ├── analyses.db          # SQLite (WAL-Modus) – alle Findings und Batches
    ├── watermark.json       # Lesestelle (Datei-Identität + Offset) und offene Nachhol-Abschnitte
    └── session.key          # Flask-Session-Secret (auto-generiert, chmod 600)

/etc/wazuh-ai-analyzer.env   # Konfiguration (chmod 600, enthält API Key + Passwort-Hash)
/etc/systemd/system/wazuh-ai-analyzer.service
```

---

## Sicherheit & Hardening

### Warum das Dashboard schützen?

Das Dashboard zeigt priorisierte Sicherheitsschwachstellen deiner Infrastruktur, betroffene Hostnamen und konkrete Angriffsvektoren. Für einen Angreifer wäre es ein fertiger Ziel-Katalog.

### Implementierte Schutzmaßnahmen

| Maßnahme | Details |
|---|---|
| Dedizierter Service-User | Läuft als unprivilegierter System-User `wazuh-ai-analyzer` (kein root), nur Mitglied der Gruppe die `alerts.json` gehört |
| systemd-Hardening | `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`; Schreibzugriff nur auf `data/` |
| Login-Pflicht | Jede Route (inkl. API) erfordert eine gültige Session |
| Passwort-Hashing | pbkdf2:sha256 via Werkzeug – Klartext wird nie gespeichert |
| Brute-Force-Schutz | Nach 5 Fehlversuchen 60s Sperre pro IP |
| ProxyFix | Echte Client-IP hinter Reverse Proxies (X-Forwarded-For) |
| Session-Key | Zufällig generiert, persistent, chmod 600 |
| Session-Cookie | `Secure` (nur HTTPS) und `SameSite=Lax` gesetzt |
| LLM-Whitelist | `overall_risk` und `severity` werden gegen Enum geprüft – Prompt Injection landet nicht in der DB |
| Prompt-Isolation | Alert-Felder (`full_log`, Agent, Benutzer, IP …) sind angreiferbeeinflussbar: Steuer-/Formatzeichen und Zeilenumbrüche werden entfernt, alles ist längenbegrenzt und geht nur als JSON-Zeile in einen Datenblock mit zufälligen Markierungen pro Anfrage; System- und Prompt-Text erklären den Block zu unvertrauenswürdigen Daten |
| Antwort-Schema | Die Modellantwort wird strikt geprüft (`validate_result`): nur `summary`/`overall_risk`/`findings`, Enums per Whitelist, Texte bereinigt und begrenzt, `affected_agents`/`rule_ids` nur aus dem Batch, max. 50 Findings. Falsche Form → wie unlesbare Antwort (begrenzte Wiederholung). Stuft das Modell eine Regel mit Level ≥ 12 als `info`/`low` ein, wird das nur geloggt und in `runtime.suspicious_downgrades` gezählt |
| noindex Meta-Tag | Suchmaschinen indexieren das Dashboard nicht |
| Generischer Titel | `Security Dashboard` statt produktspezifischer Name (erschwert Shodan-Fingerprinting) |
| WAL-Modus | SQLite Write-Ahead Logging – keine "database is locked" Fehler unter Last |
| Datei-Identität | Log-Rotation wird erkannt; die Lesestelle hängt an der Datei, nicht am Pfad – kein Alert-Verlust und keine Doppelanalyse nach Rotation oder Neustart |

### Option 1: SSH-Tunnel (empfohlen für Einzelnutzer)

Standard-Konfiguration: `LISTEN_HOST=127.0.0.1`. Zugriff von deinem PC:

```bash
ssh -L 8765:127.0.0.1:8765 user@wazuh-server
# Dann im Browser: http://localhost:8765
```

### Option 2: Reverse Proxy mit HTTPS

```bash
# Nginx mit Let's Encrypt (certbot)
apt-get install -y nginx certbot python3-certbot-nginx
certbot --nginx -d wazuh-ai.deine-domain.de
```

Nginx-Konfiguration wie im Abschnitt "Als Subdomain verfügbar machen" oben.

---

## Technik

| Komponente | Details |
|---|---|
| Backend | Python 3 + Flask |
| KI | Google Gemini 1.5 Flash (REST API, kostenlos) |
| Datenbank | SQLite (WAL-Modus, multi-threaded sicher) |
| Frontend | Vanilla JS, kein Framework |
| Service | systemd, läuft als dedizierter unprivilegierter User (MemoryLimit 256M, CPUQuota 25%) |
| Auth | Session-basiert, pbkdf2:sha256, Brute-Force-Schutz |
| Proxy-Support | Werkzeug ProxyFix (X-Forwarded-For) |
| Log-Rotation | Watcher liest die alte Datei zu Ende, Neustart-Wiederaufnahme über Datei-Identität (Hash der ersten Zeile) |
| Fehlerbehandlung | Persistente Retry-Queue (SQLite) mit Backoff und automatischem Resume |
| Historische Analyse | Nachhol-Abschnitte im Watermark, resumable nach Neustart |

---

## Lizenz

GNU General Public License v3.0 — siehe [LICENSE](LICENSE).
