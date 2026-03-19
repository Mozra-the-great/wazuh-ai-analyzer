# 🛡️ Wazuh AI Analyzer

**powered by Aeterna™** · Erstellt mithilfe von KI (Claude by Anthropic)

> ⚠️ **Sicherheitshinweis:** Das Dashboard zeigt eine priorisierte Liste deiner Sicherheitsschwachstellen inklusive betroffener Systeme. Exponiere es **niemals direkt ins Internet** ohne Authentifizierung.
> Betreibe es hinter einem SSH-Tunnel, VPN oder einem Reverse Proxy mit HTTPS.
> Das integrierte Login (Benutzername + Passwort) schützt den Zugriff – stelle trotzdem sicher, dass der Port nicht öffentlich erreichbar ist.

Analysiert Wazuh SIEM-Alerts automatisch mit **Google Gemini AI** und stellt sie in einem Web-Dashboard dar – mit KI-Erklärung, Schweregrad-Einstufung und konkreten Handlungsempfehlungen auf Deutsch.

Kostenlos nutzbar mit dem Google AI Studio Free Tier (1.500 Anfragen/Tag).

---

## Features

- 🔐 **Login-Schutz** – Benutzername + Passwort (pbkdf2:sha256), Session-basiert, Brute-Force-Schutz
- 📂 **Historische Analyse** – scannt alle vorhandenen Alert-Logs ab dem ersten Tag, nicht nur neue
- 🔄 **Log-Rotation-Support** – erkennt Wazuh-Log-Rotation automatisch per Inode-Vergleich und öffnet neu
- 🔴 **Live-Überwachung** – verfolgt `alerts.json` kontinuierlich und analysiert neue Alerts automatisch
- ⏳ **Intelligentes Batching** – sammelt Alerts und sendet sie gebündelt, um API-Tokens zu sparen
- ⚠️ **Quota-Handling** – pausiert bei erschöpftem Gemini-Kontingent, zeigt Countdown im Dashboard und macht automatisch weiter
- 🔁 **Retry-Queue** – bei Quota-Erschöpfung werden Batches geparkt und später erneut gesendet, kein Datenverlust
- 🌐 **Web-Dashboard** – Severity-Filter, Live/Historisch-Tabs, Klick-Detail mit Erklärung und Handlungsempfehlung
- 🧠 **Infra-Kontext** – beschreibe deine Infrastruktur einmalig beim Setup, Gemini gibt passendere Empfehlungen
- 🛡️ **Gehärtete Architektur** – WAL-Modus für SQLite, ProxyFix für korrekte IPs hinter Reverse Proxies, LLM-Output-Whitelist gegen Prompt Injection

---

## Wie es funktioniert

```
Wazuh alerts.json
      ↓  (tail -f, inode-aware bei Log-Rotation)
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

Bei Quota-Erschöpfung (429):
```
  Gemini 429
      ↓
  Batch → Retry-Queue  (kein Datenverlust)
      ↓  (Retry-Worker prüft alle 30s)
  Quota frei → automatische Wiederholung
```

---

## Voraussetzungen

- Debian 11/12 oder Ubuntu 22.04/24.04
- Wazuh Manager installiert und aktiv
- Internetzugang für die Gemini API
- Google AI Studio API Key (kostenlos): [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

---

## Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mozra-the-great/wazuh-ai-analyzer/main/install.sh)
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
| `HISTORY_BATCH` | `50` | Alerts pro Anfrage beim historischen Scan |
| `HISTORY_PAUSE` | `8` | Sekunden Pause zwischen historischen Batches |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Gemini Modell |
| `GEMINI_TEMPERATURE` | `0.15` | Kreativität der KI-Antworten (0.0–1.0, niedriger = deterministischer) |
| `INFRA_CONTEXT` | `a self-hosted Linux server environment` | Infrastruktur-Beschreibung für Gemini |
| `PORT` | `8765` | Web-Dashboard Port |
| `LISTEN_HOST` | `127.0.0.1` | Bind-Adresse (`0.0.0.0` nur hinter HTTPS-Proxy) |
| `DASHBOARD_USER` | `admin` | Login-Benutzername |
| `DASHBOARD_PASSWORD_HASH` | – | pbkdf2:sha256 Hash (kein Klartext!) |
| `SESSION_LIFETIME` | `28800` | Session-Dauer in Sekunden (8 Stunden) |
| `LOGIN_MAX_ATTEMPTS` | `5` | Max. Fehlversuche vor 60s Sperre |

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

Mit Nginx Proxy Manager oder direkt mit Nginx. Wichtig: `proxy_set_header X-Forwarded-For` setzen, damit das integrierte Brute-Force-Tracking die echte Client-IP sieht (ProxyFix ist bereits aktiviert):

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
- 🔁 **N warten** – Batches in der Retry-Queue (nach Quota-Fehler)
- **Abmelden** – Button oben rechts

**Quota-Banner (erscheint automatisch bei 429):**

Zeigt Fehlermeldung von Google, Uhrzeit seit wann die Quota erschöpft ist, Countdown bis zum nächsten Versuch und Anzahl wartender Batches. Verschwindet automatisch sobald die Analyse wieder läuft.

**Historischer Scan (erscheint beim ersten Start):**

Blauer Fortschrittsbalken mit Datei-Fortschritt und Anzahl verarbeiteter Alerts. Macht nach einem Neustart nahtlos weiter (Watermark-Datei).

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

# Historischen Scan neu starten (Watermark löschen)
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
bash <(curl -fsSL https://raw.githubusercontent.com/Mozra-the-great/wazuh-ai-analyzer/main/install.sh)
```

---

## Datenspeicherung

```
/opt/wazuh-ai-analyzer/
├── analyzer.py              # Backend
├── static/
│   └── index.html           # Dashboard
├── venv/                    # Python-Umgebung
└── data/
    ├── analyses.db          # SQLite (WAL-Modus) – alle Findings und Batches
    ├── watermark.json       # Fortschritt des historischen Scans
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
| Login-Pflicht | Jede Route (inkl. API) erfordert eine gültige Session |
| Passwort-Hashing | pbkdf2:sha256 via Werkzeug – Klartext wird nie gespeichert |
| Brute-Force-Schutz | Nach 5 Fehlversuchen 60s Sperre pro IP |
| ProxyFix | Echte Client-IP hinter Reverse Proxies (X-Forwarded-For) |
| Session-Key | Zufällig generiert, persistent, chmod 600 |
| LLM-Whitelist | `overall_risk` und `severity` werden gegen Enum geprüft – Prompt Injection landet nicht in der DB |
| noindex Meta-Tag | Suchmaschinen indexieren das Dashboard nicht |
| Generischer Titel | `Security Dashboard` statt produktspezifischer Name (erschwert Shodan-Fingerprinting) |
| WAL-Modus | SQLite Write-Ahead Logging – keine "database is locked" Fehler unter Last |
| Inode-Watcher | Log-Rotation wird erkannt, kein Alert-Verlust nach täglicher Wazuh-Rotation |

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
| Service | systemd (MemoryLimit 256M, CPUQuota 25%) |
| Auth | Session-basiert, pbkdf2:sha256, Brute-Force-Schutz |
| Proxy-Support | Werkzeug ProxyFix (X-Forwarded-For) |
| Log-Rotation | Inode-basierter Watcher, automatisches Reopen |
| Quota-Handling | Retry-Queue mit automatischem Resume |
| Historische Analyse | Watermark-basiert, resumable nach Neustart |

---

## Lizenz

MIT
