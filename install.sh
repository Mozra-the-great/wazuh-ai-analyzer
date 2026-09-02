#!/usr/bin/env bash
# =============================================================================
# Wazuh AI Analyzer – Installer
# Installiert den Analyzer-Service auf dem Wazuh Manager (Debian/Ubuntu)
#
# powered by Aeterna™
# Erstellt mithilfe von KI (Claude by Anthropic)
#
# Ausführen als root:
#   bash <(curl -fsSL https://raw.githubusercontent.com/Mozra-the-great/wazuh-ai-analyzer/v1.0.0/install.sh)
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "  ${CYAN}[•]${NC}  $*"; }
ok()      { echo -e "  ${GREEN}[✓]${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}[!]${NC}  $*"; }
error()   { echo -e "  ${RED}[✗]${NC}  $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Bitte als root ausführen"

INSTALL_DIR="/opt/wazuh-ai-analyzer"
SERVICE_NAME="wazuh-ai-analyzer"
SERVICE_USER="wazuh-ai-analyzer"
ENV_FILE="/etc/wazuh-ai-analyzer.env"

# Herkunft der App-Dateien.
#
# WAZUH_AI_REF: gepinnter Tag statt des floating "main"-Branches. Ein floating
# Branch ist genau der Angriffsvektor aus #4: wer den Branch (oder den GitHub-
# Account dahinter) kompromittiert, bekommt code execution als root auf jedem
# Server, der gerade installiert/updatet. Der Default-Wert hier wird von
# scripts/release.sh bei jedem Release aktualisiert.
WAZUH_AI_REF="${WAZUH_AI_REF:-v1.0.0}"
REPO_BASE="https://raw.githubusercontent.com/Mozra-the-great/wazuh-ai-analyzer"

# Mirror/Fork-Override. Nur https:// wird akzeptiert; ein anderes Schema
# (http://, file://, …) würde die Integritätsprüfung unten wertlos machen,
# da schon der Download selbst unauthentifiziert wäre.
if [[ -n "${WAZUH_AI_REPO:-}" ]]; then
    [[ "$WAZUH_AI_REPO" =~ ^https:// ]] || error "WAZUH_AI_REPO muss mit https:// beginnen"
    warn "WAZUH_AI_REPO gesetzt – lade App-Dateien von einem FREMDEN Mirror: ${WAZUH_AI_REPO}"
    warn "Die Checksummen-Prüfung unten schützt hier nur gegen Übertragungsfehler/"
    warn "abgebrochene Downloads, NICHT gegen einen bösartigen Mirror – der könnte"
    warn "checksums.sha256 gleich mit manipulieren."
fi
REPO_URL="${WAZUH_AI_REPO:-${REPO_BASE}/${WAZUH_AI_REF}}"

DEFAULT_PORT=8765

download() {
    local src="$1" dst="$2"
    if ! curl -fsSL "${REPO_URL}/${src}" -o "$dst"; then
        error "Download fehlgeschlagen: ${src}"
    fi
}

# Prüft eine bereits heruntergeladene Datei gegen checksums.sha256 (Format wie
# von sha256sum erzeugt: "<hash>  <pfad>"). Bricht ab, wenn der Eintrag FEHLT
# (nicht nur wenn er falsch ist) – ein fehlender Eintrag darf kein stiller
# Bypass der Prüfung sein.
verify_checksum() {
    local src="$1" dst="$2" checksums_file="$3"
    local expected
    expected=$(awk -v f="$src" '$2 == f { print $1; found=1 } END { if (!found) exit 1 }' "$checksums_file") \
        || error "Kein Checksum-Eintrag für '${src}' in checksums.sha256 gefunden – Abbruch (mögliches Downgrade/manipulierter Datei-Katalog)"
    local actual
    actual=$(sha256sum "$dst" | awk '{print $1}')
    if [[ "$expected" != "$actual" ]]; then
        rm -f "$dst"
        error "Integritätsprüfung fehlgeschlagen für '${src}': erwartet ${expected}, erhalten ${actual}. Datei gelöscht. Möglicher MITM-Angriff oder kompromittierter Mirror – Installation abgebrochen."
    fi
}

# =============================================================================
echo ""
echo -e "${BOLD}  ██████╗  ██████╗ ██╗    ██╗███████╗██████╗ ${NC}"
echo -e "${BOLD}  ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗${NC}"
echo -e "${BOLD}  ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝${NC}"
echo -e "${BOLD}  ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗${NC}"
echo -e "${BOLD}  ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║${NC}"
echo -e "${BOLD}  ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝${NC}"
echo ""
echo -e "  ${CYAN}Wazuh AI Analyzer${NC} – powered by Aeterna™"
echo -e "  ${CYAN}Erstellt mithilfe von KI (Claude by Anthropic)${NC}"
echo ""
echo "═══════════════════════════════════════════════════════"
echo ""

# =============================================================================
# Schritt 1: Gemini API Key abfragen
# =============================================================================
info "Google Gemini AI API Key einrichten …"
echo ""

# Prüfe ob Key bereits in env-Datei existiert
EXISTING_KEY=""
if [[ -f "$ENV_FILE" ]]; then
    EXISTING_KEY=$(grep "^GEMINI_API_KEY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- | tr -d '"')
fi

if [[ -n "$EXISTING_KEY" ]]; then
    echo -e "  ${GREEN}Vorhandener API Key gefunden: ${CYAN}${EXISTING_KEY:0:12}…${NC}"
    echo -ne "  ${BOLD}Neuen Key eingeben? (Enter = vorhandenen behalten) [j/N]:${NC} "
    read -r CHANGE_KEY </dev/tty
    echo ""
    if [[ ! "$CHANGE_KEY" =~ ^[jJyY]$ ]]; then
        GEMINI_KEY="$EXISTING_KEY"
    else
        GEMINI_KEY=""
    fi
else
    GEMINI_KEY=""
fi

if [[ -z "$GEMINI_KEY" ]]; then
    echo -e "  ${YELLOW}API Key von Google AI Studio:${NC}"
    echo -e "  ${CYAN}https://aistudio.google.com/app/apikey${NC}"
    echo ""
    echo -ne "  ${BOLD}Gemini API Key:${NC} "
    read -rs GEMINI_KEY </dev/tty
    echo ""
    [[ -n "$GEMINI_KEY" ]] || error "Kein API Key eingegeben – Abbruch"
fi

# =============================================================================
# Schritt 2: Konfiguration
# =============================================================================
echo ""
echo "───────────────────────────────────────────────────────"
info "Konfiguration …"

echo -ne "  Port für Web-Dashboard (Enter = ${DEFAULT_PORT}): "
read -r PORT_INPUT </dev/tty
PORT=${PORT_INPUT:-$DEFAULT_PORT}
[[ "$PORT" =~ ^[0-9]+$ ]] || PORT=$DEFAULT_PORT

echo -ne "  Minimales Alert-Level analysieren (Enter = 5, Range: 1–15): "
read -r LEVEL_INPUT </dev/tty
MIN_LEVEL=${LEVEL_INPUT:-5}
[[ "$MIN_LEVEL" =~ ^[0-9]+$ ]] || MIN_LEVEL=5

echo -ne "  Batch-Größe (Alerts pro Analyse, Enter = 25): "
read -r BATCH_INPUT </dev/tty
BATCH_MAX=${BATCH_INPUT:-25}
[[ "$BATCH_MAX" =~ ^[0-9]+$ ]] || BATCH_MAX=25

echo -ne "  Batch-Timeout in Sekunden (Enter = 300 = 5 Min.): "
read -r TIMEOUT_INPUT </dev/tty
BATCH_TIMEOUT=${TIMEOUT_INPUT:-300}
[[ "$BATCH_TIMEOUT" =~ ^[0-9]+$ ]] || BATCH_TIMEOUT=300

echo ""
echo -e "  ${YELLOW}Infrastruktur-Beschreibung für Gemini (gibt KI Kontext für bessere Empfehlungen):${NC}"
echo -e "  ${CYAN}Beispiel: \"Proxmox homelab mit LXC-Containern, Oracle Cloud VPS, Tailscale VPN, fail2ban\"${NC}"
echo -ne "  ${BOLD}Deine Infrastruktur (Enter = Standardtext):${NC} "
read -r INFRA_INPUT </dev/tty
INFRA_CONTEXT="${INFRA_INPUT:-a self-hosted Linux server environment}"

echo ""
echo "───────────────────────────────────────────────────────"
echo -e "  ${RED}${BOLD}⚠  Sicherheit: Login-Zugangsdaten${NC}"
echo ""
echo -e "  Das Dashboard zeigt Sicherheitsanalysen deiner Infrastruktur."
echo -e "  Es ist durch Benutzername + Passwort geschützt."
echo ""

echo -ne "  ${BOLD}Benutzername (Enter = admin):${NC} "
read -r USER_INPUT </dev/tty
DASHBOARD_USER="${USER_INPUT:-admin}"

while true; do
    echo -ne "  ${BOLD}Passwort:${NC} "
    read -rs PASS1 </dev/tty
    echo ""
    if [[ ${#PASS1} -lt 8 ]]; then
        warn "Passwort muss mindestens 8 Zeichen lang sein – nochmal."
        continue
    fi
    echo -ne "  ${BOLD}Passwort bestätigen:${NC} "
    read -rs PASS2 </dev/tty
    echo ""
    if [[ "$PASS1" != "$PASS2" ]]; then
        warn "Passwörter stimmen nicht überein – nochmal."
        continue
    fi
    break
done
# Passwort-Hash wird nach der venv-Installation generiert (Werkzeug muss verfügbar sein)
DASHBOARD_PASSWORD_HASH=""

echo ""
echo "───────────────────────────────────────────────────────"
echo -e "  ${BOLD}Bind-Adresse${NC}"
echo -e "  ${CYAN}127.0.0.1${NC} = nur localhost (SSH-Tunnel oder Reverse Proxy)"
echo -e "  ${CYAN}0.0.0.0${NC}   = alle Interfaces (nur hinter HTTPS-Proxy)"
echo -e "  ${CYAN}Eigene IP${NC} = z.B. 192.168.0.24 (empfohlen im LAN)"
echo ""
echo -ne "  ${BOLD}[1=127.0.0.1 / 2=0.0.0.0 / IP eingeben]:${NC} "
read -r BIND_CHOICE </dev/tty
if [[ "$BIND_CHOICE" == "1" ]]; then
    LISTEN_HOST="127.0.0.1"
    info "Dashboard bindet nur auf localhost ✓"
elif [[ "$BIND_CHOICE" == "2" ]]; then
    LISTEN_HOST="0.0.0.0"
    warn "Dashboard auf ALLEN Interfaces – stelle sicher dass HTTPS + Firewall konfiguriert sind!"
elif [[ "$BIND_CHOICE" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    LISTEN_HOST="$BIND_CHOICE"
    ok "Dashboard bindet auf ${LISTEN_HOST} ✓"
else
    LISTEN_HOST="127.0.0.1"
    warn "Ungültige Eingabe – fallback auf 127.0.0.1"
fi

echo ""

# =============================================================================
# Schritt 3: System-Pakete
# =============================================================================
echo "───────────────────────────────────────────────────────"
info "System-Pakete installieren …"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv curl
ok "System-Pakete installiert"

# =============================================================================
# Schritt 4: Verzeichnisse anlegen
# =============================================================================
info "Verzeichnisse anlegen …"
mkdir -p "${INSTALL_DIR}/static"
mkdir -p "${INSTALL_DIR}/data"
# Das data-Verzeichnis enthaelt die Analyse-Datenbank (priorisierte Schwachstellen,
# betroffene Hosts, Quell-IPs), das Watermark und den Flask-Session-Key. Nur der
# Service-User darf da rein - nicht die Standard-Umask (0755) erben.
chmod 700 "${INSTALL_DIR}/data"
ok "Verzeichnisse: ${INSTALL_DIR}"

# =============================================================================
# Schritt 5: Python venv + Abhängigkeiten
# =============================================================================
info "Python venv einrichten …"
python3 -m venv "${INSTALL_DIR}/venv" || error "venv-Erstellung fehlgeschlagen – python3-venv installiert?"
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
download "requirements.txt" "${INSTALL_DIR}/requirements.txt"
"${INSTALL_DIR}/venv/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
ok "Python-Pakete: $(tr '\n' ' ' < "${INSTALL_DIR}/requirements.txt")"

# Passwort hashen – jetzt wo Werkzeug im venv verfügbar ist
info "Passwort-Hash generieren …"
# Passwort über temporäre Datei übergeben um Shell-Escaping-Probleme zu vermeiden
_PASS_TMP=$(mktemp)
printf '%s' "${PASS1}" > "$_PASS_TMP"
DASHBOARD_PASSWORD_HASH=$(
    "${INSTALL_DIR}/venv/bin/python3" - <<PYEOF
import sys
from werkzeug.security import generate_password_hash
pw = open("${_PASS_TMP}").read()
print(generate_password_hash(pw))
PYEOF
)
rm -f "$_PASS_TMP"
unset PASS1 PASS2  # Klartext sofort aus dem Speicher entfernen
[[ -n "$DASHBOARD_PASSWORD_HASH" ]] || error "Hash-Generierung fehlgeschlagen"
ok "Passwort-Hash erstellt (Klartext entfernt)"

# =============================================================================
# Schritt 6: Dateien herunterladen
# =============================================================================
info "Dateien herunterladen …"

if [[ "${WAZUH_AI_ALLOW_UNVERIFIED:-0}" == "1" ]]; then
    warn "WAZUH_AI_ALLOW_UNVERIFIED=1 gesetzt – Integritätsprüfung wird ÜBERSPRUNGEN."
    warn "Heruntergeladener Code wird UNGEPRÜFT als root-vorbereitete Datei für den Service übernommen."
fi

CHECKSUMS_FILE=$(mktemp)
if [[ "${WAZUH_AI_ALLOW_UNVERIFIED:-0}" != "1" ]]; then
    if ! curl -fsSL "${REPO_URL}/checksums.sha256" -o "$CHECKSUMS_FILE"; then
        rm -f "$CHECKSUMS_FILE"
        error "Download von checksums.sha256 fehlgeschlagen – Integritätsprüfung nicht möglich. Abbruch (Bypass nur bewusst via WAZUH_AI_ALLOW_UNVERIFIED=1)."
    fi
fi

download "analyzer.py"          "${INSTALL_DIR}/analyzer.py"
download "static/index.html"    "${INSTALL_DIR}/static/index.html"

if [[ "${WAZUH_AI_ALLOW_UNVERIFIED:-0}" != "1" ]]; then
    verify_checksum "analyzer.py"       "${INSTALL_DIR}/analyzer.py"       "$CHECKSUMS_FILE"
    verify_checksum "static/index.html" "${INSTALL_DIR}/static/index.html" "$CHECKSUMS_FILE"
    ok "Integritätsprüfung (SHA-256) erfolgreich"
fi
rm -f "$CHECKSUMS_FILE"

ok "Dateien heruntergeladen"

# =============================================================================
# Schritt 7: Umgebungsvariablen schreiben
# =============================================================================
info "Konfigurationsdatei schreiben: ${ENV_FILE} …"
cat > "$ENV_FILE" <<EOF
# Wazuh AI Analyzer – Konfiguration
# Geändert: $(date '+%Y-%m-%d %H:%M:%S')
GEMINI_API_KEY="${GEMINI_KEY}"
WAZUH_ALERTS_LOG="/var/ossec/logs/alerts/alerts.json"
DB_PATH="${INSTALL_DIR}/data/analyses.db"
STATIC_DIR="${INSTALL_DIR}/static"
PORT=${PORT}
MIN_LEVEL=${MIN_LEVEL}
BATCH_MAX=${BATCH_MAX}
BATCH_TIMEOUT=${BATCH_TIMEOUT}
GEMINI_MODEL="gemini-1.5-flash"

# Infrastruktur-Beschreibung für den KI-Kontext (optional, verbessert Empfehlungen)
INFRA_CONTEXT="${INFRA_CONTEXT}"

# ── Sicherheit ────────────────────────────────────────────────────────────────
# Bind-Adresse: 127.0.0.1 = nur localhost (empfohlen, nutze SSH-Tunnel oder Reverse Proxy)
#               0.0.0.0   = alle Interfaces (nur hinter HTTPS-Proxy!)
LISTEN_HOST=${LISTEN_HOST}

# Login-Zugangsdaten
# Benutzername (Klartext, kein Geheimnis)
DASHBOARD_USER=${DASHBOARD_USER}
# Passwort-Hash (pbkdf2:sha256 via Werkzeug – KEIN Klartext)
# Neuen Hash erstellen: python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('neues_passwort'))"
DASHBOARD_PASSWORD_HASH=${DASHBOARD_PASSWORD_HASH}

# Session-Dauer in Sekunden (default: 8 Stunden = 28800)
SESSION_LIFETIME=28800

# Maximale Fehlversuche vor 60s Sperre
LOGIN_MAX_ATTEMPTS=5

# Anzahl vertrauenswürdiger Reverse-Proxy-Hops vor dieser App (0 = deaktiviert).
# Nur auf 1 setzen, wenn wirklich ein Reverse Proxy (z. B. Nginx) davor steht und
# X-Forwarded-For korrekt überschreibt – sonst kann jeder Client seine IP fürs
# Login-Rate-Limiting fälschen. Siehe README "Optional: Als Subdomain verfügbar machen".
TRUSTED_PROXY_HOPS=0

# Historische Analyse (Logs von vor der Installation)
HISTORY_BATCH=50
HISTORY_PAUSE=8
EOF
chmod 600 "$ENV_FILE"  # Enthält API Key und Passwort-Hash – nur root lesbar
ok "Konfiguration gespeichert (chmod 600)"

# =============================================================================
# Schritt 8: Dedizierter Service-User
# =============================================================================
info "Dedizierten Service-User einrichten …"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "System-User ${SERVICE_USER} angelegt"
else
    info "System-User ${SERVICE_USER} existiert bereits"
fi

# Der Service braucht nur Lesezugriff auf die Wazuh Alert-Logs, daher
# Mitgliedschaft in der Gruppe, der die Log-Datei gehört (i.d.R. "wazuh"),
# statt root-Rechten.
ALERTS_LOG_GROUP="wazuh"
if [[ -f /var/ossec/logs/alerts/alerts.json ]]; then
    detected_group=$(stat -c '%G' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true)
    [[ -n "$detected_group" ]] && ALERTS_LOG_GROUP="$detected_group"
fi
if getent group "$ALERTS_LOG_GROUP" >/dev/null 2>&1; then
    usermod -aG "$ALERTS_LOG_GROUP" "$SERVICE_USER"
    ok "${SERVICE_USER} zur Gruppe ${ALERTS_LOG_GROUP} hinzugefügt (Lesezugriff auf Alert-Logs)"
else
    warn "Gruppe ${ALERTS_LOG_GROUP} nicht gefunden – Service kann ${WAZUH_ALERTS_LOG:-alerts.json} ggf. nicht lesen. Wazuh Manager installiert?"
fi

# Installationsverzeichnis (Code, venv, Daten) dem Service-User übertragen,
# damit der laufende Prozess selbst keine root-Rechte mehr braucht. Auch bei
# einer Neuinstallation/einem Update sicher erneut ausführbar (idempotent).
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
# Bestehende Installationen: Rechte im data-Verzeichnis nachziehen, damit eine
# vor diesem Fix mit 0644 angelegte analyses.db/watermark.json nicht
# world-readable bleibt.
chmod 700 "${INSTALL_DIR}/data"
find "${INSTALL_DIR}/data" -maxdepth 1 -type f -exec chmod 600 {} +
ok "${INSTALL_DIR} gehört jetzt ${SERVICE_USER}:${SERVICE_USER} (data/ nur für diesen User lesbar)"

# =============================================================================
# Schritt 9: systemd Service
# =============================================================================
info "Systemd-Service einrichten …"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Wazuh AI Analyzer (powered by Aeterna)
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/venv/bin/python3 analyzer.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Ressourcen-Limits (schonend für LXC)
MemoryLimit=256M
CPUQuota=25%

# Hardening: der Prozess läuft unprivilegiert (siehe Schritt 8), braucht
# keine Privilegien-Eskalation und darf nur ins eigene data/-Verzeichnis
# schreiben.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${INSTALL_DIR}/data

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --quiet "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
ok "Service gestartet und aktiviert"

# =============================================================================
# Verifikation
# =============================================================================
echo ""
echo "───────────────────────────────────────────────────────"
info "Verifikation …"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Service läuft ✓"
else
    warn "Service nicht aktiv – Logs prüfen:"
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager
fi

# Wazuh Alert-Log prüfen
if [[ -f "/var/ossec/logs/alerts/alerts.json" ]]; then
    ok "Wazuh Alert-Log gefunden ✓"
else
    warn "Wazuh Alert-Log NICHT gefunden: /var/ossec/logs/alerts/alerts.json"
    warn "Stelle sicher dass Wazuh Manager läuft: systemctl status wazuh-manager"
fi

# API-Erreichbarkeit testen
sleep 3
if curl -sf "http://127.0.0.1:${PORT}/login" >/dev/null 2>&1; then
    ok "Dashboard erreichbar ✓"
else
    warn "Dashboard noch nicht erreichbar – Service startet ggf. noch"
fi

# =============================================================================
# Abschluss
# =============================================================================
IP=$(hostname -I | awk '{print $1}')
echo ""
echo "═══════════════════════════════════════════════════════"
echo -e "  ${GREEN}${BOLD}Installation abgeschlossen!${NC}"
echo ""
if [[ "$LISTEN_HOST" == "127.0.0.1" ]]; then
    echo -e "  🔒  Dashboard bindet nur auf ${CYAN}localhost${NC}"
    echo -e "      Zugriff via SSH-Tunnel:"
    echo -e "      ${YELLOW}ssh -L ${PORT}:127.0.0.1:${PORT} user@${IP}${NC}"
    echo -e "      Dann im Browser: ${CYAN}http://localhost:${PORT}/login${NC}"
    echo ""
    echo -e "      Oder Reverse Proxy (NPM / Nginx mit HTTPS) vorschalten."
else
    echo -e "  🌐  Dashboard:  ${CYAN}http://${IP}:${PORT}/login${NC}"
fi
echo -e "  👤  Login:      ${CYAN}${DASHBOARD_USER}${NC} / (Passwort wie eingegeben)"
echo -e "  🔐  Auth:       ${GREEN}Benutzername + Passwort (pbkdf2:sha256)${NC}"
echo ""
echo -e "  🔑  Gemini Key: ${CYAN}${GEMINI_KEY:0:16}…${NC}"
echo -e "  📊  Min-Level:  Wazuh-Alerts ≥ ${MIN_LEVEL}"
echo -e "  📦  Batch:      ${BATCH_MAX} Alerts oder ${BATCH_TIMEOUT}s"
echo ""
echo -e "  Passwort ändern:"
echo -e "  ${YELLOW}python3 -c \"from werkzeug.security import generate_password_hash; print(generate_password_hash('neues_pw'))\"${NC}"
echo -e "  ${YELLOW}nano ${ENV_FILE}${NC}  → DASHBOARD_PASSWORD_HASH= ersetzen"
echo -e "  ${YELLOW}systemctl restart ${SERVICE_NAME}${NC}"
echo ""
echo -e "  Nützliche Befehle:"
echo -e "  ${YELLOW}systemctl status ${SERVICE_NAME}${NC}"
echo -e "  ${YELLOW}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "  ${YELLOW}nano ${ENV_FILE}${NC}  (Konfiguration ändern)"
echo ""
echo -e "  Update:"
echo -e "  ${YELLOW}bash <(curl -fsSL ${REPO_URL}/install.sh)${NC}"
echo "═══════════════════════════════════════════════════════"
echo ""
