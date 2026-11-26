#!/usr/bin/env bash
# Wazuh AI Analyzer - installer for the release tarball (non-interactive, idempotent).
#
# Run it as root from the extracted tarball, after you verified the tarball (INSTALL.md):
#
#   sudo ./deploy/install.sh --gemini-key-file /root/gemini-key
#
# It installs this release into /opt/wazuh-ai-analyzer/releases/<version> (code and a venv
# with the hash-pinned requirements), creates the service user and the data directory,
# writes the unit and, on a first install, a settings file without secrets, then switches
# the `current` symlink and restarts the service. The previous release stays in place:
# rollback is `ln -sfn releases/<old> current && systemctl restart wazuh-ai-analyzer`.
# Nothing is downloaded except the pinned Python packages (pip --require-hashes).
set -euo pipefail

PREFIX=/opt/wazuh-ai-analyzer
SERVICE=wazuh-ai-analyzer
SERVICE_USER=wazuh-ai-analyzer
ENV_FILE=/etc/wazuh-ai-analyzer.env
CRED_DIR=/etc/wazuh-ai-analyzer
UNIT_DIR=/etc/systemd/system
PYTHON=python3
KEY_FILE=""
LXC=0
START=1

usage() {
    cat <<'USAGE'
Usage: install.sh [--gemini-key-file FILE] [--unprivileged-lxc] [--no-start]
                  [--python PYTHON] [--prefix DIR]

  --gemini-key-file FILE  copy the Gemini API key from FILE (one line) to
                          /etc/wazuh-ai-analyzer/gemini (mode 0600). Without it an existing
                          credential file is kept, or GEMINI_API_KEY in the settings file
                          is used (legacy installs); otherwise the installer stops.
  --unprivileged-lxc      install the drop-in for unprivileged containers
  --no-start              do not enable or restart the service
  --python PYTHON         Python 3.11 or newer for the venv (default: python3)
  --prefix DIR            install root (default: /opt/wazuh-ai-analyzer; the unit file
                          has the default path, the installer rewrites it)
USAGE
}

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gemini-key-file) [[ $# -ge 2 ]] || die "--gemini-key-file needs a value"; KEY_FILE="$2"; shift 2 ;;
        --unprivileged-lxc) LXC=1; shift ;;
        --no-start) START=0; shift ;;
        --python) [[ $# -ge 2 ]] || die "--python needs a value"; PYTHON="$2"; shift 2 ;;
        --prefix) [[ $# -ge 2 ]] || die "--prefix needs a value"; PREFIX="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ "$PREFIX" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--prefix must be an absolute path of letters, digits, . _ - /"

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
for needed in VERSION requirements.txt wazuh_ai_analyzer/__main__.py \
    wazuh_ai_analyzer/web/ui/ui-manifest.json deploy/wazuh-ai-analyzer.service \
    deploy/wazuh-ai-analyzer.env.example deploy/unprivileged-lxc.conf; do
    [[ -f "$SRC/$needed" ]] || die "$SRC/$needed is missing: run this from the extracted release tarball"
done
VERSION="$(<"$SRC/VERSION")"
[[ "$VERSION" =~ ^[0-9][0-9A-Za-z.-]*$ ]] || die "unexpected VERSION file"

command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found (Debian: apt install python3 python3-venv)"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "$PYTHON is older than 3.11"
"$PYTHON" -c 'import venv, ensurepip' 2>/dev/null \
    || die "the venv module is missing (Debian: apt install python3-venv)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

RELEASE="$PREFIX/releases/$VERSION"
[[ ! -e "$RELEASE" ]] || die "$RELEASE exists already: remove it to reinstall this version"

# --- the Gemini credential (its content is never printed) -------------------------------
CRED_FILE="$CRED_DIR/gemini"
KEY_FROM_ENV=0
if [[ -n "$KEY_FILE" ]]; then
    [[ -f "$KEY_FILE" && ! -L "$KEY_FILE" ]] || die "--gemini-key-file must be a regular file"
    [[ -s "$KEY_FILE" ]] || die "--gemini-key-file is empty"
elif [[ -s "$CRED_FILE" ]]; then
    info "keeping the existing credential $CRED_FILE"
elif [[ -f "$ENV_FILE" ]] && grep -q '^GEMINI_API_KEY=' "$ENV_FILE"; then
    info "no credential file: the unit uses GEMINI_API_KEY from $ENV_FILE (move it later)"
    KEY_FROM_ENV=1
else
    die "no Gemini key: pass --gemini-key-file FILE (or create $CRED_FILE)"
fi

# --- service user and directories ---------------------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$PREFIX" --shell /usr/sbin/nologin "$SERVICE_USER"
    info "created system user $SERVICE_USER"
fi
# Read access to the Wazuh alerts through the group that owns the log, not through root.
ALERTS_GROUP=wazuh
if [[ -f /var/ossec/logs/alerts/alerts.json ]]; then
    detected="$(stat -c '%G' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true)"
    if [[ -n "$detected" && "$detected" != UNKNOWN ]]; then ALERTS_GROUP="$detected"; fi
fi
if getent group "$ALERTS_GROUP" >/dev/null 2>&1; then
    usermod -aG "$ALERTS_GROUP" "$SERVICE_USER"
else
    echo "warning: group $ALERTS_GROUP not found; the service may not be able to read the alerts" >&2
fi

install -d -m 0755 -o root -g root "$PREFIX" "$PREFIX/releases"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$PREFIX/data"
chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX/data"
install -d -m 0700 -o root -g root "$CRED_DIR"
if [[ -n "$KEY_FILE" ]]; then
    install -m 0600 -o root -g root "$KEY_FILE" "$CRED_FILE"
    info "installed the Gemini credential"
fi

# --- the release: files and venv ----------------------------------------------------------
# Built in place (a venv cannot be moved), removed again when anything fails.
trap 'rm -rf "$RELEASE"' ERR
install -d -m 0755 -o root -g root "$RELEASE"
cp -R --no-preserve=ownership "$SRC/." "$RELEASE/"

info "creating the venv (hash-pinned requirements, wheels only)"
"$PYTHON" -m venv "$RELEASE/venv"
# --only-binary: nothing is built (no setup.py runs as root); --require-hashes: pip refuses
# any file that is not listed with its sha256 in requirements.txt.
"$RELEASE/venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --require-hashes -r "$RELEASE/requirements.txt"
"$RELEASE/venv/bin/python" -m compileall -q "$RELEASE/wazuh_ai_analyzer"
chown -R root:root "$RELEASE"
chmod -R go-w "$RELEASE"
trap - ERR

# --- settings (first install only) ------------------------------------------------------------
if [[ ! -e "$ENV_FILE" ]]; then
    install -m 0600 -o root -g root "$SRC/deploy/wazuh-ai-analyzer.env.example" "$ENV_FILE"
    info "wrote $ENV_FILE: set DASHBOARD_PASSWORD_HASH (see the comment in it)"
fi

# --- unit ---------------------------------------------------------------------------------------
UNIT="$UNIT_DIR/$SERVICE.service"
sed "s#/opt/wazuh-ai-analyzer#$PREFIX#g" "$SRC/deploy/wazuh-ai-analyzer.service" > "$UNIT.new"
chmod 0644 "$UNIT.new"
mv -f "$UNIT.new" "$UNIT"
DROPIN_DIR="$UNIT_DIR/$SERVICE.service.d"
if [[ "$LXC" -eq 1 ]]; then
    install -d -m 0755 "$DROPIN_DIR"
    install -m 0644 "$SRC/deploy/unprivileged-lxc.conf" "$DROPIN_DIR/unprivileged-lxc.conf"
fi
if [[ "$KEY_FROM_ENV" -eq 1 ]]; then
    install -d -m 0755 "$DROPIN_DIR"
    printf '[Service]\nLoadCredential=\n' > "$DROPIN_DIR/no-credential.conf"
else
    rm -f "$DROPIN_DIR/no-credential.conf"
fi

# --- switch ---------------------------------------------------------------------------------------
PREVIOUS=""
if [[ -L "$PREFIX/current" ]]; then
    PREVIOUS="$(readlink "$PREFIX/current")"
fi
ln -sfn "releases/$VERSION" "$PREFIX/current.new"
mv -T "$PREFIX/current.new" "$PREFIX/current"
systemctl daemon-reload
info "release $VERSION is now $PREFIX/current${PREVIOUS:+ (was $PREVIOUS)}"

if [[ "$START" -eq 0 ]]; then
    info "not started (--no-start): systemctl enable --now $SERVICE"
    exit 0
fi
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"

# Health check: the web server accepts connections once the service is up (the login page
# answers 503 while no password hash is set, which still proves the service runs).
env_value() {
    local value=""
    if [[ -f "$ENV_FILE" ]]; then
        value="$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | tr -d "\"' ")"
    fi
    printf '%s' "${value:-$2}"
}
host="$(env_value LISTEN_HOST 127.0.0.1)"
port="$(env_value PORT 8765)"
[[ "$host" == "0.0.0.0" || ! "$host" =~ ^[0-9.]+$ ]] && host=127.0.0.1
[[ "$port" =~ ^[0-9]+$ ]] || port=8765
for _ in $(seq 1 30); do
    systemctl is-active --quiet "$SERVICE" || break
    if "$PREFIX/current/venv/bin/python" -c \
        'import socket, sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()' \
        "$host" "$port" 2>/dev/null; then
        info "service is up on $host:$port"
        exit 0
    fi
    sleep 1
done
echo "error: the service did not come up; see: journalctl -u $SERVICE -n 50" >&2
if [[ -n "$PREVIOUS" ]]; then
    echo "rollback: ln -sfn $PREVIOUS $PREFIX/current && systemctl restart $SERVICE" >&2
fi
exit 1
