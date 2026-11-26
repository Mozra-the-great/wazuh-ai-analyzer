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
#
# A second instance next to the production service (a shadow run, INSTALL.md) is installed
# with --instance NAME: own unit (wazuh-ai-analyzer-NAME), data directory (data-NAME),
# settings file, credential, port and `current-NAME` symlink. The release directory is
# shared. The production instance is untouched by it.
set -euo pipefail

PREFIX=/opt/wazuh-ai-analyzer
BASE_NAME=wazuh-ai-analyzer
SERVICE_USER=wazuh-ai-analyzer
CRED_DIR=/etc/wazuh-ai-analyzer
UNIT_DIR=/etc/systemd/system
ALERTS_DIR=/var/ossec/logs/alerts
PYTHON=python3
KEY_FILE=""
INSTANCE=""
PORT_OPT=""
SEED_WATERMARK=""
ALERTS_ACCESS=auto
LXC=0
NO_OSSEC_MASK=0
START=1

usage() {
    cat <<'USAGE'
Usage: install.sh [--gemini-key-file FILE] [--unprivileged-lxc] [--no-ossec-mask]
                  [--alerts-access auto|acl|group] [--no-start] [--python PYTHON]
                  [--prefix DIR] [--instance NAME [--port PORT] [--seed-watermark FILE]]

  --gemini-key-file FILE  copy the Gemini API key from FILE (one line) to
                          /etc/wazuh-ai-analyzer/gemini (mode 0600). Without it an existing
                          credential file is kept, or GEMINI_API_KEY in the settings file
                          is used (legacy installs); otherwise the installer stops. It also
                          stops when the settings file still sets GEMINI_API_KEY or
                          GEMINI_API_KEY_FILE, because that value would win over the file.
  --unprivileged-lxc      install the drop-in for unprivileged containers
  --no-ossec-mask         install the drop-in that does not hide /var/ossec from the
                          service (only when the container refuses the tmpfs; INSTALL.md)
  --alerts-access MODE    how the service user may read the Wazuh alerts: acl (setfacl on
                          the alert directory, no group membership), group (join the group
                          that owns the log; refuses root, sudo, adm, shadow, disk, docker)
                          or auto (acl when setfacl works, else group; default)
  --no-start              do not enable or restart the service
  --python PYTHON         Python 3.11 or newer for the venv (default: python3)
  --prefix DIR            install root (default: /opt/wazuh-ai-analyzer; the unit file
                          has the default path, the installer rewrites it)
  --instance NAME         install a second instance (shadow run): unit
                          wazuh-ai-analyzer-NAME, system user wazuh-ai-analyzer-NAME,
                          data-NAME, /etc/wazuh-ai-analyzer-NAME.env, credential gemini-NAME,
                          symlink current-NAME. NAME: a-z, 0-9, starts with a letter, at most
                          12 characters. The settings file of
                          an instance starts in ANALYSIS_MODE=decision on port 8766.
  --port PORT             dashboard port written into a new settings file (default 8765,
                          8766 for an instance)
  --seed-watermark FILE   (instance only) copy FILE, normally a copy of the production
                          watermark.json, into the instance's data directory unless it has
                          one already, so that it continues from there instead of analysing
                          the whole history again
USAGE
}

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gemini-key-file) [[ $# -ge 2 ]] || die "--gemini-key-file needs a value"; KEY_FILE="$2"; shift 2 ;;
        --unprivileged-lxc) LXC=1; shift ;;
        --no-ossec-mask) NO_OSSEC_MASK=1; shift ;;
        --alerts-access) [[ $# -ge 2 ]] || die "--alerts-access needs a value"; ALERTS_ACCESS="$2"; shift 2 ;;
        --no-start) START=0; shift ;;
        --python) [[ $# -ge 2 ]] || die "--python needs a value"; PYTHON="$2"; shift 2 ;;
        --prefix) [[ $# -ge 2 ]] || die "--prefix needs a value"; PREFIX="$2"; shift 2 ;;
        --instance) [[ $# -ge 2 ]] || die "--instance needs a value"; INSTANCE="$2"; shift 2 ;;
        --port) [[ $# -ge 2 ]] || die "--port needs a value"; PORT_OPT="$2"; shift 2 ;;
        --seed-watermark) [[ $# -ge 2 ]] || die "--seed-watermark needs a value"; SEED_WATERMARK="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ "$PREFIX" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--prefix must be an absolute path of letters, digits, . _ - /"
case "$ALERTS_ACCESS" in auto|acl|group) ;; *) die "--alerts-access must be auto, acl or group" ;; esac
if [[ -n "$INSTANCE" ]]; then
    [[ "$INSTANCE" =~ ^[a-z][a-z0-9]{0,11}$ ]] || die "--instance must be 1 to 12 characters of a-z and 0-9, starting with a letter"
elif [[ -n "$SEED_WATERMARK" ]]; then
    die "--seed-watermark is for an --instance only: the production data directory is never overwritten"
fi
if [[ -n "$PORT_OPT" ]]; then
    [[ "$PORT_OPT" =~ ^[0-9]{1,5}$ ]] || die "--port must be a number from 1 to 65535"
    PORT_OPT=$((10#$PORT_OPT))
    (( PORT_OPT >= 1 && PORT_OPT <= 65535 )) || die "--port must be a number from 1 to 65535"
fi

# Names that depend on the instance. The production instance has no suffix.
SUFFIX=""
[[ -z "$INSTANCE" ]] || SUFFIX="-$INSTANCE"
SERVICE="$BASE_NAME$SUFFIX"
# An instance runs as its own system user: two services under one UID could reach each
# other through /proc/<pid>/root and the signals of that UID, whatever the unit says.
SERVICE_USER="$SERVICE_USER$SUFFIX"
ENV_FILE="/etc/$BASE_NAME$SUFFIX.env"
CRED_FILE="$CRED_DIR/gemini$SUFFIX"
CURRENT="$PREFIX/current$SUFFIX"
DATA="$PREFIX/data$SUFFIX"
DEFAULT_PORT=8765
[[ -z "$INSTANCE" ]] || DEFAULT_PORT=8766
LISTEN_PORT="${PORT_OPT:-$DEFAULT_PORT}"

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
for needed in VERSION BUILD-INFO.json requirements.txt wazuh_ai_analyzer/__main__.py \
    wazuh_ai_analyzer/web/ui/ui-manifest.json deploy/wazuh-ai-analyzer.service \
    deploy/wazuh-ai-analyzer.env.example deploy/unprivileged-lxc.conf deploy/no-ossec-mask.conf; do
    [[ -f "$SRC/$needed" ]] || die "$SRC/$needed is missing: run this from the extracted release tarball"
done
VERSION="$(<"$SRC/VERSION")"
[[ "$VERSION" =~ ^[0-9][0-9A-Za-z.-]*$ ]] || die "unexpected VERSION file"

command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found (Debian: apt install python3 python3-venv)"
"$PYTHON" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "$PYTHON is older than 3.11"
"$PYTHON" -I -c 'import venv, ensurepip' 2>/dev/null \
    || die "the venv module is missing (Debian: apt install python3-venv)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

# --- the install root --------------------------------------------------------------------------
# An old installation (analyzer.py) leaves the whole tree owned by the service user. Whoever
# owns the root directory can swap the entries below it, and this script runs as root on them:
# take the root over first, then refuse anything that is not what it creates itself.
if [[ -e "$PREFIX" || -L "$PREFIX" ]]; then
    [[ -d "$PREFIX" && ! -L "$PREFIX" ]] || die "$PREFIX is not a directory"
    chown root:root "$PREFIX"
    chmod 0755 "$PREFIX"
else
    install -d -m 0755 -o root -g root "$PREFIX"
fi
for entry in releases data "data$SUFFIX" current.new "current$SUFFIX.new"; do
    [[ ! -L "$PREFIX/$entry" ]] || die "$PREFIX/$entry is a symlink: refusing to follow it (remove it after you checked where it points)"
done
if [[ -e "$PREFIX/releases" ]]; then
    [[ -d "$PREFIX/releases" ]] || die "$PREFIX/releases is not a directory"
    [[ "$(stat -c '%u' "$PREFIX/releases")" == 0 ]] \
        || die "$PREFIX/releases is not owned by root (a leftover of an old install?): check it, then chown root:root"
    (( (8#$(stat -c '%a' "$PREFIX/releases") & 8#022) == 0 )) \
        || die "$PREFIX/releases is writable by group or others: check it, then chmod 0755"
fi
if [[ -e "$DATA" ]]; then
    [[ -d "$DATA" ]] || die "$DATA is not a directory"
fi
if [[ -e "$CURRENT" || -L "$CURRENT" ]]; then
    [[ -L "$CURRENT" ]] || die "$CURRENT exists and is not a symlink"
fi

RELEASE="$PREFIX/releases/$VERSION"
if [[ -L "$CURRENT" && "$(readlink "$CURRENT")" == "releases/$VERSION" ]]; then
    die "$VERSION is already the current release of $SERVICE: nothing to do (remove $RELEASE and the link to reinstall it)"
fi
# A release directory is shared by the instances. One that this script finished earlier for the
# very same build is reused (a shadow run first, the upgrade of the production service later);
# anything else under that name is not touched.
REUSE=0
if [[ -e "$RELEASE" || -L "$RELEASE" ]]; then
    if [[ -d "$RELEASE" && ! -L "$RELEASE" && -f "$RELEASE/.install-complete" \
        && "$(stat -c '%u' "$RELEASE")" == 0 ]] \
        && cmp -s "$SRC/BUILD-INFO.json" "$RELEASE/BUILD-INFO.json"; then
        REUSE=1
        info "release $VERSION is installed already: reusing $RELEASE"
    else
        die "$RELEASE exists already and is not a finished install of this build: remove it to reinstall this version"
    fi
fi

# --- the Gemini credential (its content is never printed) -------------------------------
KEY_FROM_ENV=0
if [[ -n "$KEY_FILE" ]]; then
    [[ -f "$KEY_FILE" && ! -L "$KEY_FILE" ]] || die "--gemini-key-file must be a regular file"
    [[ -s "$KEY_FILE" ]] || die "--gemini-key-file is empty"
    # A key in the settings file wins over the credential: the new file would be ignored.
    if [[ -f "$ENV_FILE" ]] \
        && grep -Eq "^[[:space:]]*GEMINI_API_KEY(_FILE)?=[[:space:]]*(\"[^\"]|'[^']|[^\"'[:space:]])" "$ENV_FILE"; then
        die "$ENV_FILE sets GEMINI_API_KEY or GEMINI_API_KEY_FILE, which wins over the credential file: remove that line (the key is in $KEY_FILE) or leave out --gemini-key-file"
    fi
elif [[ -s "$CRED_FILE" ]]; then
    info "keeping the existing credential $CRED_FILE"
elif [[ -f "$ENV_FILE" ]] && grep -q '^GEMINI_API_KEY=' "$ENV_FILE"; then
    info "no credential file: the unit uses GEMINI_API_KEY from $ENV_FILE (move it later)"
    KEY_FROM_ENV=1
else
    die "no Gemini key: pass --gemini-key-file FILE (or create $CRED_FILE)"
fi
if [[ -n "$SEED_WATERMARK" ]]; then
    [[ -f "$SEED_WATERMARK" && ! -L "$SEED_WATERMARK" ]] || die "--seed-watermark must be a regular file"
    [[ -s "$SEED_WATERMARK" ]] || die "--seed-watermark is empty"
    # Only a watermark is copied: whatever else a root-made copy may have followed a link to
    # (a service can leave a symlink in its data directory) is not valid watermark JSON.
    "$PYTHON" -I -c 'import json, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
data = os.read(fd, 1048577)
if len(data) > 1048576:
    sys.exit(1)
doc = json.loads(data)
ok = isinstance(doc, dict) and doc.get("version") == 2 and {"live", "backlog", "next_id"} <= set(doc)
sys.exit(0 if ok else 1)' "$SEED_WATERMARK" 2>/dev/null \
        || die "--seed-watermark is not a watermark.json (format version 2, at most 1 MiB)"
fi

# --- service user and directories ---------------------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$PREFIX" --shell /usr/sbin/nologin "$SERVICE_USER"
    info "created system user $SERVICE_USER"
fi

# Read access to the Wazuh alerts. Preferred: an ACL on the alert directory for the service
# user alone. Fallback: membership in the group that owns the log, which is refused for
# groups that grant far more than the alerts.
FORBIDDEN_GROUPS=" root sudo adm shadow disk docker wheel lxd incus libvirt kvm kmem staff systemd-journal "
grant_alerts_by_group() {
    local group=wazuh detected gid
    if [[ -f "$ALERTS_DIR/alerts.json" ]]; then
        detected="$(stat -c '%G' "$ALERTS_DIR/alerts.json" 2>/dev/null || true)"
        if [[ -n "$detected" && "$detected" != UNKNOWN ]]; then group="$detected"; fi
    fi
    if ! getent group "$group" >/dev/null 2>&1; then
        warn "group $group not found; the service may not be able to read the alerts"
        return 0
    fi
    gid="$(getent group "$group" | cut -d: -f3)"
    if [[ "$gid" == 0 || "$FORBIDDEN_GROUPS" == *" $group "* ]]; then
        die "the alerts belong to the group $group: joining it would give the service far more than the alerts. Install setfacl (apt install acl) and use --alerts-access acl, or change the group of the alert log to a dedicated one"
    fi
    if id -nG "$SERVICE_USER" | tr ' ' '\n' | grep -qx "$group"; then
        info "$SERVICE_USER is in the group $group already"
    else
        usermod -aG "$group" "$SERVICE_USER"
        info "added $SERVICE_USER to the group $group (read access to the alerts)"
    fi
}
# An earlier installation put the service user into the alert group. With the ACL in place
# that membership only widens what the service can read (agent keys, ...): remove it once
# the service user is shown to read the alerts without it.
drop_alert_group_membership() {
    local group probe
    [[ -f "$ALERTS_DIR/alerts.json" ]] || return 0
    group="$(stat -c '%G' "$ALERTS_DIR/alerts.json" 2>/dev/null || true)"
    [[ -n "$group" && "$group" != UNKNOWN ]] || return 0
    id -nG "$SERVICE_USER" | tr ' ' '\n' | grep -qx "$group" || return 0
    # Without the hiding of /var/ossec the host's directory permissions decide, and only the
    # group lets the service through /var/ossec: keep it then.
    if [[ "$NO_OSSEC_MASK" -eq 1 ]]; then
        warn "$SERVICE_USER stays in the group $group: --no-ossec-mask needs it to reach the alerts"
        return 0
    fi
    # The test runs in the mount namespace the unit gives the service (the alert directory
    # bound into an empty /var/ossec), as the service user and with fresh group membership.
    if command -v gpasswd >/dev/null 2>&1 && gpasswd -d "$SERVICE_USER" "$group" >/dev/null 2>&1; then
        if probe="$(systemd-run --quiet --wait --pipe --collect -p "User=$SERVICE_USER" \
            -p TemporaryFileSystem=/var/ossec:ro -p "BindReadOnlyPaths=$ALERTS_DIR" \
            head -c 1 "$ALERTS_DIR/alerts.json" 2>&1 >/dev/null)"; then
            info "removed $SERVICE_USER from the group $group (the ACL is enough; applies at the next restart)"
        else
            usermod -aG "$group" "$SERVICE_USER"
            [[ -z "$probe" ]] || warn "access test: $probe"
            warn "the ACL did not give $SERVICE_USER access to the alerts (or systemd-run cannot test it): it stays in the group $group"
        fi
    else
        warn "$SERVICE_USER is still in the group $group; remove it with: gpasswd -d $SERVICE_USER $group"
    fi
}
grant_alerts_by_acl() {
    # -P: never follow a symlink below the alert directory. The default ACL makes files that
    # Wazuh creates later (rotation, new days) readable as well.
    setfacl -R -P -m "u:$SERVICE_USER:rX" "$ALERTS_DIR" \
        && find "$ALERTS_DIR" -xdev -type d -exec setfacl -P -d -m "u:$SERVICE_USER:rX" {} +
}
case "$ALERTS_ACCESS" in
    acl|auto)
        if [[ ! -d "$ALERTS_DIR" || -L "$ALERTS_DIR" ]]; then
            if [[ "$ALERTS_ACCESS" == acl ]]; then die "$ALERTS_DIR is not a directory: nothing to grant access to"; fi
            warn "$ALERTS_DIR is not a directory; the service may not be able to read the alerts"
        elif command -v setfacl >/dev/null 2>&1 && grant_alerts_by_acl; then
            info "gave $SERVICE_USER read access to $ALERTS_DIR through an ACL (no group membership)"
            drop_alert_group_membership
        elif [[ "$ALERTS_ACCESS" == acl ]]; then
            die "--alerts-access acl: setfacl is missing or failed on $ALERTS_DIR (apt install acl; the file system needs ACL support)"
        else
            warn "no usable setfacl for $ALERTS_DIR: falling back to group membership"
            grant_alerts_by_group
        fi
        ;;
    group) grant_alerts_by_group ;;
esac

install -d -m 0755 -o root -g root "$PREFIX/releases"
# Only the directory itself: what is inside belongs to the service already, and a recursive
# chown as root over a tree that the service user can write to is exactly what to avoid.
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA"
if foreign="$(find "$DATA" -xdev ! -user "$SERVICE_USER" -print -quit 2>/dev/null)" && [[ -n "$foreign" ]]; then
    warn "$foreign (and maybe more) in $DATA is not owned by $SERVICE_USER: the service may not be able to write it"
fi
install -d -m 0700 -o root -g root "$CRED_DIR"
if [[ -n "$KEY_FILE" ]]; then
    install -m 0600 -o root -g root "$KEY_FILE" "$CRED_FILE"
    info "installed the Gemini credential $CRED_FILE"
fi
if [[ -n "$SEED_WATERMARK" ]]; then
    if [[ -e "$DATA/watermark.json" ]]; then
        info "$DATA/watermark.json exists already: not replaced by --seed-watermark"
    else
        install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" "$SEED_WATERMARK" "$DATA/watermark.json"
        info "seeded $DATA/watermark.json from the given file"
    fi
fi

# --- the release: files and venv ----------------------------------------------------------
if [[ "$REUSE" -eq 0 ]]; then
    # Built in place (a venv cannot be moved), removed again when anything fails.
    trap 'rm -rf "$RELEASE"' ERR
    install -d -m 0755 -o root -g root "$RELEASE"
    cp -R --no-preserve=ownership "$SRC/." "$RELEASE/"

    info "creating the venv (hash-pinned requirements, wheels only)"
    "$PYTHON" -I -m venv "$RELEASE/venv"
    # --only-binary: nothing is built (no setup.py runs as root); --require-hashes: pip refuses
    # any file that is not listed with its sha256 in requirements.txt.
    "$RELEASE/venv/bin/python" -I -m pip install --quiet --disable-pip-version-check --no-cache-dir \
        --only-binary=:all: --require-hashes -r "$RELEASE/requirements.txt"
    "$RELEASE/venv/bin/python" -I -m compileall -q "$RELEASE/wazuh_ai_analyzer"
    : > "$RELEASE/.install-complete"
    chown -R root:root "$RELEASE"
    chmod -R go-w "$RELEASE"
    trap - ERR
fi

# --- settings (first install only) ------------------------------------------------------------
if [[ ! -e "$ENV_FILE" ]]; then
    {
        sed -e "s#/opt/wazuh-ai-analyzer/current#$CURRENT#g" \
            -e "s#/opt/wazuh-ai-analyzer/data#$DATA#g" \
            -e "s#/etc/wazuh-ai-analyzer.env#$ENV_FILE#g" \
            -e "s#/etc/wazuh-ai-analyzer/gemini#$CRED_FILE#g" \
            -e "s#^PORT=.*#PORT=$LISTEN_PORT#" \
            "$SRC/deploy/wazuh-ai-analyzer.env.example"
        if [[ -n "$INSTANCE" ]]; then
            printf '\n# Instance %s: a trial run next to the production service (INSTALL.md).\n' "$INSTANCE"
            printf 'ANALYSIS_MODE=decision\n'
        fi
    } > "$ENV_FILE.new"
    chmod 0600 "$ENV_FILE.new"
    chown root:root "$ENV_FILE.new"
    mv -f "$ENV_FILE.new" "$ENV_FILE"
    info "wrote $ENV_FILE: set DASHBOARD_PASSWORD_HASH (see the comment in it)"
fi

# --- unit ---------------------------------------------------------------------------------------
UNIT="$UNIT_DIR/$SERVICE.service"
description="Wazuh AI Analyzer"
[[ -z "$INSTANCE" ]] || description="Wazuh AI Analyzer (instance $INSTANCE)"
sed -e "s#/opt/wazuh-ai-analyzer/current#$CURRENT#g" \
    -e "s#/opt/wazuh-ai-analyzer/data#$DATA#g" \
    -e "s#/etc/wazuh-ai-analyzer.env#$ENV_FILE#g" \
    -e "s#/etc/wazuh-ai-analyzer/gemini#$CRED_FILE#g" \
    -e "s#^Description=.*#Description=$description#" \
    -e "s#^User=.*#User=$SERVICE_USER#" \
    -e "s#^Group=.*#Group=$SERVICE_USER#" \
    -e "s#^SyslogIdentifier=.*#SyslogIdentifier=$SERVICE#" \
    "$SRC/deploy/wazuh-ai-analyzer.service" > "$UNIT.new"
chmod 0644 "$UNIT.new"
mv -f "$UNIT.new" "$UNIT"
DROPIN_DIR="$UNIT_DIR/$SERVICE.service.d"
if [[ "$LXC" -eq 1 ]]; then
    install -d -m 0755 "$DROPIN_DIR"
    install -m 0644 "$SRC/deploy/unprivileged-lxc.conf" "$DROPIN_DIR/unprivileged-lxc.conf"
fi
if [[ "$NO_OSSEC_MASK" -eq 1 ]]; then
    install -d -m 0755 "$DROPIN_DIR"
    install -m 0644 "$SRC/deploy/no-ossec-mask.conf" "$DROPIN_DIR/no-ossec-mask.conf"
fi
if [[ "$KEY_FROM_ENV" -eq 1 ]]; then
    install -d -m 0755 "$DROPIN_DIR"
    printf '[Service]\nLoadCredential=\n' > "$DROPIN_DIR/no-credential.conf"
else
    rm -f "$DROPIN_DIR/no-credential.conf"
fi

# --- switch ---------------------------------------------------------------------------------------
PREVIOUS=""
if [[ -L "$CURRENT" ]]; then
    PREVIOUS="$(readlink "$CURRENT")"
fi
# `ln -sfn` onto a real directory would create the link inside it: clear a leftover first.
rm -rf "$CURRENT.new"
ln -sfn "releases/$VERSION" "$CURRENT.new"
mv -T "$CURRENT.new" "$CURRENT"
systemctl daemon-reload
info "release $VERSION is now $CURRENT${PREVIOUS:+ (was $PREVIOUS)}"

if [[ "$START" -eq 0 ]]; then
    info "not started (--no-start): systemctl enable --now $SERVICE"
    exit 0
fi
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"

# Health check: the web server accepts connections once the service is up (the login page
# answers 503 while no password hash is set, which still proves the service runs). It runs
# with the interpreter of the release that was just installed, not through the symlink.
env_value() {
    local value=""
    if [[ -f "$ENV_FILE" ]]; then
        value="$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | tr -d "\"' ")"
    fi
    printf '%s' "${value:-$2}"
}
host="$(env_value LISTEN_HOST 127.0.0.1)"
port="$(env_value PORT "$LISTEN_PORT")"
[[ "$host" == "0.0.0.0" || ! "$host" =~ ^[0-9.]+$ ]] && host=127.0.0.1
[[ "$port" =~ ^[0-9]+$ ]] || port="$LISTEN_PORT"
for _ in $(seq 1 30); do
    systemctl is-active --quiet "$SERVICE" || break
    if "$RELEASE/venv/bin/python" -I -c \
        'import socket, sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()' \
        "$host" "$port" 2>/dev/null; then
        info "service is up on $host:$port"
        exit 0
    fi
    sleep 1
done
echo "error: the service did not come up; see: journalctl -u $SERVICE -n 50" >&2
if [[ -n "$PREVIOUS" ]]; then
    echo "rollback: ln -sfn $PREVIOUS $CURRENT && systemctl restart $SERVICE" >&2
fi
exit 1
