# Install and upgrade (release tarball)

This file is `INSTALL.md` inside the release tarball. A release is one file,
`wazuh-ai-analyzer-<version>.tar.gz`, built by CI from the tag (see `docs/release.md`). It holds the
Python package with the built dashboard, `requirements.txt` with a sha256 for every package, the
systemd unit and the installer under `deploy/`, and all licenses. There is nothing to compile on the
host and no Node.

Needs: systemd, Python 3.11 or newer with the `venv` module (Debian 12: `apt install python3 python3-venv`),
root, and access to PyPI for the pinned packages.

## 1. Verify the download

Download the tarball and `SHA256SUMS` from the GitHub release into one directory.

```sh
sha256sum --check --strict SHA256SUMS
gh attestation verify wazuh-ai-analyzer-<version>.tar.gz --repo Mozra-the-great/wazuh-ai-analyzer
```

The first line detects a damaged or swapped file. The second proves that GitHub Actions built the
file from that repository (build provenance); skip it where `gh` is not available, but pin the sha256
in your automation either way. Extract only after the check passed:

```sh
tar -xzf wazuh-ai-analyzer-<version>.tar.gz
cd wazuh-ai-analyzer-<version>
```

## 2. Install

Put the Gemini API key into a file that only root can read, one line, and run the installer:

```sh
sudo ./deploy/install.sh --gemini-key-file /root/gemini-key
```

The installer is non-interactive and can be run again for every new release. It

1. takes over the install root: `/opt/wazuh-ai-analyzer` becomes `root:root 0755` (an old installation
   left it to the service user, who could otherwise swap entries below it while the installer runs
   as root). It stops if `releases`, `data` or `current.new` is a symlink or `releases` is not owned by
   root, and it never runs a recursive `chown` over `data/`;
2. checks Python, creates the system user `wazuh-ai-analyzer` and gives it read access to the Wazuh
   alerts (see "Access to the alerts");
3. copies the release to `/opt/wazuh-ai-analyzer/releases/<version>/` and creates a venv there with
   `pip install --only-binary=:all: --require-hashes -r requirements.txt` (nothing is built, and pip
   refuses every file whose sha256 is not in the list);
4. stores the key as `/etc/wazuh-ai-analyzer/gemini` (root, mode 0600). On a first install it also writes
   `/etc/wazuh-ai-analyzer.env` (mode 0600) from `deploy/wazuh-ai-analyzer.env.example`, without secrets.
   It stops if `--gemini-key-file` is given while that file still sets `GEMINI_API_KEY` or
   `GEMINI_API_KEY_FILE`: such a line wins over the credential, so the new key would be ignored. Remove
   the line or leave out `--gemini-key-file`;
5. installs `/etc/systemd/system/wazuh-ai-analyzer.service`;
6. points the symlink `/opt/wazuh-ai-analyzer/current` at the new release, enables and restarts the
   service and waits until it accepts connections (checked with the interpreter of the new release).

Options: `--unprivileged-lxc` and `--no-ossec-mask` (drop-ins, see below), `--alerts-access`,
`--no-start`, `--python PYTHON`, `--prefix DIR`, and for a second instance `--instance`, `--port` and
`--seed-watermark` (see "Shadow run").

Then set the dashboard password. The dashboard answers 503 until `DASHBOARD_PASSWORD_HASH` is set:

```sh
read -rs PW; printf %s "$PW" | /opt/wazuh-ai-analyzer/current/venv/bin/python \
  -c 'import sys; from werkzeug.security import generate_password_hash as g; print(g(sys.stdin.read()))'
sudoedit /etc/wazuh-ai-analyzer.env          # DASHBOARD_PASSWORD_HASH=<the output>
sudo systemctl restart wazuh-ai-analyzer
```

The cookies are `Secure` by default, so the login works over HTTPS (a reverse proxy) or on
`localhost`; for a plain-http test set `SESSION_COOKIE_SECURE=false`. All settings are listed in
`docs/configuration.md`.

## Layout

```
/opt/wazuh-ai-analyzer/
  current -> releases/<version>      what the unit runs
  releases/<version>/                code, built dashboard, venv; read-only for the service
  data/                              database, watermark.json, session.key (service user only, 0700)
/etc/wazuh-ai-analyzer.env           settings
/etc/wazuh-ai-analyzer/gemini        the API key (systemd reads it as root: LoadCredential=)
/etc/systemd/system/wazuh-ai-analyzer.service
```

The service runs `python -m wazuh_ai_analyzer run` from `current`. It can write only to `data/`
(`ProtectSystem=strict`, `ReadWritePaths=`), reads the Wazuh alerts from `/var/ossec/logs/alerts`
(read-only), and has no capabilities, a seccomp filter and a private `/tmp`. If your alert log is
elsewhere, add `ReadOnlyPaths=<dir>` in a drop-in (`systemctl edit wazuh-ai-analyzer`).

## Access to the alerts

The service user must read `/var/ossec/logs/alerts`. `--alerts-access` chooses how:

* `acl` (what `auto` picks when `setfacl` exists and works): an ACL `u:wazuh-ai-analyzer:rX` on the alert
  directory and its files plus a default ACL on its directories, so files that Wazuh creates later are
  readable as well. The service user joins no group. Needs the `acl` package and a file system with ACL
  support.
* `group`: the service user joins the group that owns `alerts.json` (normally `wazuh`). The installer
  refuses the group `root` (GID 0), `sudo`, `adm`, `shadow`, `disk` and `docker`: joining one of them
  would give the service far more than the alerts. Use `acl`, or give the alert log a dedicated group.

An earlier installation put the service user into the `wazuh` group; the installer does not remove it.
After the first run with an ACL, `gpasswd -d wazuh-ai-analyzer wazuh` takes it out again (restart the
service afterwards).

The unit also hides the rest of `/var/ossec` from the service (`TemporaryFileSystem=/var/ossec:ro` and
`BindReadOnlyPaths=-/var/ossec/logs/alerts`): rules, agent keys, the manager's state and the other logs
do not exist for it, and the alert directory is read-only. If your alert log is elsewhere, add a drop-in
with `BindReadOnlyPaths=<directory>`.

## The Gemini key

The unit hands the key over with `LoadCredential=gemini:/etc/wazuh-ai-analyzer/gemini`; the service
reads `$CREDENTIALS_DIRECTORY/gemini`. The key never appears in the environment of the process, in
`ps` or in `systemctl show`. To rotate it, replace the file (root, 0600) and restart the service.
A `GEMINI_API_KEY` or `GEMINI_API_KEY_FILE` in `/etc/wazuh-ai-analyzer.env` still wins, which keeps an
existing legacy settings file working: with such a file and no credential, the installer adds the drop-in
`no-credential.conf` (`LoadCredential=` reset) and tells you to move the key. Details of the permission
rules are in `docs/configuration.md`.

## Upgrade

Run the installer from the new tarball (after step 1). The previous release stays in
`releases/`, the database is migrated in place at the first start (additive changes only), and
`data/` is not touched otherwise. A release directory that the installer finished earlier for the very
same build (for example by a shadow run) is reused instead of rebuilt; the installer refuses to run when
that version is already the `current` release of the instance. To check a release before it goes live, use `--no-start`, then
`python -m wazuh_ai_analyzer check-config` with the environment of the service, then restart.

From the old single-file service (`analyzer.py`, installed by the old `install.sh`): the same command
works. The old files in `/opt/wazuh-ai-analyzer/` (`analyzer.py`, `venv/`, `static/`) are left alone;
`STATIC_DIR` in the settings file is ignored with a warning, `GEMINI_MODEL` keeps its value. Remove the
old files only after the new release has run for a while: they are the way back.

## Shadow run (a second instance next to production)

A shadow run lets a new release analyse the live alerts for a while without replacing the running
service. The shadow instance is a complete second service from the same release:

| | production | `--instance shadow` |
| --- | --- | --- |
| unit | `wazuh-ai-analyzer.service` | `wazuh-ai-analyzer-shadow.service` |
| data directory (database, `watermark.json`, `session.key`, `.lock`) | `data/` | `data-shadow/` |
| settings | `/etc/wazuh-ai-analyzer.env` | `/etc/wazuh-ai-analyzer-shadow.env` (`PORT=8766`, `ANALYSIS_MODE=decision`) |
| credential | `/etc/wazuh-ai-analyzer/gemini` | `/etc/wazuh-ai-analyzer/gemini-shadow` |
| release symlink | `current` | `current-shadow` |

Both run as the same system user, but each unit may write only its own data directory
(`ReadWritePaths=`), so the shadow instance cannot touch the production database. The instance lock
(`flock` on `<data dir>/.lock`) is per data directory, which is why both can run at once. Memory is
limited per unit (`MemoryMax=256M`): plan for the sum of both.

1. Copy the production watermark: `cp /opt/wazuh-ai-analyzer/data/watermark.json /root/watermark-copy.json`.
   Without a watermark the new service analyses the existing alert logs from the start, which costs
   Gemini quota and floods the shadow database; with the copy it continues from the same position.
   The file is replaced atomically by the running service, so a copy is always whole.
2. Install without starting, with its own key file (it may hold the same key), the copy and its own port:

   ```sh
   sudo ./deploy/install.sh --instance shadow --port 8766 \
     --gemini-key-file /root/gemini-key --seed-watermark /root/watermark-copy.json --no-start
   ```

   The seed is copied only when `data-shadow/watermark.json` does not exist, with mode 0600 for the
   service user. Add `--unprivileged-lxc` in an unprivileged container, as for production.
3. Set `DASHBOARD_PASSWORD_HASH` in `/etc/wazuh-ai-analyzer-shadow.env` (see above) and check the
   settings with the environment of the instance:

   ```sh
   sudo systemd-run --pipe --wait --collect -p User=wazuh-ai-analyzer \
     -p LoadCredential=gemini:/etc/wazuh-ai-analyzer/gemini-shadow \
     -p EnvironmentFile=/etc/wazuh-ai-analyzer-shadow.env \
     /opt/wazuh-ai-analyzer/current-shadow/venv/bin/python -m wazuh_ai_analyzer check-config
   ```
4. `sudo systemctl enable --now wazuh-ai-analyzer-shadow`; the dashboard answers on port 8766 (put it
   behind the same proxy under another name, or open it over an SSH tunnel). Logs:
   `journalctl -u wazuh-ai-analyzer-shadow`.
5. Compare the findings of both dashboards for as long as you need. Production and shadow use the same
   Gemini project, so they share its quota: raise `MIN_LEVEL` or lower `GEMINI_CONCURRENCY` in the shadow
   settings if the quota gets tight.
6. End the shadow run: `sudo systemctl disable --now wazuh-ai-analyzer-shadow`. Remove it completely with
   `rm /etc/systemd/system/wazuh-ai-analyzer-shadow.service /etc/wazuh-ai-analyzer-shadow.env
   /etc/wazuh-ai-analyzer/gemini-shadow /opt/wazuh-ai-analyzer/current-shadow`, then
   `rm -r /opt/wazuh-ai-analyzer/data-shadow` and `systemctl daemon-reload`. The production upgrade that
   follows (the installer without `--instance`) reuses `releases/<version>`.

## Roll back

```sh
sudo ln -sfn releases/<previous-version> /opt/wazuh-ai-analyzer/current
sudo systemctl restart wazuh-ai-analyzer
```

The previous release reads the migrated database (the rollback tests in CI prove it for the legacy
service as well). To go back to the old single-file service instead, restore its unit file and start
it; it reads the same database and `watermark.json`. Restore the database backup only if a migration
failed half way.

## Unprivileged container (LXC)

An unprivileged container cannot set up some of the unit's kernel-facing options
(`PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`,
`ProtectKernelModules`, `ProtectProc`/`ProcSubset`). systemd then fails the service at start with
`status=218/CAPABILITIES` or `status=226/NAMESPACE`. Install with `--unprivileged-lxc`, or copy
`deploy/unprivileged-lxc.conf` to `/etc/systemd/system/wazuh-ai-analyzer.service.d/` yourself, which
switches exactly these options off. Everything seccomp- or capability-based stays on, and so does the
hiding of `/var/ossec` (`TemporaryFileSystem=`), because a tmpfs can be mounted in a user namespace. If
`journalctl -u wazuh-ai-analyzer` shows that the service cannot set up that mount (status 226/NAMESPACE),
install the second drop-in `deploy/no-ossec-mask.conf` (`--no-ossec-mask`): it goes back to a read-only
file system with the alert directory named explicitly. Report the container either way. If the service
still fails, `systemctl status wazuh-ai-analyzer` names the option; switch that one off in the same
drop-in and report it. A privileged container or a VM does not need the drop-in.

## Check the sandbox

```sh
systemd-analyze security wazuh-ai-analyzer.service --no-pager
```

What the service sees of Wazuh (needs the running service; works in a privileged container such as
CT111 and on a VM):

```sh
pid=$(systemctl show -p MainPID --value wazuh-ai-analyzer)
nsenter -t "$pid" -m -- ls -A /var/ossec                # only: logs
nsenter -t "$pid" -m -- ls -A /var/ossec/logs           # only: alerts
nsenter -t "$pid" -m -- touch /var/ossec/logs/alerts/x  # must fail: read-only
getfacl -p /var/ossec/logs/alerts                       # user:wazuh-ai-analyzer:r-x (ACL access)
```

The unit scores 1.2 (OK) on systemd 259; the CI build fails above 2.0. `docs/release.md` lists the
remaining items and why they stay open.
