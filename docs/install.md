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

1. checks Python, creates the system user `wazuh-ai-analyzer` and adds it to the group that owns the
   Wazuh alert log (read access without root);
2. copies the release to `/opt/wazuh-ai-analyzer/releases/<version>/` and creates a venv there with
   `pip install --only-binary=:all: --require-hashes -r requirements.txt` (nothing is built, and pip
   refuses every file whose sha256 is not in the list);
3. stores the key as `/etc/wazuh-ai-analyzer/gemini` (root, mode 0600). On a first install it also writes
   `/etc/wazuh-ai-analyzer.env` (mode 0600) from `deploy/wazuh-ai-analyzer.env.example`, without secrets;
4. installs `/etc/systemd/system/wazuh-ai-analyzer.service`;
5. points the symlink `/opt/wazuh-ai-analyzer/current` at the new release, enables and restarts the
   service and waits until it accepts connections.

Options: `--unprivileged-lxc` (drop-in, see below), `--no-start`, `--python PYTHON`, `--prefix DIR`.

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
`data/` is not touched otherwise. To check a release before it goes live, use `--no-start`, then
`python -m wazuh_ai_analyzer check-config` with the environment of the service, then restart.

From the old single-file service (`analyzer.py`, installed by the old `install.sh`): the same command
works. The old files in `/opt/wazuh-ai-analyzer/` (`analyzer.py`, `venv/`, `static/`) are left alone;
`STATIC_DIR` in the settings file is ignored with a warning, `GEMINI_MODEL` keeps its value. Remove the
old files only after the new release has run for a while: they are the way back.

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
switches exactly these options off. Everything seccomp- or capability-based stays on. If the service
still fails, `systemctl status wazuh-ai-analyzer` names the option; switch that one off in the same
drop-in and report it. A privileged container or a VM does not need the drop-in.

## Check the sandbox

```sh
systemd-analyze security wazuh-ai-analyzer.service --no-pager
```

CI runs this on every build and fails above an exposure level of 2.5 (`docs/release.md` has the
measured value and the options that remain open and why).
