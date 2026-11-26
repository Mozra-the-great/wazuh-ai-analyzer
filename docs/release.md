# Release build and systemd sandbox

How the release tarball of the rewrite is built, how a release is cut, and what the systemd unit
locks down. Installing it is described in `docs/install.md` (shipped as `INSTALL.md`).

## The tarball

`wazuh-ai-analyzer-<version>.tar.gz` is built by `scripts/build_release.py` (standard library only).
The single top directory `wazuh-ai-analyzer-<version>/` holds

| Path | Content |
| --- | --- |
| `wazuh_ai_analyzer/` | the package, including `web/ui/` (the built dashboard and its `ui-manifest.json`, which is git-ignored and exists only here) |
| `requirements.txt` | the hash-pinned runtime dependencies (same file as in the repository) |
| `deploy/` | `wazuh-ai-analyzer.service`, `unprivileged-lxc.conf` (drop-in), `wazuh-ai-analyzer.env.example`, `install.sh` |
| `INSTALL.md`, `docs/` | install and upgrade notes, configuration and web layer reference |
| `LICENSE`, `THIRD-PARTY-NOTICES.md`, `licenses/npm/` | GPL-3.0 text, and the license text of every npm package in the dashboard bundle (from the lockfile's non-dev set), among them the SIL OFL 1.1 texts of the fonts Inter and JetBrains Mono. A package without a license file gets a generated `DECLARED-LICENSE.txt` with what its `package.json` declares |
| `VERSION`, `BUILD-INFO.json` | version, commit and `SOURCE_DATE_EPOCH` of the build |

`decisions/` (decision definitions) is included as soon as the directory exists.

The Python dependencies are not in the tarball; the installer fetches exactly the files listed in
`requirements.txt` from PyPI (`--require-hashes --only-binary=:all:`).

### Reproducible

The same commit and the same dashboard build give the same bytes:

- every entry has mtime `SOURCE_DATE_EPOCH` (CI: the commit time), uid/gid 0, owner `root`, mode 0644
  (0755 for directories and for files that are executable in git);
- entries are sorted bytewise, the tar format is fixed (GNU), the gzip header has no file name and
  mtime 0;
- only tracked files of `wazuh_ai_analyzer/`, `deploy/`, `docs/` and `decisions/` are packed, so stray
  files, bytecode and the checkout path cannot leak in;
- the dashboard build itself is reproducible (hashed asset names, the CSP hash in the manifest).

The `release-repro` job builds the dashboard and the tarball, then deletes the dashboard build, builds
it again, runs the second tarball build from another working directory, and fails unless the two
`SHA256SUMS` and the two files are identical. The gzip stream depends on the zlib of the Python that
runs the build, so a rebuild on another machine can differ in the compressed bytes only. Compare
`gzip -dc <tarball> | sha256sum` there (the script and CI print it as `tar-sha256`). A deployment
verifies the file it downloads against the published `SHA256SUMS`; it never rebuilds.

### Build locally

```sh
(cd ui && npm ci && npm run build)
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" python scripts/build_release.py --output dist
```

The script refuses a working tree with uncommitted changes to tracked files (`--allow-dirty` is for
experiments) and a missing dashboard build.

## Cut a release

1. A PR sets `__version__` in `wazuh_ai_analyzer/__init__.py` and `version` in `pyproject.toml` to the
   release (`2.0.0`, or the PEP 440 pre-release `2.0.0rc1`); both must agree. Merge it.
2. Tag the merge commit on `main`: `git tag v2.0.0 && git push origin v2.0.0`. The tag must be the
   release form of `__version__`: for `2.0.0rc1` it is `v2.0.0-rc.1` (`build_release.py` turns
   `2.0.0rc1` into `2.0.0-rc.1`, which names the tarball, `VERSION` and `releases/<version>`), or the
   build stops.
3. The `Release` workflow builds the tarball twice, installs it on the runner, runs the sandbox
   checks, and only then `release-publish` attests the build provenance
   (`actions/attest-build-provenance`) and creates the GitHub release with the tarball, `SHA256SUMS`
   and the attestation bundle (`*.tar.gz.intoto.jsonl`). Any tag that is not a plain `vMAJOR.MINOR.PATCH` (`v2.0.0-rc.1`) becomes a pre-release.
   The job also checks that the tagged commit is on `main`.

A pull request or a manual run (`workflow_dispatch`) runs the build and sandbox jobs and publishes
nothing. Consumers verify with `sha256sum --check --strict SHA256SUMS` and
`gh attestation verify <tarball> --repo Mozra-the-great/wazuh-ai-analyzer`.

## systemd unit

`deploy/wazuh-ai-analyzer.service` runs `python -m wazuh_ai_analyzer run` as the unprivileged user
`wazuh-ai-analyzer` from `/opt/wazuh-ai-analyzer/current` (a symlink to `releases/<version>`).

| Option | Why |
| --- | --- |
| `LoadCredential=gemini:/etc/wazuh-ai-analyzer/gemini` | the key reaches the process as `$CREDENTIALS_DIRECTORY/gemini`, not through the environment, `ps` or `systemctl show` |
| `NoNewPrivileges`, `CapabilityBoundingSet=`, `AmbientCapabilities=` | no privilege gain, no capability at all (checked in CI: `CapEff` and `CapBnd` are zero) |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths=<prefix>/data`, `UMask=0077` | the data directory is the only writable path |
| `TemporaryFileSystem=/var/ossec:ro`, `BindReadOnlyPaths=-/var/ossec/logs/alerts` | `/var/ossec` (rules, agent keys, manager state, other logs) is an empty read-only tmpfs; only the alert directory is bound back in, read-only |
| `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `ProcSubset=pid` | no kernel, device or other-process access that a log analyser never needs |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | dashboard and Gemini over IP, the journal and name resolution over a Unix socket |
| `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `RemoveIPC`, `KeyringMode=private` | standard hardening; the Python service needs none of what they forbid |
| `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, then `~@privileged @resources`, `SystemCallErrorNumber=EPERM` | seccomp allow list; a blocked call returns `EPERM` instead of killing the process |
| `MemoryMax=256M`, `CPUQuota=25%` | same resource limits as the legacy unit |

### `systemd-analyze security`

Measured in CI on the release job's runner (Ubuntu, systemd 259) with the real tarball installed and the
service running: **overall exposure 1.2 (OK)**. The job fails above 2.0 (the target in #90). What is
left open and why:

| Item | Exposure | Reason |
| --- | --- | --- |
| `PrivateNetwork=` | 0.5 | the service listens on a port and calls the Gemini API |
| `RestrictAddressFamilies=~AF_(INET\|INET6)` | 0.3 | same |
| `PrivateUsers=` | 0.2 | the user namespace would hide the `wazuh` group that grants read access to the alerts |
| `IPAddressDeny=` | 0.2 | the Gemini endpoint has no stable address range; a deployment that knows its network can add `IPAddressAllow=`/`IPAddressDeny=any` in a drop-in |
| `RestrictAddressFamilies=~AF_UNIX` | 0.1 | the journal socket |
| `RootDirectory=`/`RootImage=` | 0.1 | the venv lives in the host's `/opt` |
| `DeviceAllow=` | 0.1 | systemd's own default entry |

The Debian 12 host (systemd 252) is scored with its own list of checks; measure it once on CT111 in the
rollout (P8) and note the value in the rollout record.

### Presentation of the credential

On that runner systemd presented the credential to the service user as `root:root`, mode `0440`: it
could not chown the file and granted the service user read access through an ACL. The first version of
`read_secret_file` demanded an owner equal to the service user and no group bits, and refused this
file. For files inside `$CREDENTIALS_DIRECTORY` the owner may now be root or the service user, the group
bits are not judged, and access for others is still refused; `GEMINI_API_KEY_FILE` keeps the strict
rule (`docs/configuration.md`, tests in `tests/v2/unit/test_secret.py`). `CREDENTIALS_DIRECTORY` comes from the environment, so the relaxation is tied to the directory: it is opened first and judged on the descriptor (owner the service user or root, no access for others), the file is opened relative to it, and a symlinked directory is refused. The `release-systemd` job runs
`check-config --require-api-key` through `systemd-run -p LoadCredential=...` as the service user, so this
path is exercised against the real systemd on every build.

### Unprivileged containers

`deploy/unprivileged-lxc.conf` switches off the options that need privileges on the host
(`PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
`ProtectControlGroups`, `ProtectClock`, `ProtectProc`, `ProcSubset`). The seccomp-based and
capability-based options need none and stay on. This list comes from what systemd documents for these
options; it has not been run in an unprivileged container yet (CI has none), so the rollout checks it on
a test container and corrects the drop-in if systemd names another option. CT111 itself is a privileged
container and starts with the full unit unless the rollout shows otherwise.
