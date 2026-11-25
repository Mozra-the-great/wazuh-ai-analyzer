"""Owner-only permissions for everything the service writes (#31, S8).

The data directory holds the analysis database (prioritised vulnerabilities,
affected hostnames, source IPs), the alert watermark and the session key. None
of it is meant for other local accounts, so it is kept owner-only instead of
inheriting the process umask (usually 0755/0644). Existing installs are healed
on every start, not only new ones.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

DATA_DIR_MODE = 0o700
DATA_FILE_MODE = 0o600

# SQLite creates the database and its WAL side files with the process umask.
_DB_SUFFIXES = ("", "-wal", "-shm")


def restrict(path: Path, mode: int) -> bool:
    """Best-effort chmod of an existing path; True when the path now has `mode`.

    A filesystem without POSIX modes must not take the whole service down, so a
    failure is logged, not raised.
    """
    try:
        if path.exists():
            path.chmod(mode)
            return True
    except OSError as exc:
        log.warning("Could not set mode %o on %s: %s", mode, path, exc)
    return False


def prepare_data_dir(path: Path) -> None:
    """Create the data directory (0700) or tighten an existing one."""
    # mkdir(mode=) only applies when the directory is actually created and is
    # reduced by the umask, so an existing (world-readable) directory from an
    # older install is fixed by the explicit chmod below.
    path.mkdir(parents=True, exist_ok=True, mode=DATA_DIR_MODE)
    restrict(path, DATA_DIR_MODE)


def heal_database_files(db_path: Path) -> None:
    """Restrict the database file and its `-wal` / `-shm` side files to 0600."""
    for suffix in _DB_SUFFIXES:
        restrict(Path(f"{db_path}{suffix}"), DATA_FILE_MODE)


def is_posix() -> bool:
    """True where file modes and owners mean something."""
    return os.name == "posix"
