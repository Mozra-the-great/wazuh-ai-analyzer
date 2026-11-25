"""Command line entry point: `python -m wazuh_ai_analyzer <command>`.

P1 provides the commands that need nothing but configuration and storage:

* `check-config` validates the environment and prints the effective settings
  (secrets masked). Use it in an installer or a unit's `ExecStartPre=`.
* `migrate` creates or migrates the database and tightens the permissions of the
  data directory and the database files.

The `run` command (ingest, pipeline, web server) arrives with the packages that
implement those parts; until the cutover the service is still `analyzer.py`.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sqlite3
import sys
from collections.abc import Sequence
from typing import TextIO

from . import __version__
from .config import Config, ConfigError, load_config
from .logging_setup import configure_logging
from .permissions import heal_database_files, prepare_data_dir
from .storage.db import Database
from .storage.schema import MigrationError, migrate

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_CONFIG = 78  # EX_CONFIG of sysexits.h

log = logging.getLogger("wazuh-ai")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m wazuh_ai_analyzer")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="<command>")
    check = commands.add_parser(
        "check-config", help="validate the environment and print the settings"
    )
    check.add_argument(
        "--require-api-key",
        action="store_true",
        help="also fail when no Gemini API key is configured",
    )
    commands.add_parser("migrate", help="create or migrate the database")
    return parser


def format_config(config: Config) -> list[str]:
    """One `section.name = value` line per setting. Secrets print as `***`."""
    lines: list[str] = []
    for section in dataclasses.fields(config):
        value = getattr(config, section.name)
        for item in dataclasses.fields(value):
            lines.append(f"{section.name}.{item.name} = {getattr(value, item.name)!r}")
    return lines


def _check_config(config: Config, require_api_key: bool, out: TextIO) -> int:
    if require_api_key:
        config.require_api_key()
    for line in format_config(config):
        print(line, file=out)
    if config.gemini.api_key is None:
        print("note: no Gemini API key configured (the dashboard will show 'no key')", file=out)
    return EXIT_OK


def _migrate(config: Config, out: TextIO) -> int:
    prepare_data_dir(config.paths.data_dir)
    result = migrate(Database(config.paths.db_path))
    heal_database_files(config.paths.db_path)
    if result.applied:
        applied = ", ".join(str(v) for v in result.applied)
        print(
            f"database migrated: version {result.from_version} -> {result.to_version}"
            f" (applied {applied})",
            file=out,
        )
    else:
        print(f"database already at version {result.to_version}", file=out)
    return EXIT_OK


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    args = _build_parser().parse_args(argv)
    stream = out if out is not None else sys.stdout
    try:
        config = load_config()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return EXIT_CONFIG
    configure_logging(config.secret_values())
    try:
        if args.command == "check-config":
            return _check_config(config, args.require_api_key, stream)
        return _migrate(config, stream)
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return EXIT_CONFIG
    except (MigrationError, OSError, sqlite3.Error) as exc:
        log.error("%s failed: %s", args.command, exc)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
