"""Logging with a redaction filter (S7, #41).

The filter sits on the root handlers, so it also covers library loggers (urllib3,
werkzeug) whose messages can embed a request URL or a header dump. It masks the
known secret values literally and the usual key patterns generically.

Uncaught exceptions (`sys.excepthook`, `threading.excepthook`) are routed through
logging as well (`install_exception_hooks`): the default hooks print the traceback
straight to stderr, past every filter, and a traceback can embed a request URL or a
header dump.
"""

from __future__ import annotations

import logging
import re
import sys
import threading
from collections.abc import Iterable
from types import TracebackType

LOG_FORMAT = "%(asctime)s  %(levelname)-7s  %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_KEY_PATTERN = re.compile(r"""(key=|x-goog-api-key['"]?\s*[:=]\s*['"]?)[^&\s'"]+""", re.IGNORECASE)
# Shorter values would mask ordinary words; real secrets are longer.
_MIN_SECRET_LENGTH = 4


class RedactSecrets(logging.Filter):
    """Mask secret values and API-key parameters in every record before it is emitted."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        # Longest first, so a secret that contains another one is masked entirely.
        self._secrets = sorted(
            {s for s in secrets if len(s) >= _MIN_SECRET_LENGTH}, key=len, reverse=True
        )

    def scrub(self, text: str) -> str:
        redacted = _KEY_PATTERN.sub(r"\1***", text)
        for secret in self._secrets:
            redacted = redacted.replace(secret, "***")
        return redacted

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = self.scrub(message)
        if redacted != message:
            record.msg, record.args = redacted, None
        if record.exc_info and record.exc_text is None:
            # Format the traceback now so it can be scrubbed: the formatter reuses
            # `exc_text` instead of formatting `exc_info` again.
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = self.scrub(record.exc_text)
        if record.stack_info:
            record.stack_info = self.scrub(record.stack_info)
        return True


def _log_uncaught(
    exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None
) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)
        return
    logging.getLogger("wazuh-ai").critical("Uncaught exception", exc_info=(exc_type, exc, tb))


def _log_uncaught_in_thread(args: threading.ExceptHookArgs) -> None:
    if args.exc_type is SystemExit or args.exc_value is None:
        return
    name = args.thread.name if args.thread is not None else "unknown"
    logging.getLogger("wazuh-ai").critical(
        "Uncaught exception in thread %s",
        name,
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def install_exception_hooks() -> None:
    """Send uncaught exceptions of the main and of every other thread to the log."""
    sys.excepthook = _log_uncaught
    threading.excepthook = _log_uncaught_in_thread


def configure_logging(secrets: Iterable[str] = (), level: int = logging.INFO) -> RedactSecrets:
    """Set up root logging to stderr and attach the redaction filter to its handlers."""
    logging.basicConfig(
        level=level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, stream=sys.stderr, force=True
    )
    redactor = RedactSecrets(secrets)
    for handler in logging.getLogger().handlers:
        handler.addFilter(redactor)
    install_exception_hooks()
    return redactor
