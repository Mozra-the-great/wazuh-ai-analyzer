"""Logging with a redaction filter (S7, #41).

The filter sits on the root handlers, so it also covers library loggers (urllib3,
werkzeug) whose messages can embed a request URL or a header dump. It masks the
known secret values literally and the usual key patterns generically.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterable

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


def configure_logging(secrets: Iterable[str] = (), level: int = logging.INFO) -> RedactSecrets:
    """Set up root logging to stderr and attach the redaction filter to its handlers."""
    logging.basicConfig(
        level=level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, stream=sys.stderr, force=True
    )
    redactor = RedactSecrets(secrets)
    for handler in logging.getLogger().handlers:
        handler.addFilter(redactor)
    return redactor
