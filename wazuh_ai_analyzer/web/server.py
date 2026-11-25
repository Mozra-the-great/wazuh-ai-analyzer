"""The HTTP server: waitress (R4), one process, a pool of threads.

One process on purpose: the live buffer, the quota and upstream gates and the counters
the dashboard shows live in this process, so more than one worker would show (and act
on) a part of the state each. Waitress is pure Python and has no development-server
behaviour (no debugger, no reloader).

The server is created in `start()` and runs in its own thread; `close()` stops it.
Request logging is off, so a URL with a query string never reaches a log.
"""

from __future__ import annotations

import logging
import threading
from typing import Final, Protocol, cast

from flask import Flask
from waitress.server import create_server
from waitress.wasyncore import close_all

from ..logging_setup import RedactSecrets

log = logging.getLogger(__name__)

THREADS: Final = 8
CONNECTION_LIMIT: Final = 100
CHANNEL_TIMEOUT: Final = 30
MAX_REQUEST_HEADER_BYTES: Final = 16 * 1024
MAX_REQUEST_BODY_BYTES: Final = 64 * 1024
IDENT: Final = "wazuh-ai-analyzer"
# Loggers of the server stack; their handlers get the redaction filter after setup.
SERVER_LOGGERS: Final = ("waitress", "waitress.queue", "werkzeug", "flask.app")


class _Server(Protocol):
    """The part of waitress' server objects used here (`MultiSocketServer` or
    `BaseWSGIServer`, whichever `create_server` returns for the host)."""

    effective_port: str  # waitress stores the bound port as text
    task_dispatcher: _Dispatcher

    def run(self) -> None: ...

    def close(self) -> None: ...


class _Dispatcher(Protocol):
    def shutdown(self, cancel_pending: bool = ..., timeout: int = ...) -> bool: ...


def protect_server_loggers(redactor: RedactSecrets) -> None:
    """Attach the redaction filter to the loggers (and their handlers) of waitress and
    werkzeug. Call it *after* they are set up: a library that adds its own handler later
    would otherwise log past the filter of the root handlers."""
    for name in SERVER_LOGGERS:
        logger = logging.getLogger(name)
        if redactor not in logger.filters:
            logger.addFilter(redactor)
        for handler in logger.handlers:
            if redactor not in handler.filters:
                handler.addFilter(redactor)


class WebServer:
    def __init__(
        self,
        app: Flask,
        *,
        host: str,
        port: int,
        trusted_proxy: bool,
        redactor: RedactSecrets,
    ) -> None:
        self._app = app
        self._host = host
        self._port = port
        self._trusted_proxy = trusted_proxy
        self._redactor = redactor
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """The bound port (differs from the configured one when that is 0)."""
        if self._server is None:
            raise RuntimeError("the server is not started")
        return int(self._server.effective_port)

    @property
    def thread(self) -> threading.Thread | None:
        return self._thread

    def start(self) -> threading.Thread:
        """Bind the socket (raises `OSError` when the port is taken) and serve in a thread."""
        server = cast(
            "_Server",
            create_server(
                self._app,
                host=self._host,
                port=self._port,
                threads=THREADS,
                connection_limit=CONNECTION_LIMIT,
                channel_timeout=CHANNEL_TIMEOUT,
                max_request_header_size=MAX_REQUEST_HEADER_BYTES,
                max_request_body_size=MAX_REQUEST_BODY_BYTES,
                ident=IDENT,
                expose_tracebacks=False,
                # Behind a proxy (TRUSTED_PROXY_HOPS > 0) the app's ProxyFix reads
                # X-Forwarded-*; without one waitress drops those headers before the
                # app can see (and believe) them.
                clear_untrusted_proxy_headers=not self._trusted_proxy,
            ),
        )
        protect_server_loggers(self._redactor)
        self._server = server
        thread = threading.Thread(target=server.run, name="web", daemon=True)
        thread.start()
        self._thread = thread
        log.info("Dashboard: http://%s:%d/login", self._host, self.port)
        return thread

    def close(self, timeout: float = 10.0) -> None:
        server, thread = self._server, self._thread
        if server is None:
            return
        server.task_dispatcher.shutdown()
        server.close()
        # `close()` only stops listening; idle keep-alive connections would keep the
        # event loop (and so the thread) alive until their timeout. Close them too.
        channels = getattr(server, "_map", None) or getattr(server, "map", None)
        if isinstance(channels, dict):
            close_all(channels, ignore_all=True)
        if thread is not None:
            thread.join(timeout)
