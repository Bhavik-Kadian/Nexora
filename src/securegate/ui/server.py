"""Running the dashboard: a small web server on 127.0.0.1, so only this computer can open it."""

import os
import socket
import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Any

from flask import Flask
from werkzeug.serving import BaseWSGIServer, make_server

from securegate.errors import ConfigError
from securegate.ui.app import create_app

HOST = "127.0.0.1"  # never 0.0.0.0: the dashboard must not be reachable from other computers


def _say(text: str) -> None:
    print(text, flush=True)  # show the address at once, even when the output is piped


def make_unshared_server(host: str, port: int, app: Flask, **options: Any) -> BaseWSGIServer:
    """Werkzeug's server, on a port it does not share: a busy port raises OSError.

    Werkzeug binds with SO_REUSEADDR, and Windows lets such a socket join a port that another
    server is already listening on, so a second dashboard would start without an error. The
    socket is bound here instead, the way socket.create_server does it: SO_REUSEADDR only
    outside Windows, where it just allows a quick restart. Werkzeug serves from a copy of it.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with listener:
        if os.name != "nt":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        return make_server(host, port, app, fd=listener.fileno(), **options)


def serve(
    report: Path,
    *,
    port: int,
    debug: bool = False,
    open_browser: bool = False,
    server_factory: Callable[..., Any] = make_unshared_server,
    open_url: Callable[[str], object] = webbrowser.open,
    say: Callable[[str], None] = _say,
) -> int:
    """Serve the dashboard for `report` until Ctrl+C, then return exit code 0."""
    if not 1 <= port <= 65535:
        raise ConfigError(f"--port must be a number from 1 to 65535, not {port}")
    app = create_app(report)
    app.debug = debug  # off by default; on, error details go to this terminal
    try:
        server = server_factory(HOST, port, app, threaded=True)
    except OSError as err:
        raise ConfigError(
            f"cannot start the dashboard on port {port} ({err.strerror or err}). If the "
            "dashboard is already open in another window, use that one or close it; otherwise "
            "choose another port with --port."
        ) from None
    url = f"http://{HOST}:{server.server_address[1]}/"
    say(f"SecureGate dashboard: {url}")
    say(f"Showing {report}. Press Ctrl+C to stop.")
    if open_browser:
        open_url(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
