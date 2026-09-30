"""Running the dashboard: a small web server on 127.0.0.1, so only this computer can open it."""

import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Any

from werkzeug.serving import make_server

from securegate.errors import ConfigError
from securegate.ui.app import create_app

HOST = "127.0.0.1"  # never 0.0.0.0: the dashboard must not be reachable from other computers


def _say(text: str) -> None:
    print(text, flush=True)  # show the address at once, even when the output is piped


def serve(
    report: Path,
    *,
    port: int,
    debug: bool = False,
    open_browser: bool = False,
    server_factory: Callable[..., Any] = make_server,
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
            f"cannot start the dashboard on port {port} ({err.strerror or err}). "
            "Choose another port with --port."
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
