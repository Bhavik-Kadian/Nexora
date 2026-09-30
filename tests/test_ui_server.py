"""Starting the dashboard (`securegate ui`) and the designers' sample report."""

import json
import socket
import threading
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from werkzeug.serving import make_server

from helpers import (
    GITLEAKS_CONFIG,
    POLICY_FILE,
    git_installed,
    gitleaks_installed,
    leaked,
    random_key,
)
from securegate.cli import build_parser, main
from securegate.errors import ConfigError
from securegate.policy import load_policy
from securegate.scanners.gitleaks import subprocess_runner
from securegate.ui.app import create_app
from securegate.ui.report_view import MASKED_VALUE, ReportView, load_report
from securegate.ui.sample import write_sample_report
from securegate.ui.server import HOST, serve


class FakeServer:
    """Stands in for the web server: records how it was made, then 'runs' until Ctrl+C."""

    def __init__(self, host: str, port: int, app: Any, **options: Any) -> None:
        self.host, self.port, self.app, self.options = host, port, app, options
        self.server_address = (host, port)
        self.closed = False

    def serve_forever(self) -> None:
        raise KeyboardInterrupt  # someone pressed Ctrl+C

    def server_close(self) -> None:
        self.closed = True


def run_fake(report: Path, **options: Any) -> tuple[FakeServer, list[str], int]:
    made: list[FakeServer] = []
    opened: list[str] = []

    def factory(*args: Any, **kwargs: Any) -> FakeServer:
        made.append(FakeServer(*args, **kwargs))
        return made[0]

    code = serve(
        report, server_factory=factory, open_url=opened.append, say=lambda _: None, **options
    )
    return made[0], opened, code


def test_dashboard_listens_on_this_computer_only(sample_report: Path) -> None:
    server, _, code = run_fake(sample_report, port=5000)
    assert HOST == "127.0.0.1"
    assert (server.host, server.port) == ("127.0.0.1", 5000)
    assert server.closed
    assert code == 0  # Ctrl+C stops it cleanly


def test_debug_is_off_unless_asked(sample_report: Path) -> None:
    assert run_fake(sample_report, port=5000)[0].app.debug is False
    assert run_fake(sample_report, port=5000, debug=True)[0].app.debug is True


def test_open_starts_the_browser_on_the_dashboard(sample_report: Path) -> None:
    assert run_fake(sample_report, port=5123, open_browser=True)[1] == ["http://127.0.0.1:5123/"]
    assert run_fake(sample_report, port=5123)[1] == []


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_bad_ports_are_refused(sample_report: Path, port: int) -> None:
    with pytest.raises(ConfigError, match="--port"):
        serve(sample_report, port=port)


def test_a_busy_port_is_a_clear_error(sample_report: Path) -> None:
    def busy(*_args: Any, **_kwargs: Any) -> None:
        raise OSError(10048, "Only one usage of each socket address is normally permitted")

    with pytest.raises(ConfigError, match="Choose another port with --port"):
        serve(sample_report, port=5000, server_factory=busy, say=lambda _: None)


def test_ui_command_defaults() -> None:
    args = build_parser().parse_args(["ui"])
    assert (args.report, args.port, args.open, args.debug) == ("findings.json", 5000, False, False)


def test_ui_command_exits_2_on_a_bad_port(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ui", "--port", "70000"]) == 2
    assert "--port must be a number from 1 to 65535" in capsys.readouterr().err


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


def test_real_server_answers_every_page(sample_report: Path) -> None:
    servers: list[Any] = []

    def keep(*args: Any, **kwargs: Any) -> Any:
        servers.append(make_server(*args, **kwargs))
        return servers[0]

    port = free_port()
    thread = threading.Thread(
        target=serve,
        args=(sample_report,),
        kwargs={"port": port, "server_factory": keep, "say": lambda _: None},
        daemon=True,
    )
    thread.start()
    try:
        first_id = json.loads(sample_report.read_text(encoding="utf-8"))["findings"][0]["id"]
        for path in ("/", "/findings", "/findings?decision=warn", f"/findings/{first_id}"):
            with urllib.request.urlopen(f"http://{HOST}:{port}{path}", timeout=10) as response:
                assert response.status == 200
        assert servers[0].server_address[0] == "127.0.0.1"
    finally:
        if servers:
            servers[0].shutdown()
        thread.join(timeout=10)


@pytest.mark.skipif(
    not (gitleaks_installed() and git_installed()), reason="gitleaks or git is not installed"
)
def test_sample_report_holds_about_20_real_masked_findings(tmp_path: Path) -> None:
    out = tmp_path / "sample_findings.json"
    result = write_sample_report(
        out,
        policy=load_policy(POLICY_FILE),
        policy_path="policy.yaml",
        key=random_key(),
        gitleaks_config=GITLEAKS_CONFIG,
        runner=subprocess_runner,
    )
    report = load_report(out)
    text = out.read_text(encoding="utf-8")

    assert isinstance(report, ReportView)
    assert 18 <= result.findings == len(report.findings) <= 26
    assert {f.decision for f in report.findings} == {"block", "warn", "ignore"}
    assert all(MASKED_VALUE.fullmatch(f.masked_value) for f in report.findings)
    assert leaked(result.planted, text) == []
    assert create_app(out).test_client().get("/").status_code == 200
