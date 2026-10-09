"""Shared pytest setup."""

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from fake_gitleaks import FakeGitleaks, report_for_demo
from helpers import GITLEAKS_CONFIG, POLICY_FILE, GitRepo, git_installed, random_key
from securegate.cli import main
from securegate.demo.generator import DemoResult, generate
from securegate.mask import KEY_ENV_VAR
from securegate.pipeline import run_scan
from securegate.policy import load_policy
from securegate.report import envelope, write_json
from securegate.scanners.gitleaks import Runner

SCORECARDS = pytest.StashKey[list[str]]()


def pytest_configure(config: pytest.Config) -> None:
    config.stash[SCORECARDS] = []


def pytest_terminal_summary(terminalreporter, exitstatus: int, config: pytest.Config) -> None:
    """Print the demo scorecards (recorded by test_integration.py) at the end of the run."""
    for card in config.stash.get(SCORECARDS, []):
        terminalreporter.section("SecureGate demo scorecard")
        terminalreporter.write_line(card)


@pytest.fixture
def record_scorecard(request: pytest.FixtureRequest) -> Callable[[str], None]:
    return request.config.stash[SCORECARDS].append


@pytest.fixture(autouse=True)
def _fresh_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test its own random fingerprint key, so no test creates .securegate/ here."""
    monkeypatch.setenv(KEY_ENV_VAR, secrets.token_hex(32))


@pytest.fixture(autouse=True)
def _no_real_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test ever reaches Azure: unless a test passes its own model, the AI agents count as
    not set up, even on a laptop where .securegate/ai.json exists."""
    monkeypatch.setattr("securegate.cli._azure_model", lambda: None)


@pytest.fixture(scope="session")
def demo_repo(tmp_path_factory: pytest.TempPathFactory) -> DemoResult:
    """The demo repo from the packaged catalog with seed 42, built once per test run."""
    if not git_installed():
        pytest.skip("git is not installed")
    return generate(tmp_path_factory.mktemp("demo") / "securegate-demo", seed=42)


@pytest.fixture(scope="session")
def sample_report(demo_repo: DemoResult, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A findings.json for the demo repo, written by the real pipeline. A fake Gitleaks
    "finds" every planted value, so the report covers every kind and all three decisions."""
    result = run_scan(
        demo_repo.out,
        "repo",
        policy=load_policy(POLICY_FILE),
        key=random_key(),
        gitleaks_config=GITLEAKS_CONFIG,
        runner=FakeGitleaks(report=report_for_demo(demo_repo)),
    )
    exit_code = 1 if any(f.decision == "block" for f in result.findings) else 0
    path = tmp_path_factory.mktemp("report") / "findings.json"
    write_json(
        path,
        envelope(
            exit_code=exit_code,
            target="../securegate-demo",
            mode="repo",
            log_range=None,
            policy_path="policy.yaml",
            scanner_version=result.scanner_version,
            findings=result.findings,
        ),
    )
    return path


@dataclass
class CliRun:
    exit_code: int
    out: str
    err: str
    report: dict[str, Any] | None  # findings.json after the run, if one was written

    @property
    def findings(self) -> list[dict[str, Any]]:
        return (self.report or {}).get("findings", [])


@pytest.fixture
def run_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> Callable[..., CliRun]:
    """Run the CLI in-process from inside tmp_path, capturing output and findings.json."""
    monkeypatch.chdir(tmp_path)
    report_file = tmp_path / "findings.json"

    def run(
        *args: str,
        runner: Runner | None = None,
        tool_runners: dict[str, Any] | None = None,
        model_factory: Any = None,
    ) -> CliRun:
        exit_code = main(
            list(args), runner=runner, tool_runners=tool_runners, model_factory=model_factory
        )
        captured = capsys.readouterr()
        report = (
            json.loads(report_file.read_text(encoding="utf-8")) if report_file.exists() else None
        )
        return CliRun(exit_code, captured.out, captured.err, report)

    return run


@pytest.fixture
def make_repo(tmp_path_factory: pytest.TempPathFactory) -> Callable[[], GitRepo]:
    """Create throwaway Git repositories outside tmp_path."""
    config_dir = tmp_path_factory.mktemp("gitconfig")

    def make() -> GitRepo:
        return GitRepo(tmp_path_factory.mktemp("repo"), config_dir)

    return make
