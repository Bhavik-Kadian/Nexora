"""Shared pytest setup."""

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from helpers import GitRepo
from securegate.cli import main
from securegate.mask import KEY_ENV_VAR
from securegate.scanners.gitleaks import Runner


@pytest.fixture(autouse=True)
def _fresh_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test its own random fingerprint key, so no test creates .securegate/ here."""
    monkeypatch.setenv(KEY_ENV_VAR, secrets.token_hex(32))


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

    def run(*args: str, runner: Runner | None = None) -> CliRun:
        exit_code = main(list(args), runner=runner)
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
