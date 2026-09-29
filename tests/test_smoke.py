"""Milestone 1 smoke test: the package imports and `securegate version` works."""

import pytest

from fake_gitleaks import FakeGitleaks
from securegate import __version__
from securegate.cli import main


def test_version_command_prints_version_and_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["version"], runner=FakeGitleaks())

    assert exit_code == 0
    assert capsys.readouterr().out.splitlines()[0] == f"securegate {__version__}"
