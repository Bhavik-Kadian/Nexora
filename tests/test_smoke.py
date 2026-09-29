"""Milestone 1 smoke test: the package imports and `securegate version` works."""

import pytest

from securegate import __version__
from securegate.cli import main


def test_version_command_prints_version_and_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["version"])

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == f"securegate {__version__}"
