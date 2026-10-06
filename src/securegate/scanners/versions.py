"""The installed versions of TruffleHog, Semgrep and Bandit, for `securegate version` and the menu.

Semgrep and Bandit are Python packages, so their version is read from the installed package
when no runner is given: instant, where `semgrep --version` takes seconds to start. TruffleHog
is asked with `trufflehog --version`. A program that is missing has version None.
"""

from collections.abc import Mapping
from importlib import metadata

from securegate.errors import ScannerError
from securegate.scanners.common import ProgramRunner, ToolRunner, parse_version

OTHER_SCANNERS = ("trufflehog", "semgrep", "bandit")
PYTHON_PACKAGES = ("semgrep", "bandit")


def scanner_versions(runners: Mapping[str, ToolRunner]) -> dict[str, str | None]:
    """The version of each scanner besides Gitleaks, or None when it is not installed. A runner
    in `runners` (by name) replaces the real program; tests pass fakes."""
    return {name: _version(name, runners.get(name)) for name in OTHER_SCANNERS}


def _version(name: str, runner: ToolRunner | None) -> str | None:
    if runner is None and name in PYTHON_PACKAGES:
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            pass  # perhaps installed elsewhere, as a program on PATH
    try:
        result = (runner or ProgramRunner(name, timeout=60))(["--version"])
    except (FileNotFoundError, ScannerError):
        return None
    return parse_version(result.stdout + result.stderr) if result.returncode == 0 else None
