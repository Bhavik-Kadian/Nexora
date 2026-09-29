"""Rule 2: our own files contain no key-shaped strings.

Copies every file Git would commit (tracked files plus new, not-ignored ones) and scans the copy
in dir mode. Any finding fails the test; the fix is to change our code, never to allowlist it.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from helpers import REPO_ROOT, git_installed, gitleaks_installed, scan_args

pytestmark = pytest.mark.skipif(
    not (gitleaks_installed() and git_installed() and (REPO_ROOT / ".git").exists()),
    reason="needs gitleaks, git and a Git checkout of SecureGate",
)


def test_our_own_files_have_no_findings(run_cli, tmp_path: Path) -> None:
    listed = subprocess.run(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    copy = tmp_path / "copy"
    for relative in filter(None, listed.split("\0")):
        source = REPO_ROOT / relative
        if source.is_file():
            destination = copy / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    result = run_cli(*scan_args(copy, mode="dir"))

    problems = [f"{f['rule']} at {f['file']}:{f['line']}" for f in result.findings]
    assert problems == []
    assert result.exit_code == 0
