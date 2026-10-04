"""The real TruffleHog (and Gitleaks) on a tiny repository, through the CLI.

Skipped when either program is missing. Verification is always switched off, so a fake key is
never sent to anyone; every test checks that --no-verification reached TruffleHog.
"""

from pathlib import Path

import pytest

from helpers import GitRepo, fake_acme_token, git_installed, gitleaks_installed, multi_scan_args
from securegate.mask import mask_value
from securegate.programs import find_program
from securegate.scanners.common import ProgramRunner, RunResult

pytestmark = pytest.mark.skipif(
    not (gitleaks_installed() and git_installed() and find_program("trufflehog")),
    reason="needs gitleaks, git and trufflehog (make scanners)",
)


class RecordingRunner(ProgramRunner):
    """The real TruffleHog runner, remembering every command line it ran."""

    def __init__(self) -> None:
        super().__init__("trufflehog", timeout=300)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        self.calls.append(list(args))
        return super().__call__(args, cwd=cwd)

    def scanned_without_verification(self) -> bool:
        scans = [call for call in self.calls if call[:1] == ["git"] and "--help" not in call]
        return len(scans) == 1 and "--no-verification" in scans[0]


def leak_then_remove(repo: GitRepo) -> tuple[str, str, str]:
    """main gets a commit; a branch adds a fake ACME token and removes it again; then main
    moves on, so the old base is no longer where the branch started. Returns (base, head, token)."""
    repo.write("readme.txt", "hello\n")
    base = repo.commit("start")
    repo.git("switch", "-q", "-c", "feature")
    token = fake_acme_token()
    repo.write("app/pay.py", f'"""Payments."""\n\nACME_PAY_API_KEY = "{token}"\n')
    repo.commit("add the payment key")
    repo.write("app/pay.py", '"""Payments."""\n\nACME_PAY_API_KEY = None\n')
    head = repo.commit("remove the payment key")
    repo.git("switch", "-q", "main")
    repo.write("other.txt", "main moved on\n")
    moved = repo.commit("main moves on")
    repo.git("switch", "-q", "--detach", head)
    assert base != moved
    return moved, head, token


def test_a_key_removed_later_is_found_by_both_secret_scanners(run_cli, make_repo) -> None:
    repo = make_repo()
    base, head, token = leak_then_remove(repo)
    hog = RecordingRunner()

    result = run_cli(
        *multi_scan_args(
            repo.path, "--range", f"{base}..{head}", "--no-verification", mode="range"
        ),
        tool_runners={"trufflehog": hog},
    )

    (found,) = result.findings
    assert result.exit_code == 1
    assert hog.scanned_without_verification()
    assert (found["file"], found["line"], found["decision"]) == ("app/pay.py", 3, "block")
    assert found["detectors"] == ["gitleaks", "trufflehog"]
    assert (found["validity"], found["matched_rule"]) == ("not_checked", "rule 8: provider-keys")
    assert found["masked_value"] == mask_value(token)
    assert [s["status"] for s in result.report["scanners"]] == ["ran", "ran"]


def test_the_whole_history_is_scanned_in_repo_mode(run_cli, make_repo) -> None:
    repo = make_repo()
    leak_then_remove(repo)
    hog = RecordingRunner()

    result = run_cli(
        *multi_scan_args(repo.path, "--no-verification"), tool_runners={"trufflehog": hog}
    )

    assert result.exit_code == 1
    assert hog.scanned_without_verification()
    assert [f["detectors"] for f in result.findings] == [["gitleaks", "trufflehog"]]
