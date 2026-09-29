"""Integration: scan the demo repo with the real Gitleaks and compare with ground_truth.csv.

The scorecard (hits, misses, false alarms, wrong decisions) is printed at the end of the test
run. It is reported, not asserted: the rules are not tuned to make the numbers look good.
"""

import os

import pytest

from helpers import git_installed, gitleaks_installed, scan_args
from securegate.demo.generator import DemoResult
from securegate.demo.scorecard import format_scorecard, read_ground_truth, score
from securegate.mask import KEY_ENV_VAR, fingerprint

pytestmark = pytest.mark.skipif(
    not (gitleaks_installed() and git_installed()), reason="gitleaks or git is not installed"
)


@pytest.mark.parametrize("mode", ["repo", "dir"])
def test_scan_the_demo_and_record_a_scorecard(
    run_cli, demo_repo: DemoResult, record_scorecard, mode: str
) -> None:
    result = run_cli(*scan_args(demo_repo.out, mode=mode))
    card = score(read_ground_truth(demo_repo.ground_truth), result.findings)
    record_scorecard(f"{mode} mode, seed {demo_repo.seed}\n{format_scorecard(card)}")

    assert result.exit_code == 1
    assert result.report["status"] == "fail"
    assert card.planted == len(demo_repo.planted)
    assert card.count("hit") > 0


def test_history_only_key_is_found_in_repo_mode_but_not_in_dir_mode(
    run_cli, demo_repo: DemoResult
) -> None:
    (item,) = [p for p in demo_repo.planted if p.placement == "history-only"]
    expected = fingerprint(item.raw, os.environ[KEY_ENV_VAR].encode("utf-8"))

    in_history = run_cli(*scan_args(demo_repo.out, mode="repo")).findings
    on_disk = run_cli(*scan_args(demo_repo.out, mode="dir")).findings

    assert [
        (f["file"], f["commit"], f["decision"]) for f in in_history if f["fingerprint"] == expected
    ] == [(item.file, item.commit, "block")]
    assert [f for f in on_disk if f["fingerprint"] == expected] == []
