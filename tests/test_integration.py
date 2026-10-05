"""Integration: scan the demo repo with the real scanners and compare with ground_truth.csv.

The scorecards (hits, misses, false alarms, wrong decisions) are printed at the end of the test
run, one for Gitleaks alone and one per scanner of a four-scanner scan. They are reported, not
asserted: the rules are not tuned to make the numbers look good.
"""

import json
import os

import pytest

from helpers import (
    RecordingTruffleHog,
    git_installed,
    gitleaks_installed,
    leaked,
    multi_scan_args,
    scan_args,
)
from securegate.demo.generator import DemoResult
from securegate.demo.scorecard import (
    format_scorecard,
    read_ground_truth,
    score,
    score_by_detector,
)
from securegate.mask import KEY_ENV_VAR, fingerprint
from securegate.programs import find_program

SCANNERS = ("gitleaks", "trufflehog", "semgrep", "bandit")

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


@pytest.mark.skipif(
    not all(find_program(name) for name in ("trufflehog", "semgrep", "bandit")),
    reason="needs trufflehog, semgrep and bandit (make scanners)",
)
def test_four_scanners_on_the_demo_with_a_scorecard_for_each(
    run_cli, demo_repo: DemoResult, record_scorecard
) -> None:
    hog = RecordingTruffleHog()

    result = run_cli(
        *multi_scan_args(demo_repo.out, "--no-verification", scanners="all"),
        tool_runners={"trufflehog": hog},
    )

    truth = read_ground_truth(demo_repo.ground_truth)
    runs = ", ".join(f"{s['name']} {s['status']}" for s in result.report["scanners"])
    together = format_scorecard(score(truth, result.findings))
    record_scorecard(f"four scanners together, repo mode ({runs})\n{together}")
    for name in SCANNERS:
        card = score_by_detector(truth, result.findings, name)
        record_scorecard(f"{name} alone, in the four-scanner scan\n{format_scorecard(card)}")

    assert result.exit_code == 1
    assert hog.scanned_without_verification()  # no fake key went to a real provider
    assert [s["status"] for s in result.report["scanners"][:2]] == ["ran", "ran"]
    shown = result.out + result.err + json.dumps(result.report)
    assert leaked(demo_repo.planted, shown) == []
