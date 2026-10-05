"""Leak test: no planted value may appear in findings.json, stdout, stderr, the dashboard, the
PR comment, the job summary or the SARIF file.

(a) always runs: a fake Gitleaks "finds" every planted value, so every one of them flows
    through the whole pipeline;
(b) runs the real CLI with the real Gitleaks in a separate process;
(c) always runs: fakes of all four scanners "find" every planted value, filling every field the
    real tools quote secrets in, and every output is written.
The dashboard is checked by rendering every page from such a scan.
Also checked: the hidden middle of every value of 16+ characters never shows.
Failures name only the kind and location, never the value.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fake_code_scanners import FakeBandit, FakeSemgrep, Spot
from fake_gitleaks import FakeGitleaks, report_for_demo
from fake_trufflehog import FakeTruffleHog, finding
from helpers import gitleaks_installed, leaked, multi_scan_args, scan_args
from securegate.demo.generator import DemoResult
from securegate.ui.app import create_app


def every_dashboard_page(report: Path) -> str:
    """The HTML of every dashboard page for this report, joined together."""
    client = create_app(report).test_client()
    findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
    paths = ["/", "/findings", "/findings?decision=nope", "/findings/0123456789ab"]
    paths += [f"/findings?decision={d}" for d in ("block", "warn", "ignore")]
    paths += [f"/findings/{f['id']}" for f in findings]
    return "".join(client.get(path).get_data(as_text=True) for path in paths)


def test_every_planted_value_stays_masked_through_the_pipeline(
    run_cli, demo_repo: DemoResult
) -> None:
    fake = FakeGitleaks(report=report_for_demo(demo_repo))

    result = run_cli(*scan_args(demo_repo.out), runner=fake)

    assert result.exit_code == 1
    assert len(result.findings) == len(demo_repo.planted)
    assert leaked(demo_repo.planted, result.out + result.err + json.dumps(result.report)) == []


@pytest.mark.skipif(not gitleaks_installed(), reason="gitleaks is not installed")
def test_real_scan_in_a_separate_process_leaks_nothing(
    demo_repo: DemoResult, tmp_path: Path
) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "securegate", *scan_args(demo_repo.out)],
        cwd=tmp_path,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    report = (tmp_path / "findings.json").read_text(encoding="utf-8")

    assert done.returncode == 1
    assert leaked(demo_repo.planted, done.stdout + done.stderr + report) == []
    assert leaked(demo_repo.planted, every_dashboard_page(tmp_path / "findings.json")) == []


def test_dashboard_pages_never_show_a_planted_value(
    demo_repo: DemoResult, sample_report: Path
) -> None:
    pages = every_dashboard_page(sample_report)
    assert len(json.loads(sample_report.read_text(encoding="utf-8"))["findings"]) == len(
        demo_repo.planted
    )  # every planted value was rendered somewhere
    assert leaked(demo_repo.planted, pages) == []


def test_no_planted_value_reaches_any_output_of_a_four_scanner_scan(
    run_cli, demo_repo: DemoResult, tmp_path: Path
) -> None:
    at_head = [p for p in demo_repo.planted if p.placement != "history-only"]
    trufflehog = FakeTruffleHog(
        findings=[
            finding(file=p.file, line=p.line, value=p.raw, commit=p.commit, verification_error=True)
            for p in demo_repo.planted
        ]
    )
    semgrep = FakeSemgrep(spots=[Spot("detected-secret", p.file, p.parts[0]) for p in at_head])
    bandit = FakeBandit(
        spots=[Spot("B105", p.file, p.parts[0]) for p in at_head if p.file.endswith(".py")]
    )
    outputs = {name: tmp_path / name for name in ("gate.sarif", "summary.md", "comment.md")}

    result = run_cli(
        *multi_scan_args(demo_repo.out, scanners="all"),
        "--sarif", str(outputs["gate.sarif"]),
        "--summary", str(outputs["summary.md"]),
        "--comment", str(outputs["comment.md"]),
        runner=FakeGitleaks(report=report_for_demo(demo_repo)),
        tool_runners={"trufflehog": trufflehog, "semgrep": semgrep, "bandit": bandit},
    )  # fmt: skip

    written = [path.read_text(encoding="utf-8") for path in outputs.values()]
    shown = result.out + result.err + json.dumps(result.report) + "".join(written)
    assert result.exit_code == 1
    assert [s["status"] for s in result.report["scanners"]] == ["ran"] * 4
    assert leaked(demo_repo.planted, shown) == []
