"""`securegate summary`: the Markdown written to GitHub's job summary page."""

import json
from pathlib import Path

import pytest

from helpers import leaked
from securegate.cli import main
from securegate.demo.generator import DemoResult
from securegate.summary import render_summary
from securegate.ui.report_view import load_report


def report_data(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_report(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_blocked_report_summary(sample_report: Path) -> None:
    data = report_data(sample_report)
    shown = [f for f in data["findings"] if f["decision"] in ("block", "warn")]
    text = render_summary(load_report(sample_report))
    lines = text.splitlines()

    assert lines[0] == "### SecureGate: BLOCKED (exit code 1)"
    assert "| Decision | Where | Masked value | Why | Fix |" in lines
    assert sum(line.startswith(("| BLOCK |", "| WARN |")) for line in lines) == len(shown)
    assert all(f"`{f['masked_value']}`" in text for f in shown)
    s = data["summary"]
    assert f"{s['block']} blocked, {s['warn']} warnings, {s['ignore']} ignored." in text


def test_summary_never_shows_a_planted_value(
    demo_repo: DemoResult, sample_report: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["summary", "--report", str(sample_report)])
    printed = capsys.readouterr().out
    assert exit_code == 0
    assert leaked(demo_repo.planted, printed) == []


def test_a_clean_scan_says_so(tmp_path: Path, sample_report: Path) -> None:
    data = dict(report_data(sample_report), findings=[], exit_code=0, status="pass")
    text = render_summary(load_report(write_report(tmp_path, data)))
    assert text.splitlines()[0] == "### SecureGate: PASS (exit code 0)"
    assert "No secrets found." in text


def test_range_scans_name_the_commits_and_explain_history(
    tmp_path: Path, sample_report: Path
) -> None:
    data = dict(report_data(sample_report), mode="range", range="a" * 40 + ".." + "b" * 40)
    text = render_summary(load_report(write_report(tmp_path, data)))
    assert "Scanned every commit in `aaaaaaa..bbbbbbb` with Gitleaks 8.30.1" in text
    assert "Deleting the line in a later commit does not turn this check green" in text


def test_missing_report_is_an_error_summary_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["summary", "--report", str(tmp_path / "missing.json")])
    printed = capsys.readouterr().out
    assert exit_code == 2
    assert printed.startswith("### SecureGate: ERROR")
    assert "No scan report yet." in printed


def test_failed_scan_summary_shows_the_error(tmp_path: Path) -> None:
    data = {"tool": "securegate", "status": "error", "error": "Gitleaks was not found."}
    text = render_summary(load_report(write_report(tmp_path, data)))
    assert "**The last scan failed.**" in text
    assert "Gitleaks was not found." in text


def test_table_cells_cannot_break_the_table(tmp_path: Path, sample_report: Path) -> None:
    data = report_data(sample_report)
    data["findings"][0]["reason"] = "provider-keys: a | b\nc"
    text = render_summary(load_report(write_report(tmp_path, data)))
    assert "a \\| b c" in text
