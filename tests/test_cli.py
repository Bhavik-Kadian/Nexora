"""The CLI: version, the table and summary line, findings.json, and failing closed.

Convention: raw test values never appear inside an assert.
"""

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from fake_gitleaks import FakeGitleaks, entry
from helpers import fake_aws_key_id, random_text, scan_args
from securegate import __version__
from securegate.cli import main
from securegate.mask import KEY_ENV_VAR, mask_value
from securegate.scanners.gitleaks import RunResult

FINDING_FIELDS = [
    "id",
    "rule",
    "detector",
    "file",
    "line",
    "commit",
    "author",
    "date",
    "masked_value",
    "fingerprint",
    "entropy",
    "confidence",
    "severity",
    "decision",
    "reason",
    "remediation",
]


def test_version_prints_securegate_and_gitleaks(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["version"], runner=FakeGitleaks(version="8.30.1"))
    assert exit_code == 0
    assert capsys.readouterr().out.splitlines() == [f"securegate {__version__}", "gitleaks 8.30.1"]


def test_version_works_without_gitleaks(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["version"], runner=FakeGitleaks(missing=True))
    assert exit_code == 0
    assert "gitleaks not found" in capsys.readouterr().out


def test_table_shows_decision_rule_location_and_masked_value(run_cli, tmp_path: Path) -> None:
    aws = fake_aws_key_id()
    expected_mask = mask_value(aws)
    fake = FakeGitleaks(
        report=[entry(rule="aws-access-token", file="config/settings.py", line=9, value=aws)]
    )

    result = run_cli(*scan_args(tmp_path), runner=fake)

    header, row = result.out.splitlines()[:2]
    assert header.split() == ["DECISION", "RULE", "FILE:LINE", "VALUE"]
    assert row.split() == ["block", "aws-access-token", "config/settings.py:9", expected_mask]
    assert "BLOCKED (exit code 1). Details: findings.json" in result.out
    raw_visible = aws in result.out or aws in result.err
    assert not raw_visible


def test_findings_json_envelope(run_cli, tmp_path: Path) -> None:
    fake = FakeGitleaks(
        report=[
            entry(rule="aws-access-token", file="a.py", line=1, value=fake_aws_key_id()),
            entry(rule="generic-api-key", file="b.py", line=2, value=random_text(30)),
        ]
    )
    report = run_cli(*scan_args(tmp_path), runner=fake).report

    assert {k: report[k] for k in ("tool", "version", "schema_version", "status", "exit_code")} == {
        "tool": "securegate",
        "version": __version__,
        "schema_version": 1,
        "status": "fail",
        "exit_code": 1,
    }
    assert (report["mode"], report["range"]) == ("repo", None)
    assert report["scanner"] == {"name": "gitleaks", "version": "8.30.1"}
    assert report["summary"] == {"total": 2, "block": 1, "warn": 1, "ignore": 0}
    assert list(report["findings"][0]) == FINDING_FIELDS


def test_no_findings_prints_only_the_summary(run_cli, tmp_path: Path) -> None:
    result = run_cli(*scan_args(tmp_path), runner=FakeGitleaks())
    assert result.out.splitlines() == [
        "0 findings: 0 block, 0 warn, 0 ignore -> PASS (exit code 0). Details: findings.json"
    ]


def test_failed_scan_replaces_an_older_report(run_cli, tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text('{"status": "pass", "findings": []}', encoding="utf-8")
    result = run_cli(*scan_args(tmp_path), runner=FakeGitleaks(missing=True))
    assert result.exit_code == 2
    assert result.report["status"] == "error"
    assert result.report["exit_code"] == 2
    assert "findings" not in result.report
    assert "Gitleaks was not found" in result.report["error"]


def test_invalid_policy_exits_2_with_a_clear_message(run_cli, tmp_path: Path) -> None:
    bad_policy = tmp_path / "bad-policy.yaml"
    bad_policy.write_text("version: 1\nrules:\n  - name: x\n    decison: warn\n", encoding="utf-8")
    fake = FakeGitleaks()
    result = run_cli(*scan_args(tmp_path), "--policy", str(bad_policy), runner=fake)
    assert result.exit_code == 2
    assert "did you mean 'decision'" in result.err
    assert fake.calls == []


@pytest.mark.parametrize(
    ("option", "message"),
    [("--policy", "policy file not found"), ("--gitleaks-config", "Gitleaks config not found")],
)
def test_missing_config_files_exit_2(run_cli, tmp_path: Path, option: str, message: str) -> None:
    result = run_cli(*scan_args(tmp_path), option, str(tmp_path / "missing"), runner=FakeGitleaks())
    assert result.exit_code == 2
    assert message in result.err


def test_short_fingerprint_key_exits_2(
    run_cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, "too-short")
    result = run_cli(*scan_args(tmp_path), runner=FakeGitleaks())
    assert result.exit_code == 2
    assert KEY_ENV_VAR in result.err


def test_unknown_option_is_a_usage_error_with_exit_2() -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["scan", "--no-such-option"])
    assert stopped.value.code == 2


def test_unexpected_error_fails_closed_without_details(run_cli, tmp_path: Path) -> None:
    hidden_detail = random_text(24)

    def broken(args: Sequence[str]) -> RunResult:
        raise RuntimeError(hidden_detail)

    result = run_cli(*scan_args(tmp_path), runner=broken)

    assert result.exit_code == 2
    assert "internal error (RuntimeError)" in result.err
    assert result.report["status"] == "error"
    detail_visible = hidden_detail in result.out + result.err + json.dumps(result.report)
    assert not detail_visible


def test_non_ascii_paths_are_printed_without_crashing(run_cli, tmp_path: Path) -> None:
    fake = FakeGitleaks(
        report=[entry(rule="generic-api-key", file="données/clé.py", line=1, value=random_text(20))]
    )
    result = run_cli(*scan_args(tmp_path), runner=fake)
    assert result.exit_code == 0
    assert "données/clé.py:1" in result.out
