"""The Gitleaks adapter, driven by a fake runner, so no gitleaks binary is needed.

Convention: raw test values never appear inside an assert.
"""

import json
import os
from collections.abc import Sequence
from pathlib import Path

import pytest

from fake_gitleaks import FakeGitleaks, entry
from helpers import GITLEAKS_CONFIG, fake_aws_key_id, random_text, scan_args
from securegate.scanners import gitleaks
from securegate.scanners.gitleaks import Candidate, GitleaksNotFound, RunResult, parse_report

# --- exit codes: clean -> 0, leaks -> 1, crash -> 2, missing binary -> 2 ---------------------


def test_clean_scan_exits_0(run_cli, tmp_path: Path) -> None:
    result = run_cli(*scan_args(tmp_path), runner=FakeGitleaks(report=[]))
    assert result.exit_code == 0
    assert result.report["status"] == "pass"
    assert result.findings == []


def test_blocking_leak_exits_1(run_cli, tmp_path: Path) -> None:
    fake = FakeGitleaks(
        report=[
            entry(rule="aws-access-token", file="app/settings.py", line=3, value=fake_aws_key_id())
        ]
    )
    result = run_cli(*scan_args(tmp_path), runner=fake)
    assert result.exit_code == 1
    assert [f["decision"] for f in result.findings] == ["block"]


def test_warn_only_leak_exits_0_because_the_policy_decides(run_cli, tmp_path: Path) -> None:
    fake = FakeGitleaks(
        report=[
            entry(rule="generic-api-key", file="app/settings.py", line=3, value=random_text(24))
        ]
    )
    result = run_cli(*scan_args(tmp_path), runner=fake)
    assert result.exit_code == 0
    assert [f["decision"] for f in result.findings] == ["warn"]


def test_gitleaks_crash_exits_2(run_cli, tmp_path: Path) -> None:
    fake = FakeGitleaks(report=None, scan_exit=1, stderr="ERR something broke\n")
    result = run_cli(*scan_args(tmp_path), runner=fake)
    assert result.exit_code == 2
    assert "exit code 1" in result.err
    assert "something broke" in result.err
    assert result.report["status"] == "error"
    assert "findings" not in result.report


def test_missing_gitleaks_exits_2(run_cli, tmp_path: Path) -> None:
    result = run_cli(*scan_args(tmp_path), runner=FakeGitleaks(missing=True))
    assert result.exit_code == 2
    assert "Gitleaks was not found" in result.err


def test_file_not_found_from_the_runner_means_gitleaks_is_missing(run_cli, tmp_path: Path) -> None:
    def runner(args: Sequence[str]) -> RunResult:
        raise FileNotFoundError("gitleaks")

    result = run_cli(*scan_args(tmp_path), runner=runner)
    assert result.exit_code == 2
    assert "Gitleaks was not found" in result.err


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        pytest.param(FakeGitleaks(report=[], scan_exit=99), "report is empty", id="leaks-empty"),
        pytest.param(
            FakeGitleaks(report_text="[{not json", scan_exit=99), "not valid JSON", id="garbled"
        ),
        pytest.param(FakeGitleaks(report=None, scan_exit=0), "did not write", id="no-report"),
        pytest.param(
            FakeGitleaks(report_text='{"a": 1}', scan_exit=99), "not a list", id="not-a-list"
        ),
        pytest.param(
            FakeGitleaks(report=[{"RuleID": "x"}], scan_exit=99), "lacks RuleID", id="partial"
        ),
        pytest.param(FakeGitleaks(report=[], scan_exit=126), "exit code 126", id="bad-flag"),
        pytest.param(
            FakeGitleaks(report=[], scan_exit=0, stderr="ERR [git] fatal: not a git repository"),
            "not a Git repository",
            id="exit-0-with-error-log",
        ),
    ],
)
def test_unreadable_or_suspicious_results_exit_2(
    run_cli, tmp_path: Path, fake: FakeGitleaks, message: str
) -> None:
    result = run_cli(*scan_args(tmp_path), runner=fake)
    assert result.exit_code == 2
    assert message in result.err


# --- the command line we build ---------------------------------------------------------------


def test_missing_required_flag_exits_2_before_scanning(run_cli, tmp_path: Path) -> None:
    fake = FakeGitleaks(drop_flags=("--exit-code",))
    result = run_cli(*scan_args(tmp_path), runner=fake)
    assert result.exit_code == 2
    assert "--exit-code" in result.err
    assert fake.scan_calls == []


@pytest.mark.parametrize(
    ("mode", "extra", "expected"),
    [
        ("repo", [], {"command": "git", "range": False, "staged": False}),
        ("range", ["--range=main..feature"], {"command": "git", "range": True, "staged": False}),
        ("staged", [], {"command": "git", "range": False, "staged": True}),
        ("dir", [], {"command": "dir", "range": False, "staged": False}),
    ],
)
def test_each_mode_builds_the_right_command(
    run_cli, tmp_path: Path, mode: str, extra: list[str], expected: dict[str, object]
) -> None:
    fake = FakeGitleaks()
    result = run_cli(*scan_args(tmp_path, mode=mode), *extra, runner=fake)
    args = fake.scan_args
    assert result.exit_code == 0
    assert args[:2] == [expected["command"], str(tmp_path.resolve())]
    assert ("--log-opts=main..feature" in args) is expected["range"]
    assert ("--pre-commit" in args and "--staged" in args) is expected["staged"]


@pytest.mark.parametrize("mode", ["repo", "dir"])
def test_every_scan_uses_our_config_and_safety_flags(run_cli, tmp_path: Path, mode: str) -> None:
    fake = FakeGitleaks()
    run_cli(*scan_args(tmp_path, mode=mode), runner=fake)
    args = fake.scan_args

    def value_of(flag: str) -> str:
        return args[args.index(flag) + 1]

    assert value_of("--config") == str(GITLEAKS_CONFIG.resolve())
    assert value_of("--exit-code") == "99"
    assert value_of("--report-format") == "json"
    assert value_of("--log-level") == "error"
    for flag in ("--no-banner", "--no-color", "--ignore-gitleaks-allow", "--gitleaks-ignore-path"):
        assert flag in args
    assert not any(arg.startswith("--redact") or arg in ("-v", "--verbose") for arg in args)


def test_report_lives_in_a_temporary_folder_that_is_deleted(run_cli, tmp_path: Path) -> None:
    fake = FakeGitleaks(
        report=[entry(rule="aws-access-token", file="a.py", line=1, value=fake_aws_key_id())]
    )
    run_cli(*scan_args(tmp_path), runner=fake)
    args = fake.scan_args
    report_path = Path(args[args.index("--report-path") + 1])
    assert report_path.name == "report.json"
    assert Path(args[args.index("--gitleaks-ignore-path") + 1]) == report_path.parent
    assert not report_path.parent.exists()


@pytest.mark.parametrize(
    "good_range",
    ["main..feature", "abc123...def456", "HEAD~3..HEAD", "origin/main..release/1.2", "v1.0..v1.1"],
)
def test_valid_ranges_go_to_git_log(run_cli, tmp_path: Path, good_range: str) -> None:
    fake = FakeGitleaks()
    result = run_cli(*scan_args(tmp_path, mode="range"), f"--range={good_range}", runner=fake)
    assert result.exit_code == 0
    assert f"--log-opts={good_range}" in fake.scan_args


@pytest.mark.parametrize(
    "bad_range", ["main", "--output=x..y", "-x..y", "a..b c", "a..-b", "a..b;rm", "", "a.b"]
)
def test_bad_ranges_are_refused_before_gitleaks_runs(
    run_cli, tmp_path: Path, bad_range: str
) -> None:
    fake = FakeGitleaks()
    result = run_cli(*scan_args(tmp_path, mode="range"), f"--range={bad_range}", runner=fake)
    assert result.exit_code == 2
    assert fake.calls == []


def test_range_mode_needs_a_range(run_cli, tmp_path: Path) -> None:
    result = run_cli(*scan_args(tmp_path, mode="range"), runner=FakeGitleaks())
    assert result.exit_code == 2
    assert "needs --range" in result.err


def test_range_only_works_in_range_mode(run_cli, tmp_path: Path) -> None:
    result = run_cli(*scan_args(tmp_path, mode="repo"), "--range=a..b", runner=FakeGitleaks())
    assert result.exit_code == 2
    assert "only works with --mode range" in result.err


def test_folder_with_a_gitleaksignore_is_refused(run_cli, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / ".gitleaksignore").write_text("commit:file:rule:1\n", encoding="utf-8")
    fake = FakeGitleaks()
    result = run_cli(*scan_args(target), runner=fake)
    assert result.exit_code == 2
    assert ".gitleaksignore" in result.err
    assert fake.calls == []


def test_missing_target_exits_2(run_cli, tmp_path: Path) -> None:
    result = run_cli(*scan_args(tmp_path / "nope"), runner=FakeGitleaks())
    assert result.exit_code == 2
    assert "does not exist" in result.err


# --- reading the report ----------------------------------------------------------------------


def test_dir_mode_paths_become_relative_with_forward_slashes(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    report = json.dumps(
        [
            entry(rule="r", file=f"{base.as_posix()}/app/pay.py", line=1, value="v"),
            entry(rule="r", file=str(base / "cfg" / "a.yaml"), line=2, value="v"),
        ]
    )
    assert [c.file for c in parse_report(report, base=base)] == ["app/pay.py", "cfg/a.yaml"]


def test_git_mode_paths_are_kept_with_forward_slashes() -> None:
    report = json.dumps([entry(rule="r", file="app\\pay.py", line=1, value="v")])
    assert parse_report(report, base=None)[0].file == "app/pay.py"


def test_empty_commit_author_and_zero_date_become_none() -> None:
    report = json.dumps(
        [entry(rule="r", file="a.py", line=1, value="v", date="0001-01-01T00:00:00Z")]
    )
    candidate = parse_report(report, base=None)[0]
    assert (candidate.commit, candidate.author, candidate.date) == (None, None, None)


def test_secret_falls_back_to_match_when_empty() -> None:
    fallback = random_text(20)
    item = entry(rule="r", file="a.py", line=1, value="")
    item["Match"] = fallback
    used_fallback = parse_report(json.dumps([item]), base=None)[0].value == fallback
    assert used_fallback


def test_unknown_report_fields_are_ignored() -> None:
    item = entry(rule="r", file="a.py", line=1, value="v")
    item["SomethingNew"] = {"nested": True}
    assert len(parse_report(json.dumps([item]), base=None)) == 1


def test_candidate_repr_hides_the_value() -> None:
    value = random_text(40)
    candidate = Candidate(
        rule_id="r", file="a.py", line=1, commit=None, author=None, date=None, value=value
    )
    visible = value in repr(candidate) or value in str(candidate)
    assert not visible


# --- finding the program ---------------------------------------------------------------------


def _fake_program(folder: Path) -> Path:
    program = folder / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
    program.write_text("not really gitleaks", encoding="utf-8")
    program.chmod(0o755)
    return program


def test_gitleaks_is_never_taken_from_the_current_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_program(tmp_path)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(GitleaksNotFound):
        gitleaks.find_gitleaks(path_env=os.pathsep.join([".", "", "relative/bin"]))


def test_gitleaks_is_found_in_absolute_path_folders(tmp_path: Path) -> None:
    program = _fake_program(tmp_path)
    assert gitleaks.find_gitleaks(path_env=str(tmp_path)) == program
