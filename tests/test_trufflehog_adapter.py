"""The TruffleHog adapter, with a scripted fake TruffleHog (no binary needed).

Convention: raw test values never appear inside an assert; tests compare masks, counts and
booleans, and leaks are checked with helpers.leaked-style searches that name no value.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from fake_gitleaks import FakeGitleaks, entry
from fake_trufflehog import FakeTruffleHog, finding
from helpers import (
    TRUFFLEHOG_CONFIG,
    fake_acme_token,
    fake_stripe_key,
    multi_scan_args,
    random_text,
    scan_args,
)
from securegate.errors import ConfigError, ScannerError
from securegate.mask import mask_value
from securegate.scanners import trufflehog
from securegate.scanners.common import help_flags
from securegate.scanners.trufflehog import TruffleHogNotFound, TruffleHogOutput

ALL_FLAGS = help_flags(FakeTruffleHog()(["git", "--help"]).stdout)


def scan_with(
    fake: FakeTruffleHog, *, log_range: str | None = None, verify: bool = True
) -> TruffleHogOutput:
    return trufflehog.scan(
        Path("."), runner=fake, log_range=log_range, config=TRUFFLEHOG_CONFIG, verify=verify
    )


def visible(value: str, text: str) -> bool:
    """True when the value, or the hidden middle of a long one, shows in `text`."""
    return value in text or (len(value) >= 16 and value[4:-4] in text)


# --- the command -------------------------------------------------------------------------------


def test_kingpin_switches_count_as_flags() -> None:
    assert {"--json", "--no-verification", "--since-commit", "--fail"} <= ALL_FLAGS


def test_command_scans_the_range_with_the_safety_flags() -> None:
    args = trufflehog.build_command(
        Path("."), base="abc", head="def", config=Path("c.yaml"), verify=True, flags=ALL_FLAGS
    )
    assert args[:2] == ["git", trufflehog.repo_uri(Path("."))]
    assert args[args.index("--since-commit") + 1] == "abc"
    assert args[args.index("--branch") + 1] == "def"
    for flag in ("--json", "--no-update", "--no-ignore-tag", "--fail-on-scan-errors"):
        assert flag in args
    assert "--results=verified,unknown,unverified" in args
    assert args[args.index("--config") + 1] == "c.yaml"
    assert "--fail" not in args  # its exit code would hide crashes among findings
    assert "--no-verification" not in args


def test_repo_mode_scans_the_whole_history_and_verification_can_be_switched_off() -> None:
    args = trufflehog.build_command(
        Path("."), base=None, head=None, config=None, verify=False, flags=ALL_FLAGS
    )
    assert "--since-commit" not in args and "--branch" not in args
    assert "--config" not in args
    assert "--no-verification" in args


@pytest.mark.parametrize("flag", ["no-ignore-tag", "fail-on-scan-errors", "since-commit"])
def test_a_missing_flag_is_refused_by_name(flag: str) -> None:
    flags = help_flags(FakeTruffleHog(help_without=[flag])(["git", "--help"]).stdout)
    with pytest.raises(ScannerError, match=f"--{flag}"):
        trufflehog.build_command(
            Path("."), base=None, head=None, config=None, verify=True, flags=flags
        )


def test_repo_uri_is_a_file_uri() -> None:
    uri = trufflehog.repo_uri(Path("."))
    assert uri.startswith("file://") and "\\" not in uri


@pytest.mark.parametrize(
    ("text", "parts"), [("a..b", ("a", "b")), ("main...feat", ("main", "feat"))]
)
def test_ranges_split_into_base_and_head(text: str, parts: tuple[str, str]) -> None:
    assert trufflehog.split_range(text) == parts


# --- reading the output ------------------------------------------------------------------------


def test_findings_become_candidates_with_location_author_and_date() -> None:
    value = fake_stripe_key()
    line = json.dumps(finding(file="app\\pay.py", line=7, value=value, commit="c" * 40))
    (found,) = trufflehog.parse_output(line, verify=True)
    assert (found.rule_id, found.file, found.line, found.commit) == (
        "trufflehog-stripe",
        "app/pay.py",
        7,
        "c" * 40,
    )
    assert (found.author, found.date, found.detector) == (
        "Riya Demo",
        "2025-06-03T09:00:00Z",
        "trufflehog",
    )
    assert mask_value(found.value) == mask_value(value)  # Raw, compared through its mask
    assert not visible(value, repr(found))


def test_a_custom_detector_is_named_after_our_config() -> None:
    line = json.dumps(
        finding(file="a.py", line=1, value=fake_acme_token(), custom_name="ACME Pay token")
    )
    (found,) = trufflehog.parse_output(line, verify=True)
    assert found.rule_id == "trufflehog-acme-pay-token"


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"verified": True}, "verified"),
        ({"verification_error": True}, "unknown"),
        ({}, "unverified"),
    ],
)
def test_validity_follows_the_live_check(options: dict[str, bool], expected: str) -> None:
    line = json.dumps(finding(file="a.py", line=1, value=random_text(30), **options))
    (found,) = trufflehog.parse_output(line, verify=True)
    assert found.validity == expected


def test_without_verification_nothing_counts_as_checked() -> None:
    line = json.dumps(finding(file="a.py", line=1, value=random_text(30), verified=True))
    (found,) = trufflehog.parse_output(line, verify=False)
    assert found.validity == "not_checked"


def test_log_lines_on_stdout_are_skipped() -> None:
    text = "TruffleHog. Unearth your secrets.\n\n" + json.dumps(
        finding(file="a.py", line=1, value=random_text(30))
    )
    assert len(trufflehog.parse_output(text, verify=True)) == 1


def test_a_garbled_line_is_an_error_that_names_only_its_number() -> None:
    value = fake_acme_token()
    with pytest.raises(ScannerError, match="output line 2 is not valid JSON") as caught:
        trufflehog.parse_output('noise\n{"Raw": "' + value, verify=True)
    assert not visible(value, str(caught.value))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d.pop("SourceMetadata"), "has no Git location"),
        (lambda d: d["SourceMetadata"]["Data"]["Git"].pop("file"), "lacks a file or line"),
        (lambda d: d["SourceMetadata"]["Data"]["Git"].update(line="7"), "lacks a file or line"),
        (lambda d: d.update(Raw="", RawV2=""), "has no value"),
    ],
)
def test_incomplete_findings_are_errors(change: Callable[[Any], object], message: str) -> None:
    data = finding(file="a.py", line=1, value=random_text(30))
    change(data)
    with pytest.raises(ScannerError, match=message):
        trufflehog.parse_output(json.dumps(data), verify=True)


def test_line_zero_points_at_the_first_line_and_a_bare_email_is_not_kept() -> None:
    line = json.dumps(finding(file="a.py", line=0, value=random_text(30), email="me@example.com"))
    (found,) = trufflehog.parse_output(line, verify=True)
    assert (found.line, found.author) == (1, None)


def test_error_messages_show_only_the_fixed_message() -> None:
    value = fake_stripe_key()
    stderr = "\n".join(
        [
            json.dumps({"level": "info-0", "msg": "running source"}),
            json.dumps({"level": "error", "msg": "error running scan", "error": f"key {value}"}),
            "not json at all " + value,
        ]
    )
    shown = trufflehog.error_messages(stderr)
    assert shown == ": error running scan"


# --- running it ----------------------------------------------------------------------------------


def test_a_crash_is_a_scanner_error() -> None:
    fake = FakeTruffleHog(exit_code=1, stderr=json.dumps({"level": "error", "msg": "boom"}))
    with pytest.raises(ScannerError, match=r"TruffleHog failed \(exit code 1\): boom"):
        scan_with(fake)


def test_a_missing_program_says_how_to_install_it() -> None:
    with pytest.raises(TruffleHogNotFound, match="make scanners"):
        scan_with(FakeTruffleHog(missing=True))


def test_a_missing_config_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="TruffleHog config not found"):
        trufflehog.scan(
            tmp_path,
            runner=FakeTruffleHog(),
            log_range=None,
            config=tmp_path / "x.yaml",
            verify=True,
        )


def test_the_range_and_verification_reach_the_command() -> None:
    fake = FakeTruffleHog()
    output = scan_with(fake, log_range="base1..head2", verify=False)
    args = fake.scan_args
    assert (output.version, output.candidates) == ("3.97.9", [])
    assert args[args.index("--since-commit") + 1] == "base1"
    assert args[args.index("--branch") + 1] == "head2"
    assert "--no-verification" in args


# --- through the CLI -----------------------------------------------------------------------------


def test_gitleaks_and_trufflehog_findings_of_one_key_merge(run_cli, tmp_path: Path) -> None:
    value = fake_stripe_key()
    gitleaks = FakeGitleaks(
        report=[entry(rule="stripe-access-token", file="app/pay.py", line=3, value=value)]
    )
    hog = FakeTruffleHog(findings=[finding(file="app/pay.py", line=3, value=value, verified=True)])

    result = run_cli(*multi_scan_args(tmp_path), runner=gitleaks, tool_runners={"trufflehog": hog})

    (merged,) = result.findings
    assert result.exit_code == 1
    assert (merged["detectors"], merged["validity"]) == (["gitleaks", "trufflehog"], "verified")
    assert (merged["decision"], merged["severity"], merged["matched_rule"]) == (
        "block",
        "critical",
        "rule 1: verified-live",
    )
    assert merged["masked_value"] == mask_value(value)
    assert [s["name"] for s in result.report["scanners"]] == ["gitleaks", "trufflehog"]
    assert "Scanners: Gitleaks 8.30.1; TruffleHog 3.97.9" in result.out


def test_no_secret_field_of_trufflehog_reaches_any_output(run_cli, tmp_path: Path) -> None:
    values = [fake_stripe_key(), fake_acme_token(), random_text(40)]
    hog = FakeTruffleHog(
        findings=[
            finding(file=f"f{n}.py", line=n + 1, value=v, verification_error=True)
            for n, v in enumerate(values)
        ]
    )
    result = run_cli(
        *multi_scan_args(tmp_path), runner=FakeGitleaks(), tool_runners={"trufflehog": hog}
    )

    shown = result.out + result.err + json.dumps(result.report)
    assert len(result.findings) == 3
    assert [visible(v, shown) for v in values] == [False, False, False]


def test_a_trufflehog_crash_fails_the_scan_with_exit_2(run_cli, tmp_path: Path) -> None:
    hog = FakeTruffleHog(exit_code=2)
    result = run_cli(
        *multi_scan_args(tmp_path), runner=FakeGitleaks(), tool_runners={"trufflehog": hog}
    )

    assert result.exit_code == 2
    assert result.report["status"] == "error"
    assert "findings" not in result.report  # never mistaken for a clean scan
    assert "TruffleHog failed (exit code 2)" in result.err


def test_a_missing_trufflehog_fails_the_scan_with_exit_2(run_cli, tmp_path: Path) -> None:
    hog = FakeTruffleHog(missing=True)
    result = run_cli(
        *multi_scan_args(tmp_path), runner=FakeGitleaks(), tool_runners={"trufflehog": hog}
    )
    assert (result.exit_code, result.report["status"]) == (2, "error")
    assert "TruffleHog was not found" in result.err


def test_trufflehog_is_skipped_on_files_without_history(run_cli, tmp_path: Path) -> None:
    hog = FakeTruffleHog()
    result = run_cli(
        *multi_scan_args(tmp_path, mode="dir"),
        runner=FakeGitleaks(),
        tool_runners={"trufflehog": hog},
    )
    (_, trufflehog_run) = result.report["scanners"]
    assert result.exit_code == 0
    assert (trufflehog_run["status"], trufflehog_run["required"]) == ("skipped", True)
    assert hog.calls == []


def test_no_verification_is_passed_on_and_recorded(run_cli, tmp_path: Path) -> None:
    hog = FakeTruffleHog(findings=[finding(file="a.py", line=1, value=random_text(30))])
    result = run_cli(
        *multi_scan_args(tmp_path, "--no-verification"),
        runner=FakeGitleaks(),
        tool_runners={"trufflehog": hog},
    )
    assert "--no-verification" in hog.scan_args
    assert result.findings[0]["validity"] == "not_checked"
    assert "switched off" in result.report["scanners"][1]["note"]


@pytest.mark.parametrize(
    ("scanners", "message"),
    [
        ("trufflehog", "must include gitleaks"),
        ("gitleaks,truffelhog", "did you mean 'trufflehog'"),
    ],
)
def test_bad_scanner_lists_are_refused(
    run_cli, tmp_path: Path, scanners: str, message: str
) -> None:
    result = run_cli(*multi_scan_args(tmp_path, scanners=scanners), runner=FakeGitleaks())
    assert result.exit_code == 2
    assert message in result.err


def test_gitleaks_alone_stays_the_default(run_cli, tmp_path: Path) -> None:
    hog = FakeTruffleHog()
    result = run_cli(*scan_args(tmp_path), runner=FakeGitleaks(), tool_runners={"trufflehog": hog})
    assert result.exit_code == 0
    assert hog.calls == []
    assert [s["name"] for s in result.report["scanners"]] == ["gitleaks"]
    assert "Scanners:" not in result.out
