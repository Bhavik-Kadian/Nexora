"""All four scanners through the CLI, on a real Git repository, with scripted scanners.

Convention: raw test values never appear inside an assert; masks, fields and booleans do.
"""

import json
from pathlib import Path

from conftest import CliRun
from fake_code_scanners import FakeBandit, FakeSemgrep, Spot
from fake_gitleaks import FakeGitleaks, entry
from fake_trufflehog import FakeTruffleHog
from helpers import GitRepo, multi_scan_args, random_text
from securegate.mask import mask_value


def app_repo(repo: GitRepo) -> tuple[str, str]:
    """A commit with a password next to its name (line 2) and a logged token (line 4)."""
    password = "Pw-" + random_text(18)
    repo.write(
        "app.py",
        f'import os\nAPI_PASSWORD = "{password}"\ntoken = os.environ["T"]\nprint(token)\n',
    )
    return password, repo.commit("app")


def scanners(password: str, commit: str, **semgrep_options: object) -> dict[str, object]:
    return {
        "gitleaks": FakeGitleaks(
            report=[
                entry(rule="generic-api-key", file="app.py", line=2, value=password, commit=commit)
            ]
        ),
        "trufflehog": FakeTruffleHog(),
        "semgrep": FakeSemgrep(
            spots=[Spot("securegate-secret-logged", "app.py", "print(token)")], **semgrep_options
        ),
        "bandit": FakeBandit(spots=[Spot("B105", "app.py", password)]),
    }


def run_all(
    run_cli, repo: GitRepo, fakes: dict[str, object], *extra: str, mode: str = "repo"
) -> CliRun:
    return run_cli(
        *multi_scan_args(repo.path, *extra, mode=mode, scanners="all"),
        runner=fakes["gitleaks"],
        tool_runners={name: fakes[name] for name in ("trufflehog", "semgrep", "bandit")},
    )


def test_four_scanners_give_one_merged_verdict(run_cli, make_repo) -> None:
    repo = make_repo()
    password, commit = app_repo(repo)

    result = run_all(run_cli, repo, scanners(password, commit))

    by_line = {f["line"]: f for f in result.findings}
    assert result.exit_code == 0  # warnings only
    assert sorted(by_line) == [2, 4]
    assert by_line[2]["detectors"] == ["gitleaks", "bandit"]  # Bandit joined the secret's line
    assert (by_line[2]["matched_rule"], by_line[2]["masked_value"]) == (
        "rule 10: hardcoded-passwords",
        mask_value(password),
    )
    assert by_line[4]["detectors"] == ["semgrep"]
    assert (by_line[4]["matched_rule"], by_line[4]["severity"]) == (
        "rule 13: risky-handling",
        "low",
    )
    assert by_line[4]["masked_value"] == "****"  # code, not a secret: nothing of it is shown
    assert [(s["name"], s["status"], s["required"]) for s in result.report["scanners"]] == [
        ("gitleaks", "ran", True),
        ("trufflehog", "ran", True),
        ("semgrep", "ran", False),
        ("bandit", "ran", False),
    ]


def test_no_quoted_line_or_message_reaches_any_output(run_cli, make_repo) -> None:
    repo = make_repo()
    password, commit = app_repo(repo)

    result = run_all(run_cli, repo, scanners(password, commit))

    shown = result.out + result.err + json.dumps(result.report)
    assert len(result.findings) == 2
    leaked = password in shown or password[4:-4] in shown
    assert not leaked
    assert 'API_PASSWORD = "' not in shown  # Bandit's code and Semgrep's lines are dropped


def test_a_failing_optional_scanner_is_reported_and_the_scan_goes_on(run_cli, make_repo) -> None:
    repo = make_repo()
    password, commit = app_repo(repo)

    result = run_all(run_cli, repo, scanners(password, commit, exit_code=2))

    statuses = {s["name"]: (s["status"], s["note"]) for s in result.report["scanners"]}
    assert result.exit_code == 0
    assert statuses["semgrep"] == ("did_not_run", "it failed (exit code 2)")
    assert statuses["bandit"] == ("ran", None)
    assert [f["line"] for f in result.findings] == [2]  # Bandit's and Gitleaks' finding remain
    assert "Semgrep did not run: it failed (exit code 2)" in result.out


def test_a_missing_optional_scanner_is_reported_too(run_cli, make_repo) -> None:
    repo = make_repo()
    password, commit = app_repo(repo)
    fakes = scanners(password, commit)
    fakes["bandit"] = FakeBandit(missing=True)

    result = run_all(run_cli, repo, fakes)

    bandit_run = result.report["scanners"][3]
    assert result.exit_code == 0
    assert (bandit_run["status"], bandit_run["note"]) == (
        "did_not_run",
        "it is not installed (run `make scanners`)",
    )


def test_a_range_scan_reads_only_the_files_the_range_changed(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("old.py", "print(token)\n")
    base = repo.commit("old code")
    password, head = app_repo(repo)
    fakes = scanners(password, head)

    run_all(run_cli, repo, fakes, "--range", f"{base}..{head}", mode="range")

    # old.py is unchanged, so only app.py is copied (and SecureGate's own, empty .semgrepignore)
    assert fakes["semgrep"].seen == [[".semgrepignore", "app.py"]]


def test_code_scanners_are_skipped_for_files_on_disk(run_cli, make_repo) -> None:
    repo = make_repo()
    password, commit = app_repo(repo)
    fakes = scanners(password, commit)

    result = run_all(run_cli, repo, fakes, mode="dir")

    statuses = [(s["name"], s["status"]) for s in result.report["scanners"]]
    assert statuses[2:] == [("semgrep", "skipped"), ("bandit", "skipped")]
    assert fakes["semgrep"].calls == [] and fakes["bandit"].calls == []


def test_the_output_flags_write_the_comment_summary_and_sarif(
    run_cli, make_repo, tmp_path: Path
) -> None:
    repo = make_repo()
    password, commit = app_repo(repo)
    sarif, summary, comment = (tmp_path / n for n in ("gate.sarif", "summary.md", "comment.md"))

    result = run_all(
        run_cli, repo, scanners(password, commit),
        "--sarif", str(sarif), "--summary", str(summary), "--comment", str(comment),
    )  # fmt: skip

    assert result.exit_code == 0
    assert comment.read_text(encoding="utf-8").startswith("<!-- securegate:pr-comment -->")
    assert "### SecureGate: PASSED WITH WARNINGS" in summary.read_text(encoding="utf-8")
    results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert sorted(r["ruleId"] for r in results) == [
        "rule-10-hardcoded-passwords",
        "rule-13-risky-handling",
    ]


def test_a_failed_scan_writes_error_outputs_and_removes_old_sarif(
    run_cli, make_repo, tmp_path: Path
) -> None:
    repo = make_repo()
    password, commit = app_repo(repo)
    fakes = scanners(password, commit)
    fakes["trufflehog"] = FakeTruffleHog(exit_code=2)
    sarif, comment = tmp_path / "gate.sarif", tmp_path / "comment.md"
    sarif.write_text('{"stale": true}', encoding="utf-8")

    result = run_all(run_cli, repo, fakes, "--sarif", str(sarif), "--comment", str(comment))

    assert result.exit_code == 2
    assert not sarif.exists()  # an old "all clear" must not be uploaded
    text = comment.read_text(encoding="utf-8")
    assert "### SecureGate: ERROR" in text and "TruffleHog failed (exit code 2)" in text
