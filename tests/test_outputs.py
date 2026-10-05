"""The outputs made from findings.json: the PR comment, the job summary and SARIF.

Reports are built with the real Finding, masking and envelope, written to disk and read back
through the dashboard's loader, exactly as `securegate scan --comment/--summary/--sarif` does.
Convention: raw test values never appear inside an assert; masks and counts do.
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from helpers import (
    fake_acme_token,
    fake_aws_key_id,
    fake_github_token,
    fake_private_key,
    fake_stripe_key,
    random_key,
    random_text,
)
from securegate.finding import Finding
from securegate.mask import mask_value, protect
from securegate.outputs import Targets, write_outputs
from securegate.outputs.markdown import (
    HISTORY_SENTENCE,
    MARKER,
    MAX_ROWS,
    render_comment,
    render_summary,
)
from securegate.outputs.sarif import build_sarif
from securegate.report import envelope, write_json
from securegate.scanners.common import ScannerRun
from securegate.ui.report_view import ReportView, load_report

KEY = random_key()
FOUR_RAN = [
    ScannerRun("gitleaks", "8.30.1", True, "ran"),
    ScannerRun("trufflehog", "3.97.9", True, "ran"),
    ScannerRun("semgrep", "1.179.0", False, "ran"),
    ScannerRun("bandit", "1.9.4", False, "ran"),
]


def make(
    value: str,
    *,
    rule: str,
    file: str = "app/pay.py",
    line: int = 3,
    decision: str = "block",
    severity: str = "high",
    matched_rule: str = "rule 8: provider-keys",
    detectors: tuple[str, ...] = ("gitleaks",),
    validity: str = "not_checked",
) -> Finding:
    name = matched_rule.split(": ", 1)[-1]
    return Finding(
        secret=protect(value, KEY),
        rule=rule,
        detector=detectors[0],
        file=file,
        line=line,
        commit="c" * 40,
        author="Riya Demo",
        date="2025-06-03T09:00:00Z",
        entropy=4.0,
        confidence=0.9,
        severity=severity,  # type: ignore[arg-type]
        decision=decision,  # type: ignore[arg-type]
        reason=f"{name}: why it matters",
        remediation="what to do",
        detectors=detectors,
        validity=validity,  # type: ignore[arg-type]
        matched_rule=matched_rule,
    )


def report(
    tmp_path: Path,
    findings: list[Finding],
    *,
    runs: list[ScannerRun] | None = None,
    log_range: str | None = None,
) -> ReportView:
    exit_code = 1 if any(f.decision == "block" for f in findings) else 0
    path = tmp_path / "findings.json"
    write_json(
        path,
        envelope(
            exit_code=exit_code,
            target=".",
            mode="range" if log_range else "repo",
            log_range=log_range,
            policy_path="policy.yaml",
            scanner_version="8.30.1",
            findings=findings,
            scanner_runs=runs if runs is not None else FOUR_RAN,
        ),
    )
    loaded = load_report(path)
    assert isinstance(loaded, ReportView)
    return loaded


def warning(n: int) -> Finding:
    return make(
        random_text(30),
        rule="generic-api-key",
        file=f"src/file{n}.py",
        decision="warn",
        severity="medium",
        matched_rule="rule 10: hardcoded-passwords",
    )


# --- the comment and the summary -------------------------------------------------------------


def test_the_comment_carries_the_hidden_marker_and_the_summary_does_not(tmp_path: Path) -> None:
    view = report(tmp_path, [warning(1)])
    assert render_comment(view).startswith(MARKER + "\n")
    assert MARKER not in render_summary(view)
    assert render_comment(view)[len(MARKER) + 1 :] == render_summary(view)


@pytest.mark.parametrize(
    ("findings", "verdict"),
    [
        (lambda: [make(fake_acme_token(), rule="acme-pay-token")], "BLOCKED (exit code 1)"),
        (lambda: [warning(1)], "PASSED WITH WARNINGS (exit code 0)"),
        (lambda: [], "PASSED (exit code 0)"),
    ],
)
def test_a_one_line_verdict_comes_first(
    tmp_path: Path, findings: Callable[[], list[Finding]], verdict: str
) -> None:
    text = render_summary(report(tmp_path, findings()))
    assert text.splitlines()[0] == f"### SecureGate: {verdict}"


def test_a_failed_scan_says_error_and_why(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    write_json(
        path,
        envelope(
            exit_code=2,
            target=".",
            mode="range",
            log_range="a..b",
            policy_path="policy.yaml",
            scanner_version=None,
            error="TruffleHog failed (exit code 2)",
        ),
    )
    text = render_comment(load_report(path))
    assert text.splitlines()[1] == "### SecureGate: ERROR"
    assert "TruffleHog failed (exit code 2)" in text
    assert "fails closed" in text


def test_the_table_shows_rule_place_mask_detectors_and_live_check(tmp_path: Path) -> None:
    key = fake_stripe_key()
    view = report(
        tmp_path,
        [
            make(
                key,
                rule="stripe-access-token",
                detectors=("gitleaks", "trufflehog"),
                validity="verified",
                severity="critical",
                matched_rule="rule 1: verified-live",
            )
        ],
    )
    lines = render_summary(view).splitlines()
    assert "| Decision | Rule | Where | Masked value | Found by | Live check |" in lines
    row = (
        f"| BLOCK | rule 1: verified-live | `app/pay.py:3` | `{mask_value(key)}` | "
        "Gitleaks, TruffleHog | Live: the provider confirmed it works |"
    )
    assert row in lines


PROVIDERS = [
    (fake_acme_token, "acme-pay-token", "an ACME Pay key", "ACME_PAY_API_KEY"),
    (fake_stripe_key, "trufflehog-stripe", "a Stripe key", "STRIPE_SECRET_KEY"),
    (fake_aws_key_id, "aws-access-token", "an AWS key", "AWS_ACCESS_KEY_ID"),
    (fake_github_token, "github-pat", "a GitHub token", "GITHUB_TOKEN"),
    (fake_private_key, "private-key", "a private key", "DEPLOY_PRIVATE_KEY"),
    (lambda: random_text(30), "generic-api-key", "a secret", "SECRET_NAME"),
]


def test_every_block_has_its_providers_checklist_and_the_history_sentence(tmp_path: Path) -> None:
    findings = [
        make(build(), rule=rule, file=f"f{n}.py") for n, (build, rule, _, _) in enumerate(PROVIDERS)
    ]
    text = render_comment(report(tmp_path, findings))

    sections = text.split("#### Fix ")[1:]
    assert len(sections) == len(PROVIDERS)
    for section, (_, _, title, env) in zip(sections, PROVIDERS, strict=True):
        assert f": {title} (" in section.splitlines()[0]
        for step in ("Revoke", "Create a new key", "secret manager", f'os.environ["{env}"]',
                     "Confirm that the old key no longer works"):  # fmt: skip
            assert step in section
        assert HISTORY_SENTENCE in section


def test_warnings_are_explained_and_ignored_findings_are_folded_away(tmp_path: Path) -> None:
    ignored = make(
        "YOUR_" + "API_KEY_HERE",
        rule="generic-api-key",
        decision="ignore",
        severity="info",
        matched_rule="rule 3: placeholders",
    )
    text = render_summary(report(tmp_path, [warning(1), ignored]))
    assert "#### Why these were not blocked" in text
    assert "`src/file1.py:3`" in text and "rule 10: hardcoded-passwords. why it matters" in text
    assert "<summary>Ignored: 1, because they are not secrets</summary>" in text
    assert "rule 3: placeholders. why it matters" in text


def test_a_scanner_that_did_not_run_shows_as_a_red_caution(tmp_path: Path) -> None:
    runs = [
        FOUR_RAN[0],
        ScannerRun("trufflehog", "3.97.9", True, "ran", "live checks switched off"),
        ScannerRun("semgrep", None, False, "did_not_run", "it failed (exit code 2)"),
        ScannerRun("bandit", None, False, "skipped", "it only scans the code of a commit"),
    ]
    text = render_summary(report(tmp_path, [warning(1)], runs=runs))
    assert "> [!CAUTION]\n> **Semgrep did not run**: it failed (exit code 2)." in text
    assert "Bandit was skipped: it only scans the code of a commit." in text
    assert "Note: TruffleHog: live checks switched off." in text
    assert "with Gitleaks 8.30.1 and TruffleHog 3.97.9, using `policy.yaml`" in text


def test_the_scope_names_every_scanner_that_ran(tmp_path: Path) -> None:
    text = render_summary(report(tmp_path, [], log_range=f"{'a' * 40}..{'b' * 40}"))
    assert (
        "Scanned every commit in `aaaaaaa..bbbbbbb` with Gitleaks 8.30.1, TruffleHog 3.97.9, "
        "Semgrep 1.179.0 and Bandit 1.9.4, using `policy.yaml`." in text
    )
    assert "No secrets found." in text


def test_long_reports_are_cut_to_stay_under_githubs_limit(tmp_path: Path) -> None:
    text = render_summary(report(tmp_path, [warning(n) for n in range(MAX_ROWS + 10)]))
    rows = [line for line in text.splitlines() if line.startswith("| WARN |")]
    assert len(rows) == MAX_ROWS
    assert "And 10 more: see `findings.json` in the workflow run's artifacts." in text


def test_file_names_cannot_break_the_table_or_add_html(tmp_path: Path) -> None:
    sneaky = make(random_text(30), rule="generic-api-key", file="a|b`c<script>.py",
                  decision="warn", severity="medium")  # fmt: skip
    text = render_summary(report(tmp_path, [sneaky]))
    assert "`a\\|b'c&lt;script&gt;.py:3`" in text
    assert "<script>" not in text


# --- SARIF ----------------------------------------------------------------------------------


def test_sarif_holds_blocks_and_warnings_with_the_policy_rules(tmp_path: Path) -> None:
    key = fake_acme_token()
    ignored = make(random_text(30), rule="generic-api-key", decision="ignore", severity="info",
                   matched_rule="rule 3: placeholders")  # fmt: skip
    view = report(tmp_path, [make(key, rule="acme-pay-token"), warning(1), warning(2), ignored])

    sarif = build_sarif(view)

    (run,) = sarif["runs"]
    assert (sarif["version"], run["tool"]["driver"]["name"]) == ("2.1.0", "SecureGate")
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"rule-8-provider-keys", "rule-10-hardcoded-passwords"}
    assert rules["rule-8-provider-keys"]["properties"]["security-severity"] == "8.0"
    levels = [(r["ruleId"], r["level"]) for r in run["results"]]
    assert levels == [
        ("rule-8-provider-keys", "error"),
        ("rule-10-hardcoded-passwords", "warning"),
        ("rule-10-hardcoded-passwords", "warning"),
    ]
    block = run["results"][0]
    assert mask_value(key) in block["message"]["text"]
    location = block["locations"][0]["physicalLocation"]
    assert (location["artifactLocation"]["uri"], location["region"]["startLine"]) == (
        "app/pay.py",
        3,
    )


def test_outputs_are_written_and_a_failed_scan_removes_old_sarif(tmp_path: Path) -> None:
    view = report(tmp_path, [warning(1)])
    targets = Targets(
        sarif=tmp_path / "out.sarif", summary=tmp_path / "sum.md", comment=tmp_path / "c.md"
    )
    write_outputs(view.path, targets, finished=True)
    assert json.loads(targets.sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert targets.comment.read_text(encoding="utf-8").startswith(MARKER)

    write_json(
        view.path,
        envelope(exit_code=2, target=".", mode="repo", log_range=None,
                 policy_path="policy.yaml", scanner_version=None, error="boom"),
    )  # fmt: skip
    write_outputs(view.path, targets, finished=False)
    assert not targets.sarif.exists()  # never a stale "all clear" for GitHub
    assert "### SecureGate: ERROR" in targets.summary.read_text(encoding="utf-8")
