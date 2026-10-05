"""Merging findings of the same secret or line (securegate.merge), with hand-made Findings.

Convention: raw test values never appear inside an assert; masks and fields are compared.
"""

from helpers import random_key, random_text
from securegate.finding import Decision, Finding, Severity, Validity
from securegate.mask import mask_value, protect
from securegate.merge import merge_findings

KEY = random_key()
COMMIT = "c" * 40


def make(
    detector: str,
    *,
    value: str | None = None,
    file: str = "app/pay.py",
    line: int = 3,
    commit: str | None = COMMIT,
    rule: str | None = None,
    decision: Decision = "warn",
    severity: Severity = "medium",
    validity: Validity = "not_checked",
    matched_rule: str = "rule 14: everything-else",
    confidence: float = 0.5,
) -> Finding:
    code_scanner = detector in ("semgrep", "bandit")
    return Finding(
        secret=protect(value if value is not None else random_text(30), KEY),
        rule=rule or f"{detector}-rule",
        detector=detector,
        file=file,
        line=line,
        commit=None if code_scanner else commit,
        author=None,
        date=None,
        entropy=4.0,
        confidence=confidence,
        severity=severity,
        decision=decision,
        reason=f"{matched_rule}: why",
        remediation=f"fix for {matched_rule}",
        validity=validity,
        matched_rule=matched_rule,
    )


def test_the_same_key_from_both_secret_scanners_becomes_one_finding() -> None:
    value = random_text(32)
    gitleaks = make(
        "gitleaks",
        value=value,
        rule="stripe-access-token",
        decision="block",
        severity="high",
        matched_rule="rule 8: provider-keys",
        confidence=0.9,
    )
    hog = make(
        "trufflehog",
        value=value,
        rule="trufflehog-stripe",
        decision="block",
        severity="critical",
        validity="verified",
        matched_rule="rule 1: verified-live",
        confidence=1.0,
    )

    (merged,) = merge_findings([hog, gitleaks])

    assert merged.detectors == ("gitleaks", "trufflehog")
    assert (merged.rule, merged.detector) == ("stripe-access-token", "gitleaks")
    assert (merged.decision, merged.severity, merged.validity) == ("block", "critical", "verified")
    assert merged.matched_rule == "rule 1: verified-live"
    assert merged.remediation == "fix for rule 1: verified-live"
    assert merged.confidence == 1.0
    assert merged.masked_value == mask_value(value)


def test_trufflehog_line_numbers_may_drift_by_a_little() -> None:
    value = random_text(32)
    merged = merge_findings(
        [make("gitleaks", value=value, line=3), make("trufflehog", value=value, line=4)]
    )
    assert [(f.line, f.detectors) for f in merged] == [(3, ("gitleaks", "trufflehog"))]


def test_two_different_keys_on_one_line_stay_two_findings() -> None:
    merged = merge_findings([make("gitleaks"), make("gitleaks")])
    assert len(merged) == 2


def test_the_same_key_in_two_commits_or_files_stays_apart() -> None:
    value = random_text(32)
    merged = merge_findings(
        [
            make("gitleaks", value=value),
            make("gitleaks", value=value, commit="d" * 40),
            make("gitleaks", value=value, file="other.py"),
        ]
    )
    assert len(merged) == 3


def test_the_same_finding_twice_from_one_scanner_is_reported_once() -> None:
    value = random_text(32)
    merged = merge_findings(
        [
            make("gitleaks", value=value, rule="generic-api-key"),
            make("gitleaks", value=value, rule="acme-pay-token"),
        ]
    )
    assert [(f.rule, f.detectors) for f in merged] == [("acme-pay-token", ("gitleaks",))]


def test_bandit_joins_the_secret_on_its_line_instead_of_a_finding_of_its_own() -> None:
    value = random_text(32)
    secret = make(
        "gitleaks", value=value, rule="generic-api-key", matched_rule="rule 10: hardcoded-passwords"
    )
    bandit = make(
        "bandit",
        rule="bandit-B105",
        decision="warn",
        severity="medium",
        matched_rule="rule 10: hardcoded-passwords",
    )

    (merged,) = merge_findings([bandit, secret])

    assert merged.detectors == ("gitleaks", "bandit")
    assert (merged.detector, merged.commit) == ("gitleaks", COMMIT)
    assert merged.masked_value == mask_value(value)  # the secret scanner's value is shown


def test_the_strongest_decision_wins_with_its_rule() -> None:
    secret = make(
        "gitleaks", decision="ignore", severity="info", matched_rule="rule 3: placeholders"
    )
    semgrep = make(
        "semgrep",
        rule="securegate-getenv-default",
        decision="warn",
        severity="low",
        matched_rule="rule 13: risky-handling",
    )

    (merged,) = merge_findings([secret, semgrep])

    assert (merged.decision, merged.matched_rule) == ("warn", "rule 13: risky-handling")
    assert merged.severity == "low"  # the highest of info and low


def test_code_findings_on_a_line_without_a_secret_merge_with_each_other() -> None:
    merged = merge_findings([make("bandit", line=9), make("semgrep", line=9)])
    assert [(f.detectors, f.commit, f.line) for f in merged] == [(("semgrep", "bandit"), None, 9)]


def test_code_findings_on_other_lines_stay_apart() -> None:
    merged = merge_findings([make("gitleaks", line=3), make("bandit", line=4)])
    assert sorted(f.detectors for f in merged) == [("bandit",), ("gitleaks",)]


def test_a_code_finding_joins_every_secret_on_its_line() -> None:
    merged = merge_findings([make("gitleaks"), make("gitleaks"), make("bandit")])
    assert [f.detectors for f in merged] == [("gitleaks", "bandit"), ("gitleaks", "bandit")]


def test_nothing_in_nothing_out() -> None:
    assert merge_findings([]) == []
