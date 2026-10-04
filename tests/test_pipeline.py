"""The pipeline: raw candidates in, masked and fingerprinted Findings out.

Convention: raw test values never appear inside an assert.
"""

import json

import pytest

from helpers import POLICY_FILE, fake_aws_key_id, fake_stripe_key, random_key, random_text
from securegate import confidence
from securegate.entropy import shannon_entropy
from securegate.mask import fingerprint, mask_value
from securegate.pipeline import build_findings
from securegate.policy import Policy, load_policy
from securegate.scanners.gitleaks import Candidate


@pytest.fixture(scope="module")
def policy() -> Policy:
    return load_policy(POLICY_FILE)


def candidate(rule_id: str, file: str, value: str, line: int = 1) -> Candidate:
    return Candidate(
        rule_id=rule_id, file=file, line=line, commit=None, author=None, date=None, value=value
    )


def test_candidates_become_masked_findings_with_policy_verdicts(policy: Policy) -> None:
    key, aws = random_key(), fake_aws_key_id()
    expected = (mask_value(aws), fingerprint(aws, key), shannon_entropy(aws))

    (finding,) = build_findings([candidate("aws-access-token", "app/b.py", aws)], policy, key)

    assert (finding.masked_value, finding.fingerprint) == expected[:2]
    assert finding.entropy == pytest.approx(expected[2])
    assert (finding.rule, finding.decision, finding.severity) == (
        "aws-access-token",
        "block",
        "high",
    )
    assert finding.reason.startswith("provider-keys: ")
    assert finding.matched_rule == "rule 8: provider-keys"
    assert finding.confidence == 0.9
    assert finding.detector == "gitleaks"


def test_no_raw_value_survives_in_findings(policy: Policy) -> None:
    values = [fake_aws_key_id(), random_text(40), random_text(8)]
    candidates = [
        candidate("aws-access-token", "app/a.py", values[0]),
        candidate("generic-api-key", "app/b.py", values[1]),
        candidate("generic-api-key", "tests/c.py", values[2]),
    ]
    findings = build_findings(candidates, policy, random_key())
    dumped = json.dumps([f.to_dict() for f in findings]) + repr(findings)
    leaked_positions = [i for i, value in enumerate(values) if value in dumped]
    assert leaked_positions == []


def test_findings_are_sorted_block_then_warn_then_ignore(policy: Policy) -> None:
    candidates = [
        candidate("generic-api-key", "b.py", "x" * 20),  # placeholder: ignore
        candidate("generic-api-key", "a.py", random_text(30)),  # warn
        candidate("stripe-access-token", "z.py", fake_stripe_key()),  # live format: block
    ]
    findings = build_findings(candidates, policy, random_key())
    assert [f.decision for f in findings] == ["block", "warn", "ignore"]


@pytest.mark.parametrize(
    ("rule_id", "entropy", "expected"),
    [
        ("stripe-access-token", 1.0, 0.9),
        ("aws-access-token", 5.0, 0.9),
        ("generic-api-key", 3.0, 0.5),
        ("generic-api-key", 4.5, 0.75),
        ("generic-api-key", 6.0, 0.8),
        ("generic-api-key", 0.0, 0.0),
    ],
)
def test_confidence_rule(rule_id: str, entropy: float, expected: float) -> None:
    assert confidence.estimate(rule_id, entropy) == expected
