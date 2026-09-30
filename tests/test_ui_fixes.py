"""'How to fix' advice, one finding at a time."""

from dataclasses import replace

import pytest

from securegate.ui.fixes import how_to_fix
from securegate.ui.report_view import FindingView

BLOCKED = FindingView(
    id="0123456789ab",
    rule="stripe-access-token",
    detector="gitleaks",
    file="payments/stripe_client.py",
    line=5,
    commit="0" * 40,
    author="Riya Demo",
    date="2025-06-05T09:00:00Z",
    masked_value="sk_l****abcd",
    fingerprint="0123456789ab" + "0" * 52,
    entropy=4.5,
    confidence=0.9,
    severity="critical",
    decision="block",
    reason="provider-keys: A payment, cloud or private key gives direct access.",
    remediation="Treat it as leaked.",
)


def test_a_real_key_is_revoked_replaced_stored_then_removed() -> None:
    fix = how_to_fix(BLOCKED)
    starts = (
        "Revoke it at the provider.",
        "Create a new key.",
        "Store the new one in a secret manager",
        "Remove the old one from the code.",
    )
    in_order = [step.startswith(start) for step, start in zip(fix.steps, starts, strict=True)]
    assert in_order == [True, True, True, True]
    assert "Stripe Dashboard" in fix.steps[0]


@pytest.mark.parametrize(
    ("rule", "where"),
    [
        ("aws-access-token", "IAM"),
        ("github-pat", "Personal access tokens"),
        ("acme-pay-token", "ACME Pay dashboard"),
        ("private-key", "public half"),
        ("some-new-provider-token", "provider's dashboard or admin page"),
    ],
)
def test_revoke_advice_names_the_right_place(rule: str, where: str) -> None:
    assert where in how_to_fix(replace(BLOCKED, rule=rule)).steps[0]


def test_a_private_key_is_replaced_by_a_new_key_pair() -> None:
    assert how_to_fix(replace(BLOCKED, rule="private-key")).steps[1] == "Create a new key pair."


def test_history_is_mentioned_only_when_there_is_a_commit() -> None:
    assert "Git history" in how_to_fix(BLOCKED).steps[-1]
    assert "Git history" not in how_to_fix(replace(BLOCKED, commit=None)).steps[-1]


def test_a_test_key_warning_explains_the_folder() -> None:
    warned = replace(
        BLOCKED,
        decision="warn",
        file="tests/fixtures/stripe.json",
        reason="tests-fixtures-docs: Found in tests, fixtures or docs.",
    )
    fix = how_to_fix(warned)
    assert fix.summary.startswith("Why it is only a warning")
    assert "tests, fixtures or docs folder" in fix.summary
    assert fix.steps[-1].startswith("If it is real, treat it like a blocked secret")


def test_a_generic_warning_asks_to_check_it() -> None:
    warned = replace(BLOCKED, decision="warn", reason="everything-else: A possible secret.")
    fix = how_to_fix(warned)
    assert "no specific rule in the policy covers it" in fix.summary
    assert fix.steps[0].startswith("Check whether it is a real secret")


def test_a_placeholder_is_explained_not_fixed() -> None:
    ignored = replace(
        BLOCKED,
        decision="ignore",
        reason="placeholders: The value looks like a placeholder.",
    )
    fix = how_to_fix(ignored)
    assert fix.summary == (
        "Why it is ignored: the policy rule “placeholders” matched. "
        "The value looks like a placeholder."
    )
    assert fix.steps[0] == "Nothing needs to be done."
