"""'How to fix' advice for one finding, in plain words. Pure: it only reads the finding.

A blocked finding is treated as a real, leaked key: revoke it, replace it, keep the new one in a
secret manager, then remove it from the code. A warning or an ignored finding gets an
explanation of why it was not blocked, and what to do if it turns out to be real.
"""

from dataclasses import dataclass

from securegate.ui.report_view import FindingView


@dataclass(frozen=True)
class Fix:
    summary: str  # what this finding means, in one or two sentences
    steps: tuple[str, ...]  # what to do, in order


# Where to revoke a key, by scanner rule. Other rules get the general advice.
REVOKE_AT = {
    "stripe-access-token": (
        "In the Stripe Dashboard, open Developers > API keys and roll this key, which revokes it."
    ),
    "aws-access-token": (
        "In the AWS console, open IAM > Users > Security credentials, then deactivate and "
        "delete this access key."
    ),
    "aws-amazon-bedrock-api-key-long-lived": (
        "In the AWS console, open Amazon Bedrock > API keys and revoke this key."
    ),
    "aws-amazon-bedrock-api-key-short-lived": (
        "In the AWS console, open Amazon Bedrock > API keys and revoke this key."
    ),
    "github-pat": (
        "In GitHub, open Settings > Developer settings > Personal access tokens and delete "
        "this token."
    ),
    "github-fine-grained-pat": (
        "In GitHub, open Settings > Developer settings > Personal access tokens and delete "
        "this token."
    ),
    "github-oauth": "In GitHub, open Settings > Applications and revoke the app's access.",
    "github-app-token": "In the GitHub App's settings, revoke the token or rotate its keys.",
    "github-refresh-token": "In GitHub, revoke the app authorization that issued this token.",
    "acme-pay-token": (
        "In the ACME Pay dashboard, revoke this key. (ACME Pay is the invented provider used "
        "in SecureGate's demos.)"
    ),
    "private-key": (
        "Stop trusting this key: remove its public half from every server, deploy-key "
        "setting and certificate that accepts it."
    ),
}
REVOKE_ANYWHERE = "Revoke it where it was issued, in the provider's dashboard or admin page."
STORE_SAFELY = (
    "Store the new one in a secret manager, such as Azure Key Vault, AWS Secrets Manager or "
    "your CI system's secret settings, and have the app read it from there or from an "
    "environment variable."
)
IF_REAL = (
    "If it is real, treat it like a blocked secret: revoke it at the provider, create a new "
    "one, store it in a secret manager and remove it from the code."
)


def how_to_fix(finding: FindingView) -> Fix:
    if finding.decision == "ignore":
        return _ignored(finding)
    if finding.decision == "warn":
        return _warning(finding)
    return _real_secret(finding)


def _real_secret(finding: FindingView) -> Fix:
    remove = "Remove the old one from the code."
    if finding.commit:
        remove += (
            " It is also in the Git history, so deleting the line alone is not enough: "
            "revoking it in step 1 is what makes the copy in the history useless."
        )
    new_one = "Create a new key pair." if finding.rule == "private-key" else "Create a new key."
    return Fix(
        summary=(
            "This looks like a real secret. Anyone who can read the code, or its history, can "
            "use it, so treat it as leaked."
        ),
        steps=(
            f"Revoke it at the provider. {REVOKE_AT.get(finding.rule, REVOKE_ANYWHERE)}",
            new_one,
            STORE_SAFELY,
            remove,
        ),
    )


def _warning(finding: FindingView) -> Fix:
    if finding.policy_rule == "tests-fixtures-docs":
        return Fix(
            summary=(
                "Why it is only a warning: it was found in a tests, fixtures or docs folder, "
                "where fake values such as test keys are common. SecureGate reports it, but "
                "does not block it."
            ),
            steps=(
                "Check that the value is fake, for example a test-mode key or an example "
                "copied from documentation.",
                "If it is fake, nothing needs to be done. A placeholder such as YOUR_KEY_HERE "
                "makes that obvious to the next reader.",
                IF_REAL,
            ),
        )
    return Fix(
        summary=(
            "Why it is only a warning: it may be a secret, but no specific rule in the policy "
            "covers it. SecureGate reports it, but does not block it."
        ),
        steps=(
            "Check whether it is a real secret: a password, key or token that gives access "
            "to something.",
            "If it is not a secret, nothing needs to be done.",
            IF_REAL,
        ),
    )


def _ignored(finding: FindingView) -> Fix:
    rule = f"the policy rule “{finding.policy_rule}”" if finding.policy_rule else "the policy"
    return Fix(
        summary=f"Why it is ignored: {rule} matched. {finding.reason_text}",
        steps=(
            "Nothing needs to be done.",
            f"{IF_REAL} Then ask the team to fix the policy rule that let it through.",
        ),
    )
