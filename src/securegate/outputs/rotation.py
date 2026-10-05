"""The rotation checklist for a blocked key, by provider. Pure: it only reads the finding.

A blocked key is treated as leaked: revoke it, create a new one, keep the new one in a secret
manager, read it from the environment, and confirm that the old one is dead. The provider is
recognised from the scanner rule or from the first four characters of the masked value (the
only part of a key that SecureGate ever shows).
"""

from dataclasses import dataclass

from securegate.ui.fixes import REVOKE_ANYWHERE, REVOKE_AT
from securegate.ui.report_view import FindingView


@dataclass(frozen=True)
class Provider:
    title: str  # what the key is, for the heading: "a Stripe key"
    revoke: str  # the first step: where and how to revoke it
    env: str  # the environment variable the code should read instead
    confirm: str  # how to see that the old key no longer works


ACME = Provider(
    title="an ACME Pay key",
    revoke=f"Revoke the key at ACME Pay. {REVOKE_AT['acme-pay-token']}",
    env="ACME_PAY_API_KEY",
    confirm="In the ACME Pay dashboard, the old key shows as revoked.",
)
STRIPE = Provider(
    title="a Stripe key",
    revoke=f"Revoke the key at Stripe. {REVOKE_AT['stripe-access-token']}",
    env="STRIPE_SECRET_KEY",
    confirm="In the Stripe Dashboard, the old key is no longer listed under Developers > API keys.",
)
AWS = Provider(
    title="an AWS key",
    revoke=f"Revoke the key at AWS. {REVOKE_AT['aws-access-token']}",
    env="AWS_ACCESS_KEY_ID",
    confirm="In IAM > Users > Security credentials, the old access key is deleted.",
)
GITHUB = Provider(
    title="a GitHub token",
    revoke=f"Revoke the token at GitHub. {REVOKE_AT['github-pat']}",
    env="GITHUB_TOKEN",
    confirm="In Settings > Developer settings, the old token is no longer listed.",
)
PRIVATE_KEY = Provider(
    title="a private key",
    revoke=f"Revoke the key. {REVOKE_AT['private-key']}",
    env="DEPLOY_PRIVATE_KEY",
    confirm="Connecting with the old key is refused everywhere it used to work.",
)
GENERIC = Provider(
    title="a secret",
    revoke=f"Revoke the secret. {REVOKE_ANYWHERE}",
    env="SECRET_NAME",
    confirm="Try the old secret once where it was used: it must now be refused.",
)

_RULE_WORDS = (
    (ACME, "acme"),
    (STRIPE, "stripe"),
    (AWS, "aws"),
    (GITHUB, "github"),
    (PRIVATE_KEY, "private"),
)
_STARTS = (
    (ACME, ("acme",)),
    (STRIPE, ("sk_l", "rk_l", "sk_t", "rk_t")),
    (AWS, ("AKIA", "ASIA", "ABIA", "ACCA", "ABSK", "bedr")),
    (GITHUB, ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "gith")),
    (PRIVATE_KEY, ("----",)),
)


def provider_for(finding: FindingView) -> Provider:
    """ACME Pay, Stripe, AWS, GitHub or a private key, when the rule or the masked value says
    so; otherwise the generic checklist."""
    rule = finding.rule.lower()
    for provider, word in _RULE_WORDS:
        if word in rule:
            return provider
    start = finding.masked_value[:4]
    for provider, starts in _STARTS:
        if start in starts:
            return provider
    return GENERIC
