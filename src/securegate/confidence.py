"""Confidence: a 0-to-1 score for "how sure are we that this is a real secret".

v0.1 uses a deliberately simple rule. A later milestone replaces it with a learned model, so
keep the signature estimate(rule_id, entropy) -> float. Confidence never decides anything:
only the policy engine decides block / warn / ignore.
"""

SPECIFIC_RULE_CONFIDENCE = 0.9  # the rule matched a known key format (AWS, Stripe, ...)
GENERIC_CAP = 0.8  # a generic match is never as certain as a known format
ENTROPY_SCALE = 6.0  # a long random base64 string has about 6 bits of entropy per character
# Rules that match a word next to a value rather than a key format: Gitleaks' generic rule,
# Bandit's password checks, SecureGate's own Semgrep rules and p/secrets' password rules.
GENERIC_PREFIXES = (
    "generic",
    "bandit-",
    "securegate-",
    "hardcoded-",
    "detected-username-and-password",
    "detected-ssh-password",
)


def estimate(rule_id: str, entropy: float) -> float:
    """Known key formats score 0.9; generic matches score entropy / 6, capped at 0.8."""
    if not rule_id.startswith(GENERIC_PREFIXES):
        return SPECIFIC_RULE_CONFIDENCE
    return round(min(GENERIC_CAP, max(0.0, entropy / ENTROPY_SCALE)), 2)
