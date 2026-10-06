"""Fake ACME Pay tokens, for showing the merge gate in a public repository.

ACME Pay is SecureGate's invented payment provider, so these tokens unlock nothing, and GitHub's
push protection does not know their format. SecureGate's own rule, acme-pay-token, blocks them.
"""

import secrets
import string

PREFIX = "acme_" + "live_"
TEST_PREFIX = "acme_" + "test_"
ALPHABET = string.ascii_letters + string.digits
LENGTH = 32


def new_demo_token() -> str:
    """A fresh, random, fake ACME Pay token: acme_live_ and 32 letters and digits."""
    return PREFIX + _random_part()


def new_test_token() -> str:
    """A fresh, random, fake ACME Pay test-mode token: acme_test_ and 32 letters and digits."""
    return TEST_PREFIX + _random_part()


def _random_part() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
