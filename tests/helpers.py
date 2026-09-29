"""Helpers shared by the tests. Test values are built at runtime; nothing key-shaped is stored."""

import secrets
import string

_ALPHABET = string.ascii_letters + string.digits


def random_text(length: int) -> str:
    """Fresh random letters and digits."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def random_key() -> bytes:
    """A fresh random fingerprint key."""
    return secrets.token_hex(32).encode("ascii")
