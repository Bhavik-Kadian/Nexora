"""Shared pytest setup."""

import secrets

import pytest

from securegate.mask import KEY_ENV_VAR


@pytest.fixture(autouse=True)
def _fresh_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test its own random fingerprint key, so no test creates .securegate/ here."""
    monkeypatch.setenv(KEY_ENV_VAR, secrets.token_hex(32))
