"""Charges a customer through ACME Pay (SecureGate's invented payment provider)."""

ACME_PAY_API_KEY = "acme_live_1Cj4M5CpxYCmiABcbbpH2RWdJfQfJuTc"


def charge(amount_cents: int) -> dict[str, object]:
    return {"amount": amount_cents, "currency": "eur", "key_set": bool(ACME_PAY_API_KEY)}
