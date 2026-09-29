"""The Finding record: it can only be built from a MaskedSecret."""

import dataclasses
import json

import pytest

from helpers import random_key, random_text
from securegate.finding import Finding
from securegate.mask import protect

FIELD_ORDER = [
    "id",
    "rule",
    "detector",
    "file",
    "line",
    "commit",
    "author",
    "date",
    "masked_value",
    "fingerprint",
    "entropy",
    "confidence",
    "severity",
    "decision",
    "reason",
    "remediation",
]


def make_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "secret": protect(random_text(40), random_key()),
        "rule": "generic-api-key",
        "detector": "gitleaks",
        "file": "config/settings.py",
        "line": 12,
        "commit": "0" * 40,
        "author": "Riya Demo",
        "date": "2025-06-03T09:00:00Z",
        "entropy": 4.12345,
        "confidence": 0.6789,
        "severity": "medium",
        "decision": "warn",
        "reason": "everything-else: not covered by a more specific rule",
        "remediation": "Check whether it is a real secret.",
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


def test_a_raw_string_is_rejected() -> None:
    with pytest.raises(TypeError, match="MaskedSecret"):
        make_finding(secret=random_text(40))


def test_to_dict_has_the_documented_fields_in_order() -> None:
    assert list(make_finding().to_dict()) == FIELD_ORDER


def test_to_dict_is_json_ready_and_rounded() -> None:
    data = make_finding().to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["entropy"] == 4.123
    assert data["confidence"] == 0.68


def test_id_masked_value_and_fingerprint_come_from_the_masked_secret() -> None:
    secret = protect(random_text(40), random_key())
    finding = make_finding(secret=secret)
    assert (finding.id, finding.masked_value, finding.fingerprint) == (
        secret.id,
        secret.masked,
        secret.fingerprint,
    )


def test_raw_value_never_appears_in_repr_str_or_json() -> None:
    raw = random_text(40)
    finding = make_finding(secret=protect(raw, random_key()))
    visible = raw in repr(finding) or raw in str(finding) or raw in json.dumps(finding.to_dict())
    assert not visible


@pytest.mark.parametrize(("field", "value"), [("decision", "allow"), ("severity", "urgent")])
def test_unknown_decision_or_severity_is_rejected(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        make_finding(**{field: value})


def test_findings_are_immutable() -> None:
    finding = make_finding()
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.decision = "ignore"  # type: ignore[misc]
