"""The Finding: one detected secret, safe to print, store and share.

A Finding never holds the raw value. It can only be built from a MaskedSecret, and only
securegate.mask.protect() can create one, so every Finding has gone through the masking step.
"""

from dataclasses import dataclass
from typing import Literal

from securegate.mask import MaskedSecret

Decision = Literal["block", "warn", "ignore"]
Severity = Literal["critical", "high", "medium", "low", "info"]
# Is the key live? Only TruffleHog asks the provider: "verified" = it works right now, "unknown" =
# the check failed with an error, "unverified" = found but not confirmed live, "not_checked" =
# nobody asked (other scanners, or verification switched off). Strongest first.
Validity = Literal["verified", "unknown", "unverified", "not_checked"]

DECISIONS: tuple[Decision, ...] = ("block", "warn", "ignore")
SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")
VALIDITIES: tuple[Validity, ...] = ("verified", "unknown", "unverified", "not_checked")


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    """One finding. `secret` carries the masked value and the fingerprint."""

    secret: MaskedSecret
    rule: str  # scanner rule that matched, e.g. "aws-access-token"
    detector: str  # scanner that found it first, e.g. "gitleaks"
    file: str  # path relative to the scanned folder, "/" separators
    line: int  # line where the value starts
    commit: str | None  # commit that added it; None when scanning files on disk
    author: str | None
    date: str | None
    entropy: float  # Shannon entropy of the raw value, bits per character
    confidence: float  # 0 to 1: how sure we are that this is a real secret
    severity: Severity
    decision: Decision
    reason: str  # which policy rule decided, and why
    remediation: str  # what to do next
    detectors: tuple[str, ...] = ()  # every scanner that found it; empty means (detector,)
    validity: Validity = "not_checked"
    matched_rule: str = ""  # the policy rule that decided, e.g. "rule 8: provider-keys"

    def __post_init__(self) -> None:
        if not isinstance(self.secret, MaskedSecret):
            raise TypeError(
                "a Finding needs a MaskedSecret from securegate.mask.protect(), never a raw value"
            )
        if self.decision not in DECISIONS:
            raise ValueError(f"unknown decision {self.decision!r}; use one of {DECISIONS}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}; use one of {SEVERITIES}")
        if self.validity not in VALIDITIES:
            raise ValueError(f"unknown validity {self.validity!r}; use one of {VALIDITIES}")
        if not self.detectors:
            object.__setattr__(self, "detectors", (self.detector,))

    @property
    def id(self) -> str:
        return self.secret.id

    @property
    def masked_value(self) -> str:
        return self.secret.masked

    @property
    def fingerprint(self) -> str:
        return self.secret.fingerprint

    def to_dict(self) -> dict[str, object]:
        """The Finding as JSON-ready data, fields in the documented order."""
        return {
            "id": self.id,
            "rule": self.rule,
            "detector": self.detector,
            "detectors": list(self.detectors),
            "file": self.file,
            "line": self.line,
            "commit": self.commit,
            "author": self.author,
            "date": self.date,
            "masked_value": self.masked_value,
            "fingerprint": self.fingerprint,
            "entropy": round(self.entropy, 3),
            "confidence": round(self.confidence, 2),
            "validity": self.validity,
            "severity": self.severity,
            "decision": self.decision,
            "matched_rule": self.matched_rule,
            "reason": self.reason,
            "remediation": self.remediation,
        }
