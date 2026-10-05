"""Candidate: one raw finding from a scanner, before masking. Only the pipeline may read `value`."""

from dataclasses import dataclass, field

from securegate.finding import Validity


@dataclass(frozen=True, slots=True)
class Candidate:
    """One raw finding. `value` is the raw secret: never print, log or store it."""

    rule_id: str
    file: str
    line: int
    commit: str | None
    author: str | None
    date: str | None
    value: str = field(repr=False)
    detector: str = "gitleaks"  # the scanner that found it
    validity: Validity = "not_checked"  # only TruffleHog checks whether a key is live
    code: bool = False  # `value` is the code that handles a secret, not a secret: show none of it
