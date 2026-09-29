"""The scorecard: compare SecureGate's findings with the demo's ground_truth.csv.

Every planted line lands in exactly one bucket:
  hit             SecureGate decided what the catalog expected (for a decoy: silent or ignored)
  miss            a block/warn item that SecureGate did not report, or ignored
  wrong decision  reported, but blocked instead of warned (or the other way round)
  false alarm     a decoy that SecureGate blocked or warned about
Findings that match no planted line, and were blocked or warned about, are false alarms too.
"""

import csv
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

BUCKETS = {"hit": "hits", "miss": "misses", "wrong decision": "wrong decisions",
           "false alarm": "false alarms"}  # fmt: skip
STRENGTH = {"block": 2, "warn": 1, "ignore": 0}


@dataclass(frozen=True)
class TruthRow:
    file: str
    line: int
    commit: str
    kind: str
    is_secret: bool
    expected: str


@dataclass(frozen=True)
class Outcome:
    bucket: str
    what: str  # the planted kind, or the scanner rule for an unplanned finding
    location: str  # file:line
    expected: str | None  # None for an unplanned finding
    got: str | None  # SecureGate's decision; None when it reported nothing


@dataclass(frozen=True)
class Scorecard:
    outcomes: tuple[Outcome, ...]
    planted: int
    secrets: int

    def in_bucket(self, bucket: str) -> list[Outcome]:
        return [outcome for outcome in self.outcomes if outcome.bucket == bucket]

    def count(self, bucket: str) -> int:
        return len(self.in_bucket(bucket))


def read_ground_truth(path: Path) -> list[TruthRow]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [
            TruthRow(
                file=row["file"],
                line=int(row["line"]),
                commit=row["commit"],
                kind=row["kind"],
                is_secret=_is_true(row["is_secret"]),
                expected=row["expected"],
            )
            for row in csv.DictReader(handle)
        ]


def score(truth: Sequence[TruthRow], findings: Sequence[Mapping[str, object]]) -> Scorecard:
    """Match findings (as in findings.json) to planted lines by file and line, and by commit
    when the finding has one."""
    matched: set[int] = set()
    outcomes: list[Outcome] = []
    for row in truth:
        hits = [
            index
            for index, finding in enumerate(findings)
            if finding.get("file") == row.file
            and finding.get("line") == row.line
            and finding.get("commit") in (None, row.commit)
        ]
        matched.update(hits)
        decisions = [str(findings[index].get("decision")) for index in hits]
        got = max(decisions, key=lambda d: STRENGTH.get(d, 0), default=None)
        outcomes.append(
            Outcome(
                _bucket(row.expected, got), row.kind, f"{row.file}:{row.line}", row.expected, got
            )
        )
    for index, finding in enumerate(findings):
        decision = finding.get("decision")
        if index not in matched and decision in ("block", "warn"):
            location = f"{finding.get('file')}:{finding.get('line')}"
            what = f"unplanned {finding.get('rule')}"
            outcomes.append(Outcome("false alarm", what, location, None, str(decision)))
    return Scorecard(tuple(outcomes), planted=len(truth), secrets=sum(r.is_secret for r in truth))


def format_scorecard(card: Scorecard) -> str:
    """A plain-text scorecard for people: counts, then every problem with its location."""
    decoys = card.planted - card.secrets
    lines = [f"planted lines: {card.planted} ({card.secrets} secret, {decoys} decoy)"]
    for bucket, label in BUCKETS.items():
        outcomes = card.in_bucket(bucket)
        lines.append(f"  {label:<16} {len(outcomes)}")
        if bucket != "hit":
            lines.extend(
                f"      {o.what} at {o.location}: expected {o.expected or 'nothing'}, "
                f"got {o.got or 'nothing'}"
                for o in outcomes
            )
    return "\n".join(lines)


def _is_true(text: str) -> bool:
    return text.strip().lower() == "true"


def _bucket(expected: str, got: str | None) -> str:
    silent = got in (None, "ignore")
    if expected == "ignore":
        return "hit" if silent else "false alarm"
    if silent:
        return "miss"
    return "hit" if got == expected else "wrong decision"
