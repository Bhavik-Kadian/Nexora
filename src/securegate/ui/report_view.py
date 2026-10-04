"""Reading findings.json for the dashboard.

load_report() returns a ReportView when the file is a usable SecureGate report, or a
ReportProblem when it is missing, broken or from a failed scan; the dashboard shows a problem
as a friendly page with the exact command that creates a report. Every masked value is checked
again here, so a report that somehow holds an unmasked value is refused, never displayed.
"""

import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from securegate.finding import DECISIONS, SEVERITIES, VALIDITIES

SCHEMA_VERSION = 1
# How the dashboard and the reports say what TruffleHog's live check found.
LIVE_CHECK = {
    "verified": "Live: the provider confirmed it works",
    "unknown": "Unknown: the live check failed",
    "unverified": "Not confirmed live",
    "not_checked": "Not checked",
}
MASKED_VALUE = re.compile(r"\*{4}|[ -~]{4}\*{4}[ -~]{4}")  # what mask.mask_value() produces
FINDING_ID = re.compile(r"[0-9a-f]{12}")
DECISION_ORDER = {decision: position for position, decision in enumerate(DECISIONS)}
RESULTS = {0: "PASS", 1: "BLOCKED", 2: "ERROR"}
MODE_DESCRIPTIONS = {
    "repo": "The whole Git history",
    "range": "A range of commits",
    "staged": "Changes staged for commit",
    "dir": "Files on disk",
}
TEXT_FIELDS = (
    "id",
    "rule",
    "detector",
    "file",
    "masked_value",
    "fingerprint",
    "severity",
    "decision",
    "reason",
    "remediation",
)
OPTIONAL_TEXT_FIELDS = ("commit", "author", "date")
NUMBER_FIELDS = ("entropy", "confidence")


@dataclass(frozen=True)
class Field:
    """One field of a finding, for the detail page."""

    label: str
    key: str  # the name in findings.json
    value: str | None  # None: not recorded, for example no commit when files were scanned
    code: bool = False  # shown in the monospace font


@dataclass(frozen=True)
class FindingView:
    """One finding as the dashboard shows it (masked value only)."""

    id: str
    rule: str
    detector: str
    file: str
    line: int
    commit: str | None
    author: str | None
    date: str | None
    masked_value: str
    fingerprint: str
    entropy: float
    confidence: float
    severity: str
    decision: str
    reason: str
    remediation: str
    detectors: tuple[str, ...] = ()  # empty in reports from before Layer 2
    validity: str = "not_checked"
    matched_rule: str = ""  # "rule 8: provider-keys"; empty in reports from before Layer 2

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    @property
    def found_by(self) -> tuple[str, ...]:
        """Every scanner that found it, such as ("gitleaks", "trufflehog")."""
        return self.detectors or (self.detector,)

    @property
    def live_check(self) -> str:
        return LIVE_CHECK.get(self.validity, self.validity)

    @property
    def policy_rule(self) -> str:
        """The policy rule that decided: the reason starts with its name."""
        name, colon, _ = self.reason.partition(":")
        return name.strip() if colon else ""

    @property
    def reason_text(self) -> str:
        _, colon, text = self.reason.partition(":")
        return text.strip() if colon else self.reason

    def fields(self) -> list[Field]:
        """Every field, in findings.json order, with a label for people."""
        return [
            Field("Id", "id", self.id, code=True),
            Field("Rule", "rule", self.rule, code=True),
            Field("Detector", "detector", self.detector),
            Field("Found by", "detectors", ", ".join(self.found_by)),
            Field("File", "file", self.file, code=True),
            Field("Line", "line", str(self.line)),
            Field("Commit", "commit", self.commit, code=True),
            Field("Author", "author", self.author),
            Field("Date", "date", self.date),
            Field("Masked value", "masked_value", self.masked_value, code=True),
            Field("Fingerprint", "fingerprint", self.fingerprint, code=True),
            Field("Entropy", "entropy", f"{self.entropy:.3f} bits per character"),
            Field("Confidence", "confidence", f"{self.confidence:.2f} (0 to 1)"),
            Field("Live check", "validity", self.live_check),
            Field("Severity", "severity", self.severity),
            Field("Decision", "decision", self.decision),
            Field("Policy rule", "matched_rule", self.matched_rule or None, code=True),
            Field("Reason", "reason", self.reason),
            Field("Remediation", "remediation", self.remediation),
        ]


@dataclass(frozen=True)
class ReportView:
    path: Path
    status: str
    exit_code: int | None
    scanned_at: datetime | None
    target: str
    mode: str
    log_range: str | None
    scanner_version: str | None
    policy: str
    securegate_version: str
    findings: tuple[FindingView, ...]  # blocks first, then warnings, then ignored

    @property
    def result(self) -> str:
        return RESULTS.get(self.exit_code, "UNKNOWN") if self.exit_code is not None else "UNKNOWN"

    @property
    def mode_description(self) -> str:
        return MODE_DESCRIPTIONS.get(self.mode, self.mode)

    def count(self, decision: str | None = None) -> int:
        return len(self.filtered(decision))

    def filtered(self, decision: str | None) -> tuple[FindingView, ...]:
        return tuple(f for f in self.findings if decision is None or f.decision == decision)

    def severity_counts(self) -> list[tuple[str, int]]:
        counts = Counter(f.severity for f in self.findings)
        return [(severity, counts[severity]) for severity in SEVERITIES]

    def by_id(self, finding_id: str) -> list[FindingView]:
        """Every place this secret was found: the id names the secret, not the place."""
        return [f for f in self.findings if f.id == finding_id]


@dataclass(frozen=True)
class ReportProblem:
    path: Path
    title: str
    detail: str
    commands: tuple[str, ...]  # the exact commands that create a report at `path`


class _Unusable(Exception):
    """The file is JSON, but not a report the dashboard can show."""


def load_report(path: Path) -> ReportView | ReportProblem:
    commands = report_commands(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ReportProblem(
            path, "No scan report yet", f"There is no report at {path} yet.", commands
        )
    except (OSError, UnicodeDecodeError) as err:
        detail = f"{path} could not be read ({type(err).__name__})."
        return ReportProblem(path, "The scan report can't be read", detail, commands)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        detail = f"{path} is not valid JSON ({err.msg} at line {err.lineno})."
        return ReportProblem(path, "The scan report can't be read", detail, commands)
    if isinstance(data, dict) and data.get("status") == "error":
        detail = f"The scan stopped with an error: {data.get('error') or 'unknown error'}"
        return ReportProblem(path, "The last scan failed", detail, commands)
    try:
        return _report(path, data)
    except _Unusable as err:
        return ReportProblem(path, "This report can't be shown", str(err), commands)


def report_commands(path: Path) -> tuple[str, ...]:
    """The exact commands, run in the SecureGate folder, that create the report at `path`."""
    if path == Path("findings-demo.json"):
        return ("make demo", "make scan-demo")
    program = r".venv\Scripts\securegate" if os.name == "nt" else ".venv/bin/securegate"
    out = f'"{path}"' if " " in str(path) else str(path)
    return (f"{program} scan . --mode repo --out {out}",)


def _report(path: Path, data: object) -> ReportView:
    if not isinstance(data, dict) or data.get("tool") != "securegate":
        raise _Unusable(f"{path} is not a SecureGate findings report.")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise _Unusable(f"{path} was written by a different version of SecureGate.")
    raw_findings = data.get("findings")
    if not isinstance(raw_findings, list):
        raise _Unusable(f"{path} has no list of findings.")
    findings = [_finding(item, number) for number, item in enumerate(raw_findings, start=1)]
    findings.sort(key=lambda f: (DECISION_ORDER[f.decision], f.file, f.line, f.rule))
    scanner = data.get("scanner") if isinstance(data.get("scanner"), dict) else {}
    exit_code = data.get("exit_code")
    return ReportView(
        path=path,
        status=_text(data.get("status")) or "unknown",
        exit_code=exit_code
        if isinstance(exit_code, int) and not isinstance(exit_code, bool)
        else None,
        scanned_at=_time(data.get("scanned_at")),
        target=_text(data.get("target")) or "unknown",
        mode=_text(data.get("mode")) or "unknown",
        log_range=_text(data.get("range")),
        scanner_version=_text(scanner.get("version")),
        policy=_text(data.get("policy")) or "unknown",
        securegate_version=_text(data.get("version")) or "unknown",
        findings=tuple(findings),
    )


def _finding(item: object, number: int) -> FindingView:
    where = f"Finding #{number}"
    if not isinstance(item, dict):
        raise _Unusable(f"{where} is not an object.")
    for key in TEXT_FIELDS:
        if not isinstance(item.get(key), str):
            raise _Unusable(f"{where} has no '{key}'.")
    for key in OPTIONAL_TEXT_FIELDS:
        if item.get(key) is not None and not isinstance(item.get(key), str):
            raise _Unusable(f"{where} has an unexpected '{key}'.")
    for key in (*NUMBER_FIELDS, "line"):
        value = item.get(key)
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise _Unusable(f"{where} has no number for '{key}'.")
    if item["decision"] not in DECISIONS or item["severity"] not in SEVERITIES:
        raise _Unusable(f"{where} has an unknown decision or severity.")
    if not FINDING_ID.fullmatch(item["id"]):
        raise _Unusable(f"{where} has an id that is not 12 hexadecimal characters.")
    if not MASKED_VALUE.fullmatch(item["masked_value"]):
        raise _Unusable(
            f"{where} holds a value that is not masked, so the dashboard will not show this "
            "report. Scan again to write a new one."
        )
    detectors = item.get("detectors", [])
    if not isinstance(detectors, list) or not all(isinstance(d, str) and d for d in detectors):
        raise _Unusable(f"{where} has an unexpected 'detectors'.")
    validity = item.get("validity", "not_checked")
    if validity not in VALIDITIES:
        raise _Unusable(f"{where} has an unknown 'validity'.")
    matched_rule = item.get("matched_rule", "")
    if not isinstance(matched_rule, str):
        raise _Unusable(f"{where} has an unexpected 'matched_rule'.")
    return FindingView(
        id=item["id"],
        rule=item["rule"],
        detector=item["detector"],
        file=item["file"],
        line=int(item["line"]),
        commit=item.get("commit"),
        author=item.get("author"),
        date=item.get("date"),
        masked_value=item["masked_value"],
        fingerprint=item["fingerprint"],
        entropy=float(item["entropy"]),
        confidence=float(item["confidence"]),
        severity=item["severity"],
        decision=item["decision"],
        reason=item["reason"],
        remediation=item["remediation"],
        detectors=tuple(detectors),
        validity=validity,
        matched_rule=matched_rule,
    )


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None
