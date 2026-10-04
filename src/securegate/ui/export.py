"""Downloads from the dashboard: the findings as CSV or JSON. Pure: it only reads the report.

Everything is built from the dashboard's ReportView, which has already refused any report that
holds a value that is not masked, so a download can only ever contain masked values. The JSON
download is itself a SecureGate report: the dashboard and `securegate summary` can read it.
"""

import csv
import io
import json
import re
from collections import Counter
from collections.abc import Sequence

from securegate.finding import DECISIONS
from securegate.ui.report_view import SCHEMA_VERSION, FindingView, ReportView

CSV_COLUMNS = (
    "decision",
    "severity",
    "rule",
    "file",
    "line",
    "masked_value",
    "policy_rule",
    "reason",
    "remediation",
    "commit",
    "author",
    "date",
    "confidence",
    "entropy",
    "detector",
    "id",
    "fingerprint",
)
# A spreadsheet program runs a cell that starts with one of these as a formula. Masked values
# such as ----****---- start with a dash, so such cells get an apostrophe in front: text again.
FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")
BYTE_ORDER_MARK = "﻿"  # tells Excel that the file is UTF-8
_UNSAFE_IN_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def findings_csv(findings: Sequence[FindingView]) -> str:
    """One row per finding, with a header row."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for finding in findings:
        writer.writerow([_cell(value) for value in _csv_row(finding)])
    return BYTE_ORDER_MARK + out.getvalue()


def findings_json(
    report: ReportView, findings: Sequence[FindingView], *, decision: str | None
) -> str:
    """The findings as a SecureGate report (schema version 1), with the scan's details, the
    totals of the findings it holds, and where they were exported from."""
    counts = Counter(finding.decision for finding in findings)
    data = {
        "tool": "securegate",
        "version": report.securegate_version,
        "schema_version": SCHEMA_VERSION,
        "status": report.status,
        "exit_code": report.exit_code,
        "scanned_at": (
            report.scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ") if report.scanned_at else None
        ),
        "target": report.target,
        "mode": report.mode,
        "range": report.log_range,
        "scanner": {"name": "gitleaks", "version": report.scanner_version},
        "policy": report.policy,
        "exported": {"from": report.path.name, "decision": decision},
        "summary": {"total": len(findings), **{d: counts[d] for d in DECISIONS}},
        "findings": [_json_finding(finding) for finding in findings],
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def download_name(report: ReportView, suffix: str, decision: str | None = None) -> str:
    """A file name for a download, such as findings-demo-block.csv: only safe characters."""
    stem = _UNSAFE_IN_NAME.sub("-", report.path.stem).strip("-.") or "findings"
    return f"{stem}-{decision}{suffix}" if decision else f"{stem}{suffix}"


def _csv_row(f: FindingView) -> tuple[object, ...]:
    return (
        f.decision,
        f.severity,
        f.rule,
        f.file,
        f.line,
        f.masked_value,
        f.policy_rule,
        f.reason_text,
        f.remediation,
        f.commit,
        f.author,
        f.date,
        f.confidence,
        f.entropy,
        f.detector,
        f.id,
        f.fingerprint,
    )


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_STARTS) else text


def _json_finding(f: FindingView) -> dict[str, object]:
    """One finding, with the keys and order of findings.json."""
    return {
        "id": f.id,
        "rule": f.rule,
        "detector": f.detector,
        "detectors": list(f.found_by),
        "file": f.file,
        "line": f.line,
        "commit": f.commit,
        "author": f.author,
        "date": f.date,
        "masked_value": f.masked_value,
        "fingerprint": f.fingerprint,
        "entropy": f.entropy,
        "confidence": f.confidence,
        "validity": f.validity,
        "severity": f.severity,
        "decision": f.decision,
        "matched_rule": f.matched_rule,
        "reason": f.reason,
        "remediation": f.remediation,
    }
