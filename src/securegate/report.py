"""Presenting results: the terminal table and findings.json. Only masked values get here."""

import json
import os
import tempfile
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from securegate import __version__
from securegate.errors import ConfigError
from securegate.finding import DECISIONS, Finding
from securegate.scanners.common import ScannerRun

SCHEMA_VERSION = 1
COLUMNS = ("DECISION", "RULE", "FILE:LINE", "VALUE")
STATUS_BY_EXIT_CODE = {0: "pass", 1: "fail", 2: "error"}
RESULT_BY_EXIT_CODE = {0: "PASS", 1: "BLOCKED", 2: "ERROR"}


def render_table(findings: Sequence[Finding]) -> str:
    """A plain-text table: decision, rule, file:line and the masked value."""
    rows = [(f.decision, f.rule, f"{f.file}:{f.line}", f.masked_value) for f in findings]
    widths = [max([len(COLUMNS[i]), *(len(row[i]) for row in rows)]) for i in range(len(COLUMNS))]
    return "\n".join(_table_row(cells, widths) for cells in [COLUMNS, *rows])


def blocked_details(findings: Sequence[Finding]) -> str:
    """For each blocked finding: where it is, the masked value, why it was blocked, and the fix
    (the policy's one-line remediation)."""
    lines = ["Blocked:"]
    for f in findings:
        if f.decision == "block":
            lines += [
                f"  {f.file}:{f.line}  {f.masked_value}",
                f"    why: {f.reason}",
                f"    fix: {f.remediation or 'see the policy rule named above'}",
            ]
    return "\n".join(lines)


def summary_line(findings: Sequence[Finding], exit_code: int, out_path: Path | None) -> str:
    counts = Counter(f.decision for f in findings)
    noun = "finding" if len(findings) == 1 else "findings"
    parts = ", ".join(f"{counts[d]} {d}" for d in DECISIONS)
    details = f" Details: {out_path}" if out_path else ""
    result = RESULT_BY_EXIT_CODE[exit_code]
    return f"{len(findings)} {noun}: {parts} -> {result} (exit code {exit_code}).{details}"


def envelope(
    *,
    exit_code: int,
    target: str,
    mode: str,
    log_range: str | None,
    policy_path: str,
    scanner_version: str | None,
    findings: Sequence[Finding] | None = None,
    error: str | None = None,
    scanner_runs: Sequence[ScannerRun] | None = None,
) -> dict[str, object]:
    """The findings.json content. An error report has no "findings" key, so nobody can
    mistake a failed scan for a clean one. "scanner" names Gitleaks, as before; "scanners"
    lists every scanner and how it fared."""
    data: dict[str, object] = {
        "tool": "securegate",
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS_BY_EXIT_CODE[exit_code],
        "exit_code": exit_code,
        "scanned_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "mode": mode,
        "range": log_range,
        "scanner": {"name": "gitleaks", "version": scanner_version},
        "policy": policy_path,
    }
    if scanner_runs is not None:
        data["scanners"] = [run.to_dict() for run in scanner_runs]
    if error is not None or findings is None:
        data["error"] = error or "unknown error"
        return data
    counts = Counter(f.decision for f in findings)
    data["summary"] = {"total": len(findings), **{d: counts[d] for d in DECISIONS}}
    data["findings"] = [f.to_dict() for f in findings]
    return data


def write_json(path: Path, data: dict[str, object]) -> None:
    """Write JSON atomically, so a half-written findings.json is never left behind."""
    write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def write_text(path: Path, text: str) -> None:
    """Write a file atomically: readers see the old file or the whole new one, never half."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            os.replace(temp_name, path)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
    except OSError as err:
        raise ConfigError(f"cannot write the report {path}: {err}") from None


def _table_row(cells: Sequence[str], widths: Sequence[int]) -> str:
    return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True)).rstrip()
