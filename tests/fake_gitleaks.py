"""A scripted stand-in for the gitleaks program, so adapter tests need no binary.

It answers `version` and `<command> --help` like Gitleaks 8.30.1. For a scan it writes the
configured report to the --report-path the adapter passed, and returns the configured exit code.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from securegate.scanners.gitleaks import GitleaksNotFound, RunResult

GLOBAL_FLAGS = [
    "--baseline-path",
    "--config",
    "--diagnostics",
    "--enable-rule",
    "--exit-code",
    "--gitleaks-ignore-path",
    "--help",
    "--ignore-gitleaks-allow",
    "--log-level",
    "--max-decode-depth",
    "--no-banner",
    "--no-color",
    "--redact",
    "--report-format",
    "--report-path",
    "--timeout",
    "--verbose",
]
GIT_FLAGS = ["--log-opts", "--platform", "--pre-commit", "--staged"]
DIR_FLAGS = ["--follow-symlinks"]


def entry(
    *,
    rule: str,
    file: str,
    line: int,
    value: str,
    commit: str = "",
    author: str = "",
    date: str = "",
) -> dict[str, object]:
    """One report entry shaped like Gitleaks 8.30.1 output."""
    return {
        "RuleID": rule,
        "Description": "test entry",
        "StartLine": line,
        "EndLine": line,
        "StartColumn": 1,
        "EndColumn": 10,
        "Match": f"VALUE = {value}",
        "Secret": value,
        "File": file,
        "SymlinkFile": "",
        "Commit": commit,
        "Entropy": 4.2,
        "Author": author,
        "Email": "",
        "Date": date,
        "Message": "",
        "Tags": [],
        "Fingerprint": f"{commit}:{file}:{rule}:{line}",
    }


@dataclass
class FakeGitleaks:
    report: list[dict[str, object]] | None = field(default_factory=list)  # None: write no report
    report_text: str | None = None  # raw report text, e.g. garbled JSON
    scan_exit: int | None = None  # default: 99 when the report has entries, else 0
    stderr: str = ""
    version: str = "8.30.1"
    missing: bool = False
    drop_flags: tuple[str, ...] = ()
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, args: Sequence[str]) -> RunResult:
        call = list(args)
        if self.missing:
            raise GitleaksNotFound("Gitleaks was not found (fake).")
        self.calls.append(call)
        if call == ["version"]:
            return RunResult(0, f"{self.version}\n", "")
        if call[1:] == ["--help"]:
            flags = GLOBAL_FLAGS + (GIT_FLAGS if call[0] == "git" else DIR_FLAGS)
            kept = [flag for flag in flags if flag not in self.drop_flags]
            listed = "\n".join(f"      {flag} string   description" for flag in kept)
            return RunResult(0, f"Usage:\n  gitleaks {call[0]} [flags]\n\nFlags:\n{listed}\n", "")
        return self._scan(call)

    def _scan(self, call: list[str]) -> RunResult:
        report_path = Path(call[call.index("--report-path") + 1])
        if self.report_text is not None:
            report_path.write_text(self.report_text, encoding="utf-8")
        elif self.report is not None:
            report_path.write_text(json.dumps(self.report), encoding="utf-8")
        exit_code = self.scan_exit if self.scan_exit is not None else (99 if self.report else 0)
        return RunResult(exit_code, "", self.stderr)

    @property
    def scan_calls(self) -> list[list[str]]:
        return [c for c in self.calls if c != ["version"] and c[1:] != ["--help"]]

    @property
    def scan_args(self) -> list[str]:
        (only,) = self.scan_calls
        return only
