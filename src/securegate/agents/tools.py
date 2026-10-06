"""The agents' tools: what an agent may look at, already redacted. Every tool only reads.

No tool writes, runs a command the model chose, or reaches the network. The model picks a tool
and a finding id or a rule number; SecureGate checks both and answers with JSON text, which
passes through redact.redact_text once more before it is sent. Code lines come from Git, at the
commit that added the value, through redact.redact_context: the value is taken out exactly, or
no lines are sent at all.
"""

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from securegate.agents.redact import Target, contains_value, redact_context, redact_text
from securegate.errors import SecureGateError
from securegate.outputs.rotation import provider_for
from securegate.policy import Policy
from securegate.scanners.changes import Git
from securegate.ui.report_view import FindingView, ReportView

MAX_FINDINGS = 20
CONTEXT_LINES = 6
MAX_LINE = 300
MAX_FILE_BYTES = 1_000_000
COMMIT = re.compile(r"[0-9a-f]{7,40}")
FINDING_ID = re.compile(r"[0-9a-f]{12}")

_FINDING_ID_PARAMETER = {"finding_id": {"type": "string", "description": "The finding's id."}}
DESCRIPTIONS = {
    "list_findings": (
        "The findings to advise on, blocked first: masked values only, never a whole secret.",
        {},
    ),
    "code_context": (
        "The lines around a finding, at the commit that added its value. <SECRET> marks where "
        "the value was, other string literals on its line read <STRING>, and anything else "
        "shaped like a secret reads <REDACTED>. When SecureGate cannot take the value out "
        "exactly, it sends no lines.",
        _FINDING_ID_PARAMETER,
    ),
    "policy_rule": (
        "A rule of policy.yaml, by its number: what it decides, how severe, why and the fix.",
        {"number": {"type": "integer", "description": "The rule's number, such as 8."}},
    ),
    "provider_steps": (
        "SecureGate's checklist for the kind of key a finding is: where to revoke it, the usual "
        "environment variable name, and how to confirm that the old key no longer works.",
        _FINDING_ID_PARAMETER,
    ),
    "git_facts": (
        "Who added a finding's value and when, and whether it is still in the newest code.",
        _FINDING_ID_PARAMETER,
    ),
}


@dataclass(frozen=True)
class Workspace:
    report: ReportView
    key: bytes  # the fingerprint key that made the report; values are located with it
    git: Git | None  # runs git in the scanned repository; None when it is not one
    repo: Path | None  # the scanned folder, for findings without a commit (dir mode)
    policy: Policy | None
    patterns: tuple[re.Pattern[str], ...] = ()  # policy.yaml's value patterns, for redaction


class ToolBox:
    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self._tools: dict[str, Callable[[dict[str, object]], dict[str, object]]] = {
            "list_findings": lambda _args: {"findings": self.rows()},
            "code_context": self._code_context,
            "policy_rule": self._policy_rule,
            "provider_steps": self._provider_steps,
            "git_facts": self._git_facts,
        }

    def findings(self) -> list[FindingView]:
        """The blocked and warned findings, one place per finding id, blocked first."""
        seen: set[str] = set()
        chosen = []
        for finding in self.workspace.report.findings:  # sorted: blocks, warnings, ignored
            if finding.decision == "ignore" or finding.id in seen:
                continue
            seen.add(finding.id)
            chosen.append(finding)
        return chosen[:MAX_FINDINGS]

    def rows(self, findings: Sequence[FindingView] | None = None) -> list[dict[str, object]]:
        return [_row(f) for f in (self.findings() if findings is None else findings)]

    def specs(self, names: Sequence[str]) -> list[dict[str, object]]:
        """The function definitions the model is offered."""
        specs = []
        for name in names:
            description, properties = DESCRIPTIONS[name]
            specs.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": description,
                        "strict": True,
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "required": list(properties),
                            "additionalProperties": False,
                        },
                    },
                }
            )
        return specs

    def call(self, name: str, arguments: str) -> str:
        """Run one tool. The answer is JSON text, redacted once more; a bad request gets an
        error the model can read, never an exception."""
        tool = self._tools.get(name)
        if tool is None:
            result: dict[str, object] = {"error": "There is no tool with that name."}
        else:
            try:
                parsed = json.loads(arguments or "{}")
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                result = tool(parsed)
            else:
                result = {"error": "The arguments were not a JSON object."}
        return redact_text(json.dumps(result, ensure_ascii=False), self.workspace.patterns)

    def context(self, finding: FindingView) -> list[str] | None:
        """The redacted lines around a finding (also used by the fix agent itself), or None."""
        lines = self._file_lines(finding.file, finding.commit)
        if lines is None:
            return None
        first = max(1, finding.line - CONTEXT_LINES)
        window = lines[first - 1 : finding.line + CONTEXT_LINES]
        redacted = redact_context(
            window, first, self._targets(finding), self.workspace.key, self.workspace.patterns
        )
        return None if redacted is None else [line[:MAX_LINE] for line in redacted]

    def first_line(self, finding: FindingView) -> int:
        return max(1, finding.line - CONTEXT_LINES)

    # --- the tools ----------------------------------------------------------------------------

    def _code_context(self, args: dict[str, object]) -> dict[str, object]:
        finding = self._finding(args)
        if finding is None:
            return {"error": "Unknown finding id: use an id from list_findings."}
        lines = self.context(finding)
        if lines is None:
            return {
                "available": False,
                "why": "SecureGate could not take the value out of these lines exactly, or "
                "could not read them, so it sends none of them.",
            }
        return {
            "file": finding.file,
            "first_line": self.first_line(finding),
            "finding_line": finding.line,
            "lines": lines,
        }

    def _policy_rule(self, args: dict[str, object]) -> dict[str, object]:
        number = args.get("number")
        policy = self.workspace.policy
        if policy is None:
            return {"available": False, "why": "policy.yaml could not be read here."}
        for rule in policy.rules:
            if isinstance(number, int) and rule.number == number:
                return {
                    "number": rule.number,
                    "name": rule.name,
                    "decision": rule.decision,
                    "severity": rule.severity,
                    "reason": rule.reason,
                    "remediation": rule.remediation,
                }
        return {"error": "There is no rule with that number."}

    def _provider_steps(self, args: dict[str, object]) -> dict[str, object]:
        finding = self._finding(args)
        if finding is None:
            return {"error": "Unknown finding id: use an id from list_findings."}
        provider = provider_for(finding)
        return {
            "key_kind": provider.title,
            "revoke": provider.revoke,
            "environment_variable": provider.env,
            "confirm": provider.confirm,
        }

    def _git_facts(self, args: dict[str, object]) -> dict[str, object]:
        finding = self._finding(args)
        if finding is None:
            return {"error": "Unknown finding id: use an id from list_findings."}
        return {
            "commit": finding.commit[:7] if finding.commit else None,
            "author": finding.author,
            "date": finding.date,
            "still_in_newest_code": self.still_in_newest_code(finding),
        }

    def still_in_newest_code(self, finding: FindingView) -> bool | None:
        """Whether the value is still in the newest version of its file (HEAD); None when
        SecureGate cannot tell, for a short value. Without a commit, it is in today's files."""
        if not finding.commit:
            return True
        newest = self._file_lines(finding.file, "HEAD")
        if newest is None:
            return False
        target = Target(finding.line, finding.masked_value, finding.fingerprint, finding.rule)
        present = contains_value(newest, target, self.workspace.key)
        if present is None:  # a short value: the same line at the same place is good enough
            added = self._file_lines(finding.file, finding.commit)
            same = (
                added is not None
                and len(newest) >= finding.line
                and len(added) >= finding.line
                and newest[finding.line - 1] == added[finding.line - 1]
            )
            return True if same else None
        return present

    # --- helpers ------------------------------------------------------------------------------

    def _finding(self, args: dict[str, object]) -> FindingView | None:
        finding_id = args.get("finding_id")
        if not (isinstance(finding_id, str) and FINDING_ID.fullmatch(finding_id)):
            return None
        return next((f for f in self.findings() if f.id == finding_id), None)

    def _targets(self, finding: FindingView) -> list[Target]:
        return [
            Target(f.line, f.masked_value, f.fingerprint, f.rule)
            for f in self.workspace.report.findings
            if (f.file, f.commit) == (finding.file, finding.commit)
        ]

    def _file_lines(self, file: str, commit: str | None) -> list[str] | None:
        """The file as it is at `commit` (a commit id or HEAD), or on disk without one."""
        if commit is None:
            return self._disk_lines(file)
        if self.workspace.git is None or not (commit == "HEAD" or COMMIT.fullmatch(commit)):
            return None
        try:
            data = self.workspace.git(["show", f"{commit}:{file}"])
        except SecureGateError:
            return None
        return data[:MAX_FILE_BYTES].decode("utf-8", "replace").splitlines()

    def _disk_lines(self, file: str) -> list[str] | None:
        repo = self.workspace.repo
        if repo is None:
            return None
        root = repo.resolve()
        path = (root / file).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            return None  # a report could name any path; only files inside the scan are read
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES)
        except OSError:
            return None
        return data.decode("utf-8", "replace").splitlines()


def _row(finding: FindingView) -> dict[str, object]:
    return {
        "id": finding.id,
        "decision": finding.decision,
        "severity": finding.severity,
        "policy_rule": finding.matched_rule or finding.policy_rule,
        "scanner_rule": finding.rule,
        "file": finding.file,
        "line": finding.line,
        "masked_value": finding.masked_value,
        "found_by": list(finding.found_by),
        "live_check": finding.live_check,
        "commit": finding.commit[:7] if finding.commit else None,
        "date": finding.date,
    }
