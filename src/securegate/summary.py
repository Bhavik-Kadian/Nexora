"""A short Markdown summary of a findings.json, for GitHub's job summary page.

It reads the report through the dashboard's loader, which refuses any report holding a value
that is not masked, so a summary can only ever contain masked values.
"""

import re

from securegate.ui.report_view import FindingView, ReportProblem, ReportView

SHOWN = ("block", "warn")  # ignored findings are only counted
FULL_SHA = re.compile(r"[0-9a-f]{40}")
IN_HISTORY = (
    "Deleting the line in a later commit does not turn this check green: every commit in the "
    "pull request is scanned, and the key stays in its history. Treat the key as leaked: "
    "revoke it and replace it."
)


def render_summary(report: ReportView | ReportProblem) -> str:
    if isinstance(report, ReportProblem):
        return _lines(
            "### SecureGate: ERROR",
            "",
            f"**{report.title}.** {report.detail}",
            "",
            "SecureGate fails closed: without a finished scan, the check cannot pass.",
        )
    exit_code = "" if report.exit_code is None else f" (exit code {report.exit_code})"
    lines = [f"### SecureGate: {report.result}{exit_code}", "", _scope(report), ""]
    rows = [f for f in report.findings if f.decision in SHOWN]
    if rows:
        lines += ["| Decision | Where | Masked value | Why | Fix |", "|---|---|---|---|---|"]
        lines += [_row(f) for f in rows]
        lines.append("")
    if report.findings:
        blocked, warned, ignored = (report.count(d) for d in ("block", "warn", "ignore"))
        lines.append(f"{blocked} blocked, {warned} warnings, {ignored} ignored.")
    else:
        lines.append("No secrets found.")
    if report.count("block") and report.log_range:
        lines += ["", IN_HISTORY]
    return _lines(*lines)


def _scope(report: ReportView) -> str:
    scanner = f"Gitleaks {report.scanner_version}" if report.scanner_version else "Gitleaks"
    tools = f"with {scanner} and `{_plain(report.policy)}`"
    if report.log_range:
        return f"Scanned every commit in `{_short_range(report.log_range)}` {tools}."
    return f"Scanned {report.mode_description.lower()} of `{_plain(report.target)}` {tools}."


def _row(f: FindingView) -> str:
    cells = (
        f.decision.upper(),
        f"`{_plain(f.location)}`",
        f"`{_plain(f.masked_value)}`",
        _plain(f.reason),
        _plain(f.remediation),
    )
    return "| " + " | ".join(cells) + " |"


def _short_range(log_range: str) -> str:
    """abc...(40 hex)..def...(40 hex) becomes abc1234..def5678."""
    parts = re.split(r"(\.{2,3})", log_range)
    return "".join(p[:7] if FULL_SHA.fullmatch(p) else p for p in parts)


def _plain(text: str) -> str:
    """Safe inside a Markdown table cell or code span: no pipes, backticks or line breaks."""
    return " ".join(text.split()).replace("|", "\\|").replace("`", "'")


def _lines(*lines: str) -> str:
    return "\n".join(lines) + "\n"
