"""The Markdown report: the pull request comment and the job summary. Pure: it only reads the
checked report.

Both come from one template, templates/report.md.j2; the comment starts with a hidden marker,
so the workflow updates its own comment instead of adding a new one on every run. The report
was read back through ui.report_view.load_report(), which refuses any value that is not
masked, and every value put into the Markdown goes through `safe` (Jinja's finalize): no pipe,
backtick, line break or HTML tag from a file name or a reason can break the table or the page.
"""

import re
from dataclasses import dataclass

import jinja2

from securegate.outputs.rotation import provider_for
from securegate.ui.report_view import (
    SCANNER_LABELS,
    FindingView,
    ReportProblem,
    ReportView,
    ScannerView,
)

MARKER = "<!-- securegate:pr-comment -->"
MAX_ROWS = 50  # GitHub refuses comments over 65,536 characters
MAX_CHECKLISTS = 10
HISTORY_SENTENCE = "Deleting the line is not enough: the key stays in Git history."
IN_HISTORY = (
    "Deleting the line in a later commit does not turn this check green: every commit in the "
    "pull request is scanned, and the key stays in its history. Treat the key as leaked: "
    "revoke it and replace it."
)
FULL_SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Row:
    decision: str
    rule: str
    location: str
    masked: str
    found_by: str
    live: str


@dataclass(frozen=True)
class Checklist:
    location: str
    masked: str
    title: str
    revoke: str
    env: str
    confirm: str
    rule: str
    why: str


@dataclass(frozen=True)
class Explained:
    location: str
    masked: str
    rule: str
    why: str


def safe(value: object) -> str:
    """Make a value safe inside Markdown: one line, no table pipes, no code-span backticks and
    no HTML tags. Applied to every {{ }} in the template."""
    text = " ".join(("" if value is None else str(value)).split())
    return text.replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


_ENV = jinja2.Environment(
    loader=jinja2.PackageLoader("securegate.outputs", "templates"),
    autoescape=False,  # noqa: S701 - Markdown, not HTML: `safe` escapes every value
    finalize=safe,
    undefined=jinja2.StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)


def render_comment(report: ReportView | ReportProblem) -> str:
    return _render(report, comment=True)


def render_summary(report: ReportView | ReportProblem) -> str:
    return _render(report, comment=False)


def verdict(report: ReportView) -> str:
    """BLOCKED, PASSED WITH WARNINGS or PASSED (ERROR for a scan that did not finish)."""
    if report.exit_code == 1:
        return "BLOCKED"
    if report.exit_code != 0:
        return "ERROR"
    return "PASSED WITH WARNINGS" if report.count("warn") else "PASSED"


def _render(report: ReportView | ReportProblem, *, comment: bool) -> str:
    template = _ENV.get_template("report.md.j2")
    if isinstance(report, ReportProblem):
        return template.render(comment=comment, problem=report)
    return template.render(comment=comment, problem=None, **_context(report))


def _context(report: ReportView) -> dict[str, object]:
    blocks = report.filtered("block")
    warnings = report.filtered("warn")
    ignored = report.filtered("ignore")
    shown = [*blocks, *warnings]
    ran = [s for s in report.scanners if s.status == "ran"]
    return {
        "verdict": verdict(report),
        "exit_code": report.exit_code,
        "range": _short_range(report.log_range) if report.log_range else None,
        "what": report.mode_description[:1].lower() + report.mode_description[1:],
        "target": report.target,
        "policy": report.policy,
        "scanners": _scanner_list(ran),
        "not_run": [s for s in report.scanners if s.status == "did_not_run"],
        "skipped": [s for s in report.scanners if s.status == "skipped"],
        "notes": [s for s in ran if s.note],
        "rows": [_row(f) for f in shown[:MAX_ROWS]],
        "more_rows": max(0, len(shown) - MAX_ROWS),
        "checklists": [_checklist(f) for f in blocks[:MAX_CHECKLISTS]],
        "more_checklists": max(0, len(blocks) - MAX_CHECKLISTS),
        "warnings": [_explained(f) for f in warnings[:MAX_ROWS]],
        "ignored": [_explained(f) for f in ignored[:MAX_ROWS]],
        "more_ignored": max(0, len(ignored) - MAX_ROWS),
        "counts": (len(blocks), len(warnings), len(ignored)),
        "any_findings": bool(report.findings),
        "in_history": IN_HISTORY if blocks and report.log_range else None,
        "history_sentence": HISTORY_SENTENCE,
    }


def _scanner_list(ran: list[ScannerView]) -> str:
    names = [f"{s.label} {s.version}" if s.version else s.label for s in ran] or ["Gitleaks"]
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def _rule(f: FindingView) -> str:
    return f.matched_rule or f.policy_rule or "policy"


def _found_by(f: FindingView) -> str:
    return ", ".join(SCANNER_LABELS.get(name, name) for name in f.found_by)


def _row(f: FindingView) -> Row:
    return Row(
        decision=f.decision.upper(),
        rule=_rule(f),
        location=f.location,
        masked=f.masked_value,
        found_by=_found_by(f),
        live=f.live_check,
    )


def _checklist(f: FindingView) -> Checklist:
    provider = provider_for(f)
    return Checklist(
        location=f.location,
        masked=f.masked_value,
        title=provider.title,
        revoke=provider.revoke,
        env=provider.env,
        confirm=provider.confirm,
        rule=_rule(f),
        why=f.reason_text,
    )


def _explained(f: FindingView) -> Explained:
    return Explained(location=f.location, masked=f.masked_value, rule=_rule(f), why=f.reason_text)


def _short_range(log_range: str) -> str:
    """abc...(40 hex)..def...(40 hex) becomes abc1234..def5678."""
    parts = re.split(r"(\.{2,3})", log_range)
    return "".join(p[:7] if FULL_SHA.fullmatch(p) else p for p in parts)
