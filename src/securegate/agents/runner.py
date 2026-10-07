"""`securegate agents`: ask the three agents about a report, and keep their advice in it.

The advice goes into the report's "advice" section, and is read back through the same checks
the dashboard uses (ui.report_view.load_report). If what the agents wrote does not pass them,
only a "failed" status is kept: nothing an agent wrote is stored without being checked. The
findings, their decisions and the exit code are never touched.
"""

import json
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from pathlib import Path

from securegate.agents.advice import AGENTS, LIMITS, Advice, AgentStatus
from securegate.agents.client import Model
from securegate.agents.fix import fix
from securegate.agents.incident import incident
from securegate.agents.loop import Outcome
from securegate.agents.redact import policy_patterns
from securegate.agents.sanitize import clean_text
from securegate.agents.tools import ToolBox, Workspace
from securegate.agents.triage import triage
from securegate.errors import ConfigError, SecureGateError
from securegate.policy import Policy, load_policy
from securegate.report import write_json
from securegate.scanners.changes import git_runner
from securegate.ui.report_view import ReportProblem, ReportView, load_report

NOT_SET_UP = "The AI agents are not set up where this scan ran, so none were asked."
NOT_KEPT = "The agents' answer did not pass SecureGate's checks, so it was not kept."


def parse_only(text: str) -> tuple[str, ...]:
    names = tuple(dict.fromkeys(name.strip().lower() for name in text.split(",") if name.strip()))
    unknown = [name for name in names if name not in AGENTS]
    if not names or unknown:
        raise ConfigError(f"--only takes a list of: {', '.join(AGENTS)}")
    return names


def ask_agents(
    report_path: Path,
    *,
    model: Model | None,
    key: bytes,
    repo: Path | None = None,
    only: Sequence[str] = AGENTS,
    visibility: str = "unknown",
    now: Callable[[], datetime],
) -> Advice:
    """The agents' advice about the report at `report_path` (not yet stored)."""
    report = _readable(report_path)
    made_at = now().strftime("%Y-%m-%dT%H:%M:%SZ")
    if model is None:
        statuses = {name: AgentStatus("skipped", NOT_SET_UP) for name in only}
        return Advice("skipped", NOT_SET_UP, None, made_at, statuses)
    policy = _policy(report)
    folder = repo or Path(report.target)
    workspace = Workspace(
        report=report,
        key=key,
        git=git_runner(folder) if folder.is_dir() else None,
        repo=folder if folder.is_dir() else None,
        policy=policy,
        patterns=policy_patterns(policy) if policy else (),
    )
    toolbox = ToolBox(workspace)
    outcomes: dict[str, Outcome[object]] = {}
    if "triage" in only:
        outcomes["triage"] = triage(model, toolbox)
    if "fix" in only:
        outcomes["fix"] = fix(model, toolbox)
    if "incident" in only:
        outcomes["incident"] = incident(model, toolbox, visibility=visibility, now=now)
    return Advice(
        status=_overall(outcomes.values()),
        note=None,
        model=clean_text(model.name, LIMITS["model"]) or None,
        made_at=made_at,
        agents={name: AgentStatus(o.status, _note(o.note)) for name, o in outcomes.items()},
        triage=_result(outcomes.get("triage"), ()),
        fixes=_result(outcomes.get("fix"), ()),
        incident=_result(outcomes.get("incident"), None),
    )


def store_advice(report_path: Path, advice: Advice) -> Advice:
    """Put the advice into the report, then read it back through the dashboard's checks. Returns
    what was kept: the advice, or a "failed" status when it did not pass."""
    data = json.loads(report_path.read_text(encoding="utf-8"))
    data["advice"] = advice.to_dict()
    write_json(report_path, data)
    kept = load_report(report_path)
    if isinstance(kept, ReportView) and kept.advice is not None:
        return kept.advice
    failed = Advice(
        "failed",
        NOT_KEPT,
        advice.model,
        advice.made_at,
        {name: AgentStatus("failed", None) for name in advice.agents},
    )
    data["advice"] = failed.to_dict()
    write_json(report_path, data)
    return failed


def _readable(report_path: Path) -> ReportView:
    report = load_report(report_path)
    if isinstance(report, ReportProblem):
        raise ConfigError(f"{report_path}: {report.title}. {report.detail}")
    if report.exit_code not in (0, 1):
        raise ConfigError(f"{report_path} is not the report of a finished scan")
    return report


def _policy(report: ReportView) -> Policy | None:
    try:
        return load_policy(Path(report.policy))
    except SecureGateError:
        return None  # the agents still run; the policy_rule tool says it is not available


def _overall(outcomes: Iterable[Outcome[object]]) -> str:
    statuses = [o.status for o in outcomes]
    if "ok" in statuses:
        return "ok"
    return "failed" if "failed" in statuses else "skipped"


def _note(note: str | None) -> str | None:
    return (clean_text(note, LIMITS["note"]) or None) if note else None


def _result(outcome: Outcome[object] | None, default: object) -> object:
    return default if outcome is None or outcome.result is None else outcome.result
