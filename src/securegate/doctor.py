"""`securegate doctor`: is this laptop, and the GitHub repository, ready for the merge gate demo?

Each check prints PASS, FAIL or SKIP with one line of detail. Exit code 0 when nothing failed,
1 when something did. The checks only read: they change nothing here or on GitHub.
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

from securegate.errors import SecureGateError
from securegate.github import GitHubError, Tools, gh_logged_in, origin_slug, run
from securegate.policy import load_policy
from securegate.scanners.common import ToolRunner
from securegate.scanners.versions import scanner_versions

WORKFLOW = Path(".github") / "workflows" / "secret-gate.yml"
JOB = "secret-gate"
BRANCH = "main"
PINNED = {
    "gitleaks": "GITLEAKS_VERSION",
    "trufflehog": "TRUFFLEHOG_VERSION",
    "semgrep": "SEMGREP_VERSION",
    "bandit": "BANDIT_VERSION",
}
INSTALL_HINT = {
    "gitleaks": "winget install Gitleaks.Gitleaks",
    "trufflehog": "make scanners",
    "semgrep": "make scanners",
    "bandit": "make scanners",
}

Status = Literal["PASS", "FAIL", "SKIP"]


@dataclass(frozen=True, slots=True)
class Check:
    status: Status
    name: str
    detail: str

    def line(self) -> str:
        return f"{self.status}  {self.name}: {self.detail}"


def run_checks(
    root: Path,
    tools: Tools,
    *,
    gitleaks_version: Callable[[], str | None],
    tool_runners: Mapping[str, ToolRunner],
) -> list[Check]:
    """Every check, in the order they are printed. `root` is SecureGate's own checkout."""
    workflow = _load_workflow(root / WORKFLOW)
    checks = _version_checks(workflow, gitleaks_version, tool_runners)
    checks.append(_policy_check(root))
    checks.append(_local_workflow_check(workflow))
    checks.extend(_github_checks(root, tools))
    return checks


def exit_code(checks: list[Check]) -> int:
    return 1 if any(c.status == "FAIL" for c in checks) else 0


def _load_workflow(path: Path) -> Mapping[str, object] | str:
    """The parsed workflow, or why it could not be read."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError:
        return f"{WORKFLOW.as_posix()} is missing"
    except yaml.YAMLError:
        return f"{WORKFLOW.as_posix()} is not valid YAML"
    return data if isinstance(data, Mapping) else f"{WORKFLOW.as_posix()} is not a workflow"


def _version_checks(
    workflow: Mapping[str, object] | str,
    gitleaks_version: Callable[[], str | None],
    tool_runners: Mapping[str, ToolRunner],
) -> list[Check]:
    env = workflow.get("env") if isinstance(workflow, Mapping) else None
    pins = env if isinstance(env, Mapping) else {}
    found = {"gitleaks": gitleaks_version(), **scanner_versions(tool_runners)}
    checks = []
    for tool, variable in PINNED.items():
        pinned, version = pins.get(variable), found.get(tool)
        if not isinstance(pinned, str):
            checks.append(Check("FAIL", tool, f"the workflow pins no version ({variable})"))
        elif version is None:
            checks.append(Check("FAIL", tool, f"not installed ({INSTALL_HINT[tool]})"))
        elif version != pinned:
            checks.append(Check("FAIL", tool, f"{version} installed, the merge gate uses {pinned}"))
        else:
            checks.append(Check("PASS", tool, f"{version}, the version the merge gate uses"))
    return checks


def _policy_check(root: Path) -> Check:
    try:
        policy = load_policy(root / "policy.yaml")
    except SecureGateError as err:
        return Check("FAIL", "policy", str(err))
    return Check("PASS", "policy", f"policy.yaml loads ({len(policy.rules)} rules)")


def _local_workflow_check(workflow: Mapping[str, object] | str) -> Check:
    if isinstance(workflow, str):
        return Check("FAIL", "workflow", workflow)
    jobs = workflow.get("jobs")
    if not isinstance(jobs, Mapping) or JOB not in jobs:
        return Check("FAIL", "workflow", f"{WORKFLOW.as_posix()} has no job called {JOB}")
    return Check("PASS", "workflow", f"{WORKFLOW.as_posix()} has the job {JOB}")


def _github_checks(root: Path, tools: Tools) -> list[Check]:
    try:
        logged_in = gh_logged_in(tools.gh)
    except GitHubError as err:
        return [Check("FAIL", "gh", str(err)), *_skipped("gh is missing")]
    if not logged_in:
        return [Check("FAIL", "gh", "not logged in (run `gh auth login`)"), *_skipped("no login")]
    checks = [Check("PASS", "gh", "logged in")]
    try:
        slug = origin_slug(tools.git, root)
    except GitHubError as err:
        return [*checks, Check("FAIL", "origin", str(err)), *_skipped("no GitHub origin")[1:]]
    checks.append(Check("PASS", "origin", slug))

    contents = run(
        tools.gh, "gh", ["api", f"repos/{slug}/contents/{WORKFLOW.as_posix()}?ref={BRANCH}"]
    )
    if contents.returncode == 0:
        checks.append(Check("PASS", "workflow on GitHub", f"{WORKFLOW.as_posix()} is on {BRANCH}"))
    else:
        checks.append(
            Check("FAIL", "workflow on GitHub", f"{WORKFLOW.as_posix()} is not on {BRANCH} yet")
        )
    checks.append(_ruleset_check(tools, slug))
    return checks


def _ruleset_check(tools: Tools, slug: str) -> Check:
    name = "required check"
    result = run(tools.gh, "gh", ["api", f"repos/{slug}/rules/branches/{BRANCH}"])
    if result.returncode != 0:
        return Check("SKIP", name, f"could not read the rules of {BRANCH} (no permission?)")
    try:
        rules = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return Check("SKIP", name, "GitHub's answer was not JSON")
    if _requires_check(rules, JOB):
        return Check("PASS", name, f"{BRANCH} cannot be merged until {JOB} passes")
    return Check(
        "FAIL",
        name,
        f"{BRANCH} does not require the {JOB} check yet, so a red check does not lock the "
        "merge button (see docs/merge-gate.md, the one-time setting)",
    )


def _requires_check(rules: object, context: str) -> bool:
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, Mapping) or rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters")
        if not isinstance(parameters, Mapping):
            continue
        required = parameters.get("required_status_checks")
        for item in required if isinstance(required, list) else []:
            if isinstance(item, Mapping) and item.get("context") == context:
                return True
    return False


def _skipped(reason: str) -> list[Check]:
    return [
        Check("SKIP", "origin", reason),
        Check("SKIP", "workflow on GitHub", reason),
        Check("SKIP", "required check", reason),
    ]
