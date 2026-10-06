"""`securegate ci-report`: download findings.json from a merge gate run, to open it in the
dashboard.

The merge gate uploads findings.json (masked values only) as the artifact "findings". This picks
a secret-gate run: the newest one, the one given with --run, or the newest one for the newest
commit of pull request --pr. With --wait it waits until that run has finished. Then it downloads
the artifact with gh, checks it the way the dashboard does (load_report: masked values only), and
saves it to `out`.
"""

import json
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from securegate.github import GitHubError, Tools, check, origin_slug
from securegate.ui.report_view import ReportProblem, ReportView, load_report

WORKFLOW_FILE = "secret-gate.yml"
ARTIFACT = "findings"
RUN_FIELDS = "databaseId,headBranch,headSha,conclusion,status"
POLL_SECONDS = 5
WAIT_LIMIT_SECONDS = 15 * 60
RUNS_PER_BRANCH = 20


@dataclass(frozen=True, slots=True)
class GateRun:
    id: int
    branch: str
    head_sha: str
    status: str  # queued, in_progress, completed, ...
    conclusion: str  # success or failure once completed


@dataclass(frozen=True, slots=True)
class Downloaded:
    run: GateRun
    saved: Path
    report: ReportView
    merge_state: str | None  # GitHub's mergeStateStatus of the pull request, with --pr only


def download_report(
    repo: Path,
    tools: Tools,
    out: Path,
    *,
    run_id: int | None = None,
    pull_request: int | None = None,
    wait: bool = False,
    say: Callable[[str], None] = lambda _line: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Downloaded:
    slug = origin_slug(tools.git, repo)
    if pull_request is not None:
        head_branch, head_sha = _pull_request_head(tools, slug, pull_request)
        what = f"pull request #{pull_request}"

        def fetch() -> GateRun | None:
            return _run_for_commit(tools, slug, head_branch, head_sha)

    elif run_id is not None:
        what = f"run {run_id}"

        def fetch() -> GateRun | None:
            return _parse_run(_gh_json(tools, ["run", "view", str(run_id), "--repo", slug]))

    else:
        what = "the newest pull request"

        def fetch() -> GateRun | None:
            runs = _gh_json(
                tools,
                ["run", "list", "--repo", slug, "--workflow", WORKFLOW_FILE, "--limit", "1"],
            )
            return _parse_run(runs[0]) if isinstance(runs, list) and runs else None

    run = _finished_run(fetch, what=what, wait=wait, say=say, sleep=sleep, clock=clock)
    report = _download(tools, slug, run, out)
    merge_state = None
    if pull_request is not None:
        state = _gh_json(
            tools, ["pr", "view", str(pull_request), "--repo", slug], fields="mergeStateStatus"
        )
        merge_state = state.get("mergeStateStatus") if isinstance(state, dict) else None
    return Downloaded(run, out, report, merge_state if isinstance(merge_state, str) else None)


def merge_line(run: GateRun, merge_state: str | None) -> str | None:
    """What GitHub lets people do with the pull request now, in words."""
    if merge_state == "BLOCKED":
        return "Merging: locked. GitHub will not let anyone merge this pull request."
    if merge_state in ("CLEAN", "UNSTABLE", "HAS_HOOKS") and run.conclusion != "success":
        return (
            "Merging: NOT locked. The check is red, but main does not require it yet "
            "(see `securegate doctor`)."
        )
    if merge_state in ("CLEAN", "HAS_HOOKS"):
        return "Merging: allowed. The check is green."
    return None


def _finished_run(
    fetch: Callable[[], GateRun | None],
    *,
    what: str,
    wait: bool,
    say: Callable[[str], None],
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> GateRun:
    started = clock()
    announced = False
    while True:
        run = fetch()
        if run is not None and run.status == "completed":
            return run
        if not wait:
            if run is None:
                raise GitHubError(f"the merge gate has not run for {what} yet")
            raise GitHubError(
                f"run {run.id} has not finished yet; try again in a minute, or add --wait"
            )
        if clock() - started > WAIT_LIMIT_SECONDS:
            raise GitHubError(
                f"the merge gate did not finish for {what} within "
                f"{WAIT_LIMIT_SECONDS // 60} minutes"
            )
        if not announced:
            say(f"Waiting for the merge gate's check on {what} (it takes about a minute)...")
            announced = True
        sleep(POLL_SECONDS)


def _download(tools: Tools, slug: str, run: GateRun, out: Path) -> ReportView:
    scratch = Path(tempfile.mkdtemp(prefix="securegate-ci-report-"))
    try:
        check(
            tools.gh,
            "gh",
            ["run", "download", str(run.id), "--repo", slug, "--name", ARTIFACT,
             "--dir", str(scratch)],
        )  # fmt: skip
        downloaded = scratch / "findings.json"
        if not downloaded.is_file():
            raise GitHubError(f"run {run.id} has no findings.json in its {ARTIFACT} artifact")
        report = load_report(downloaded)
        if isinstance(report, ReportProblem):
            raise GitHubError(f"the downloaded report cannot be shown: {report.title}")
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(downloaded, out)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)  # our own temporary folder only
    saved = load_report(out)  # the same bytes, read from where they stay
    if isinstance(saved, ReportProblem):
        raise GitHubError(f"the saved report cannot be shown: {saved.title}")
    return saved


def _pull_request_head(tools: Tools, slug: str, number: int) -> tuple[str, str]:
    data = _gh_json(
        tools, ["pr", "view", str(number), "--repo", slug], fields="headRefName,headRefOid"
    )
    branch = data.get("headRefName") if isinstance(data, dict) else None
    sha = data.get("headRefOid") if isinstance(data, dict) else None
    if not isinstance(branch, str) or not isinstance(sha, str):
        raise GitHubError(f"gh did not say which commit pull request #{number} is at")
    return branch, sha


def _run_for_commit(tools: Tools, slug: str, branch: str, sha: str) -> GateRun | None:
    """The newest secret-gate run for commit `sha` of `branch`, if it has started."""
    runs = _gh_json(
        tools,
        ["run", "list", "--repo", slug, "--workflow", WORKFLOW_FILE, "--branch", branch,
         "--limit", str(RUNS_PER_BRANCH)],
    )  # fmt: skip
    for item in runs if isinstance(runs, list) else []:
        run = _parse_run(item)
        if run is not None and run.head_sha == sha:
            return run  # gh lists the newest first
    return None


def _gh_json(tools: Tools, args: list[str], *, fields: str = RUN_FIELDS) -> object:
    out = check(tools.gh, "gh", [*args, "--json", fields])
    try:
        return json.loads(out or "null")
    except json.JSONDecodeError:
        raise GitHubError("gh gave output that is not JSON") from None


def _parse_run(data: object) -> GateRun | None:
    if not isinstance(data, dict) or not isinstance(data.get("databaseId"), int):
        return None
    return GateRun(
        id=data["databaseId"],
        branch=str(data.get("headBranch") or "?"),
        head_sha=str(data.get("headSha") or ""),
        status=str(data.get("status") or "?"),
        conclusion=str(data.get("conclusion") or "?"),
    )
