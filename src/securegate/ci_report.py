"""`securegate ci-report`: download findings.json from a merge gate run, to open it in the
dashboard.

The merge gate uploads findings.json (masked values only) as the artifact "findings". This picks
the newest secret-gate run (or the run given with --run), downloads that artifact with gh, checks
it the way the dashboard does (load_report: masked values only), and saves it to `out`.
"""

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from securegate.github import GitHubError, Tools, check, origin_slug
from securegate.ui.report_view import ReportProblem, load_report

WORKFLOW_FILE = "secret-gate.yml"
ARTIFACT = "findings"


@dataclass(frozen=True, slots=True)
class Downloaded:
    run_id: int
    branch: str
    conclusion: str
    saved: Path


def download_report(repo: Path, tools: Tools, out: Path, run_id: int | None = None) -> Downloaded:
    slug = origin_slug(tools.git, repo)
    run = _find_run(tools, slug, run_id)
    scratch = Path(tempfile.mkdtemp(prefix="securegate-ci-report-"))
    try:
        check(
            tools.gh,
            "gh",
            [
                "run",
                "download",
                str(run["id"]),
                "--repo",
                slug,
                "--name",
                ARTIFACT,
                "--dir",
                str(scratch),
            ],
        )
        downloaded = scratch / "findings.json"
        if not downloaded.is_file():
            raise GitHubError(f"run {run['id']} has no findings.json in its {ARTIFACT} artifact")
        report = load_report(downloaded)
        if isinstance(report, ReportProblem):
            raise GitHubError(f"the downloaded report cannot be shown: {report.title}")
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(downloaded, out)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)  # our own temporary folder only
    return Downloaded(run["id"], run["branch"], run["conclusion"], out)


def _find_run(tools: Tools, slug: str, run_id: int | None) -> dict[str, object]:
    fields = "databaseId,headBranch,conclusion,status"
    if run_id is None:
        out = check(
            tools.gh,
            "gh",
            [
                "run",
                "list",
                "--repo",
                slug,
                "--workflow",
                WORKFLOW_FILE,
                "--limit",
                "1",
                "--json",
                fields,
            ],
        )
    else:
        out = check(tools.gh, "gh", ["run", "view", str(run_id), "--repo", slug, "--json", fields])
    try:
        data = json.loads(out or "null")
    except json.JSONDecodeError:
        raise GitHubError("gh gave output that is not JSON") from None
    if isinstance(data, list):
        if not data:
            raise GitHubError(f"the merge gate ({WORKFLOW_FILE}) has not run on GitHub yet")
        data = data[0]
    if not isinstance(data, dict) or not isinstance(data.get("databaseId"), int):
        raise GitHubError("gh did not say which run to download")
    if data.get("status") != "completed":
        raise GitHubError(f"run {data['databaseId']} has not finished yet; try again in a minute")
    return {
        "id": data["databaseId"],
        "branch": str(data.get("headBranch") or "?"),
        "conclusion": str(data.get("conclusion") or "?"),
    }
