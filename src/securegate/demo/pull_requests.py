"""`securegate demo-pr` and `securegate demo-cleanup`: real pull requests for showing the merge
gate, and a way to remove them all.

demo-pr:
  * refuses unless the working tree is clean, gh is logged in and origin is on GitHub;
  * works in a temporary git worktree made from origin/main, on a new branch
    demo/<scenario>-<UTC time>, so your own checkout never changes;
  * commits with --no-verify (the laptop gate would stop the demo leak), pushes exactly that
    branch, and opens the pull request against main with gh.
demo-cleanup closes every open pull request whose branch starts with demo/, and deletes the
remaining demo/ branches on origin and here. Neither ever pushes to, commits to or deletes main:
every branch name is checked against `demo/` before git or gh touches it.
"""

import contextlib
import json
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from securegate.demo import scenarios
from securegate.github import GitHubError, Tools, check, gh_logged_in, origin_slug, run

DEMO_BRANCH = re.compile(r"demo/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)*")
BASE = "main"
PR_LIMIT = 200


class DemoRefused(GitHubError):
    """demo-pr or demo-cleanup refused to start, and changed nothing."""


@dataclass(frozen=True, slots=True)
class OpenedPullRequest:
    url: str
    branch: str
    scenario: scenarios.Scenario


@dataclass(frozen=True, slots=True)
class Cleanup:
    closed: tuple[int, ...]  # pull request numbers
    remote_deleted: tuple[str, ...]  # branches deleted on origin
    local_deleted: tuple[str, ...]
    kept: tuple[str, ...]  # local branches left alone (checked out here)


def open_demo_pr(
    name: str,
    repo: Path,
    tools: Tools,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    values: dict[str, str] | None = None,
) -> OpenedPullRequest:
    """Push scenario `name` to a new demo/ branch on origin and open its pull request."""
    scenario = scenarios.build(name, values or scenarios.fresh_values())
    if check(tools.git, "git", ["status", "--porcelain"], cwd=repo).strip():
        raise DemoRefused(
            "the working tree has uncommitted changes; commit or stash them first, "
            "so the demo cannot pick them up"
        )
    slug = origin_slug(tools.git, repo)
    if not gh_logged_in(tools.gh):
        raise DemoRefused("gh is not logged in; run `gh auth login` first")
    branch = f"demo/{name}-{now().astimezone(UTC):%Y%m%d-%H%M%S}"
    _require_demo(branch)

    check(
        tools.git,
        "git",
        ["fetch", "--no-tags", "origin", f"+refs/heads/{BASE}:refs/remotes/origin/{BASE}"],
        cwd=repo,
    )
    scratch = Path(tempfile.mkdtemp(prefix="securegate-demo-pr-"))
    worktree = scratch / "worktree"
    try:
        check(
            tools.git,
            "git",
            ["worktree", "add", "--no-track", "-b", branch, str(worktree), f"origin/{BASE}"],
            cwd=repo,
        )
        try:
            for commit in scenario.commits:
                _commit(tools, worktree, commit)
            check(
                tools.git,
                "git",
                ["push", "--no-verify", "origin", f"refs/heads/{branch}:refs/heads/{branch}"],
                cwd=worktree,
            )
            body = scratch / "body.md"
            body.write_text(scenario.body, encoding="utf-8")
            url = check(
                tools.gh,
                "gh",
                [
                    "pr",
                    "create",
                    "--repo",
                    slug,
                    "--base",
                    BASE,
                    "--head",
                    branch,
                    "--title",
                    f"Demo: {scenario.title} (never merge)",
                    "--body-file",
                    str(body),
                ],
                cwd=worktree,
            ).strip()
        finally:
            with contextlib.suppress(GitHubError):
                run(tools.git, "git", ["worktree", "remove", "--force", str(worktree)], cwd=repo)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)  # our own temporary folder only
    return OpenedPullRequest(url=url, branch=branch, scenario=scenario)


def cleanup(repo: Path, tools: Tools) -> Cleanup:
    """Close the open demo pull requests and delete every demo/ branch, on origin and here."""
    slug = origin_slug(tools.git, repo)
    if not gh_logged_in(tools.gh):
        raise DemoRefused("gh is not logged in; run `gh auth login` first")

    closed = []
    for number, _branch in _open_demo_prs(tools, slug):
        check(
            tools.gh,
            "gh",
            ["pr", "close", str(number), "--repo", slug, "--delete-branch"],
            cwd=repo,
        )
        closed.append(number)

    remote_deleted = []
    for branch in _remote_demo_branches(tools, repo):
        check(
            tools.git, "git", ["push", "--no-verify", "origin", f":refs/heads/{branch}"], cwd=repo
        )
        remote_deleted.append(branch)

    check(tools.git, "git", ["worktree", "prune"], cwd=repo)
    current = run(tools.git, "git", ["branch", "--show-current"], cwd=repo).stdout.strip()
    local_deleted, kept = [], []
    for branch in _local_demo_branches(tools, repo):
        if branch == current:
            kept.append(branch)
            continue
        check(tools.git, "git", ["branch", "-D", branch], cwd=repo)
        local_deleted.append(branch)
    return Cleanup(tuple(closed), tuple(remote_deleted), tuple(local_deleted), tuple(kept))


def is_demo_branch(name: str) -> bool:
    return DEMO_BRANCH.fullmatch(name) is not None and ".." not in name


def _require_demo(branch: str) -> None:
    if not is_demo_branch(branch):
        raise DemoRefused(f"refusing to touch a branch outside demo/: {branch!r}")


def _commit(tools: Tools, worktree: Path, commit: scenarios.Commit) -> None:
    for path, content in commit.files.items():
        target = worktree / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    check(tools.git, "git", ["add", "--", *commit.files], cwd=worktree)
    check(
        tools.git,
        "git",
        ["commit", "--no-verify", "--quiet", "-m", commit.message],
        cwd=worktree,
    )


def _open_demo_prs(tools: Tools, slug: str) -> list[tuple[int, str]]:
    out = check(
        tools.gh,
        "gh",
        [
            "pr",
            "list",
            "--repo",
            slug,
            "--state",
            "open",
            "--limit",
            str(PR_LIMIT),
            "--json",
            "number,headRefName,isCrossRepository",
        ],
    )
    try:
        listed = json.loads(out or "[]")
    except json.JSONDecodeError:
        raise GitHubError("gh pr list gave output that is not JSON") from None
    found = []
    for item in listed if isinstance(listed, list) else []:
        if not isinstance(item, dict) or item.get("isCrossRepository"):
            continue  # a fork's branch is not ours to delete
        number, branch = item.get("number"), item.get("headRefName")
        if isinstance(number, int) and isinstance(branch, str) and is_demo_branch(branch):
            found.append((number, branch))
    return found


def _remote_demo_branches(tools: Tools, repo: Path) -> list[str]:
    out = check(tools.git, "git", ["ls-remote", "--heads", "origin", "refs/heads/demo/*"], cwd=repo)
    branches = []
    for line in out.splitlines():
        _, _, ref = line.partition("\t")
        branch = ref.strip().removeprefix("refs/heads/")
        if ref.startswith("refs/heads/") and is_demo_branch(branch):
            branches.append(branch)
    return branches


def _local_demo_branches(tools: Tools, repo: Path) -> list[str]:
    out = check(
        tools.git,
        "git",
        ["for-each-ref", "--format=%(refname:short)", "refs/heads/demo/"],
        cwd=repo,
    )
    return [line.strip() for line in out.splitlines() if is_demo_branch(line.strip())]
