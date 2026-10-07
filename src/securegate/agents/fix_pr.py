"""`securegate agent-fix --pr N`: a pull request that takes the keys out of a pull request's
newest code.

From this laptop only, with your own gh login: the merge gate keeps its read-only token.
  1. It refuses a dirty working tree, a missing gh login, an origin that is not on GitHub, and
     a pull request that is closed or comes from a fork.
  2. It fetches the pull request's branch and makes a temporary worktree on a new branch from
     it, so your own checkout never changes.
  3. It scans the pull request's commits here, with Gitleaks, so every value is located with
     this laptop's fingerprint key: a downloaded report is never trusted for this.
  4. The fix agent chooses the environment variable for each key.
  5. SecureGate makes each edit itself: the quoted literal that holds the key becomes an
     environment read, and a Python file gets `import os` when it needs it. A line where the
     key is not alone in a quoted literal is left for a person.
  6. It commits, pushes that one branch and opens a pull request into the pull request's branch.
The keys stay in the history of the original pull request, so the new one says to revoke them.
"""

import contextlib
import json
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from securegate.agents.client import Model
from securegate.agents.fix import LANGUAGES, fix
from securegate.agents.redact import (
    Target,
    find_value_line,
    policy_patterns,
    replace_quoted_value,
)
from securegate.agents.tools import ToolBox, Workspace
from securegate.demo.pull_requests import PR_URL, DemoRefused, is_demo_branch
from securegate.github import GitHubError, Tools, check, gh_logged_in, origin_slug, run
from securegate.outputs.markdown import safe
from securegate.pipeline import run_scan
from securegate.policy import load_policy
from securegate.report import envelope, write_json
from securegate.scanners import gitleaks
from securegate.scanners.changes import git_runner
from securegate.ui.report_view import FindingView, ReportProblem, load_report

LAST_FIX = Path("reports") / "fix-pr.json"  # the newest fix pull request, for the menu
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
PYTHON_IMPORTS_OS = re.compile(r"^\s*(?:import os\b|from os import )", re.MULTILINE)
IMPORT_LINE = re.compile(r"^(?:import |from \S+ import )")
EXPRESSIONS = {"python": 'os.environ["{name}"]', "javascript": "process.env.{name}"}


@dataclass(frozen=True)
class FixedLine:
    file: str
    line: int  # where the key was, in the newest code
    masked_value: str
    env_var: str


@dataclass(frozen=True)
class FixPullRequest:
    url: str | None  # None when nothing could be fixed, so nothing was opened
    branch: str | None
    fixed: tuple[FixedLine, ...]
    skipped: tuple[str, ...]  # why each other finding was not fixed, with masked values only


def open_fix_pr(
    number: int,
    repo: Path,
    tools: Tools,
    *,
    model: Model,
    key: bytes,
    runner: gitleaks.Runner,
    policy_path: Path,
    gitleaks_config: Path,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FixPullRequest:
    if check(tools.git, "git", ["status", "--porcelain"], cwd=repo).strip():
        raise DemoRefused(
            "the working tree has uncommitted changes; commit or stash them first, so the fix "
            "cannot pick them up"
        )
    slug = origin_slug(tools.git, repo)
    if not gh_logged_in(tools.gh):
        raise DemoRefused("gh is not logged in; run `gh auth login` first")
    head, base = _pull_request(tools, slug, number)
    check(
        tools.git,
        "git",
        ["fetch", "--no-tags", "origin",
         f"+refs/heads/{head}:refs/remotes/origin/{head}",
         f"+refs/heads/{base}:refs/remotes/origin/{base}"],
        cwd=repo,
    )  # fmt: skip
    head_sha = check(tools.git, "git", ["rev-parse", f"origin/{head}"], cwd=repo).strip()
    base_sha = check(
        tools.git, "git", ["merge-base", f"origin/{base}", f"origin/{head}"], cwd=repo
    ).strip()
    branch = _fix_branch(head, now())

    scratch = Path(tempfile.mkdtemp(prefix="securegate-agent-fix-"))
    worktree = scratch / "worktree"
    pushed = False
    try:
        check(
            tools.git,
            "git",
            ["worktree", "add", "--no-track", "-b", branch, str(worktree), f"origin/{head}"],
            cwd=repo,
        )
        try:
            fixed, skipped, files = _edit(
                worktree, scratch, model=model, key=key, runner=runner,
                policy_path=policy_path, gitleaks_config=gitleaks_config,
                log_range=f"{base_sha}..{head_sha}",
            )  # fmt: skip
            if not fixed:
                return FixPullRequest(None, None, (), tuple(skipped))
            names = sorted({f.env_var for f in fixed})
            title = (
                f"Read {names[0]} from the environment"
                if len(names) == 1
                else "Read the keys from the environment"
            )
            check(tools.git, "git", ["add", "--", *files], cwd=worktree)
            check(tools.git, "git", ["commit", "--quiet", "-m", title], cwd=worktree)
            check(
                tools.git,
                "git",
                ["push", "--no-verify", "origin", f"refs/heads/{branch}:refs/heads/{branch}"],
                cwd=worktree,
            )
            pushed = True
            body = scratch / "body.md"
            body.write_text(_body(number, fixed, skipped), encoding="utf-8")
            url = check(
                tools.gh,
                "gh",
                ["pr", "create", "--repo", slug, "--base", head, "--head", branch,
                 "--title", f"Fix #{number}: {title.lower()}", "--body-file", str(body)],
                cwd=worktree,
            ).strip()  # fmt: skip
        finally:
            with contextlib.suppress(GitHubError):
                run(tools.git, "git", ["worktree", "remove", "--force", str(worktree)], cwd=repo)
                if not pushed:  # nothing left this laptop: the branch is of no use
                    run(tools.git, "git", ["branch", "-D", branch], cwd=repo)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)  # our own temporary folder only
    _note(url, branch)
    return FixPullRequest(url, branch, tuple(fixed), tuple(skipped))


def load_last_fix(path: Path = LAST_FIX) -> str | None:
    """The newest fix pull request's link, when it is a GitHub pull request link."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    url = data.get("url") if isinstance(data, dict) else None
    return url if isinstance(url, str) and PR_URL.fullmatch(url) else None


def _pull_request(tools: Tools, slug: str, number: int) -> tuple[str, str]:
    out = check(
        tools.gh,
        "gh",
        ["pr", "view", str(number), "--repo", slug, "--json",
         "state,headRefName,baseRefName,isCrossRepository"],
    )  # fmt: skip
    try:
        data = json.loads(out)
    except ValueError:
        raise GitHubError("gh gave output that is not JSON") from None
    if not isinstance(data, dict):
        raise GitHubError("gh gave output that is not JSON")
    if data.get("state") != "OPEN":
        raise DemoRefused(f"pull request #{number} is not open")
    if data.get("isCrossRepository"):
        raise DemoRefused(f"pull request #{number} comes from a fork: its branch is not ours")
    head, base = data.get("headRefName"), data.get("baseRefName")
    for name in (head, base):
        if not (isinstance(name, str) and BRANCH.fullmatch(name) and ".." not in name):
            raise DemoRefused(f"pull request #{number} has a branch name SecureGate will not use")
    return str(head), str(base)


def _fix_branch(head: str, when: datetime) -> str:
    stamp = f"{when.astimezone(UTC):%Y%m%d-%H%M%S}"
    if is_demo_branch(head):  # so that demo-cleanup removes it with the demo
        branch = f"demo/fix-{head.removeprefix('demo/').replace('/', '-')}-{stamp}"
    else:
        branch = f"securegate-fix/{head}-{stamp}"
    if not (BRANCH.fullmatch(branch) and ".." not in branch):
        raise DemoRefused("SecureGate could not make a safe name for the fix branch")
    return branch


def _edit(
    worktree: Path,
    scratch: Path,
    *,
    model: Model,
    key: bytes,
    runner: gitleaks.Runner,
    policy_path: Path,
    gitleaks_config: Path,
    log_range: str,
) -> tuple[list[FixedLine], list[str], list[str]]:
    """Scan the pull request here, ask the fix agent, and make the edits it allows."""
    policy = load_policy(policy_path)
    result = run_scan(
        worktree, "range", policy=policy, key=key, gitleaks_config=gitleaks_config,
        runner=runner, log_range=log_range,
    )  # fmt: skip
    report_path = scratch / "findings.json"
    write_json(
        report_path,
        envelope(
            exit_code=1 if any(f.decision == "block" for f in result.findings) else 0,
            target=str(worktree),
            mode="range",
            log_range=log_range,
            policy_path=str(policy_path),
            scanner_version=result.scanner_version,
            findings=result.findings,
        ),
    )
    report = load_report(report_path)
    if isinstance(report, ReportProblem):
        raise GitHubError(f"the pull request's scan could not be read back: {report.title}")
    toolbox = ToolBox(
        Workspace(report, key, git_runner(worktree), worktree, policy, policy_patterns(policy))
    )
    outcome = fix(model, toolbox)
    if outcome.status != "ok" or not outcome.result:
        return [], [outcome.note or "The fix agent had no change to suggest."], []
    findings = {f.id: f for f in toolbox.findings()}
    fixed: list[FixedLine] = []
    skipped: list[str] = []
    changed: dict[str, list[str]] = {}
    for suggestion in outcome.result:
        finding = findings[suggestion.finding]
        lines = changed.get(finding.file) or _read(worktree / finding.file)
        done = _replace(lines, finding, key, suggestion.env_var)
        if isinstance(done, str):
            skipped.append(f"{finding.location} ({finding.masked_value}): {done}")
            continue
        index = done
        changed[finding.file] = lines
        fixed.append(FixedLine(finding.file, index + 1, finding.masked_value, suggestion.env_var))
    for file, lines in changed.items():
        if LANGUAGES.get(PurePosixPath(file).suffix.lower()) == "python":
            _add_import_os(lines)
        (worktree / file).write_text("".join(lines), encoding="utf-8", newline="")
    return fixed, skipped, sorted(changed)


def _read(path: Path) -> list[str]:
    """The file's lines with their own line endings, so the edit changes nothing else."""
    return path.read_bytes().decode("utf-8").splitlines(keepends=True)


def _replace(lines: list[str], finding: FindingView, key: bytes, env_var: str) -> int | str:
    """Edit `lines` in place: the index of the line changed, or why it was left alone."""
    target = Target(finding.line, finding.masked_value, finding.fingerprint, finding.rule)
    bare = [line.rstrip("\r\n") for line in lines]
    index = find_value_line(bare, target, key)
    if index is None:
        return "the key is no longer in the newest code"
    language = LANGUAGES[PurePosixPath(finding.file).suffix.lower()]
    expression = EXPRESSIONS[language].format(name=env_var)
    new = replace_quoted_value(bare[index], target, key, expression)
    if new is None or find_value_line([new], target, key) is not None:
        return "the key is not alone in one quoted string, so a person should fix this line"
    ending = lines[index][len(bare[index]) :]
    lines[index] = new + ending
    return index


def _add_import_os(lines: list[str]) -> None:
    """Add `import os` to a Python file that does not import it yet: with the other imports,
    or else after the module's docstring."""
    if PYTHON_IMPORTS_OS.search("".join(lines)):
        return
    ending = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    first_import = next((i for i, line in enumerate(lines) if IMPORT_LINE.match(line)), None)
    if first_import is not None:
        lines.insert(first_import, f"import os{ending}")
        return
    position = _after_docstring(lines)
    lines[position:position] = [f"import os{ending}", ending]


def _after_docstring(lines: list[str]) -> int:
    if not lines or not lines[0].lstrip().startswith(('"""', "'''")):
        return 0
    quote = lines[0].lstrip()[:3]
    if lines[0].count(quote) >= 2:
        return 2 if len(lines) > 1 and not lines[1].strip() else 1
    for index in range(1, len(lines)):
        if quote in lines[index]:
            after = index + 1
            return after + 1 if after < len(lines) and not lines[after].strip() else after
    return 0


def _body(number: int, fixed: list[FixedLine], skipped: list[str]) -> str:
    rows = "\n".join(
        f"| `{safe(f.file)}:{f.line}` | `{safe(f.masked_value)}` | `{safe(f.env_var)}` |"
        for f in fixed
    )
    left = "".join(f"\n- {safe(reason)}" for reason in skipped)
    left_alone = f"\n\nLeft for a person:{left}" if skipped else ""
    return (
        f"**Opened by `securegate agent-fix --pr {number}`.** It takes the keys out of the "
        f"newest code of #{number}: each one is now read from an environment variable.\n\n"
        "| Where | Masked value | Now read from |\n|---|---|---|\n"
        f"{rows}{left_alone}\n\n"
        f"**This does not undo the leak.** The keys are still in the history of #{number}, and "
        "anyone who can see it can read them. Revoke each key at its provider and make a new "
        "one (the AI incident plan lists the steps), then set the new key as the environment "
        "variable above wherever the code runs.\n\n"
        "The AI fix agent chose the variable names; SecureGate made each edit itself and checked "
        "it, and no AI ever saw a whole key.\n"
    )


def _note(url: str, branch: str) -> None:
    if not PR_URL.fullmatch(url):
        return
    LAST_FIX.parent.mkdir(parents=True, exist_ok=True)
    LAST_FIX.write_text(json.dumps(asdict(_Note(url, branch))) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class _Note:
    url: str
    branch: str
