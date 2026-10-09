"""Running git and gh for the demo kit, `doctor` and `ci-report`.

Both programs are injected as ToolRunners, so tests pass fakes (or a real git on a temporary
repository with a local "origin"). Error messages name the command and its exit code only:
the programs' own output is never repeated, because it could quote file contents.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from securegate.errors import SecureGateError
from securegate.scanners.common import ProgramRunner, RunResult, ToolRunner

GIT_TIMEOUT = 5 * 60  # seconds; a push or fetch over a slow network
GH_TIMEOUT = 2 * 60

# https://github.com/owner/repo(.git) or git@github.com:owner/repo(.git)
_GITHUB_URL = re.compile(
    r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"(?P<slug>[A-Za-z0-9-]+/[A-Za-z0-9._-]+?)(?:\.git)?/?"
)


class GitHubError(SecureGateError):
    """git or gh refused, failed or is missing (exit code 2)."""


@dataclass(frozen=True, slots=True)
class Tools:
    git: ToolRunner
    gh: ToolRunner


def real_tools() -> Tools:
    return Tools(git=ProgramRunner("git", GIT_TIMEOUT), gh=ProgramRunner("gh", GH_TIMEOUT))


def run(runner: ToolRunner, name: str, args: list[str], *, cwd: Path | None = None) -> RunResult:
    """Run `name args` and return the result, whatever its exit code. Raises GitHubError when
    the program is missing."""
    try:
        return runner(args, cwd=cwd)
    except FileNotFoundError:
        hint = " (install GitHub CLI: winget install GitHub.cli)" if name == "gh" else ""
        raise GitHubError(f"{name} was not found{hint}") from None


def check(runner: ToolRunner, name: str, args: list[str], *, cwd: Path | None = None) -> str:
    """Run `name args`; return its output, or raise GitHubError if it failed."""
    result = run(runner, name, args, cwd=cwd)
    if result.returncode != 0:
        raise GitHubError(f"`{name} {_shown(args)}` failed (exit code {result.returncode})")
    return result.stdout


def origin_slug(git: ToolRunner, repo: Path) -> str:
    """owner/name of the GitHub repository that `origin` points to. The configured URL is read
    as written (url.*.insteadOf rewrites are not applied), so a test can point git elsewhere."""
    result = run(git, "git", ["config", "--get", "remote.origin.url"], cwd=repo)
    url = result.stdout.strip()
    if result.returncode != 0 or not url:
        raise GitHubError("this repository has no remote called origin")
    found = _GITHUB_URL.fullmatch(url)
    if found is None:
        raise GitHubError("origin is not a GitHub repository")
    return found.group("slug")


def gh_logged_in(gh: ToolRunner) -> bool:
    return run(gh, "gh", ["auth", "status"]).returncode == 0


def _shown(args: list[str]) -> str:
    """The first words of a command, for an error message (no file names or bodies)."""
    words = []
    for arg in args:
        if arg.startswith("-") or "/" in arg or "\\" in arg:
            break
        words.append(arg)
    return " ".join(words[:3])
