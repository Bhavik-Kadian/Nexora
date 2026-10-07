"""Layer 3, M4: `securegate agent-fix --pr N`, a fix pull request opened from the laptop.

A real git works on a throwaway repository whose "GitHub" is a bare repository next to it; gh,
Gitleaks and the model are fakes. Planted values are made at runtime and never asserted on.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fake_gitleaks import FakeGitleaks, entry
from fake_model import FakeModel, answer, given
from helpers import GITLEAKS_CONFIG, POLICY_FILE, GitRepo, git_installed, random_key
from securegate.agents.fix_pr import LAST_FIX, load_last_fix, open_fix_pr
from securegate.agents.redact import VALUE_MARK
from securegate.demo import scenarios
from securegate.demo.pull_requests import DemoRefused, open_demo_pr
from securegate.scanners.common import RunResult
from test_demo_kit import PR_URL, Origin

NOW = datetime(2026, 10, 7, 9, 30, 0, tzinfo=UTC)
LATER = datetime(2026, 10, 7, 9, 45, 0, tzinfo=UTC)
pytestmark = pytest.mark.skipif(not git_installed(), reason="git is not installed")


def env_fixes(messages: list) -> object:
    """The fix agent's answer: read each key from its usual environment variable."""
    fixes = []
    for item in given(messages):
        name = item["usual_environment_variable"]
        fixes.append(
            {
                "finding_id": item["finding_id"],
                "env_var": name,
                "replacement": item["line_now"].replace(f'"{VALUE_MARK}"', f'os.environ["{name}"]'),
                "import_line": "import os",
                "why": "The code reads the key when it runs.",
            }
        )
    return answer({"fixes": fixes})


class Leak:
    """A demo pull request on the fake GitHub, and what the fix needs to know about it."""

    def __init__(self, origin: Origin, scene: str) -> None:
        self.origin = origin
        self.values = scenarios.fresh_values()
        opened = open_demo_pr(
            scene, origin.repo.path, origin.tools, now=lambda: NOW, values=self.values
        )
        self.branch = opened.branch
        self.first_commit = origin.bare.git(
            "rev-list", "--reverse", f"main..{self.branch}"
        ).split()[0]
        origin.gh.answers["pr view"] = RunResult(
            0,
            json.dumps(
                {
                    "state": "OPEN",
                    "headRefName": self.branch,
                    "baseRefName": "main",
                    "isCrossRepository": False,
                }
            ),
            "",
        )

    def gitleaks(self) -> FakeGitleaks:
        """Gitleaks "finds" the token where the scene put it: payments.py, line 3."""
        return FakeGitleaks(
            report=[
                entry(
                    rule="acme-pay-token",
                    file="demo-app/payments.py",
                    line=3,
                    value=self.values["acme_live"],
                    commit=self.first_commit,
                    author="Test Author",
                    date="2026-10-07T09:30:15Z",
                )
            ]
        )

    def fix(self, model: FakeModel, key: bytes) -> object:
        return open_fix_pr(
            7,
            self.origin.repo.path,
            self.origin.tools,
            model=model,
            key=key,
            runner=self.gitleaks(),
            policy_path=POLICY_FILE,
            gitleaks_config=GITLEAKS_CONFIG,
            now=lambda: LATER,
        )


@pytest.fixture
def at_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run from a folder of our own, as from the SecureGate folder (reports/ is written here)."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def leak(make_repo: Callable[[], GitRepo], at_home: Path) -> Leak:
    return Leak(Origin(make_repo), "leak")


def test_the_fix_pull_request_reads_the_key_from_the_environment(leak: Leak) -> None:
    origin = leak.origin
    done = leak.fix(FakeModel(fix_suggestions=[env_fixes]), random_key())
    assert done.url == PR_URL
    assert done.branch.startswith("demo/fix-leak-")
    assert [(f.file, f.line, f.env_var) for f in done.fixed] == [
        ("demo-app/payments.py", 3, "ACME_PAY_API_KEY")
    ]
    fixed = origin.bare.git("show", f"{done.branch}:demo-app/payments.py").splitlines()
    assert fixed[:5] == [
        '"""Charges a customer through ACME Pay (SecureGate\'s invented payment provider)."""',
        "",
        "import os",
        "",
        'ACME_PAY_API_KEY = os.environ["ACME_PAY_API_KEY"]',
    ]
    token_left = leak.values["acme_live"] in "\n".join(fixed)
    assert not token_left
    create = origin.gh.called("pr create")[-1]  # the first one opened the demo
    assert create[create.index("--base") + 1] == leak.branch
    assert create[create.index("--head") + 1] == done.branch
    body_has_token = any(leak.values["acme_live"] in body for body in origin.gh.bodies)
    assert not body_has_token
    assert "This does not undo the leak." in origin.gh.bodies[-1]


def test_your_own_checkout_never_changes(leak: Leak) -> None:
    origin = leak.origin
    head_before = origin.repo.git("rev-parse", "HEAD")
    leak.fix(FakeModel(fix_suggestions=[env_fixes]), random_key())
    assert origin.repo.git("rev-parse", "HEAD") == head_before
    assert origin.repo.git("branch", "--show-current") == "main"
    assert len(origin.repo.git("worktree", "list").splitlines()) == 1


def test_the_menu_can_find_the_fix_pull_request(leak: Leak, at_home: Path) -> None:
    leak.fix(FakeModel(fix_suggestions=[env_fixes]), random_key())
    assert (at_home / LAST_FIX).is_file()
    assert load_last_fix(at_home / LAST_FIX) == PR_URL


def test_a_key_only_in_an_older_commit_gets_no_fix(
    make_repo: Callable[[], GitRepo], at_home: Path
) -> None:
    deleted = Leak(Origin(make_repo), "deleted-later")
    remote_before = deleted.origin.remote_branches()
    done = deleted.fix(FakeModel(), random_key())
    assert (done.url, done.fixed) == (None, ())
    assert len(deleted.origin.gh.called("pr create")) == 1  # only the demo's own
    assert deleted.origin.remote_branches() == remote_before
    assert not any(b.startswith("demo/fix-") for b in deleted.origin.local_branches())


def test_an_agent_that_suggests_nothing_usable_opens_nothing(leak: Leak) -> None:
    def unusable(messages: list) -> object:
        return answer({"fixes": []})

    done = leak.fix(FakeModel(fix_suggestions=[unusable, unusable]), random_key())
    assert done.url is None
    assert done.skipped == ("the model's answer could not be used",)
    assert len(leak.origin.gh.called("pr create")) == 1  # only the demo's own


def test_a_fork_or_a_closed_pull_request_is_refused(leak: Leak) -> None:
    for state, fork, message in [
        ("OPEN", True, "comes from a fork"),
        ("CLOSED", False, "not open"),
    ]:
        leak.origin.gh.answers["pr view"] = RunResult(
            0,
            json.dumps(
                {
                    "state": state,
                    "headRefName": leak.branch,
                    "baseRefName": "main",
                    "isCrossRepository": fork,
                }
            ),
            "",
        )
        with pytest.raises(DemoRefused, match=message):
            leak.fix(FakeModel(fix_suggestions=[env_fixes]), random_key())


def test_a_dirty_working_tree_is_refused(leak: Leak) -> None:
    leak.origin.repo.write("notes.txt", "work in progress\n")
    with pytest.raises(DemoRefused, match="uncommitted changes"):
        leak.fix(FakeModel(fix_suggestions=[env_fixes]), random_key())


def test_the_command_needs_the_ai_agents(run_cli) -> None:
    result = run_cli("agent-fix", "--pr", "7", model_factory=lambda: None)
    assert result.exit_code == 2
    assert "agent-fix needs the AI agents" in result.err
