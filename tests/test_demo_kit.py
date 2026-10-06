"""The demo kit: `securegate demo-pr`, `demo-cleanup`, `doctor` and `ci-report`.

demo-pr and demo-cleanup run a real git on a throwaway repository whose "origin" is a local bare
repository (git rewrites the GitHub URL to it); gh is a fake that records its commands.
Convention: fake values never appear inside an assert; tests compare booleans instead.
"""

import json
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from helpers import (
    POLICY_FILE,
    REPO_ROOT,
    GitRepo,
    git_installed,
    gitleaks_installed,
    scan_args,
)
from securegate.ci_report import download_report
from securegate.demo import scenarios
from securegate.demo.pull_requests import DemoRefused, cleanup, is_demo_branch, open_demo_pr
from securegate.doctor import exit_code, run_checks
from securegate.entropy import shannon_entropy
from securegate.github import GitHubError, Tools
from securegate.policy import decide, load_policy
from securegate.scanners.common import RunResult

SLUG = "demo-owner/demo-repo"
GITHUB_URL = f"https://github.com/{SLUG}.git"
PR_URL = f"https://github.com/{SLUG}/pull/7"
NOW = datetime(2026, 10, 6, 9, 30, 15, tzinfo=UTC)

needs_git = pytest.mark.skipif(not git_installed(), reason="git is not installed")


class FakeGh:
    """Records every gh command. Answers are set per command, by its first two words."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.bodies: list[str] = []  # the text of every --body-file
        self.answers: dict[str, RunResult] = {
            "auth status": RunResult(0, "", ""),
            "pr create": RunResult(0, PR_URL + "\n", ""),
            "pr list": RunResult(0, "[]", ""),
            "pr close": RunResult(0, "", ""),
        }
        self.on_call: dict[str, Callable[[list[str]], None]] = {}

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        self.calls.append(list(args))
        if "--body-file" in args:
            body = Path(args[args.index("--body-file") + 1])
            self.bodies.append(body.read_text(encoding="utf-8"))
        key = " ".join(args[:2])
        if key in self.on_call:
            self.on_call[key](args)
        if args[0] == "api":
            return self.answers.get(f"api {args[1]}", RunResult(1, "", "not found"))
        return self.answers.get(key, RunResult(0, "", ""))

    def called(self, words: str) -> list[list[str]]:
        return [call for call in self.calls if " ".join(call).startswith(words)]


class IsolatedGit:
    """The real git, without the user's own Git settings (hooks, signing, identity)."""

    def __init__(self, env: dict[str, str]) -> None:
        self.env = env

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        done = subprocess.run(
            ["git", "-c", "commit.gpgsign=false", *args],
            cwd=cwd,
            env=self.env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        return RunResult(done.returncode, done.stdout, done.stderr)


class Origin:
    """A checkout whose origin (on "GitHub") is really a bare repository next to it."""

    def __init__(self, make_repo: Callable[[], GitRepo]) -> None:
        self.bare = make_repo()
        shutil.rmtree(self.bare.path)
        self.bare.path.mkdir()
        self.bare.git("init", "-q", "--bare", "-b", "main")
        self.repo = make_repo()
        self.repo.git("remote", "add", "origin", GITHUB_URL)
        self.repo.git("config", f"url.{self.bare.path.as_posix()}.insteadOf", GITHUB_URL)
        self.repo.write("README.md", "# Demo\n")
        self.repo.commit("First commit")
        self.repo.git("push", "-q", "origin", "main")
        self.gh = FakeGh()
        self.tools = Tools(git=IsolatedGit(self.repo.env), gh=self.gh)

    def remote_branches(self) -> list[str]:
        out = self.bare.git("for-each-ref", "--format=%(refname:short)", "refs/heads/")
        return sorted(out.splitlines())

    def local_branches(self) -> list[str]:
        out = self.repo.git("for-each-ref", "--format=%(refname:short)", "refs/heads/")
        return sorted(out.splitlines())

    def remote_file(self, branch: str, path: str, ref_suffix: str = "") -> str:
        return self.bare.git("show", f"{branch}{ref_suffix}:{path}")


@pytest.fixture
def origin(make_repo: Callable[[], GitRepo]) -> Origin:
    if not git_installed():
        pytest.skip("git is not installed")
    return Origin(make_repo)


# --- the scenarios --------------------------------------------------------------------------


def _decision(path: str, value: str, rule_id: str = "acme-pay-token") -> str:
    verdict = decide(
        load_policy(POLICY_FILE),
        rule_id=rule_id,
        path=path,
        value=value,
        entropy=shannon_entropy(value),
    )
    return f"rule {verdict.number}: {verdict.decision}"


def test_every_scenario_builds_and_its_body_says_never_merge() -> None:
    values = scenarios.fresh_values()
    for name in scenarios.NAMES:
        scenario = scenarios.build(name, values)
        assert scenario.commits
        assert "Never merge it" in scenario.body
        texts = [scenario.body, scenario.title, scenario.story, scenario.expected]
        any_value_shown = any(v in text for v in values.values() for text in texts)
        assert not any_value_shown


def test_the_leak_scenario_plants_a_live_token_the_policy_blocks() -> None:
    values = scenarios.fresh_values()
    files = scenarios.build("leak", values).commits[0].files
    assert list(files) == ["demo-app/payments.py"]
    planted = values["acme_live"] in files["demo-app/payments.py"]
    assert planted
    assert _decision("demo-app/payments.py", values["acme_live"]) == "rule 8: block"


def test_deleted_later_adds_the_token_then_reads_it_from_the_environment() -> None:
    values = scenarios.fresh_values()
    first, second = scenarios.build("deleted-later", values).commits
    in_first = values["acme_live"] in first.files["demo-app/payments.py"]
    in_second = values["acme_live"] in second.files["demo-app/payments.py"]
    assert (in_first, in_second) == (True, False)
    assert 'os.environ["ACME_PAY_API_KEY"]' in second.files["demo-app/payments.py"]


def test_the_decoys_live_in_tests_and_are_ignored_or_only_warned_about() -> None:
    values = scenarios.fresh_values()
    files = scenarios.build("decoys", values).commits[0].files
    path = "demo-app/tests/test_payments.py"
    assert list(files) == [path]
    assert _decision(path, "YOUR_API_KEY_HERE") == "rule 3: ignore"
    assert _decision(path, "changeme", "generic-api-key") == "rule 3: ignore"
    assert _decision(path, values["acme_test"]) == "rule 7: warn"
    assert _decision(path, values["order_id"], "generic-api-key") == "rule 7: warn"
    planted = all(values[k] in files[path] for k in ("acme_test", "order_id"))
    assert planted


def test_the_risky_scenario_logs_a_token_and_hardcodes_a_password() -> None:
    values = scenarios.fresh_values()
    text = scenarios.build("risky", values).commits[0].files["demo-app/client.py"]
    password_planted = f'DB_PASSWORD = "{values["password"]}"' in text
    assert password_planted
    assert 'log.info("Connecting to ACME Pay with %s", api_token)' in text
    assert _decision("demo-app/client.py", values["password"], "bandit-B105") == "rule 10: warn"


def test_the_clean_scenario_has_nothing_secret() -> None:
    values = scenarios.fresh_values()
    files = scenarios.build("clean", values).commits[0].files
    any_value = any(v in text for v in values.values() for text in files.values())
    assert not any_value


@pytest.mark.skipif(not gitleaks_installed(), reason="gitleaks is not installed")
@pytest.mark.parametrize(
    ("name", "expected_exit"),
    [("clean", 0), ("leak", 1), ("deleted-later", 0), ("decoys", 0), ("risky", 0)],
)
def test_gitleaks_and_the_policy_agree_with_each_scenario_on_its_newest_files(
    run_cli, tmp_path: Path, name: str, expected_exit: int
) -> None:
    """Only the newest files, in dir mode: deleted-later is clean here, and red only because
    the merge gate reads every commit (checked in the demo-pr test below)."""
    folder = tmp_path / "pr"
    for commit in scenarios.build(name, scenarios.fresh_values()).commits:
        for path, content in commit.files.items():
            (folder / path).parent.mkdir(parents=True, exist_ok=True)
            (folder / path).write_text(content, encoding="utf-8")

    result = run_cli(*scan_args(folder, mode="dir"))

    assert result.exit_code == expected_exit


# --- demo-pr --------------------------------------------------------------------------------


@needs_git
def test_demo_pr_pushes_one_new_demo_branch_and_opens_its_pull_request(origin: Origin) -> None:
    values = scenarios.fresh_values()
    main_before = origin.bare.git("rev-parse", "main")
    head_before = origin.repo.git("rev-parse", "HEAD")

    opened = open_demo_pr("leak", origin.repo.path, origin.tools, now=lambda: NOW, values=values)

    assert opened.url == PR_URL
    assert opened.branch == "demo/leak-20261006-093015"
    assert origin.remote_branches() == ["demo/leak-20261006-093015", "main"]
    assert origin.bare.git("rev-parse", "main") == main_before
    assert origin.repo.git("rev-parse", "HEAD") == head_before
    assert origin.repo.git("branch", "--show-current") == "main"
    assert origin.repo.git("status", "--porcelain") == ""
    assert len(origin.repo.git("worktree", "list").splitlines()) == 1
    pushed = values["acme_live"] in origin.remote_file(opened.branch, "demo-app/payments.py")
    assert pushed
    (create,) = origin.gh.called("pr create")
    assert create[create.index("--repo") + 1] == SLUG
    assert create[create.index("--base") + 1] == "main"
    assert create[create.index("--head") + 1] == opened.branch
    body_has_token = any(values["acme_live"] in body for body in origin.gh.bodies)
    assert not body_has_token


@needs_git
def test_demo_pr_deleted_later_keeps_the_token_in_the_first_commit(origin: Origin) -> None:
    values = scenarios.fresh_values()
    opened = open_demo_pr(
        "deleted-later", origin.repo.path, origin.tools, now=lambda: NOW, values=values
    )
    log = origin.bare.git("log", "--format=%s", f"main..{opened.branch}").splitlines()
    assert log == [
        "Demo: Read the ACME Pay key from the environment",
        "Demo: Charge customers with ACME Pay",
    ]
    in_head = values["acme_live"] in origin.remote_file(opened.branch, "demo-app/payments.py")
    in_first = values["acme_live"] in origin.remote_file(
        opened.branch, "demo-app/payments.py", "~1"
    )
    assert (in_first, in_head) == (True, False)


@needs_git
def test_demo_pr_starts_from_origin_main_not_from_the_local_branch(origin: Origin) -> None:
    origin.repo.git("switch", "-q", "-c", "feature")
    origin.repo.write("local-only.txt", "not pushed\n")
    origin.repo.commit("A local commit")

    opened = open_demo_pr("clean", origin.repo.path, origin.tools, now=lambda: NOW)

    files = origin.bare.git("ls-tree", "-r", "--name-only", opened.branch).splitlines()
    assert files == ["README.md", "demo-app/greeting.py"]
    assert origin.repo.git("branch", "--show-current") == "feature"


@needs_git
def test_demo_pr_refuses_a_dirty_working_tree_and_changes_nothing(origin: Origin) -> None:
    origin.repo.write("notes.txt", "work in progress\n")
    with pytest.raises(DemoRefused, match="uncommitted changes"):
        open_demo_pr("leak", origin.repo.path, origin.tools, now=lambda: NOW)
    assert origin.remote_branches() == ["main"]
    assert origin.local_branches() == ["main"]
    assert origin.gh.called("pr create") == []


@needs_git
def test_demo_pr_refuses_without_a_gh_login(origin: Origin) -> None:
    origin.gh.answers["auth status"] = RunResult(1, "", "not logged in")
    with pytest.raises(DemoRefused, match="gh auth login"):
        open_demo_pr("leak", origin.repo.path, origin.tools, now=lambda: NOW)
    assert origin.remote_branches() == ["main"]


@needs_git
def test_demo_pr_refuses_an_origin_that_is_not_on_github(origin: Origin) -> None:
    origin.repo.git("remote", "set-url", "origin", origin.bare.path.as_posix())
    with pytest.raises(GitHubError, match="not a GitHub repository"):
        open_demo_pr("leak", origin.repo.path, origin.tools, now=lambda: NOW)
    assert origin.remote_branches() == ["main"]


@needs_git
def test_demo_pr_cleans_up_its_worktree_when_gh_fails(origin: Origin) -> None:
    origin.gh.answers["pr create"] = RunResult(1, "", "already exists")
    with pytest.raises(GitHubError, match="gh pr create"):
        open_demo_pr("clean", origin.repo.path, origin.tools, now=lambda: NOW)
    assert len(origin.repo.git("worktree", "list").splitlines()) == 1
    assert origin.repo.git("rev-parse", "main") == origin.bare.git("rev-parse", "main")


@needs_git
def test_the_cli_prints_the_url_and_never_the_token(
    origin: Origin, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from securegate.cli import main

    values = scenarios.fresh_values()
    monkeypatch.setattr(scenarios, "fresh_values", lambda: values)
    monkeypatch.chdir(origin.repo.path)

    code = main(["demo-pr", "leak"], tool_runners={"git": origin.tools.git, "gh": origin.gh})

    printed = capsys.readouterr()
    assert code == 0
    assert PR_URL in printed.out
    shown = any(v in printed.out + printed.err for v in values.values())
    assert not shown


# --- demo-cleanup ---------------------------------------------------------------------------


@needs_git
def test_cleanup_removes_demo_branches_and_pull_requests_only(origin: Origin) -> None:
    for branch in ("demo/leak-1", "demo/clean-2", "feature"):
        origin.repo.git("branch", branch)
        origin.repo.git("push", "-q", "origin", branch)
    origin.repo.git("branch", "demo/local-only")
    origin.gh.answers["pr list"] = RunResult(
        0,
        json.dumps(
            [
                {"number": 3, "headRefName": "demo/leak-1", "isCrossRepository": False},
                {"number": 4, "headRefName": "feature", "isCrossRepository": False},
                {"number": 5, "headRefName": "demo/fork", "isCrossRepository": True},
            ]
        ),
        "",
    )
    origin.gh.on_call["pr close"] = lambda args: origin.bare.git(
        "branch", "-D", "demo/leak-1"
    )  # what --delete-branch does on GitHub

    done = cleanup(origin.repo.path, origin.tools)

    assert done.closed == (3,)
    assert [call[2] for call in origin.gh.called("pr close")] == ["3"]
    assert done.remote_deleted == ("demo/clean-2",)
    assert sorted(done.local_deleted) == ["demo/clean-2", "demo/leak-1", "demo/local-only"]
    assert origin.remote_branches() == ["feature", "main"]
    assert origin.local_branches() == ["feature", "main"]


@needs_git
def test_cleanup_keeps_a_demo_branch_that_is_checked_out(origin: Origin) -> None:
    origin.repo.git("switch", "-q", "-c", "demo/current")
    done = cleanup(origin.repo.path, origin.tools)
    assert done.kept == ("demo/current",)
    assert "demo/current" in origin.local_branches()


@pytest.mark.parametrize(
    ("name", "allowed"),
    [
        ("demo/leak-20261006-093015", True),
        ("demo/secret-gate", True),
        ("main", False),
        ("demo", False),
        ("demo/", False),
        ("demos/leak", False),
        ("demo/../main", False),
        ("refs/heads/main", False),
        ("demo/-x", False),
    ],
)
def test_only_demo_branches_are_ever_touched(name: str, allowed: bool) -> None:
    assert is_demo_branch(name) is allowed


# --- doctor ---------------------------------------------------------------------------------


class FakeGit:
    def __init__(self, url: str | None = GITHUB_URL) -> None:
        self.url = url

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        if args[:2] == ["config", "--get"] and self.url:
            return RunResult(0, self.url + "\n", "")
        return RunResult(1, "", "")


class FakeVersion:
    def __init__(self, version: str | None) -> None:
        self.version = version

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        if self.version is None:
            raise FileNotFoundError("missing")
        return RunResult(0, f"tool {self.version}\n", "")


def _pins() -> dict[str, str]:
    import yaml

    workflow = REPO_ROOT / ".github" / "workflows" / "secret-gate.yml"
    return yaml.safe_load(workflow.read_text(encoding="utf-8"))["env"]


def _doctor(gh: FakeGh, *, root: Path = REPO_ROOT, versions: dict[str, str | None] | None = None):
    pins = _pins()
    found = versions or {
        "gitleaks": pins["GITLEAKS_VERSION"],
        "trufflehog": pins["TRUFFLEHOG_VERSION"],
        "semgrep": pins["SEMGREP_VERSION"],
        "bandit": pins["BANDIT_VERSION"],
    }
    return run_checks(
        root,
        Tools(git=FakeGit(), gh=gh),
        gitleaks_version=lambda: found["gitleaks"],
        tool_runners={
            name: FakeVersion(found[name]) for name in ("trufflehog", "semgrep", "bandit")
        },
    )


def _ready_gh() -> FakeGh:
    gh = FakeGh()
    gh.answers[f"api repos/{SLUG}/contents/.github/workflows/secret-gate.yml?ref=main"] = RunResult(
        0, "{}", ""
    )
    rules = [
        {"type": "pull_request", "parameters": {}},
        {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "secret-gate"}]},
        },
    ]
    gh.answers[f"api repos/{SLUG}/rules/branches/main"] = RunResult(0, json.dumps(rules), "")
    return gh


def test_doctor_passes_when_everything_is_ready() -> None:
    checks = _doctor(_ready_gh())
    assert [c.status for c in checks] == ["PASS"] * 10
    assert exit_code(checks) == 0


def test_doctor_fails_without_the_required_check() -> None:
    gh = _ready_gh()
    gh.answers[f"api repos/{SLUG}/rules/branches/main"] = RunResult(0, "[]", "")
    checks = _doctor(gh)
    assert [(c.name, c.status) for c in checks if c.status != "PASS"] == [
        ("required check", "FAIL")
    ]
    assert exit_code(checks) == 1


def test_doctor_skips_the_rules_it_cannot_read() -> None:
    gh = _ready_gh()
    gh.answers[f"api repos/{SLUG}/rules/branches/main"] = RunResult(1, "", "forbidden")
    checks = _doctor(gh)
    assert [(c.name, c.status) for c in checks if c.status != "PASS"] == [
        ("required check", "SKIP")
    ]
    assert exit_code(checks) == 0


def test_doctor_names_wrong_and_missing_scanner_versions() -> None:
    pins = _pins()
    versions = {
        "gitleaks": "8.0.0",
        "trufflehog": None,
        "semgrep": pins["SEMGREP_VERSION"],
        "bandit": pins["BANDIT_VERSION"],
    }
    checks = _doctor(_ready_gh(), versions=versions)
    failed = {c.name: c.detail for c in checks if c.status == "FAIL"}
    assert set(failed) == {"gitleaks", "trufflehog"}
    assert "8.0.0 installed" in failed["gitleaks"]
    assert "make scanners" in failed["trufflehog"]


def test_doctor_without_gh_login_fails_once_and_skips_github() -> None:
    gh = _ready_gh()
    gh.answers["auth status"] = RunResult(1, "", "")
    checks = _doctor(gh)
    assert [(c.name, c.status) for c in checks[-4:]] == [
        ("gh", "FAIL"),
        ("origin", "SKIP"),
        ("workflow on GitHub", "SKIP"),
        ("required check", "SKIP"),
    ]


def test_doctor_fails_on_a_broken_policy_and_a_missing_workflow(tmp_path: Path) -> None:
    (tmp_path / "policy.yaml").write_text("version: 1\nrules: nope\n", encoding="utf-8")
    checks = _doctor(_ready_gh(), root=tmp_path)
    failed = [c.name for c in checks if c.status == "FAIL"]
    assert failed == ["gitleaks", "trufflehog", "semgrep", "bandit", "policy", "workflow"]


def test_the_doctor_command_prints_one_line_per_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from securegate.cli import main

    monkeypatch.chdir(REPO_ROOT)
    code = main(
        ["doctor"],
        runner=lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()),
        tool_runners={"git": FakeGit(), "gh": _ready_gh()},
    )
    out = capsys.readouterr().out
    assert code == 1  # Gitleaks is "missing" here
    assert out.count("PASS  ") + out.count("FAIL  ") == 10
    assert "FAIL  gitleaks: not installed" in out


# --- ci-report ------------------------------------------------------------------------------


def _ci_gh(report: Path | None, *, status: str = "completed") -> FakeGh:
    gh = FakeGh()
    run = {"databaseId": 42, "headBranch": "demo/leak-1", "conclusion": "failure", "status": status}
    gh.answers["run list"] = RunResult(0, json.dumps([run]), "")
    gh.answers["run view"] = RunResult(0, json.dumps(run), "")

    def download(args: list[str]) -> None:
        if report is not None:
            folder = Path(args[args.index("--dir") + 1])
            shutil.copyfile(report, folder / "findings.json")

    gh.on_call["run download"] = download
    return gh


def test_ci_report_downloads_the_newest_run_and_checks_it(
    sample_report: Path, tmp_path: Path
) -> None:
    gh = _ci_gh(sample_report)
    out = tmp_path / "findings-ci.json"
    done = download_report(tmp_path, Tools(git=FakeGit(), gh=gh), out)
    assert (done.run_id, done.branch, done.conclusion) == (42, "demo/leak-1", "failure")
    assert out.read_bytes() == sample_report.read_bytes()
    (download,) = gh.called("run download")
    assert download[2:6] == ["42", "--repo", SLUG, "--name"]


def test_ci_report_refuses_a_report_that_is_not_masked(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    out = tmp_path / "findings-ci.json"
    with pytest.raises(GitHubError, match="cannot be shown"):
        download_report(tmp_path, Tools(git=FakeGit(), gh=_ci_gh(bad)), out)
    assert not out.exists()


def test_ci_report_waits_for_a_run_that_has_not_finished(tmp_path: Path) -> None:
    gh = _ci_gh(None, status="in_progress")
    with pytest.raises(GitHubError, match="not finished"):
        download_report(tmp_path, Tools(git=FakeGit(), gh=gh), tmp_path / "out.json", 42)
    assert gh.called("run download") == []


def test_ci_report_cli_downloads_without_opening(
    sample_report: Path, run_cli, tmp_path: Path
) -> None:
    result = run_cli(
        "ci-report", "--no-open", tool_runners={"git": FakeGit(), "gh": _ci_gh(sample_report)}
    )
    assert result.exit_code == 0
    assert "run 42 (demo/leak-1, failure)" in result.out
    assert (tmp_path / "findings-ci.json").is_file()


def test_ci_report_fails_closed_when_gh_is_missing(run_cli) -> None:
    def missing(args: list[str], *, cwd: Path | None = None) -> RunResult:
        raise FileNotFoundError("gh")

    result = run_cli("ci-report", "--no-open", tool_runners={"git": FakeGit(), "gh": missing})
    assert result.exit_code == 2
    assert "gh was not found" in result.err
