"""The gates' configuration files: the laptop gate (.pre-commit-config.yaml) and the merge
gate (.github/workflows/secret-gate.yml)."""

import re
import subprocess
import tomllib

import pytest
import yaml

from helpers import REPO_ROOT
from securegate.programs import find_program

PRE_COMMIT = REPO_ROOT / ".pre-commit-config.yaml"
HOOK_LAUNCHER = REPO_ROOT / "tools" / "precommit_hook.py"


def runtime_dependencies() -> list[str]:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["project"]["dependencies"]


# --- laptop gate --------------------------------------------------------------------------


def test_pre_commit_runs_one_local_securegate_hook() -> None:
    config = yaml.safe_load(PRE_COMMIT.read_text(encoding="utf-8"))
    (repo,) = config["repos"]
    (hook,) = repo["hooks"]

    assert repo["repo"] == "local"
    assert hook["id"] == "securegate"
    assert hook["language"] == "python"
    assert hook["entry"] == "python tools/precommit_hook.py"
    assert (hook["pass_filenames"], hook["always_run"]) == (False, True)
    assert hook["stages"] == ["pre-commit"]


def test_hook_environment_has_what_securegate_needs_to_scan() -> None:
    hook = yaml.safe_load(PRE_COMMIT.read_text(encoding="utf-8"))["repos"][0]["hooks"][0]
    needed = [d for d in runtime_dependencies() if not d.startswith("Flask")]  # the dashboard
    assert hook["additional_dependencies"] == needed


def test_hook_launcher_scans_the_staged_changes() -> None:
    text = HOOK_LAUNCHER.read_text(encoding="utf-8")
    assert '["scan", ".", "--mode", "staged"' in text


def test_make_hooks_installs_the_hook() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"^hooks:\n\t.*-m pre_commit install --install-hooks$", makefile, re.M)


# --- merge gate -----------------------------------------------------------------------------

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "secret-gate.yml"
WORKFLOW_TEXT = WORKFLOW.read_text(encoding="utf-8")
SPEC = yaml.safe_load(WORKFLOW_TEXT)
JOB = SPEC["jobs"]["secret-gate"]
SCAN = "Scan every commit in this pull request"
PINNED_TOOLS = {
    "Gitleaks": "GITLEAKS_VERSION",
    "TruffleHog": "TRUFFLEHOG_VERSION",
    "Semgrep": "SEMGREP_VERSION",
    "Bandit": "BANDIT_VERSION",
}


def step(name: str) -> dict:
    (found,) = [s for s in JOB["steps"] if s["name"] == name]
    return found


def step_using(action: str) -> dict:
    (found,) = [s for s in JOB["steps"] if s.get("uses", "").startswith(f"{action}@")]
    return found


def test_runs_on_every_pull_request_to_main_without_path_filters() -> None:
    triggers = SPEC.get("on", SPEC.get(True))  # YAML 1.1 reads the key `on` as True
    assert triggers == {"pull_request": {"branches": ["main"]}}


def test_one_run_per_pull_request_and_a_new_push_cancels_the_old_one() -> None:
    assert SPEC["concurrency"] == {
        "group": "secret-gate-${{ github.event.pull_request.number }}",
        "cancel-in-progress": True,
    }


def test_reads_the_code_comments_and_uploads_sarif_and_nothing_more() -> None:
    assert SPEC["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
        "security-events": "write",
    }


def test_one_job_named_secret_gate_on_ubuntu_with_a_time_limit() -> None:
    assert list(SPEC["jobs"]) == ["secret-gate"]
    assert JOB.get("name", "secret-gate") == "secret-gate"
    assert (JOB["runs-on"], JOB["timeout-minutes"]) == ("ubuntu-latest", 10)


def test_actions_are_pinned_to_commits_of_their_latest_major_version() -> None:
    pins = re.findall(r"uses: ([\w-]+/[\w/-]+)@(\S+) # (v\d+)\.\d+\.\d+", WORKFLOW_TEXT)
    assert sorted(pins) == [
        ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1", "v7"),
        ("actions/setup-python", "5fda3b95a4ea91299a34e894583c3862153e4b97", "v7"),
        ("actions/upload-artifact", "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7"),
        ("github/codeql-action/upload-sarif", "2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2", "v4"),
    ]
    assert WORKFLOW_TEXT.count("uses:") == len(pins)


def test_checkout_reads_the_whole_history_and_python_is_3_12_with_a_pip_cache() -> None:
    checkout = step_using("actions/checkout")["with"]
    python = step_using("actions/setup-python")["with"]
    assert (checkout["fetch-depth"], checkout["persist-credentials"]) == (0, False)
    assert (python["python-version"], python["cache"]) == ("3.12", "pip")


def test_every_tool_version_is_pinned_once_at_the_top_and_named_in_claude_md() -> None:
    claude = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    env = SPEC["env"]
    for tool, variable in PINNED_TOOLS.items():
        assert f"{tool} {env[variable]}" in claude
        assert variable not in JOB.get("env", {})  # one place only
    for variable in ("GITLEAKS_CHECKSUMS_SHA256", "TRUFFLEHOG_CHECKSUMS_SHA256"):
        assert re.fullmatch(r"[0-9a-f]{64}", env[variable])


@pytest.mark.parametrize(
    ("name", "release"),
    [
        ("Gitleaks", "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"),
        (
            "TruffleHog",
            "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}",
        ),
    ],
)
def test_downloads_are_checked_against_the_pinned_checksums_before_use(
    name: str, release: str
) -> None:
    install = step(f"Install {name} (checksum verified)")["run"]
    assert release in install
    assert install.count("sha256sum --check --strict") == 2
    assert install.index("sha256sum") < install.index("tar -xzf")  # checked before it is used
    assert not re.search(r"\|\s*(sh|bash)\b", install)  # nothing is piped into a shell


def test_semgrep_and_bandit_are_installed_at_their_pinned_versions() -> None:
    install = step("Install Semgrep and Bandit (pinned)")["run"]
    assert '"semgrep==${SEMGREP_VERSION}"' in install
    assert '"bandit==${BANDIT_VERSION}"' in install


def test_securegate_and_its_rules_come_from_the_base_branch() -> None:
    install = step("Install SecureGate from the base branch")["run"]
    scan = step(SCAN)["run"]
    assert 'git worktree add --detach "$RUNNER_TEMP/gate" "$BASE_SHA"' in install
    assert "pip install -e ." in install
    assert 'gate="$RUNNER_TEMP/gate"' in scan
    for option in (
        '--policy "$gate/policy.yaml"',
        '--gitleaks-config "$gate/.gitleaks.toml"',
        '--trufflehog-config "$gate/.trufflehog.yaml"',
        '--semgrep-rules "$gate/rules/securegate-risky.yml"',
    ):
        assert option in scan


def test_the_scan_judges_every_commit_with_four_scanners_and_saves_its_exit_code() -> None:
    scan = step(SCAN)
    command = 'securegate scan . --mode range --range "$BASE_SHA..$HEAD_SHA" --scanners all'
    assert JOB["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert JOB["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert scan["id"] == "scan"
    assert command in scan["run"]
    for option in ("--sarif", "--summary", "--comment", "--out"):
        assert option in scan["run"]
    assert "--no-verification" not in scan["run"]  # on GitHub, TruffleHog checks live keys
    assert scan["run"].startswith("set +e")
    assert 'echo "exit_code=$?" >> "$GITHUB_OUTPUT"' in scan["run"]


def test_summary_sarif_and_findings_are_always_kept_and_never_decide() -> None:
    names = ("Write the job summary", "Upload SARIF to the Security tab", "Upload findings.json")
    for name in names:
        found = step(name)
        assert found["if"].startswith("always()")
        assert found["continue-on-error"] is True
    assert '>> "$GITHUB_STEP_SUMMARY"' in step("Write the job summary")["run"]
    assert step_using("actions/upload-artifact")["with"]["name"] == "findings"


def test_sarif_is_uploaded_only_after_a_finished_scan_and_never_from_forks() -> None:
    upload = step("Upload SARIF to the Security tab")
    assert "steps.scan.outputs.exit_code == '0'" in upload["if"]
    assert "steps.scan.outputs.exit_code == '1'" in upload["if"]
    assert "env.FROM_FORK == 'false'" in upload["if"]
    assert upload["with"]["category"] == "secret-gate"


def test_the_comment_is_posted_or_updated_with_the_job_token_except_for_forks() -> None:
    comment = step("Post or update the pull request comment")
    assert comment["if"] == "always() && env.FROM_FORK == 'false'"
    assert comment["continue-on-error"] is True
    assert comment["env"]["GH_TOKEN"] == "${{ github.token }}"  # noqa: S105 - GitHub fills it in
    assert "<!-- securegate:pr-comment -->" in comment["run"]
    assert "--method PATCH" in comment["run"] and "--method POST" in comment["run"]
    assert JOB["env"]["FROM_FORK"] == (
        "${{ github.event.pull_request.head.repo.full_name != github.repository }}"
    )


def test_the_last_step_passes_or_fails_with_the_saved_exit_code() -> None:
    last = JOB["steps"][-1]
    assert last["if"] == "always()"
    assert last["env"]["SCAN_EXIT"] == "${{ steps.scan.outputs.exit_code }}"
    assert 'code="${SCAN_EXIT:-2}"' in last["run"]  # no saved code: the gate fails
    assert last["run"].rstrip().endswith('exit "$code"')


def test_github_data_never_reaches_a_script_directly() -> None:
    scripts = "\n".join(s.get("run", "") for s in JOB["steps"])
    assert "${{" not in scripts  # everything arrives through env


def test_every_step_is_explained_in_a_comment() -> None:
    lines = WORKFLOW_TEXT.splitlines()
    unexplained = [
        line.strip()
        for number, line in enumerate(lines)
        if line.strip().startswith("- name:") and not lines[number - 1].strip().startswith("#")
    ]
    assert unexplained == []


@pytest.mark.skipif(not find_program("actionlint"), reason="actionlint is not installed")
def test_actionlint_finds_no_problem() -> None:
    done = subprocess.run(
        [str(find_program("actionlint")), str(WORKFLOW)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert (done.returncode, done.stdout) == (0, "")
