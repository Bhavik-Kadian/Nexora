"""The gates' configuration files: the laptop gate (.pre-commit-config.yaml) and the merge
gate (.github/workflows/secret-gate.yml)."""

import re
import tomllib

import yaml

from helpers import REPO_ROOT

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


def step(name: str) -> dict:
    (found,) = [s for s in JOB["steps"] if s["name"] == name]
    return found


def step_using(action: str) -> dict:
    (found,) = [s for s in JOB["steps"] if s.get("uses", "").startswith(f"{action}@")]
    return found


def test_runs_on_every_pull_request_and_nothing_else() -> None:
    triggers = SPEC.get("on", SPEC.get(True))  # YAML 1.1 reads the key `on` as True
    assert triggers == {"pull_request": None}  # no path, branch or type filters


def test_can_only_read_the_code() -> None:
    assert SPEC["permissions"] == {"contents": "read"}


def test_one_job_named_secret_gate_on_ubuntu() -> None:
    assert list(SPEC["jobs"]) == ["secret-gate"]
    assert JOB.get("name", "secret-gate") == "secret-gate"
    assert JOB["runs-on"] == "ubuntu-latest"


def test_actions_are_pinned_to_commits_of_their_latest_major_version() -> None:
    pins = re.findall(r"uses: ([\w-]+/[\w-]+)@(\S+) # (v\d+)\.\d+\.\d+", WORKFLOW_TEXT)
    assert sorted(pins) == [
        ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1", "v7"),
        ("actions/setup-python", "5fda3b95a4ea91299a34e894583c3862153e4b97", "v7"),
    ]
    assert WORKFLOW_TEXT.count("uses:") == len(pins)


def test_checkout_reads_the_whole_history_and_python_is_3_12() -> None:
    assert step_using("actions/checkout")["with"]["fetch-depth"] == 0
    assert step_using("actions/setup-python")["with"]["python-version"] == "3.12"


def test_securegate_and_its_rules_come_from_the_base_branch() -> None:
    install = step("Install SecureGate from the base branch")["run"]
    scan = step("Scan every commit in this pull request")["run"]
    assert 'git worktree add --detach "$RUNNER_TEMP/gate" "$BASE_SHA"' in install
    assert "pip install -e ." in install
    assert '--policy "$RUNNER_TEMP/gate/policy.yaml"' in scan
    assert '--gitleaks-config "$RUNNER_TEMP/gate/.gitleaks.toml"' in scan


def test_gitleaks_is_the_version_in_claude_md_and_checksum_verified() -> None:
    claude = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    pinned = re.search(r"Gitleaks (\d+\.\d+\.\d+)", claude)
    install = step("Install Gitleaks (checksum verified)")["run"]

    assert pinned is not None
    assert JOB["env"]["GITLEAKS_VERSION"] == pinned.group(1)
    assert re.fullmatch(r"[0-9a-f]{64}", JOB["env"]["GITLEAKS_CHECKSUMS_SHA256"])
    assert "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}" in install
    assert install.count("sha256sum --check --strict") == 2
    assert install.index("sha256sum") < install.index("tar -xzf")  # checked before it is used


def test_every_commit_of_the_pull_request_is_scanned_and_decides_the_result() -> None:
    scan = step("Scan every commit in this pull request")
    assert JOB["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert JOB["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert scan["run"].startswith('securegate scan . --mode range --range "$BASE_SHA..$HEAD_SHA"')
    assert "continue-on-error" not in scan and "if" not in scan  # its exit code decides


def test_a_summary_is_always_written() -> None:
    summary = step("Write the summary")
    assert summary["if"] == "always()"
    assert summary["continue-on-error"] is True
    assert "securegate summary" in summary["run"]
    assert '>> "$GITHUB_STEP_SUMMARY"' in summary["run"]
    assert JOB["steps"][-1] is summary


def test_every_step_is_explained_in_a_comment() -> None:
    lines = WORKFLOW_TEXT.splitlines()
    unexplained = [
        line.strip()
        for number, line in enumerate(lines)
        if line.strip().startswith("- name:") and not lines[number - 1].strip().startswith("#")
    ]
    assert unexplained == []
