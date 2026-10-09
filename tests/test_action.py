"""The GitHub Action (action.yml): SecureGate's merge gate for any repository. It must install
the same scanners at the same pinned versions as this repository's own gate, judge with rules
the pull request cannot change, and fail closed."""

import re
import tomllib

import pytest
import yaml

from helpers import REPO_ROOT
from securegate import __version__

ACTION_TEXT = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
ACTION = yaml.safe_load(ACTION_TEXT)
STEPS = ACTION["runs"]["steps"]
WORKFLOW_TEXT = (REPO_ROOT / ".github" / "workflows" / "secret-gate.yml").read_text(
    encoding="utf-8"
)
WORKFLOW = yaml.safe_load(WORKFLOW_TEXT)
SCAN = "Scan every commit in this pull request"
AGENTS = "Ask the AI agents (advice only)"
COMMENT = "Post or update the pull request comment"
SARIF = "Upload SARIF to the Security tab"
SAME_REPOSITORY = "github.event.pull_request.head.repo.full_name == github.repository"


def step(name: str) -> dict:
    (found,) = [s for s in STEPS if s["name"] == name]
    return found


def workflow_step(name: str) -> dict:
    (found,) = [s for s in WORKFLOW["jobs"]["secret-gate"]["steps"] if s["name"] == name]
    return found


def test_a_composite_action_whose_scripts_all_run_in_bash() -> None:
    assert ACTION["runs"]["using"] == "composite"
    assert ACTION["name"] == "SecureGate secret gate"
    assert ACTION["branding"] == {"icon": "shield", "color": "green"}
    for found in STEPS:
        if "run" in found:
            assert found["shell"] == "bash", found["name"]


def test_scanner_versions_and_checksums_are_the_workflows() -> None:
    pinned: dict[str, str] = {}
    for found in STEPS:
        pinned.update(found.get("env", {}))
    for variable in (
        "GITLEAKS_VERSION",
        "GITLEAKS_CHECKSUMS_SHA256",
        "TRUFFLEHOG_VERSION",
        "TRUFFLEHOG_CHECKSUMS_SHA256",
        "SEMGREP_VERSION",
        "BANDIT_VERSION",
    ):
        assert pinned[variable] == WORKFLOW["env"][variable], variable


@pytest.mark.parametrize(
    "name",
    [
        "Install Gitleaks (checksum verified)",
        "Install TruffleHog (checksum verified)",
        "Install Semgrep and Bandit (pinned)",
    ],
)
def test_the_scanners_are_installed_word_for_word_like_the_workflow(name: str) -> None:
    assert step(name)["run"] == workflow_step(name)["run"]


def test_actions_are_pinned_to_the_same_commits_as_the_workflow() -> None:
    pin = re.compile(r"uses: ([\w-]+/[\w/-]+)@(\S+) # (v[\d.]+)")
    workflow_pins = {action: (sha, version) for action, sha, version in pin.findall(WORKFLOW_TEXT)}
    action_pins = pin.findall(ACTION_TEXT)  # with the example in the header comment
    assert len(action_pins) == 4
    for action, sha, version in action_pins:
        assert workflow_pins[action] == (sha, version), action
    assert len(re.findall(r"^\s+uses:", ACTION_TEXT, re.M)) == 3  # every step that uses one


def test_securegate_comes_from_the_action_never_from_the_pull_request() -> None:
    install = step("Install SecureGate from the action")["run"]
    assert install == 'pip install "$GITHUB_ACTION_PATH" -c "$GITHUB_ACTION_PATH/constraints.txt"'


def test_the_policy_comes_from_the_base_branch() -> None:
    policy = step("Take the policy from the base branch")
    assert policy["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert 'git show "$BASE_SHA:$wanted" > "$out/policy.yaml"' in policy["run"]
    assert 'cp "$GITHUB_ACTION_PATH/policy.yaml" "$out/policy.yaml"' in policy["run"]
    assert "exit 2" in policy["run"]  # a policy file named but never merged fails closed
    assert ACTION["inputs"]["policy"]["default"] == ""
    names = [found["name"] for found in STEPS]
    assert names.index("Take the policy from the base branch") < names.index(SCAN)


def test_the_scan_is_the_workflows_with_the_actions_own_scanner_rules() -> None:
    scan = step(SCAN)
    command = 'securegate scan . --mode range --range "$BASE_SHA..$HEAD_SHA" --scanners all'
    assert command in scan["run"]
    assert command in workflow_step(SCAN)["run"]
    assert scan["id"] == "scan"
    assert scan["env"] == {
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
    }
    assert 'gate="$GITHUB_ACTION_PATH"' in scan["run"]
    for option in (
        '--policy "$out/policy.yaml"',
        '--gitleaks-config "$gate/.gitleaks.toml"',
        '--trufflehog-config "$gate/.trufflehog.yaml"',
        '--semgrep-rules "$gate/rules/securegate-risky.yml"',
        '--out "$out/findings.json"',
        '--sarif "$out/securegate.sarif"',
        '--summary "$out/summary.md"',
        '--comment "$out/comment.md"',
    ):
        assert option in scan["run"]
    assert "--no-verification" not in scan["run"]  # on GitHub, TruffleHog checks live keys
    assert scan["run"].startswith("set +e")
    assert 'echo "exit_code=$?" >> "$GITHUB_OUTPUT"' in scan["run"]


def test_only_a_pull_request_with_its_base_commit_is_scanned() -> None:
    first = STEPS[0]
    assert first["name"] == "Check the event and the checkout"
    assert "if" not in first  # a failure here skips the scan, so the last step fails
    assert '[ "$EVENT_NAME" != "pull_request" ]' in first["run"]
    assert 'git cat-file -e "${BASE_SHA}^{commit}"' in first["run"]
    assert first["run"].count("exit 2") == 2


def test_the_last_step_passes_or_fails_with_the_saved_exit_code() -> None:
    last = STEPS[-1]
    assert (last["id"], last["if"]) == ("result", "always()")
    assert last["env"]["SCAN_EXIT"] == "${{ steps.scan.outputs.exit_code }}"
    assert 'code="${SCAN_EXIT:-2}"' in last["run"]  # no saved code: the gate fails
    assert last["run"].rstrip().endswith('exit "$code"')
    assert ACTION["outputs"]["exit-code"]["value"] == "${{ steps.result.outputs.exit-code }}"


def test_reports_and_advice_never_decide() -> None:
    for name in ("Write the job summary", SARIF, "Upload findings.json", COMMENT, AGENTS):
        found = step(name)
        assert found["if"].startswith("always()"), name
        assert found["continue-on-error"] is True, name


def test_sarif_and_the_comment_follow_the_workflows_rules() -> None:
    sarif = step(SARIF)
    assert "steps.scan.outputs.exit_code == '0'" in sarif["if"]
    assert "steps.scan.outputs.exit_code == '1'" in sarif["if"]
    assert SAME_REPOSITORY in sarif["if"]  # a fork's token cannot upload
    assert sarif["with"]["category"] == "secret-gate"
    comment = step(COMMENT)
    assert SAME_REPOSITORY in comment["if"]
    assert comment["env"]["GH_TOKEN"] == "${{ inputs.github-token }}"  # noqa: S105 - GitHub's
    assert comment["run"] == workflow_step(COMMENT)["run"]


def test_the_ai_agents_are_asked_only_with_a_key_and_after_the_exit_code_is_saved() -> None:
    agents = step(AGENTS)
    names = [found["name"] for found in STEPS]
    assert names.index(SCAN) < names.index(AGENTS) < names.index("Write the job summary")
    assert "inputs.ai-key != ''" in agents["if"]
    assert "steps.scan.outputs.exit_code == '0'" in agents["if"]
    assert agents["env"]["SECUREGATE_AI_KEY"] == "${{ inputs.ai-key }}"
    assert agents["run"] == workflow_step(AGENTS)["run"]


def test_github_data_never_reaches_a_script_directly() -> None:
    scripts = "\n".join(found.get("run", "") for found in STEPS)
    assert "${{" not in scripts  # everything arrives through env


def test_every_step_is_explained_in_a_comment() -> None:
    lines = ACTION_TEXT.splitlines()
    unexplained = [
        line.strip()
        for number, line in enumerate(lines)
        if line.strip().startswith("- name:") and not lines[number - 1].strip().startswith("#")
    ]
    assert unexplained == []


def test_the_docs_show_the_action_at_this_version() -> None:
    usage = f"uses: Bhavik-Kadian/Nexora@v{__version__}"
    assert usage in ACTION_TEXT
    assert usage in (REPO_ROOT / "docs" / "install.md").read_text(encoding="utf-8")


def test_constraints_pin_every_direct_dependency_at_the_same_version() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    direct = project["dependencies"] + project["optional-dependencies"]["dev"]
    lines = (REPO_ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines()
    pins = {
        name.lower().replace("_", "-"): version
        for name, version in (line.split("==") for line in lines if line and line[0] != "#")
    }
    for requirement in direct:
        name, version = requirement.split("==")
        assert pins[name.lower()] == version, requirement
