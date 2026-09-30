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
