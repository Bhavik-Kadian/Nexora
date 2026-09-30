"""The laptop gate: a staged scan that blocks a commit says where, what (masked), why and how
to fix it, and never shows the raw token.

Convention: raw test values never appear inside an assert.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fake_gitleaks import FakeGitleaks, entry
from helpers import (
    GITLEAKS_CONFIG,
    POLICY_FILE,
    REPO_ROOT,
    fake_acme_token,
    git_installed,
    gitleaks_installed,
    scan_args,
)
from securegate.mask import mask_value

needs_gitleaks = pytest.mark.skipif(
    not (gitleaks_installed() and git_installed()), reason="gitleaks or git is not installed"
)


def assert_blocked_message(output: str, location: str, masked: str) -> None:
    lines = output.splitlines()
    start = lines.index("Blocked:")
    assert lines[start + 1].split() == [location, masked]
    assert lines[start + 2].startswith("    why: provider-keys: ")
    assert lines[start + 3].startswith("    fix: Treat it as leaked.")


def test_staged_block_message_with_a_fake_scanner(run_cli, tmp_path: Path) -> None:
    token = fake_acme_token()
    fake = FakeGitleaks(
        report=[entry(rule="acme-pay-token", file="app/pay.py", line=3, value=token)]
    )

    result = run_cli(*scan_args(tmp_path, mode="staged"), runner=fake)

    assert result.exit_code == 1
    assert "--staged" in fake.scan_args
    assert_blocked_message(result.out, "app/pay.py:3", mask_value(token))
    token_visible = token in result.out + result.err + str(result.report)
    assert not token_visible


@needs_gitleaks
def test_staged_block_message_with_real_gitleaks(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("README.md", "demo\n")
    repo.commit("first")
    token = fake_acme_token()
    repo.write("app/pay.py", f'ACME_PAY_API_KEY = "{token}"\n')
    repo.git("add", "app/pay.py")

    result = run_cli(*scan_args(repo.path, mode="staged"))

    assert result.exit_code == 1
    assert_blocked_message(result.out, "app/pay.py:1", mask_value(token))
    token_visible = token in result.out + result.err + str(result.report)
    assert not token_visible


@needs_gitleaks
@pytest.mark.parametrize("stage_a_token", [True, False])
def test_the_hook_launcher_blocks_only_staged_secrets(make_repo, stage_a_token: bool) -> None:
    repo = make_repo()
    shutil.copy(POLICY_FILE, repo.path / "policy.yaml")
    shutil.copy(GITLEAKS_CONFIG, repo.path / ".gitleaks.toml")
    token = fake_acme_token()
    repo.write("app/pay.py", f'ACME_PAY_API_KEY = "{token}"\n')  # on disk either way
    if stage_a_token:
        repo.git("add", "app/pay.py")

    done = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "precommit_hook.py")],
        cwd=repo.path,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    report = (repo.path / ".securegate" / "staged-findings.json").read_text(encoding="utf-8")

    assert done.returncode == (1 if stage_a_token else 0)
    if stage_a_token:
        assert_blocked_message(done.stdout, "app/pay.py:1", mask_value(token))
    token_visible = token in done.stdout + done.stderr + report
    assert not token_visible
