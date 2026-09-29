"""The adapter against the real Gitleaks binary: proves our flags work with the installed version.

Skipped when Gitleaks is not installed. Convention: raw test values never appear inside an assert.
"""

import json
from pathlib import Path

import pytest

from helpers import fake_acme_token, git_installed, gitleaks_installed, scan_args

pytestmark = pytest.mark.skipif(
    not (gitleaks_installed() and git_installed()), reason="gitleaks or git is not installed"
)


def _visible(value: str, result) -> bool:
    return value in result.out or value in result.err or value in json.dumps(result.report)


def test_repo_mode_finds_a_committed_key(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("README.md", "demo\n")
    repo.commit("first")
    token = fake_acme_token()
    repo.write("app/pay.py", f'ACME_PAY_KEY = "{token}"\n')
    sha = repo.commit("add payments")

    result = run_cli(*scan_args(repo.path, mode="repo"))

    assert result.exit_code == 1
    (finding,) = result.findings
    assert (finding["rule"], finding["file"], finding["line"], finding["commit"]) == (
        "acme-pay-token",
        "app/pay.py",
        1,
        sha,
    )
    assert (finding["decision"], finding["author"]) == ("block", "Test Author")
    assert not _visible(token, result)


def test_repo_mode_on_a_clean_repo_exits_0(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("README.md", "nothing secret here\n")
    repo.commit("first")
    result = run_cli(*scan_args(repo.path, mode="repo"))
    assert result.exit_code == 0
    assert result.findings == []


def test_a_key_deleted_later_is_still_found_in_history(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("scripts/once.py", f'KEY = "{fake_acme_token()}"\n')
    added = repo.commit("one-off script")
    (repo.path / "scripts" / "once.py").unlink()
    repo.commit("remove one-off script")

    history = run_cli(*scan_args(repo.path, mode="repo"))
    on_disk = run_cli(*scan_args(repo.path, mode="dir"))

    assert history.exit_code == 1
    assert [f["commit"] for f in history.findings] == [added]
    assert on_disk.exit_code == 0


def test_range_mode_scans_only_the_given_commits(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("README.md", "demo\n")
    base = repo.commit("first")
    repo.write("app/pay.py", f'ACME_PAY_KEY = "{fake_acme_token()}"\n')
    with_key = repo.commit("add key")
    repo.write("app/other.py", "print('hello')\n")
    repo.commit("unrelated")

    including = run_cli(*scan_args(repo.path, mode="range"), f"--range={base}..HEAD")
    excluding = run_cli(*scan_args(repo.path, mode="range"), f"--range={with_key}..HEAD")

    assert including.exit_code == 1
    assert excluding.exit_code == 0


def test_staged_mode_scans_only_staged_changes(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("README.md", "demo\n")
    repo.commit("first")
    repo.write("app/pay.py", f'ACME_PAY_KEY = "{fake_acme_token()}"\n')

    unstaged = run_cli(*scan_args(repo.path, mode="staged"))
    repo.git("add", "app/pay.py")
    staged = run_cli(*scan_args(repo.path, mode="staged"))

    assert unstaged.exit_code == 0
    assert staged.exit_code == 1
    assert [(f["file"], f["commit"], f["date"]) for f in staged.findings] == [
        ("app/pay.py", None, None)
    ]


def test_dir_mode_reports_paths_relative_to_the_folder(run_cli, tmp_path: Path) -> None:
    folder = tmp_path / "plain"
    (folder / "config").mkdir(parents=True)
    (folder / "config" / "app.py").write_text(
        f'ACME_PAY_KEY = "{fake_acme_token()}"\n', encoding="utf-8"
    )
    result = run_cli(*scan_args(folder, mode="dir"))
    assert result.exit_code == 1
    assert [(f["file"], f["line"], f["commit"]) for f in result.findings] == [
        ("config/app.py", 1, None)
    ]


def test_repo_mode_on_a_plain_folder_fails_closed(run_cli, tmp_path: Path) -> None:
    # Gitleaks itself exits 0 here and only logs an error; SecureGate must not report a pass.
    folder = tmp_path / "not-a-repo"
    folder.mkdir()
    result = run_cli(*scan_args(folder, mode="repo"))
    assert result.exit_code == 2
    assert "not a Git repository" in result.err


def test_gitleaks_allow_comments_do_not_hide_findings(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("app/pay.py", f'ACME_PAY_KEY = "{fake_acme_token()}"  # gitleaks:allow\n')
    repo.commit("sneaky")
    result = run_cli(*scan_args(repo.path, mode="repo"))
    assert result.exit_code == 1


def test_repo_with_a_gitleaksignore_is_refused(run_cli, make_repo) -> None:
    repo = make_repo()
    repo.write("app/pay.py", f'ACME_PAY_KEY = "{fake_acme_token()}"\n')
    repo.write(".gitleaksignore", "anything\n")
    repo.commit("hide it")
    result = run_cli(*scan_args(repo.path, mode="repo"))
    assert result.exit_code == 2
    assert ".gitleaksignore" in result.err
