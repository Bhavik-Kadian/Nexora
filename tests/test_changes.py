"""The private copy of the code that Semgrep and Bandit read (scanners/changes.py), real git."""

from pathlib import Path

import pytest

from helpers import GitRepo, git_installed
from securegate.errors import ScannerError
from securegate.scanners import changes

pytestmark = pytest.mark.skipif(not git_installed(), reason="git is not installed")


def branch_with_changes(repo: GitRepo) -> tuple[str, str]:
    """main has three files; a branch adds, changes and deletes some, and main moves on."""
    repo.write("keep.py", "x = 1\n")
    repo.write("change.py", "y = 1\n")
    repo.write("gone.py", "z = 1\n")
    repo.commit("start")
    repo.git("switch", "-q", "-c", "feature")
    repo.write("added.py", "a = 1\n")
    repo.write("change.py", "y = 2\n")
    (repo.path / "gone.py").unlink()
    repo.write(".semgrepignore", "*.py\n")
    repo.write("tests/test_a.py", "t = 1\n")
    head = repo.commit("feature work")
    repo.git("switch", "-q", "main")
    repo.write("main_only.py", "m = 1\n")
    moved = repo.commit("main moves on")
    return moved, head


def test_changed_files_are_those_of_the_branch_that_still_exist(make_repo) -> None:
    repo = make_repo()
    base, head = branch_with_changes(repo)
    git = changes.git_runner(repo.path)
    assert sorted(changes.changed_files(git, base, head)) == [
        ".semgrepignore",
        "added.py",
        "change.py",
        "tests/test_a.py",
    ]


def test_the_copy_holds_the_files_at_head_and_never_their_ignore_files(
    make_repo, tmp_path: Path
) -> None:
    repo = make_repo()
    base, head = branch_with_changes(repo)
    repo.write("change.py", "y = 3  # not committed\n")  # the working tree must not matter
    git = changes.git_runner(repo.path)

    snapshot = changes.take_snapshot(git, head, changes.changed_files(git, base, head), tmp_path)

    assert snapshot.files == ("added.py", "change.py", "tests/test_a.py")
    assert (tmp_path / "change.py").read_text(encoding="utf-8") == "y = 2\n"
    assert (tmp_path / ".semgrepignore").read_text(encoding="utf-8") == ""  # ours: skip nothing


def test_repo_mode_copies_every_tracked_file_at_head(make_repo, tmp_path: Path) -> None:
    repo = make_repo()
    repo.write("a.py", "a = 1\n")
    repo.write("pkg/b.py", "b = 1\n")
    repo.write("pkg/.gitignore", "*.log\n")
    repo.commit("files")
    git = changes.git_runner(repo.path)

    snapshot = changes.take_snapshot(git, "HEAD", changes.tracked_files(git, "HEAD"), tmp_path)

    assert snapshot.files == ("a.py", "pkg/b.py")
    assert not (tmp_path / "pkg" / ".gitignore").exists()


def test_names_with_pattern_characters_are_copied_literally(make_repo, tmp_path: Path) -> None:
    repo = make_repo()
    repo.write("weird[1].py", "w = 1\n")  # as a pattern, [1] would also match weird1.py
    repo.write("weird1.py", "v = 1\n")
    repo.commit("odd names")
    git = changes.git_runner(repo.path)

    snapshot = changes.take_snapshot(git, "HEAD", ["weird[1].py"], tmp_path)

    assert snapshot.files == ("weird[1].py",)
    assert not (tmp_path / "weird1.py").exists()


@pytest.mark.parametrize(
    "path", ["../outside.py", "/abs.py", "a\\b.py", "c:/x.py", ".gitignore", "sub/.bandit", ""]
)
def test_unsafe_or_ignore_paths_are_never_copied(path: str) -> None:
    assert not changes._copyable(path)


def test_a_git_failure_is_a_scanner_error(make_repo) -> None:
    repo = make_repo()
    git = changes.git_runner(repo.path)
    with pytest.raises(ScannerError, match="git diff failed"):
        changes.changed_files(git, "no-such-base", "no-such-head")
