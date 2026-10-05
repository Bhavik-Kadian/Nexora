"""The files Semgrep and Bandit read: a private copy of the code as it is at head.

Semgrep and Bandit look at code, not at history, so they get the files of one commit: in a
range scan, the files the range changed that still exist at its end; in a repo scan, every
tracked file at HEAD. The copy comes from Git (`git archive`), not from the working tree, so it
is exactly the commit being judged, and it lives in a private temporary folder.

Files that only tell scanners what to skip (.semgrepignore, .gitignore, .bandit) are left out,
and an empty .semgrepignore is written instead, so a pull request cannot hide code from them.
"""

import io
import subprocess
import tarfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from securegate.errors import ScannerError
from securegate.programs import find_program

LEFT_OUT = frozenset({".semgrepignore", ".gitignore", ".bandit"})
CHUNK = 200  # paths per `git archive` run, far below Windows' command-line limit
TIMEOUT_SECONDS = 5 * 60

Git = Callable[[list[str]], bytes]
"""Runs `git <args>` in the scanned repository and returns its output. Raises ScannerError."""


@dataclass(frozen=True, slots=True)
class Snapshot:
    folder: Path  # the private copy
    files: tuple[str, ...]  # the copied files, relative, with "/" separators


def git_runner(repo: Path) -> Git:
    """The real git, found on PATH, run inside `repo`."""

    def run(args: list[str]) -> bytes:
        program = find_program("git")
        if program is None:
            raise ScannerError("git was not found")
        try:
            done = subprocess.run(  # noqa: S603 - absolute program path; arguments built by us
                [str(program), "-C", str(repo), *args],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(f"git {args[0]} did not finish in time") from None
        except OSError as err:
            raise ScannerError(f"could not start git: {err}") from None
        if done.returncode != 0:
            raise ScannerError(f"git {args[0]} failed (exit code {done.returncode})")
        return done.stdout

    return run


def changed_files(git: Git, base: str, head: str) -> list[str]:
    """Files that the commits from `base` to `head` added or changed and that still exist."""
    out = git(["diff", "--name-only", "-z", "--diff-filter=d", f"{base}...{head}"])
    return [path for path in out.decode("utf-8", "replace").split("\0") if path]


def tracked_files(git: Git, ref: str) -> list[str]:
    out = git(["ls-tree", "-r", "-z", "--name-only", ref])
    return [path for path in out.decode("utf-8", "replace").split("\0") if path]


def take_snapshot(git: Git, ref: str, paths: Sequence[str], folder: Path) -> Snapshot:
    """Copy `paths` as they are at `ref` into `folder`."""
    wanted = [path for path in paths if _copyable(path)]
    for start in range(0, len(wanted), CHUNK):
        chunk = wanted[start : start + CHUNK]
        data = git(["--literal-pathspecs", "archive", "--format=tar", ref, "--", *chunk])
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            tar.extractall(folder, filter="data")  # refuses absolute paths and outside links
    (folder / ".semgrepignore").write_text("", encoding="utf-8")  # skip nothing
    return Snapshot(folder, tuple(path for path in wanted if (folder / path).is_file()))


def _copyable(path: str) -> bool:
    """A plain relative path that is not a scanner's ignore file. Backslashes and colons are
    refused too: on Windows they would mean another folder or a drive."""
    parts = PurePosixPath(path).parts
    return (
        bool(parts)
        and not path.startswith("/")
        and ".." not in parts
        and "\\" not in path
        and ":" not in path
        and parts[-1] not in LEFT_OUT
    )
