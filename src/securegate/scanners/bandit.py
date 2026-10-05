"""Bandit adapter: runs Bandit's hardcoded-password checks on the Python files of a private
copy of the code, and returns raw candidates.

Bandit runs three tests: B105 (a password string), B106 (a password passed to a function) and
B107 (a password as a default argument). Of its output only the test id, the file and the line
are kept. `code` quotes the line and its neighbours, and `issue_text` quotes the password itself
("Possible hardcoded password: '...'"): neither is ever kept. The password is taken out of
issue_text in memory, only for the pipeline to mask it; reports describe the finding by its
test id.

Bandit is optional: when it fails, the scan goes on and the report says that it did not run.
"""

import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from securegate.errors import ScannerError
from securegate.scanners.candidate import Candidate
from securegate.scanners.changes import Snapshot
from securegate.scanners.common import (
    ProgramRunner,
    RunResult,
    ToolRunner,
    help_flags,
    missing_flags,
    parse_version,
)

DETECTOR = "bandit"
TESTS = ("B105", "B106", "B107")
TIMEOUT_SECONDS = 5 * 60
NAMES_PER_RUN = 8000  # characters of file names per run, far below Windows' command-line limit
# --ignore-nosec: a `# nosec` comment cannot hide a finding. --exit-zero: Bandit's exit code
# then means "it ran" (0) or "it failed", instead of mixing failures with findings.
REQUIRED_FLAGS = ("--format", "--quiet", "--tests", "--ignore-nosec", "--exit-zero")
_PASSWORD = re.compile(r": '(.*)'$", re.DOTALL)


@dataclass(frozen=True, slots=True)
class BanditOutput:
    version: str
    candidates: list[Candidate]  # raw values inside
    note: str | None  # what Bandit could not do, for the report


def subprocess_runner() -> ToolRunner:
    """The real runner: the bandit program found on PATH or in .venv's scripts folder."""
    return ProgramRunner("bandit", TIMEOUT_SECONDS)


def scan(snapshot: Snapshot, *, runner: ToolRunner) -> BanditOutput:
    """Run Bandit on the Python files of the private copy. Raises ScannerError on failure."""
    version, flags = probe(runner)
    missing = missing_flags(REQUIRED_FLAGS, flags)
    if missing:
        raise ScannerError(f"the installed Bandit lacks {', '.join(missing)}")
    files = [file for file in snapshot.files if file.endswith(".py")]
    candidates: list[Candidate] = []
    unread = 0
    for chunk in _chunks(files):
        result = _call(runner, build_command(chunk), cwd=snapshot.folder)
        if result.returncode != 0:
            raise ScannerError(f"it failed (exit code {result.returncode})")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise ScannerError("its output is not JSON") from None
        if not isinstance(data, dict):
            raise ScannerError("its output is not a report")
        candidates += parse_results(data)
        errors = data.get("errors")
        unread += len(errors) if isinstance(errors, list) else 0
    note = f"it could not read {unread} file{'s' if unread != 1 else ''}" if unread else None
    return BanditOutput(version, candidates, note)


def probe(runner: ToolRunner) -> tuple[str, frozenset[str]]:
    version_run = _call(runner, ["--version"])
    help_run = _call(runner, ["--help"])
    if version_run.returncode != 0 or help_run.returncode != 0:
        raise ScannerError("it does not answer --version or --help")
    version = parse_version(version_run.stdout + version_run.stderr) or "unknown"
    return version, help_flags(help_run.stdout + help_run.stderr)


def build_command(files: Sequence[str]) -> list[str]:
    return ["-f", "json", "-q", "-t", ",".join(TESTS), "--ignore-nosec", "--exit-zero", *files]


def parse_results(data: dict[str, object]) -> list[Candidate]:
    results = data.get("results")
    if not isinstance(results, list):
        raise ScannerError("its output has no list of results")
    return [_candidate(item, number) for number, item in enumerate(results, start=1)]


# --- helpers ---------------------------------------------------------------------------------


def _call(runner: ToolRunner, args: list[str], cwd: Path | None = None) -> RunResult:
    try:
        return runner(args, cwd=cwd)
    except FileNotFoundError:
        raise ScannerError("it is not installed (run `make scanners`)") from None


def _chunks(files: Sequence[str]) -> Iterator[list[str]]:
    chunk: list[str] = []
    size = 0
    for file in files:
        if chunk and size + len(file) > NAMES_PER_RUN:
            yield chunk
            chunk, size = [], 0
        chunk.append(file)
        size += len(file) + 1
    if chunk:
        yield chunk


def _candidate(item: object, number: int) -> Candidate:
    where = f"Bandit result #{number}"
    if not isinstance(item, dict):
        raise ScannerError(f"{where} is not an object")
    test_id, filename, line = item.get("test_id"), item.get("filename"), item.get("line_number")
    issue_text = item.get("issue_text")
    if not (
        isinstance(test_id, str)
        and test_id
        and isinstance(filename, str)
        and filename
        and isinstance(line, int)
        and not isinstance(line, bool)
    ):
        raise ScannerError(f"{where} lacks a test, file or line")
    file = filename.replace("\\", "/").removeprefix("./")
    rule = f"bandit-{test_id}"
    found = _PASSWORD.search(issue_text) if isinstance(issue_text, str) else None
    if found and found.group(1):
        value, code = found.group(1), False
    else:  # no password to show: name the place, and show none of it
        value, code = f"{rule}@{file}:{line}", True
    return Candidate(
        rule_id=rule,
        file=file,
        line=max(line, 1),
        commit=None,  # Bandit reads the files at head, not a commit of the history
        author=None,
        date=None,
        value=value,
        detector=DETECTOR,
        code=code,
    )
