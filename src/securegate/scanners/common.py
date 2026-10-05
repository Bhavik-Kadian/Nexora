"""What the scanner adapters share: running a program, reading its flags, saying how it went."""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from securegate.errors import ScannerError
from securegate.programs import find_program

Status = Literal["ran", "did_not_run", "skipped"]

# `--json`, and kingpin's spelling of on/off switches, `--[no-]json`: both mean the flag exists.
_FLAG_PATTERN = re.compile(r"--(?:\[no-\])?([a-z0-9][a-z0-9-]*)")
_VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")


@dataclass(frozen=True, slots=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


class ToolRunner(Protocol):
    """Runs one program with `args`, optionally inside `cwd`.

    Raises FileNotFoundError when the program is not installed. Tests pass fakes instead.
    """

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult: ...


@dataclass(frozen=True, slots=True)
class ScannerRun:
    """How one scanner fared in a scan, for findings.json and the reports."""

    name: str  # gitleaks, trufflehog, semgrep or bandit
    version: str | None
    required: bool  # a required scanner that fails stops the scan (exit code 2)
    status: Status
    # Why it did not run or was skipped, or what it could not do: a short lowercase phrase,
    # such as "live checks switched off with --no-verification".
    note: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "required": self.required,
            "status": self.status,
            "note": self.note,
        }


class ProgramRunner:
    """The real runner for one program, found on PATH or in .venv's scripts folder (never in the
    current folder). Output is read as UTF-8; a run longer than `timeout` seconds is an error."""

    def __init__(self, program: str, timeout: int) -> None:
        self.program = program
        self.timeout = timeout

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        found = find_program(self.program)
        if found is None:
            raise FileNotFoundError(self.program)
        try:
            proc = subprocess.run(  # noqa: S603 - absolute program path; arguments built by us
                [str(found), *args],
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(
                f"{self.program} did not finish within {self.timeout // 60} minutes"
            ) from None
        except OSError as err:
            raise ScannerError(f"could not start {self.program} ({found}): {err}") from None
        return RunResult(proc.returncode, proc.stdout, proc.stderr)


def help_flags(help_text: str) -> frozenset[str]:
    """Every --flag named in a program's help text, written as --name."""
    return frozenset(f"--{name}" for name in _FLAG_PATTERN.findall(help_text))


def parse_version(text: str) -> str | None:
    found = _VERSION_PATTERN.search(text)
    return found.group(0) if found else None


def missing_flags(needed: tuple[str, ...], available: frozenset[str]) -> list[str]:
    return [flag for flag in needed if flag not in available]
