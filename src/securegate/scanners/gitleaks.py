"""Gitleaks adapter: runs Gitleaks and returns what it found as raw candidates.

Raw values stay in memory. The JSON report is written into a private temporary folder, read
once, and deleted together with the folder; it is never logged or printed. Only
securegate.pipeline should call scan(), because the candidates it returns hold raw values.

Gitleaks runs through an injected `runner`, so tests can replace the real program.
"""

import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, get_args

from securegate.errors import ConfigError, ScannerError

Mode = Literal["repo", "range", "staged", "dir"]
MODES: tuple[Mode, ...] = get_args(Mode)

DETECTOR = "gitleaks"
LEAKS_EXIT_CODE = 99  # passed as --exit-code, because Gitleaks uses 1 for both leaks and errors
TIMEOUT_SECONDS = 30 * 60
REPORT_NAME = "report.json"
ZERO_DATE = "0001-01-01T00:00:00Z"  # what Gitleaks reports when there is no commit date
INSTALL_HINT = (
    "Install Gitleaks (Windows: winget install Gitleaks.Gitleaks, macOS: brew install gitleaks) "
    "and make sure it is on PATH."
)

# Flags SecureGate cannot work safely without. --log-level and --no-banner keep stderr empty on
# success, which is how failures that still exit 0 are caught.
REQUIRED_FLAGS = (
    "--config",
    "--report-format",
    "--report-path",
    "--exit-code",
    "--no-banner",
    "--log-level",
    "--ignore-gitleaks-allow",
    "--gitleaks-ignore-path",
)
MODE_FLAGS: dict[Mode, tuple[str, ...]] = {
    "repo": (),
    "range": ("--log-opts",),
    "staged": ("--pre-commit", "--staged"),
    "dir": (),
}
# A commit range such as main..feature or abc123...def456: no spaces, no leading "-", so it
# cannot smuggle extra options into `git log`.
_REF = r"[A-Za-z0-9_][A-Za-z0-9_./~^@{}-]*"
RANGE_PATTERN = re.compile(rf"{_REF}\.\.\.?{_REF}")
_FLAG_PATTERN = re.compile(r"--[a-z0-9][a-z0-9-]*")
_VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")
_ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


class GitleaksNotFound(ScannerError):
    """The gitleaks program is not installed or not on PATH."""


@dataclass(frozen=True, slots=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str]], RunResult]
"""Runs `gitleaks <args>`. Raises GitleaksNotFound (or FileNotFoundError) if it is missing."""


@dataclass(frozen=True, slots=True)
class Candidate:
    """One raw finding. `value` is the raw secret: never print, log or store it."""

    rule_id: str
    file: str
    line: int
    commit: str | None
    author: str | None
    date: str | None
    value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class GitleaksInfo:
    version: str
    flags: dict[str, frozenset[str]]  # "git" / "dir" -> flags listed by `gitleaks <cmd> --help`


@dataclass(frozen=True, slots=True)
class ScanOutput:
    gitleaks_version: str
    candidates: list[Candidate]  # raw values inside


# --- the real runner -------------------------------------------------------------------------


def find_gitleaks(path_env: str | None = None) -> Path:
    """Find the gitleaks program in the PATH folders.

    Relative PATH entries such as "." are skipped: a scanned repository could contain a fake
    gitleaks program, and Windows would otherwise run it from the current folder.
    """
    names = ("gitleaks.exe", "gitleaks") if os.name == "nt" else ("gitleaks",)
    search = os.environ.get("PATH", "") if path_env is None else path_env
    for folder in search.split(os.pathsep):
        if not folder or not os.path.isabs(folder):
            continue
        for name in names:
            candidate = Path(folder) / name
            if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                return candidate
    raise GitleaksNotFound(f"Gitleaks was not found. {INSTALL_HINT}")


def subprocess_runner(args: Sequence[str]) -> RunResult:
    """The real runner: runs the gitleaks program found on PATH."""
    program = find_gitleaks()
    try:
        proc = subprocess.run(  # noqa: S603 - absolute program path; arguments from build_command
            [str(program), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ScannerError(
            f"Gitleaks did not finish within {TIMEOUT_SECONDS // 60} minutes"
        ) from None
    except OSError as err:
        raise ScannerError(f"could not start Gitleaks ({program}): {err}") from None
    return RunResult(proc.returncode, proc.stdout, proc.stderr)


# --- scanning --------------------------------------------------------------------------------


def scan(
    target: Path,
    mode: Mode,
    *,
    config: Path,
    runner: Runner,
    log_range: str | None = None,
) -> ScanOutput:
    """Run Gitleaks on `target` and return raw candidates (for securegate.pipeline only)."""
    _check_arguments(target, mode, config, log_range)
    target = target.resolve()
    _refuse_gitleaksignore(target)
    info = probe(runner)
    command = "dir" if mode == "dir" else "git"
    try:
        with tempfile.TemporaryDirectory(prefix="securegate-") as tmp:
            report = Path(tmp) / REPORT_NAME
            args = build_command(
                mode,
                target,
                config=config.resolve(),
                report=report,
                ignore_dir=Path(tmp),
                flags=info.flags[command],
                log_range=log_range,
            )
            result = _run(runner, args)
            _check_outcome(result, target)
            candidates = parse_report(_read_report(report), base=target if mode == "dir" else None)
    except OSError as err:  # includes a temporary folder that could not be created or deleted
        raise ScannerError(f"problem with the temporary report folder: {err}") from None
    if result.returncode == LEAKS_EXIT_CODE and not candidates:
        raise ScannerError("Gitleaks said it found leaks, but its report is empty")
    return ScanOutput(info.version, candidates)


def probe(runner: Runner) -> GitleaksInfo:
    """Ask Gitleaks for its version and for the flags each command supports."""
    version_run = _run(runner, ["version"])
    if version_run.returncode != 0:
        raise ScannerError(
            f"`gitleaks version` failed (exit code {version_run.returncode})"
            f"{_stderr_tail(version_run.stderr)}"
        )
    flags: dict[str, frozenset[str]] = {}
    for command in ("git", "dir"):
        help_run = _run(runner, [command, "--help"])
        if help_run.returncode != 0:
            raise ScannerError(
                f"`gitleaks {command} --help` failed (exit code {help_run.returncode})"
            )
        flags[command] = frozenset(_FLAG_PATTERN.findall(help_run.stdout))
    return GitleaksInfo(_parse_version(version_run.stdout), flags)


def gitleaks_version(runner: Runner) -> str | None:
    """The installed Gitleaks version, or None when Gitleaks is missing or broken."""
    try:
        result = _run(runner, ["version"])
    except ScannerError:
        return None
    return _parse_version(result.stdout) if result.returncode == 0 else None


def build_command(
    mode: Mode,
    target: Path,
    *,
    config: Path,
    report: Path,
    ignore_dir: Path,
    flags: frozenset[str],
    log_range: str | None,
) -> list[str]:
    """The Gitleaks arguments for one scan, using only flags this Gitleaks version has."""
    missing = [flag for flag in (*REQUIRED_FLAGS, *MODE_FLAGS[mode]) if flag not in flags]
    if missing:
        raise ScannerError(
            f"the installed Gitleaks does not support {', '.join(missing)}, which SecureGate "
            f"needs for {mode} mode. Please upgrade Gitleaks (SecureGate is tested with 8.30.1)."
        )
    args = ["dir" if mode == "dir" else "git", str(target)]
    if mode == "range":
        args.append(f"--log-opts={log_range}")
    elif mode == "staged":
        args += ["--pre-commit", "--staged"]
    args += [
        "--config", str(config),
        "--report-format", "json",
        "--report-path", str(report),
        "--exit-code", str(LEAKS_EXIT_CODE),
        "--no-banner",
        "--log-level", "error",
        "--ignore-gitleaks-allow",
        "--gitleaks-ignore-path", str(ignore_dir),
    ]  # fmt: skip
    if "--no-color" in flags:
        args.append("--no-color")
    return args


def parse_report(text: str, *, base: Path | None) -> list[Candidate]:
    """Turn the report into candidates, reading only the fields we need.

    Match and Secret hold the secret; only Secret (or Match when Secret is empty) is kept, in
    memory. `base` is the scanned folder in dir mode, used to make paths relative.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        raise ScannerError(
            f"the Gitleaks report is not valid JSON ({err.msg} at line {err.lineno})"
        ) from None
    if not isinstance(data, list):
        raise ScannerError("the Gitleaks report is not a list of findings")
    return [_candidate(entry, number, base) for number, entry in enumerate(data, start=1)]


def validate_range(log_range: str | None) -> str:
    if log_range is None:
        raise ConfigError("--mode range needs --range, for example --range main..feature")
    if not RANGE_PATTERN.fullmatch(log_range):
        raise ConfigError(
            f"--range '{log_range}' is not a commit range. Use A..B or A...B, where A and B "
            "are commits, branches or tags (no spaces, not starting with '-')."
        )
    return log_range


# --- helpers ---------------------------------------------------------------------------------


def _check_arguments(target: Path, mode: Mode, config: Path, log_range: str | None) -> None:
    if mode not in MODES:
        raise ConfigError(f"unknown mode '{mode}'; use one of: {', '.join(MODES)}")
    if mode == "range":
        validate_range(log_range)
    elif log_range is not None:
        raise ConfigError("--range only works with --mode range")
    if not target.exists():
        raise ConfigError(f"nothing to scan: {target} does not exist")
    if not config.is_file():
        raise ConfigError(
            f"Gitleaks config not found: {config} (run from the SecureGate folder, "
            "or pass --gitleaks-config)"
        )


def _refuse_gitleaksignore(target: Path) -> None:
    ignore_file = target / ".gitleaksignore"
    if ignore_file.exists():
        raise ScannerError(
            f"{ignore_file} exists. Gitleaks would silently skip the findings listed in it, "
            "so SecureGate's policy could not see them. Move those exceptions into "
            "policy.yaml and delete the file."
        )


def _run(runner: Runner, args: Sequence[str]) -> RunResult:
    try:
        return runner(args)
    except FileNotFoundError:
        raise GitleaksNotFound(f"Gitleaks was not found. {INSTALL_HINT}") from None


def _check_outcome(result: RunResult, target: Path) -> None:
    if result.returncode not in (0, LEAKS_EXIT_CODE):
        raise ScannerError(
            f"Gitleaks failed (exit code {result.returncode}){_stderr_tail(result.stderr)}"
        )
    if result.stderr.strip():
        # With --log-level error, Gitleaks writes to stderr only when something went wrong,
        # yet it may still exit 0 (for example on a folder that is not a Git repository).
        hint = ""
        if "not a git repository" in result.stderr.lower():
            hint = f" {target} is not a Git repository; use --mode dir for plain folders."
        raise ScannerError(f"Gitleaks reported an error{_stderr_tail(result.stderr)}.{hint}")


def _read_report(report: Path) -> str:
    try:
        return report.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ScannerError("Gitleaks did not write its report") from None
    except (OSError, UnicodeDecodeError) as err:
        raise ScannerError(f"cannot read the Gitleaks report ({type(err).__name__})") from None


def _candidate(entry: object, number: int, base: Path | None) -> Candidate:
    if not isinstance(entry, dict):
        raise ScannerError(f"Gitleaks report entry #{number} is not an object")
    rule_id, file, line = entry.get("RuleID"), entry.get("File"), entry.get("StartLine")
    if (
        not isinstance(rule_id, str)
        or not rule_id
        or not isinstance(file, str)
        or not file
        or not isinstance(line, int)
        or isinstance(line, bool)
    ):
        raise ScannerError(f"Gitleaks report entry #{number} lacks RuleID, File or StartLine")
    secret, match = entry.get("Secret"), entry.get("Match")
    if isinstance(secret, str) and secret:
        value = secret
    else:
        value = match if isinstance(match, str) else ""
    date = _text_or_none(entry.get("Date"))
    return Candidate(
        rule_id=rule_id,
        file=_relative_posix(file, base),
        line=line,
        commit=_text_or_none(entry.get("Commit")),
        author=_text_or_none(entry.get("Author")),
        date=None if date == ZERO_DATE else date,
        value=value,
    )


def _relative_posix(reported: str, base: Path | None) -> str:
    """Use '/' separators; in dir mode, make the path relative to the scanned folder."""
    path = reported.replace("\\", "/")
    if base is None:
        return path  # Git modes already report paths relative to the repository root
    folder = base if base.is_dir() else base.parent
    prefix = folder.as_posix().rstrip("/") + "/"
    head = path[: len(prefix)]
    if head == prefix or (os.name == "nt" and head.lower() == prefix.lower()):
        return path[len(prefix) :]
    return path


def _text_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _parse_version(stdout: str) -> str:
    found = _VERSION_PATTERN.search(stdout)
    return found.group(0) if found else (stdout.strip()[:40] or "unknown")


def _stderr_tail(stderr: str, lines: int = 3, width: int = 200) -> str:
    """The last few stderr lines, shortened. Gitleaks logs never contain secret values at
    --log-level error, and the report itself is never shown."""
    kept = [_ANSI_PATTERN.sub("", line).strip() for line in stderr.splitlines() if line.strip()]
    if not kept:
        return ""
    return ": " + " | ".join(line[:width] for line in kept[-lines:])
