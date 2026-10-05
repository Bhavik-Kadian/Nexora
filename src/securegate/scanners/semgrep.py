"""Semgrep adapter: runs Semgrep on a private copy of the code and returns raw candidates.

Semgrep reads code at head, not history. It runs two rule sets: p/secrets from the Semgrep
registry (secret formats) and SecureGate's rules/securegate-risky.yml (code that handles a
secret in a risky way). If p/secrets cannot be downloaded, SecureGate runs its own rules alone
and says so.

Of Semgrep's output only the rule id, the file and the position are read. `extra.lines` and
`extra.message` quote the code, and so the secret: they are never kept. The value is cut out of
SecureGate's own copy of the file, in memory, and handed to securegate.pipeline.

Semgrep is optional: when it fails, the scan goes on and the report says that it did not run.
"""

import json
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

DETECTOR = "semgrep"
REGISTRY = "p/secrets"
TIMEOUT_SECONDS = 10 * 60
OUR_RULES_PREFIX = "securegate-"  # rules/securegate-risky.yml: code findings, not secrets
OFFLINE_NOTE = "it could not load p/secrets (no internet?), so it ran SecureGate's own rules only"
# --disable-nosem: a `# nosemgrep` comment cannot hide a finding. --no-rewrite-rule-ids keeps
# rule ids as written. --project-root makes the private copy the project, so only the empty
# .semgrepignore there applies (Semgrep would otherwise skip tests/ and more by default).
REQUIRED_FLAGS = (
    "--config",
    "--json",
    "--metrics",
    "--disable-version-check",
    "--disable-nosem",
    "--no-git-ignore",
    "--no-rewrite-rule-ids",
    "--project-root",
)
QUOTES = "\"'`"


@dataclass(frozen=True, slots=True)
class SemgrepOutput:
    version: str
    candidates: list[Candidate]  # raw values inside
    note: str | None  # what Semgrep could not do, for the report


def subprocess_runner() -> ToolRunner:
    """The real runner: the semgrep program found on PATH or in .venv's scripts folder."""
    return ProgramRunner("semgrep", TIMEOUT_SECONDS)


def scan(
    snapshot: Snapshot, *, rules: Path, runner: ToolRunner, registry: bool = True
) -> SemgrepOutput:
    """Run Semgrep on the private copy. Raises ScannerError when it cannot run at all."""
    if not rules.is_file():
        raise ScannerError(f"its rules file {rules} was not found")
    version, flags = probe(runner)
    missing = missing_flags(REQUIRED_FLAGS, flags)
    if missing:
        raise ScannerError(f"the installed Semgrep lacks {', '.join(missing)}")
    ours = str(rules.resolve())
    data, exit_code = _run(runner, [REGISTRY, ours] if registry else [ours], snapshot)
    note = None
    if data is None and registry:
        data, exit_code = _run(runner, [ours], snapshot)
        note = OFFLINE_NOTE
    if data is None:
        raise ScannerError(f"it failed (exit code {exit_code})")
    return SemgrepOutput(version, parse_results(data, snapshot), _with_unread(note, data))


def probe(runner: ToolRunner) -> tuple[str, frozenset[str]]:
    version_run = _call(runner, ["--version"])
    help_run = _call(runner, ["scan", "--help"])
    if version_run.returncode != 0 or help_run.returncode != 0:
        raise ScannerError("it does not answer --version or --help")
    version = parse_version(version_run.stdout + version_run.stderr) or "unknown"
    return version, help_flags(help_run.stdout + help_run.stderr)


def build_command(configs: list[str]) -> list[str]:
    """`semgrep scan` on the current folder (the private copy), with SecureGate's flags."""
    args = ["scan"]
    for config in configs:
        args += ["--config", config]
    return [
        *args,
        "--json",
        "--metrics",
        "off",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        "--no-rewrite-rule-ids",
        "--project-root",
        ".",
        ".",
    ]


def parse_results(data: dict[str, object], snapshot: Snapshot) -> list[Candidate]:
    """Turn Semgrep's results into candidates: rule id, file and position, and the value cut
    out of the private copy."""
    results = data.get("results")
    if not isinstance(results, list):
        raise ScannerError("its output has no list of results")
    return [_candidate(item, number, snapshot) for number, item in enumerate(results, start=1)]


def rule_id(check_id: str) -> str:
    """generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key becomes
    detected-stripe-api-key; our own rule ids have no dots and stay as they are."""
    return check_id.rsplit(".", 1)[-1]


# --- helpers ---------------------------------------------------------------------------------


def _call(runner: ToolRunner, args: list[str], cwd: Path | None = None) -> RunResult:
    try:
        return runner(args, cwd=cwd)
    except FileNotFoundError:
        raise ScannerError("it is not installed (run `make scanners`)") from None


def _run(
    runner: ToolRunner, configs: list[str], snapshot: Snapshot
) -> tuple[dict[str, object] | None, int]:
    """Semgrep's JSON, or None when it failed. Semgrep exits 0 when it ran, findings or not."""
    result = _call(runner, build_command(configs), cwd=snapshot.folder)
    if result.returncode != 0:
        return None, result.returncode
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, result.returncode
    return (data, 0) if isinstance(data, dict) else (None, 0)


def _with_unread(note: str | None, data: dict[str, object]) -> str | None:
    """Add how many files Semgrep could not read (syntax errors and the like)."""
    errors = data.get("errors")
    unread = len(errors) if isinstance(errors, list) else 0
    if not unread:
        return note
    extra = f"it could not read {unread} file{'s' if unread != 1 else ''}"
    return f"{note}; {extra}" if note else extra


def _candidate(item: object, number: int, snapshot: Snapshot) -> Candidate:
    where = f"Semgrep result #{number}"
    if not isinstance(item, dict):
        raise ScannerError(f"{where} is not an object")
    check_id, path = item.get("check_id"), item.get("path")
    start, end = item.get("start"), item.get("end")
    if not (
        isinstance(check_id, str)
        and check_id
        and isinstance(path, str)
        and path
        and isinstance(start, dict)
        and isinstance(end, dict)
    ):
        raise ScannerError(f"{where} lacks a rule, file or position")
    line = _int(start.get("line"), where)
    begin, finish = _int(start.get("offset"), where), _int(end.get("offset"), where)
    file = path.replace("\\", "/").removeprefix("./")
    rule = rule_id(check_id)
    span = _read_span(snapshot, file, begin, finish, where)
    code = rule.startswith(OUR_RULES_PREFIX)
    value = span if code else span.strip().strip(QUOTES)
    if not value:  # nothing to show or fingerprint: name the place instead
        value, code = f"{rule}@{file}:{line}", True
    return Candidate(
        rule_id=rule,
        file=file,
        line=max(line, 1),
        commit=None,  # Semgrep reads the files at head, not a commit of the history
        author=None,
        date=None,
        value=value,
        detector=DETECTOR,
        code=code,
    )


def _int(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScannerError(f"{where} has no line or offsets")
    return value


def _read_span(snapshot: Snapshot, file: str, begin: int, finish: int, where: str) -> str:
    folder = snapshot.folder.resolve()
    source = (folder / file).resolve()
    if not source.is_relative_to(folder) or not source.is_file():
        raise ScannerError(f"{where} points outside the scanned files")
    data = source.read_bytes()
    if not 0 <= begin <= finish <= len(data):
        raise ScannerError(f"{where} has offsets outside its file")
    return data[begin:finish].decode("utf-8", "replace")
