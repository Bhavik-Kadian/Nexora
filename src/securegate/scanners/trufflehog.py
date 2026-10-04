"""TruffleHog adapter: runs TruffleHog over the Git history and returns raw candidates.

TruffleHog can ask the provider whether a key it found still works, which Gitleaks cannot. It
prints one JSON object per finding. Raw values stay in memory: only `Raw` is read (or `RawV2`
when `Raw` is empty), and only to hand it to securegate.pipeline, which masks it at once.
`Redacted`, `ExtraData`, `StructuredData`, `SecretParts` and the text of `VerificationError`
can also hold the secret and are never kept. TruffleHog's logs (stderr) are never shown, apart
from the fixed message of an error-level log line.

TruffleHog runs through an injected runner, so tests can replace the real program.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from securegate.errors import ConfigError, ScannerError
from securegate.finding import Validity
from securegate.scanners.candidate import Candidate
from securegate.scanners.common import (
    ProgramRunner,
    RunResult,
    ToolRunner,
    help_flags,
    missing_flags,
    parse_version,
)

DETECTOR = "trufflehog"
TIMEOUT_SECONDS = 20 * 60
RESULTS = "verified,unknown,unverified"  # everything except results TruffleHog would filter
INSTALL_HINT = (
    "Install it with `make scanners`, which checks the download against TruffleHog's release "
    "checksums, or put trufflehog on PATH."
)
# Flags SecureGate cannot work safely without: --no-ignore-tag stops a `trufflehog:ignore`
# comment from hiding a finding, --fail-on-scan-errors turns a partial scan into an error, and
# --no-update stops TruffleHog from replacing itself with a version nobody pinned.
REQUIRED_FLAGS = (
    "--json",
    "--no-update",
    "--no-ignore-tag",
    "--fail-on-scan-errors",
    "--results",
    "--no-verification",
    "--config",
    "--since-commit",
    "--branch",
)
_RANGE_SPLIT = re.compile(r"\.{2,3}")
_SLUG = re.compile(r"[^a-z0-9]+")


class TruffleHogNotFound(ScannerError):
    """The trufflehog program is not installed."""


@dataclass(frozen=True, slots=True)
class TruffleHogOutput:
    version: str
    candidates: list[Candidate]  # raw values inside


def subprocess_runner() -> ToolRunner:
    """The real runner: the trufflehog program found on PATH or in .venv's scripts folder."""
    return ProgramRunner("trufflehog", TIMEOUT_SECONDS)


def scan(
    target: Path,
    *,
    runner: ToolRunner,
    log_range: str | None,
    config: Path | None,
    verify: bool,
) -> TruffleHogOutput:
    """Scan the Git history of `target` (all of it, or the commits in `log_range`)."""
    if config is not None and not config.is_file():
        raise ConfigError(
            f"TruffleHog config not found: {config} (run from the SecureGate folder, "
            "or pass --trufflehog-config)"
        )
    version, flags = probe(runner)
    base, head = split_range(log_range) if log_range else (None, None)
    args = build_command(
        target,
        base=base,
        head=head,
        config=config.resolve() if config else None,
        verify=verify,
        flags=flags,
    )
    result = _run(runner, args)
    if result.returncode != 0:
        raise ScannerError(
            f"TruffleHog failed (exit code {result.returncode}){error_messages(result.stderr)}"
        )
    return TruffleHogOutput(version, parse_output(result.stdout, verify=verify))


def probe(runner: ToolRunner) -> tuple[str, frozenset[str]]:
    """TruffleHog's version, and the flags `trufflehog git` supports."""
    version_run = _run(runner, ["--version"])
    if version_run.returncode != 0:
        raise ScannerError(f"`trufflehog --version` failed (exit code {version_run.returncode})")
    help_run = _run(runner, ["git", "--help"])
    if help_run.returncode != 0:
        raise ScannerError(f"`trufflehog git --help` failed (exit code {help_run.returncode})")
    version = parse_version(version_run.stdout + version_run.stderr) or "unknown"
    return version, help_flags(help_run.stdout + help_run.stderr)


def build_command(
    target: Path,
    *,
    base: str | None,
    head: str | None,
    config: Path | None,
    verify: bool,
    flags: frozenset[str],
) -> list[str]:
    """The TruffleHog arguments for one scan, using only flags this version has."""
    missing = missing_flags(REQUIRED_FLAGS, flags)
    if missing:
        raise ScannerError(
            f"the installed TruffleHog does not support {', '.join(missing)}, which SecureGate "
            "needs. Install the pinned version with `make scanners`."
        )
    args = ["git", repo_uri(target)]
    if base is not None and head is not None:
        args += ["--since-commit", base, "--branch", head]
    args += [
        "--json",
        "--no-update",
        "--no-ignore-tag",
        "--fail-on-scan-errors",
        f"--results={RESULTS}",
    ]
    if not verify:
        args.append("--no-verification")
    if config is not None:
        args += ["--config", str(config)]
    return args


def repo_uri(target: Path) -> str:
    """file:///home/me/repo on Linux and macOS, file://C:/Users/me/repo on Windows."""
    return "file://" + target.resolve().as_posix()


def split_range(log_range: str) -> tuple[str, str]:
    """A..B or A...B (already checked by the Gitleaks adapter) becomes (A, B)."""
    base, head = _RANGE_SPLIT.split(log_range, maxsplit=1)
    return base, head


def parse_output(stdout: str, *, verify: bool) -> list[Candidate]:
    """Turn TruffleHog's JSON lines into candidates.

    Lines that are not JSON objects are skipped (TruffleHog logs to stderr, but nothing else on
    stdout may be trusted to be a finding); a line that starts like JSON but cannot be read is
    an error, so a garbled report can never pass as a clean scan.
    """
    candidates = []
    for number, line in enumerate(stdout.splitlines(), start=1):
        text = line.strip()
        if not text.startswith("{"):
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise ScannerError(f"TruffleHog output line {number} is not valid JSON") from None
        candidates.append(_candidate(data, number, verify))
    return candidates


def error_messages(stderr: str, limit: int = 3) -> str:
    """The fixed `msg` of TruffleHog's error-level log lines. Their other fields are never
    shown: error details can quote a request, and a request can carry the key."""
    messages = []
    for line in stderr.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("level") == "error":
            message = data.get("msg")
            if isinstance(message, str) and message.strip():
                messages.append(message.strip()[:120])
    if not messages:
        return ""
    return ": " + " | ".join(messages[-limit:])


# --- helpers ---------------------------------------------------------------------------------


def _run(runner: ToolRunner, args: list[str]) -> RunResult:
    try:
        return runner(args)
    except FileNotFoundError:
        raise TruffleHogNotFound(f"TruffleHog was not found. {INSTALL_HINT}") from None


def _candidate(data: object, number: int, verify: bool) -> Candidate:
    where = f"TruffleHog finding on output line {number}"
    if not isinstance(data, dict):
        raise ScannerError(f"{where} is not an object")
    git = _git_metadata(data)
    if git is None:
        raise ScannerError(f"{where} has no Git location")
    file, line = git.get("file"), git.get("line")
    if not isinstance(file, str) or not file or isinstance(line, bool) or not isinstance(line, int):
        raise ScannerError(f"{where} lacks a file or line")
    value = _first_text(data.get("Raw"), data.get("RawV2"))
    if value is None:
        raise ScannerError(f"{where} has no value")
    return Candidate(
        rule_id=rule_id(data),
        file=file.replace("\\", "/"),
        line=max(line, 1),  # TruffleHog says 0 when it cannot tell; point at the first line
        commit=_text_or_none(git.get("commit")),
        author=_author(git.get("email")),
        date=_date(git.get("timestamp")),
        value=value,
        detector=DETECTOR,
        validity=validity(data, verify),
    )


def rule_id(data: dict[str, object]) -> str:
    """trufflehog-<detector>, such as trufflehog-stripe. A custom detector from our config
    (DetectorName CustomRegex) is named by its `name`, such as trufflehog-acme-pay-token."""
    name = data.get("DetectorName")
    if name == "CustomRegex":
        extra = data.get("ExtraData")
        custom = extra.get("name") if isinstance(extra, dict) else None
        name = custom if isinstance(custom, str) and custom else name
    slug = _SLUG.sub("-", name.lower()).strip("-") if isinstance(name, str) else ""
    return f"trufflehog-{slug or 'unknown'}"


def validity(data: dict[str, object], verify: bool) -> Validity:
    if not verify:
        return "not_checked"
    if data.get("Verified") is True:
        return "verified"
    error = data.get("VerificationError")
    if isinstance(error, str) and error.strip():
        return "unknown"
    return "unverified"


def _git_metadata(data: dict[str, object]) -> dict[str, object] | None:
    found: object = data
    for key in ("SourceMetadata", "Data", "Git"):
        found = found.get(key) if isinstance(found, dict) else None
    return found if isinstance(found, dict) else None


def _first_text(*values: object) -> str | None:
    return next((v for v in values if isinstance(v, str) and v), None)


def _text_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _author(email: object) -> str | None:
    """'Riya Demo <riya@example.com>' becomes 'Riya Demo'. A bare address is not kept."""
    if not isinstance(email, str) or "<" not in email:
        return None
    return email.split("<", 1)[0].strip() or None


def _date(timestamp: object) -> str | None:
    """'2025-06-02 09:00:00 +0000' becomes '2025-06-02T09:00:00Z'."""
    if not isinstance(timestamp, str):
        return None
    try:
        moment = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return None
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
