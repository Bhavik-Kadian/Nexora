"""A scripted stand-in for the trufflehog program, so adapter tests need no binary.

It answers `--version` and `git --help` like TruffleHog 3.97.9 (including kingpin's `--[no-]x`
spelling of switches). For a scan it prints the configured JSON lines and returns the
configured exit code. Every field that can hold the secret (Raw, RawV2, Redacted, ExtraData,
SecretParts, VerificationError) is filled with the planted value, so tests can prove that
SecureGate keeps none of them.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from securegate.scanners.common import RunResult

SWITCHES = [
    "help",
    "json",
    "no-verification",
    "no-color",
    "no-ignore-tag",
    "no-update",
    "fail",
    "fail-on-scan-errors",
    "bare",
    "trust-local-git-config",
]
VALUED = [
    "log-level=0",
    "results=RESULTS",
    "config=CONFIG",
    "concurrency=N",
    "since-commit=SINCE-COMMIT",
    "branch=BRANCH",
    "max-depth=MAX-DEPTH",
]


def git_help(without: Sequence[str] = ()) -> str:
    """`trufflehog git --help`, optionally missing some flags (named without dashes)."""
    lines = ["usage: trufflehog git [<flags>] <uri>", "", "Flags:"]
    lines += [f"      --[no-]{name}   a switch" for name in SWITCHES if name not in without]
    lines += [f"      --{spec}   a value" for spec in VALUED if spec.split("=")[0] not in without]
    return "\n".join(lines) + "\n"


def finding(
    *,
    file: str,
    line: int,
    value: str,
    commit: str = "",
    detector: str = "Stripe",
    custom_name: str | None = None,
    verified: bool = False,
    verification_error: bool = False,
    email: str = "Riya Demo <riya@example.com>",
    timestamp: str = "2025-06-03 09:00:00 +0000",
) -> dict[str, object]:
    """One JSON line, shaped like TruffleHog 3.97.9 output, with the secret in every field
    that can carry it."""
    data: dict[str, object] = {
        "SourceMetadata": {
            "Data": {
                "Git": {
                    "commit": commit,
                    "file": file,
                    "email": email,
                    "repository": "file:///tmp/repo",
                    "timestamp": timestamp,
                    "line": line,
                    "repository_local_path": "trufflehog-clone-1",
                }
            }
        },
        "SourceID": 1,
        "SourceType": 16,
        "SourceName": "trufflehog - git",
        "DetectorType": 904 if custom_name else 17,
        "DetectorName": "CustomRegex" if custom_name else detector,
        "DetectorDescription": "test entry",
        "DecoderName": "PLAIN",
        "Verified": verified,
        "VerificationFromCache": False,
        "Raw": value,
        "RawV2": value + ":" + value,
        "Redacted": value,
        "ExtraData": {"name": custom_name} if custom_name else {"account": value},
        "StructuredData": None,
        "SecretParts": {"key": value},
    }
    if verification_error:
        data["VerificationError"] = f"request with {value} failed"
    return data


@dataclass
class FakeTruffleHog:
    """Configure what TruffleHog "finds", then pass the instance as the trufflehog runner."""

    findings: list[dict[str, object]] = field(default_factory=list)
    exit_code: int = 0
    stderr: str = ""
    stdout_noise: list[str] = field(default_factory=list)  # extra non-JSON stdout lines
    version: str = "3.97.9"
    help_without: Sequence[str] = ()
    missing: bool = False
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        self.calls.append(list(args))
        if self.missing:
            raise FileNotFoundError("trufflehog")
        if args == ["--version"]:
            return RunResult(0, f"trufflehog {self.version}\n", "")
        if args == ["git", "--help"]:
            return RunResult(0, git_help(self.help_without), "")
        lines = [*self.stdout_noise, *(json.dumps(item) for item in self.findings)]
        return RunResult(self.exit_code, "\n".join(lines) + ("\n" if lines else ""), self.stderr)

    @property
    def scan_args(self) -> list[str]:
        """The arguments of the scan itself (not the version or help questions)."""
        (scan,) = [c for c in self.calls if c not in (["--version"], ["git", "--help"])]
        return scan
