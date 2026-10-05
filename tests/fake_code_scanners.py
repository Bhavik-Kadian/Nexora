"""Scripted stand-ins for the semgrep and bandit programs, so tests need neither.

They answer --version and --help like Semgrep 1.179.0 and Bandit 1.9.4. For a scan they read
the private copy they are run in (cwd), find each configured value in its file, and report it
the way the real program would, including the fields that quote the secret (Semgrep's
extra.lines and extra.message, Bandit's code and issue_text), so tests can prove SecureGate
keeps none of them.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from securegate.scanners.common import RunResult

SEMGREP_FLAGS = [
    "--config=VAL",
    "--json",
    "--metrics=ENUM",
    "--disable-version-check",
    "--disable-nosem",
    "--no-git-ignore",
    "--no-rewrite-rule-ids",
    "--project-root=VAL",
    "--quiet",
]
BANDIT_FLAGS = ["--format", "--quiet", "--tests", "--ignore-nosec", "--exit-zero", "--recursive"]


@dataclass(frozen=True)
class Spot:
    """Something a fake scanner reports: `text` is searched for in `file`."""

    rule: str  # Semgrep check_id, or Bandit test id such as B105
    file: str
    text: str  # the exact text to point at (for Bandit: the password)


def _locate(folder: Path, spot: Spot) -> tuple[int, int, int, str]:
    """Byte offsets, line number and the full line of `spot.text` in its file."""
    data = (folder / spot.file).read_bytes()
    start = data.index(spot.text.encode("utf-8"))
    end = start + len(spot.text.encode("utf-8"))
    line = data.count(b"\n", 0, start) + 1
    full_line = data.splitlines()[line - 1].decode("utf-8")
    return start, end, line, full_line


@dataclass
class FakeSemgrep:
    spots: list[Spot] = field(default_factory=list)
    exit_code: int = 0
    registry_offline: bool = False  # a scan that asks for p/secrets fails, like without internet
    errors: int = 0  # files Semgrep "could not read"
    help_without: tuple[str, ...] = ()
    missing: bool = False
    calls: list[list[str]] = field(default_factory=list)
    seen: list[list[str]] = field(default_factory=list)  # the files in the copy, per scan

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        self.calls.append(list(args))
        if self.missing:
            raise FileNotFoundError("semgrep")
        if cwd is not None:
            self.seen.append(
                sorted(p.relative_to(cwd).as_posix() for p in cwd.rglob("*") if p.is_file())
            )
        if args == ["--version"]:
            return RunResult(0, "1.179.0\n", "")
        if args == ["scan", "--help"]:
            flags = [f for f in SEMGREP_FLAGS if f.split("=")[0] not in self.help_without]
            return RunResult(0, "\n".join(f"       {f}\n           a flag" for f in flags), "")
        if self.registry_offline and "p/secrets" in args:
            return RunResult(2, "", "requests.exceptions.ProxyError: semgrep.dev unreachable\n")
        if self.exit_code:
            return RunResult(self.exit_code, "", "Semgrep crashed\n")
        assert cwd is not None
        results = []
        for spot in self.spots:
            start, end, line, full_line = _locate(cwd, spot)
            results.append(
                {
                    "check_id": spot.rule,
                    "path": spot.file.replace("/", "\\"),
                    "start": {"line": line, "col": 1, "offset": start},
                    "end": {"line": line, "col": 2, "offset": end},
                    "extra": {
                        "lines": full_line,
                        "message": f"found {spot.text}",
                        "metadata": {},
                        "severity": "WARNING",
                    },
                }
            )
        errors = [{"type": "Syntax error", "level": "warn"} for _ in range(self.errors)]
        data = {"results": results, "errors": errors, "paths": {"scanned": []}, "version": "1"}
        return RunResult(0, json.dumps(data), "")

    @property
    def scans(self) -> list[list[str]]:
        return [c for c in self.calls if c[:1] == ["scan"] and c != ["scan", "--help"]]

    def configs(self, scan: list[str]) -> list[str]:
        return [scan[i + 1] for i, arg in enumerate(scan) if arg == "--config"]


@dataclass
class FakeBandit:
    spots: list[Spot] = field(default_factory=list)
    exit_code: int = 0
    garbled: bool = False
    unreadable: list[str] = field(default_factory=list)  # files reported in "errors"
    missing: bool = False
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        self.calls.append(list(args))
        if self.missing:
            raise FileNotFoundError("bandit")
        if args == ["--version"]:
            return RunResult(0, "bandit 1.9.4\n  python version = 3.12.10\n", "")
        if args == ["--help"]:
            return RunResult(0, "\n".join(f"  {flag} VALUE   a flag" for flag in BANDIT_FLAGS), "")
        if self.exit_code:
            return RunResult(self.exit_code, "", "bandit crashed\n")
        if self.garbled:
            return RunResult(0, "{ not json", "")
        assert cwd is not None
        targets = [a for a in args if a.endswith(".py")]
        results = []
        for spot in self.spots:
            if spot.file not in targets:
                continue
            _, _, line, full_line = _locate(cwd, spot)
            results.append(
                {
                    "test_id": spot.rule,
                    "filename": ".\\" + spot.file.replace("/", "\\"),
                    "line_number": line,
                    "issue_text": f"Possible hardcoded password: '{spot.text}'",
                    "code": f"{line} {full_line}\n",
                    "issue_severity": "LOW",
                    "issue_confidence": "MEDIUM",
                }
            )
        errors = [{"filename": f, "reason": "syntax error"} for f in self.unreadable]
        return RunResult(0, json.dumps({"results": results, "errors": errors}), "")

    @property
    def scans(self) -> list[list[str]]:
        return [c for c in self.calls if c[:1] == ["-f"]]
