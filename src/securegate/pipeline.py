"""The pipeline: raw candidates -> entropy -> policy -> masked, fingerprinted Findings.

This is the boundary for raw values. The scanners' raw candidates come in, Findings (masked
value and fingerprint only) go out, and no raw value ever leaves these functions.

Gitleaks always runs. More scanners can join (`ScannerSetup`); each candidate is decided by the
policy on its own, then findings of the same secret or line are merged (securegate.merge).
TruffleHog is required like Gitleaks: if it is asked for and fails, the scan fails (exit 2).
Semgrep and Bandit are optional: if one fails, the scan goes on and records that it did not run.
"""

import tarfile
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from securegate import confidence
from securegate.entropy import shannon_entropy
from securegate.errors import ConfigError, ScannerError
from securegate.finding import Finding
from securegate.mask import protect
from securegate.merge import merge_findings
from securegate.policy import Policy, decide
from securegate.scanners import bandit, changes, gitleaks, semgrep, trufflehog
from securegate.scanners.candidate import Candidate
from securegate.scanners.common import ScannerRun, ToolRunner
from securegate.validate import did_you_mean

DECISION_ORDER = {"block": 0, "warn": 1, "ignore": 2}
SCANNERS = ("gitleaks", "trufflehog", "semgrep", "bandit")  # the order they run and are listed
REQUIRED = frozenset({"gitleaks", "trufflehog"})
CODE_SCANNERS = ("semgrep", "bandit")  # they read the code at head, from a private copy
HISTORY_MODES = ("repo", "range")  # the modes that have a Git history to scan
LABELS = {
    "gitleaks": "Gitleaks",
    "trufflehog": "TruffleHog",
    "semgrep": "Semgrep",
    "bandit": "Bandit",
}


@dataclass(frozen=True, slots=True)
class ScannerSetup:
    """Which scanners run besides Gitleaks, and how. The default runs Gitleaks only."""

    extra: tuple[str, ...] = ()  # from SCANNERS, without gitleaks
    runners: Mapping[str, ToolRunner] = field(default_factory=dict)  # tests pass fakes
    trufflehog_config: Path | None = None
    verify: bool = True  # let TruffleHog ask providers whether keys are live
    semgrep_rules: Path | None = None  # rules/securegate-risky.yml

    def runner(self, name: str, real: Callable[[], ToolRunner]) -> ToolRunner:
        return self.runners.get(name) or real()


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding]
    scanner_version: str  # Gitleaks
    scanner_runs: tuple[ScannerRun, ...] = ()  # how each scanner fared


def parse_scanners(text: str) -> tuple[str, ...]:
    """`all`, or a comma-separated list that includes gitleaks. Returns the scanners to run
    besides Gitleaks, in their usual order."""
    wanted = text.strip().lower()
    names = SCANNERS if wanted == "all" else [p.strip() for p in wanted.split(",") if p.strip()]
    for name in names:
        if name not in SCANNERS:
            raise ConfigError(
                f"--scanners: unknown scanner '{name}'{did_you_mean(name, SCANNERS)}. "
                f"Use a comma-separated list of {', '.join(SCANNERS)}, or all"
            )
    if "gitleaks" not in names:
        raise ConfigError("--scanners must include gitleaks, which always runs (or use: all)")
    return tuple(name for name in SCANNERS if name in names and name != "gitleaks")


def run_scan(
    target: Path,
    mode: gitleaks.Mode,
    *,
    policy: Policy,
    key: bytes,
    gitleaks_config: Path,
    runner: gitleaks.Runner,
    log_range: str | None = None,
    setup: ScannerSetup | None = None,
) -> ScanResult:
    """Scan `target` and return masked Findings. The raw candidates never leave this call."""
    setup = setup or ScannerSetup()
    output = gitleaks.scan(target, mode, config=gitleaks_config, runner=runner, log_range=log_range)
    runs = [ScannerRun("gitleaks", output.gitleaks_version, required=True, status="ran")]
    candidates = list(output.candidates)
    if "trufflehog" in setup.extra:
        run, found = _run_trufflehog(target, mode, log_range, setup)
        runs.append(run)
        candidates += found
    code_scanners = [name for name in setup.extra if name in CODE_SCANNERS]
    if code_scanners:
        code_runs, found = _run_code_scanners(code_scanners, target, mode, log_range, setup)
        runs += code_runs
        candidates += found
    findings = build_findings(candidates, policy, key)
    return ScanResult(findings, output.gitleaks_version, tuple(runs))


def build_findings(
    candidates: Iterable[Candidate],
    policy: Policy,
    key: bytes,
    detector: str | None = None,
) -> list[Finding]:
    """Turn raw candidates into Findings: decide each one, merge the findings of the same secret
    or line, and sort them block first, then warn, then ignore. `detector` overrides the
    scanner named by each candidate."""
    findings = [_to_finding(c, policy, key, detector or c.detector) for c in candidates]
    return sorted(
        merge_findings(findings),
        key=lambda f: (DECISION_ORDER[f.decision], f.file, f.line, f.rule, f.commit or ""),
    )


def _run_trufflehog(
    target: Path, mode: gitleaks.Mode, log_range: str | None, setup: ScannerSetup
) -> tuple[ScannerRun, list[Candidate]]:
    """TruffleHog is required: anything that goes wrong raises, and the scan fails."""
    if mode not in HISTORY_MODES:
        note = "it only scans Git history (repo and range modes)"
        return ScannerRun("trufflehog", None, True, "skipped", note), []
    output = trufflehog.scan(
        target,
        runner=setup.runner("trufflehog", trufflehog.subprocess_runner),
        log_range=log_range if mode == "range" else None,
        config=setup.trufflehog_config,
        verify=setup.verify,
    )
    note = None if setup.verify else "live checks switched off with --no-verification"
    return ScannerRun("trufflehog", output.version, True, "ran", note), output.candidates


def _run_code_scanners(
    names: list[str], target: Path, mode: gitleaks.Mode, log_range: str | None, setup: ScannerSetup
) -> tuple[list[ScannerRun], list[Candidate]]:
    """Semgrep and Bandit read one private copy of the code at head. They are optional: when
    one fails, it is recorded as not run and the scan goes on."""
    if mode not in HISTORY_MODES:
        note = "it only scans the code of a commit (repo and range modes)"
        return [ScannerRun(name, None, False, "skipped", note) for name in names], []
    runs: list[ScannerRun] = []
    candidates: list[Candidate] = []
    with tempfile.TemporaryDirectory(prefix="securegate-code-") as tmp:
        try:
            snapshot = _snapshot(target, mode, log_range, Path(tmp))
        except (ScannerError, OSError, tarfile.TarError) as err:
            note = f"the files to scan could not be copied ({_reason(err)})"
            return [ScannerRun(name, None, False, "did_not_run", note) for name in names], []
        for name in names:
            try:
                version, found, note = _scan_code(name, snapshot, setup)
            except Exception as err:  # optional: say why it did not run, and go on
                runs.append(ScannerRun(name, None, False, "did_not_run", _reason(err)))
                continue
            runs.append(ScannerRun(name, version, False, "ran", note))
            candidates += found
    return runs, candidates


def _snapshot(
    target: Path, mode: gitleaks.Mode, log_range: str | None, folder: Path
) -> changes.Snapshot:
    git = changes.git_runner(target.resolve())
    if mode == "range" and log_range:
        base, head = trufflehog.split_range(log_range)
        return changes.take_snapshot(git, head, changes.changed_files(git, base, head), folder)
    return changes.take_snapshot(git, "HEAD", changes.tracked_files(git, "HEAD"), folder)


def _scan_code(
    name: str, snapshot: changes.Snapshot, setup: ScannerSetup
) -> tuple[str, list[Candidate], str | None]:
    if name == "semgrep":
        if setup.semgrep_rules is None:
            raise ScannerError("no rules file was given (--semgrep-rules)")
        runner = setup.runner("semgrep", semgrep.subprocess_runner)
        out = semgrep.scan(snapshot, rules=setup.semgrep_rules, runner=runner)
        return out.version, out.candidates, out.note
    found = bandit.scan(snapshot, runner=setup.runner("bandit", bandit.subprocess_runner))
    return found.version, found.candidates, found.note


def _reason(err: Exception) -> str:
    """Why an optional scanner did not run. SecureGate's own messages hold no secrets; for
    anything else only the kind of error is shown, never its text."""
    if isinstance(err, ScannerError):
        return str(err)
    return f"internal error ({type(err).__name__})"


def _to_finding(candidate: Candidate, policy: Policy, key: bytes, detector: str) -> Finding:
    entropy = shannon_entropy(candidate.value)
    verdict = decide(
        policy,
        rule_id=candidate.rule_id,
        path=candidate.file,
        value=candidate.value,
        entropy=entropy,
        validity=candidate.validity,
    )
    return Finding(
        secret=protect(candidate.value, key, hide_all=candidate.code),
        rule=candidate.rule_id,
        detector=detector,
        file=candidate.file,
        line=candidate.line,
        commit=candidate.commit,
        author=candidate.author,
        date=candidate.date,
        entropy=entropy,
        confidence=confidence.estimate(candidate.rule_id, entropy),
        severity=verdict.severity,
        decision=verdict.decision,
        reason=verdict.reason,
        remediation=verdict.remediation,
        validity=candidate.validity,
        matched_rule=verdict.label,
    )
