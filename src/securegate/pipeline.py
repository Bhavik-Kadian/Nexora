"""The pipeline: raw candidates -> entropy -> policy -> masked, fingerprinted Findings.

This is the boundary for raw values. The scanners' raw candidates come in, Findings (masked
value and fingerprint only) go out, and no raw value ever leaves these functions.

Gitleaks always runs. More scanners can join (`ScannerSetup`); each candidate is decided by the
policy on its own, then findings of the same secret or line are merged (securegate.merge).
TruffleHog is required like Gitleaks: if it is asked for and fails, the scan fails (exit 2).
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from securegate import confidence
from securegate.entropy import shannon_entropy
from securegate.errors import ConfigError
from securegate.finding import Finding
from securegate.mask import protect
from securegate.merge import merge_findings
from securegate.policy import Policy, decide
from securegate.scanners import gitleaks, trufflehog
from securegate.scanners.candidate import Candidate
from securegate.scanners.common import ScannerRun, ToolRunner
from securegate.validate import did_you_mean

DECISION_ORDER = {"block": 0, "warn": 1, "ignore": 2}
SCANNERS = ("gitleaks", "trufflehog")  # in the order they run and are listed
REQUIRED = frozenset({"gitleaks", "trufflehog"})
HISTORY_MODES = ("repo", "range")  # the modes that have a Git history to scan
LABELS = {"gitleaks": "Gitleaks", "trufflehog": "TruffleHog"}


@dataclass(frozen=True, slots=True)
class ScannerSetup:
    """Which scanners run besides Gitleaks, and how. The default runs Gitleaks only."""

    extra: tuple[str, ...] = ()  # from SCANNERS, without gitleaks
    runners: Mapping[str, ToolRunner] = field(default_factory=dict)  # tests pass fakes
    trufflehog_config: Path | None = None
    verify: bool = True  # let TruffleHog ask providers whether keys are live

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
    for name in setup.extra:
        run, found = _run_extra(name, target, mode, log_range, setup)
        runs.append(run)
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


def _run_extra(
    name: str, target: Path, mode: gitleaks.Mode, log_range: str | None, setup: ScannerSetup
) -> tuple[ScannerRun, list[Candidate]]:
    required = name in REQUIRED
    if mode not in HISTORY_MODES:
        note = "it only scans Git history (repo and range modes)"
        return ScannerRun(name, None, required, "skipped", note), []
    output = trufflehog.scan(
        target,
        runner=setup.runner(name, trufflehog.subprocess_runner),
        log_range=log_range if mode == "range" else None,
        config=setup.trufflehog_config,
        verify=setup.verify,
    )
    note = None if setup.verify else "live checks switched off with --no-verification"
    return ScannerRun(name, output.version, required, "ran", note), output.candidates


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
        secret=protect(candidate.value, key),
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
