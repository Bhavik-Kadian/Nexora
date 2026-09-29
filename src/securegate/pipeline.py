"""The pipeline: raw candidates -> entropy -> policy -> masked, fingerprinted Findings.

This is the boundary for raw values. The scanner's raw candidates come in, Findings (masked
value and fingerprint only) go out, and no raw value ever leaves these functions.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from securegate import confidence
from securegate.entropy import shannon_entropy
from securegate.finding import Finding
from securegate.mask import protect
from securegate.policy import Policy, decide
from securegate.scanners import gitleaks

DECISION_ORDER = {"block": 0, "warn": 1, "ignore": 2}


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding]
    scanner_version: str


def run_scan(
    target: Path,
    mode: gitleaks.Mode,
    *,
    policy: Policy,
    key: bytes,
    gitleaks_config: Path,
    runner: gitleaks.Runner,
    log_range: str | None = None,
) -> ScanResult:
    """Scan `target` and return masked Findings. The raw candidates never leave this call."""
    output = gitleaks.scan(target, mode, config=gitleaks_config, runner=runner, log_range=log_range)
    return ScanResult(build_findings(output.candidates, policy, key), output.gitleaks_version)


def build_findings(
    candidates: Iterable[gitleaks.Candidate],
    policy: Policy,
    key: bytes,
    detector: str = gitleaks.DETECTOR,
) -> list[Finding]:
    """Turn raw candidates into Findings, sorted block first, then warn, then ignore."""
    findings = [_to_finding(candidate, policy, key, detector) for candidate in candidates]
    return sorted(
        findings,
        key=lambda f: (DECISION_ORDER[f.decision], f.file, f.line, f.rule, f.commit or ""),
    )


def _to_finding(
    candidate: gitleaks.Candidate, policy: Policy, key: bytes, detector: str
) -> Finding:
    entropy = shannon_entropy(candidate.value)
    verdict = decide(
        policy,
        rule_id=candidate.rule_id,
        path=candidate.file,
        value=candidate.value,
        entropy=entropy,
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
    )
