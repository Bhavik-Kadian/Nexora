"""Merging: findings of the same secret, or of the same line, become one finding. Pure.

Each scanner's finding has already been decided on its own by the policy. Merging then:
  1. joins findings of the same key in the same file and commit (Gitleaks and TruffleHog often
     both find it; TruffleHog's line number can be slightly off, so the line need not match);
  2. adds Semgrep and Bandit to the detectors of a secret found on their file and line, instead
     of making a separate finding; on a line without such a secret, their findings join up;
  3. keeps the strongest decision (with its rule, reason and fix), the highest severity, the
     strongest validity, and every detector.
Two different secrets found on one line by the same scanner stay two findings.
"""

from collections.abc import Iterable
from dataclasses import replace

from securegate.finding import DECISIONS, SEVERITIES, VALIDITIES, Finding

SECRET_SCANNERS = ("gitleaks", "trufflehog")
DETECTOR_ORDER = {name: n for n, name in enumerate(("gitleaks", "trufflehog", "semgrep", "bandit"))}


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merged findings, in no particular order (the pipeline sorts them)."""
    ordered = sorted(findings, key=_detector_rank)
    groups = _secret_groups(f for f in ordered if f.detector in SECRET_SCANNERS)
    groups += _attach_code_findings(
        groups, (f for f in ordered if f.detector not in SECRET_SCANNERS)
    )
    return [combine(group) for group in groups]


def combine(group: list[Finding]) -> Finding:
    """One finding for a group: the primary finding's place and value, the strongest verdict."""
    primary = min(group, key=_primary_rank)
    winner = min(group, key=_verdict_rank)
    detectors = sorted({d for f in group for d in f.detectors}, key=_rank_of_detector)
    return replace(
        primary,
        detectors=tuple(detectors),
        validity=min((f.validity for f in group), key=VALIDITIES.index),
        severity=min((f.severity for f in group), key=SEVERITIES.index),
        decision=winner.decision,
        matched_rule=winner.matched_rule,
        reason=winner.reason,
        remediation=winner.remediation,
        confidence=max(f.confidence for f in group),
    )


def _secret_groups(findings: Iterable[Finding]) -> list[list[Finding]]:
    groups: list[list[Finding]] = []
    same_key: dict[tuple[str, str | None, str], list[list[Finding]]] = {}
    for finding in findings:
        candidates = same_key.setdefault((finding.file, finding.commit, finding.fingerprint), [])
        target = next((g for g in candidates if any(m.line == finding.line for m in g)), None)
        if target is None:  # the same key nearby, from a scanner not yet in that group
            target = next(
                (g for g in candidates if finding.detector not in {m.detector for m in g}), None
            )
        if target is None:
            target = []
            candidates.append(target)
            groups.append(target)
        target.append(finding)
    return groups


def _attach_code_findings(
    secret_groups: list[list[Finding]], findings: Iterable[Finding]
) -> list[list[Finding]]:
    """Semgrep and Bandit look at lines of code: add each finding to the secrets found on its
    file and line, or group it with the other code findings on that line."""
    on_line: dict[tuple[str, int], list[list[Finding]]] = {}
    for group in secret_groups:
        for spot in {(m.file, m.line) for m in group}:
            on_line.setdefault(spot, []).append(group)
    code_groups: dict[tuple[str, int], list[Finding]] = {}
    for finding in findings:
        anchors = on_line.get((finding.file, finding.line))
        if anchors:
            for group in anchors:
                group.append(finding)
        else:
            code_groups.setdefault((finding.file, finding.line), []).append(finding)
    return list(code_groups.values())


def _rank_of_detector(name: str) -> int:
    return DETECTOR_ORDER.get(name, len(DETECTOR_ORDER))


def _detector_rank(finding: Finding) -> tuple[int, str, int, str]:
    return (_rank_of_detector(finding.detector), finding.file, finding.line, finding.rule)


def _primary_rank(finding: Finding) -> tuple[int, bool, int]:
    """The finding whose place and value the merged finding shows: a secret scanner first, a
    specific rule before a generic one, then the earliest line."""
    return (_rank_of_detector(finding.detector), finding.rule.startswith("generic"), finding.line)


def _verdict_rank(finding: Finding) -> tuple[int, int, int]:
    return (
        DECISIONS.index(finding.decision),
        SEVERITIES.index(finding.severity),
        _rank_of_detector(finding.detector),
    )
