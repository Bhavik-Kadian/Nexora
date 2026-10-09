"""SARIF 2.1.0 for GitHub's Security tab, built from SecureGate's findings. Pure.

It is built from the checked report (masked values only), never from a scanner's own output.
Each policy rule that blocked or warned becomes one SARIF rule, so GitHub shows the policy's
name and severity; ignored findings are left out. Blocks are "error", warnings "warning".
"""

import re

from securegate import __version__
from securegate.ui.report_view import FindingView, ReportView

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Bhavik-Kadian/Nexora"
LEVELS = {"block": "error", "warn": "warning"}
# GitHub sorts code scanning alerts by this number: 9+ critical, 7+ high, 4+ medium, else low.
SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 0.0}
_SLUG = re.compile(r"[^a-z0-9]+")


def build_sarif(report: ReportView) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    scores: dict[str, float] = {}  # the highest severity among each rule's findings
    results = []
    for finding in report.findings:
        if finding.decision not in LEVELS:
            continue
        rule_id = _rule_id(finding)
        rules.setdefault(rule_id, _rule(rule_id, finding))
        scores[rule_id] = max(scores.get(rule_id, 0.0), SECURITY_SEVERITY[finding.severity])
        results.append(_result(rule_id, finding))
    for rule_id, rule in rules.items():
        rule["properties"] = {
            "tags": ["security", "secret"],
            "security-severity": f"{scores[rule_id]:.1f}",
        }
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureGate",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _rule_id(finding: FindingView) -> str:
    """rule 8: provider-keys becomes rule-8-provider-keys."""
    label = finding.matched_rule or finding.policy_rule or "securegate"
    return _SLUG.sub("-", label.lower()).strip("-")


def _rule(rule_id: str, finding: FindingView) -> dict[str, object]:
    label = finding.matched_rule or finding.policy_rule or "SecureGate"
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": label},
        "fullDescription": {"text": finding.reason_text},
        "help": {"text": finding.remediation or "Treat it as leaked: revoke and replace it."},
    }


def _result(rule_id: str, finding: FindingView) -> dict[str, object]:
    found_by = ", ".join(finding.found_by)
    message = (
        f"{finding.decision.upper()}: {finding.masked_value} "
        f"({finding.matched_rule or finding.policy_rule or 'policy'}). Found by {found_by}. "
        f"Live check: {finding.live_check}. {finding.reason_text}"
    )
    return {
        "ruleId": rule_id,
        "level": LEVELS[finding.decision],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
        "properties": {
            "decision": finding.decision,
            "maskedValue": finding.masked_value,
            "detectors": list(finding.found_by),
            "validity": finding.validity,
            "commit": finding.commit,
        },
    }
