"""A sample findings file for the designers: a real scan of a demo repo, masked as always.

The usual demo repo gives 11 findings. To get about 20 real ones, the sample demo holds the
DemoPay app twice: once as usual and once more under billing/, like a second service in the
same repository. It is built in a temporary folder that is deleted afterwards.
"""

import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from securegate.demo.catalog import load_catalog
from securegate.demo.generator import PlantedLine, generate
from securegate.pipeline import run_scan
from securegate.policy import Policy
from securegate.report import envelope, write_json
from securegate.scanners.gitleaks import Runner

SECOND_SERVICE = "billing"
SAMPLE_SEED = 42
SAMPLE_TARGET = "securegate-demo (sample: DemoPay and a billing copy)"


@dataclass(frozen=True)
class SampleResult:
    findings: int
    planted: tuple[PlantedLine, ...]  # what was planted, for the leak test


def write_sample_report(
    out: Path,
    *,
    policy: Policy,
    policy_path: str,
    key: bytes,
    gitleaks_config: Path,
    runner: Runner,
) -> SampleResult:
    """Build the sample demo repo, scan it for real and write the report to `out`."""
    items = load_catalog()
    copies = [
        replace(item, number=len(items) + item.number, file=f"{SECOND_SERVICE}/{item.file}")
        for item in items
    ]
    with tempfile.TemporaryDirectory(prefix="securegate-sample-") as scratch:
        demo = generate(Path(scratch) / "securegate-demo", seed=SAMPLE_SEED, catalog=items + copies)
        result = run_scan(
            demo.out, "repo", policy=policy, key=key, gitleaks_config=gitleaks_config, runner=runner
        )
    exit_code = 1 if any(f.decision == "block" for f in result.findings) else 0
    write_json(
        out,
        envelope(
            exit_code=exit_code,
            target=SAMPLE_TARGET,
            mode="repo",
            log_range=None,
            policy_path=policy_path,
            scanner_version=result.scanner_version,
            findings=result.findings,
        ),
    )
    return SampleResult(findings=len(result.findings), planted=demo.planted)
