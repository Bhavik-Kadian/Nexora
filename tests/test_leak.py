"""Leak test: no planted value may appear in findings.json, stdout or stderr.

(a) always runs: a fake Gitleaks "finds" every planted value, so every one of them flows
    through the whole pipeline;
(b) runs the real CLI with the real Gitleaks in a separate process.
Also checked: the hidden middle of every value of 16+ characters never shows.
Failures name only the kind and location, never the value.
"""

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from fake_gitleaks import FakeGitleaks, entry
from helpers import gitleaks_installed, scan_args
from securegate.demo.generator import DemoResult, PlantedLine

RULE_FOR_KIND = {
    "aws_key_pair": "aws-access-token",
    "stripe_live": "stripe-access-token",
    "github_pat": "github-pat",
    "acme_token": "acme-pay-token",
    "private_key_block": "private-key",
}


def leaked(planted: Sequence[PlantedLine], text: str) -> list[str]:
    """Where a planted value, or the hidden middle of a long one, shows up in `text`."""
    found = []
    for item in planted:
        for part in item.parts:
            if part in text or (len(part) >= 16 and part[4:-4] in text):
                found.append(f"{item.kind} at {item.file}:{item.line}")
                break
    return found


def test_every_planted_value_stays_masked_through_the_pipeline(
    run_cli, demo_repo: DemoResult
) -> None:
    fake = FakeGitleaks(
        report=[
            entry(
                rule=RULE_FOR_KIND.get(p.kind, "generic-api-key"),
                file=p.file,
                line=p.line,
                value=p.raw,
                commit=p.commit,
                author="Riya Demo",
            )
            for p in demo_repo.planted
        ]
    )

    result = run_cli(*scan_args(demo_repo.out), runner=fake)

    assert result.exit_code == 1
    assert len(result.findings) == len(demo_repo.planted)
    assert leaked(demo_repo.planted, result.out + result.err + json.dumps(result.report)) == []


@pytest.mark.skipif(not gitleaks_installed(), reason="gitleaks is not installed")
def test_real_scan_in_a_separate_process_leaks_nothing(
    demo_repo: DemoResult, tmp_path: Path
) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "securegate", *scan_args(demo_repo.out)],
        cwd=tmp_path,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    report = (tmp_path / "findings.json").read_text(encoding="utf-8")

    assert done.returncode == 1
    assert leaked(demo_repo.planted, done.stdout + done.stderr + report) == []
