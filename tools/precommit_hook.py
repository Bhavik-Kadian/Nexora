"""The laptop gate's entry point, run by pre-commit before each commit.

pre-commit runs this in its own Python environment, where SecureGate is not installed, so it
loads SecureGate from this checkout's src/ folder. It then scans only the staged changes:
`securegate scan . --mode staged`. Exit code 1 stops the commit, 2 means the scan failed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securegate.cli import main  # imported after the line above puts src/ on the path

STAGED_SCAN = ["scan", ".", "--mode", "staged", "--out", ".securegate/staged-findings.json"]

if __name__ == "__main__":
    raise SystemExit(main(STAGED_SCAN))
