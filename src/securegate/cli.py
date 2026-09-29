"""Command-line entry point: `securegate <command>`.

The CLI only parses arguments, runs one command and turns the outcome into an exit code:
0 = pass, 1 = at least one finding is "block", 2 = tool error. Errors fail closed: any problem,
expected or not, ends with exit code 2.
"""

import argparse
import contextlib
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from securegate import __version__
from securegate.demo.app import AUTHOR_NAME
from securegate.demo.generator import generate
from securegate.errors import SecureGateError
from securegate.mask import default_state_dir, load_hmac_key
from securegate.pipeline import run_scan
from securegate.policy import load_policy
from securegate.report import envelope, render_table, summary_line, write_json
from securegate.scanners import gitleaks

EXIT_PASS = 0
EXIT_BLOCK = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securegate",
        description="Secret-scanning gate for Git repositories.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = commands.add_parser("scan", help="scan a repository or folder for secrets")
    scan.add_argument("path", nargs="?", default=".", help="what to scan (default: .)")
    scan.add_argument(
        "--mode",
        choices=gitleaks.MODES,
        default="repo",
        help="repo = full Git history (default), range = the commits in --range, "
        "staged = changes staged for commit, dir = files on disk",
    )
    scan.add_argument(
        "--range", dest="log_range", metavar="A..B", help="commit range for --mode range"
    )
    scan.add_argument("--out", default="findings.json", help="JSON report (default: %(default)s)")
    scan.add_argument("--policy", default="policy.yaml", help="policy file (default: %(default)s)")
    scan.add_argument(
        "--gitleaks-config", default=".gitleaks.toml", help="Gitleaks config (default: %(default)s)"
    )

    demo = commands.add_parser("demo-repo", help="build the demo repo with planted secrets")
    demo.add_argument(
        "--out",
        default="../securegate-demo",
        help="folder to build it in, outside any Git repository (default: %(default)s)",
    )
    demo.add_argument("--seed", type=int, default=42, help="same seed, same repo (default: 42)")
    demo.add_argument(
        "--force", action="store_true", help="rebuild a folder made by an earlier demo-repo run"
    )

    commands.add_parser("version", help="print the SecureGate and Gitleaks versions")
    return parser


def main(argv: Sequence[str] | None = None, *, runner: gitleaks.Runner | None = None) -> int:
    _tolerant_console()
    args = build_parser().parse_args(argv)
    runner = runner or gitleaks.subprocess_runner
    try:
        if args.command == "version":
            return _version(runner)
        if args.command == "demo-repo":
            return _demo_repo(args)
        return _scan(args, runner)
    except SecureGateError as err:
        print(f"securegate: error: {err}", file=sys.stderr)
    except KeyboardInterrupt:
        print("securegate: interrupted", file=sys.stderr)
    except Exception as err:  # fail closed on anything unexpected; never print the details
        print(
            f"securegate: internal error ({type(err).__name__}); failing closed with exit code 2",
            file=sys.stderr,
        )
    return EXIT_ERROR


def _scan(args: argparse.Namespace, runner: gitleaks.Runner) -> int:
    out = Path(args.out)
    report_fields = {
        "target": args.path,
        "mode": args.mode,
        "log_range": args.log_range,
        "policy_path": args.policy,
    }
    scanner_version: str | None = None
    try:
        policy = load_policy(Path(args.policy))
        key = load_hmac_key(os.environ, default_state_dir())
        result = run_scan(
            Path(args.path),
            args.mode,
            policy=policy,
            key=key,
            gitleaks_config=Path(args.gitleaks_config),
            runner=runner,
            log_range=args.log_range,
        )
        scanner_version = result.scanner_version
    except SecureGateError as err:
        _write_error_report(out, report_fields, str(err))
        raise
    except KeyboardInterrupt:
        _write_error_report(out, report_fields, "interrupted")
        raise
    except Exception as err:
        _write_error_report(out, report_fields, f"internal error ({type(err).__name__})")
        raise

    exit_code = EXIT_BLOCK if any(f.decision == "block" for f in result.findings) else EXIT_PASS
    write_json(
        out,
        envelope(
            exit_code=exit_code,
            scanner_version=scanner_version,
            findings=result.findings,
            **report_fields,
        ),
    )
    if result.findings:
        print(render_table(result.findings))
        print()
    print(summary_line(result.findings, exit_code, out))
    return exit_code


def _write_error_report(out: Path, report_fields: dict[str, str | None], message: str) -> None:
    """Replace any older report, so a failed scan never leaves a stale 'pass' behind.

    If even that fails, the original error still ends the run with exit code 2.
    """
    with contextlib.suppress(SecureGateError):
        write_json(
            out,
            envelope(exit_code=EXIT_ERROR, scanner_version=None, error=message, **report_fields),
        )


def _demo_repo(args: argparse.Namespace) -> int:
    result = generate(Path(args.out), seed=args.seed, force=args.force)
    secrets = sum(line.is_secret for line in result.planted)
    decoys = len(result.planted) - secrets
    print(f"Demo repo ready: {result.out}")
    print(f"  {len(result.commits)} commits by {AUTHOR_NAME}, seed {result.seed}")
    print(f"  planted: {secrets} secret lines and {decoys} decoy lines")
    print(f"  ground truth: {result.ground_truth}")
    print("Next: scan it with `make scan-demo`")
    return EXIT_PASS


def _version(runner: gitleaks.Runner) -> int:
    print(f"securegate {__version__}")
    found = gitleaks.gitleaks_version(runner)
    print(f"gitleaks {found}" if found else "gitleaks not found (it is needed for scans)")
    return EXIT_PASS


def _tolerant_console() -> None:
    """Never crash on characters the console cannot show (older Windows code pages)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
