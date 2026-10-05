"""Command-line entry point: `securegate <command>`.

The CLI only parses arguments, runs one command and turns the outcome into an exit code:
0 = pass, 1 = at least one finding is "block", 2 = tool error. Errors fail closed: any problem,
expected or not, ends with exit code 2.
"""

import argparse
import contextlib
import logging
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from securegate import __version__
from securegate.demo.app import AUTHOR_NAME
from securegate.demo.generator import generate
from securegate.demo.token import new_demo_token
from securegate.errors import SecureGateError
from securegate.mask import default_state_dir, load_hmac_key
from securegate.outputs import Targets, write_outputs
from securegate.pipeline import LABELS, ScannerSetup, parse_scanners, run_scan
from securegate.policy import load_policy
from securegate.report import (
    blocked_details,
    envelope,
    render_table,
    summary_line,
    write_json,
)
from securegate.scanners import gitleaks
from securegate.scanners.common import ScannerRun, ToolRunner

EXIT_PASS = 0
EXIT_BLOCK = 1
EXIT_ERROR = 2
DASHBOARD_PORT = 5000


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
    scan.add_argument(
        "--scanners",
        default="gitleaks",
        metavar="LIST",
        help="scanners to run, comma-separated: gitleaks (always), trufflehog, semgrep, bandit, "
        "or all (default: %(default)s). The others only run in repo and range modes",
    )
    scan.add_argument(
        "--no-verification",
        action="store_true",
        help="do not let TruffleHog ask providers whether the keys it finds still work",
    )
    scan.add_argument(
        "--trufflehog-config",
        default=".trufflehog.yaml",
        help="TruffleHog config with SecureGate's own detectors (default: %(default)s)",
    )
    scan.add_argument(
        "--semgrep-rules",
        default="rules/securegate-risky.yml",
        help="SecureGate's own Semgrep rules (default: %(default)s)",
    )
    scan.add_argument(
        "--sarif", metavar="FILE", help="also write SARIF 2.1.0 for GitHub's Security tab"
    )
    scan.add_argument("--summary", metavar="FILE", help="also write the Markdown job summary")
    scan.add_argument(
        "--comment", metavar="FILE", help="also write the Markdown pull request comment"
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

    ui = commands.add_parser("ui", help="show a report in the read-only dashboard")
    ui.add_argument(
        "--report", default="findings.json", help="report to show (default: %(default)s)"
    )
    ui.add_argument(
        "--port", type=int, default=DASHBOARD_PORT, help="port on 127.0.0.1 (default: %(default)s)"
    )
    ui.add_argument("--open", action="store_true", help="open the dashboard in your web browser")
    ui.add_argument("--debug", action="store_true", help="print error details in this terminal")

    sample = commands.add_parser(
        "sample-report", help="write a sample findings file for designers (needs Gitleaks)"
    )
    sample.add_argument("--out", default="sample_findings.json", help="default: %(default)s")
    sample.add_argument("--policy", default="policy.yaml", help="default: %(default)s")
    sample.add_argument("--gitleaks-config", default=".gitleaks.toml", help="default: %(default)s")

    commands.add_parser(
        "demo-token", help="print a new fake ACME Pay token, for demos of the merge gate"
    )

    summary = commands.add_parser(
        "summary", help="print a short Markdown summary of a report (masked values only)"
    )
    summary.add_argument("--report", default="findings.json", help="default: %(default)s")

    commands.add_parser("version", help="print the SecureGate and Gitleaks versions")

    commands.add_parser(
        "menu", help="open the menu: scan, see the rules and open the dashboard without typing"
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: gitleaks.Runner | None = None,
    tool_runners: Mapping[str, ToolRunner] | None = None,
) -> int:
    """Run one command. `runner` replaces Gitleaks and `tool_runners` the other scanners
    (by name: "trufflehog", "semgrep", "bandit"); tests pass fakes."""
    _tolerant_console()
    args = build_parser().parse_args(argv)
    runner = runner or gitleaks.subprocess_runner
    try:
        if args.command == "version":
            return _version(runner)
        if args.command == "demo-repo":
            return _demo_repo(args)
        if args.command == "ui":
            return _ui(args)
        if args.command == "sample-report":
            return _sample_report(args, runner)
        if args.command == "summary":
            return _summary(args)
        if args.command == "demo-token":
            print(new_demo_token())  # fake by design: ACME Pay does not exist
            return EXIT_PASS
        if args.command == "menu":
            return _menu(runner)
        return _scan(args, runner, tool_runners or {})
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


def _scan(
    args: argparse.Namespace, runner: gitleaks.Runner, tool_runners: Mapping[str, ToolRunner]
) -> int:
    out = Path(args.out)
    targets = Targets(
        sarif=Path(args.sarif) if args.sarif else None,
        summary=Path(args.summary) if args.summary else None,
        comment=Path(args.comment) if args.comment else None,
    )
    report_fields = {
        "target": args.path,
        "mode": args.mode,
        "log_range": args.log_range,
        "policy_path": args.policy,
    }
    scanner_version: str | None = None
    try:
        extra = parse_scanners(args.scanners)
        setup = ScannerSetup(
            extra=extra,
            runners=tool_runners,
            trufflehog_config=Path(args.trufflehog_config) if "trufflehog" in extra else None,
            verify=not args.no_verification,
            semgrep_rules=Path(args.semgrep_rules),
        )
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
            setup=setup,
        )
        scanner_version = result.scanner_version
        exit_code = EXIT_BLOCK if any(f.decision == "block" for f in result.findings) else EXIT_PASS
        write_json(
            out,
            envelope(
                exit_code=exit_code,
                scanner_version=scanner_version,
                findings=result.findings,
                scanner_runs=result.scanner_runs,
                **report_fields,
            ),
        )
        if targets.any:
            write_outputs(out, targets, finished=True)
    except SecureGateError as err:
        _fail(out, report_fields, targets, str(err))
        raise
    except KeyboardInterrupt:
        _fail(out, report_fields, targets, "interrupted")
        raise
    except Exception as err:
        _fail(out, report_fields, targets, f"internal error ({type(err).__name__})")
        raise

    if result.findings:
        print(render_table(result.findings))
        print()
    if exit_code == EXIT_BLOCK:
        print(blocked_details(result.findings))
        print()
    if setup.extra:
        print(_scanners_line(result.scanner_runs))
    print(summary_line(result.findings, exit_code, out))
    return exit_code


def _scanners_line(runs: Sequence[ScannerRun]) -> str:
    """Which scanners ran, for example: Scanners: Gitleaks 8.30.1, TruffleHog 3.97.9."""
    parts = []
    for run in runs:
        name = LABELS.get(run.name, run.name)
        if run.status == "ran":
            ran = f"{name} {run.version}" if run.version else name
            parts.append(f"{ran} ({run.note})" if run.note else ran)
        else:
            parts.append(f"{name} {run.status.replace('_', ' ')}: {run.note or 'no reason given'}")
    return "Scanners: " + "; ".join(parts)


def _fail(out: Path, report_fields: dict[str, str | None], targets: Targets, message: str) -> None:
    """Replace any older report and outputs, so a failed scan never leaves a stale 'pass'
    behind: findings.json gets an error report, the comment and summary say ERROR, and an old
    SARIF file is removed. If even that fails, the original error still means exit code 2."""
    with contextlib.suppress(SecureGateError):
        write_json(
            out,
            envelope(exit_code=EXIT_ERROR, scanner_version=None, error=message, **report_fields),
        )
    if targets.any:
        with contextlib.suppress(SecureGateError):
            write_outputs(out, targets, finished=False)


def _demo_repo(args: argparse.Namespace) -> int:
    result = generate(Path(args.out), seed=args.seed, force=args.force)
    real = sum(line.is_secret for line in result.planted)
    decoys = len(result.planted) - real
    print(f"Demo repo ready: {result.out}")
    print(f"  {len(result.commits)} commits by {AUTHOR_NAME}, seed {result.seed}")
    print(f"  planted: {real} secret lines and {decoys} decoy lines")
    print(f"  ground truth: {result.ground_truth}")
    print("Next: scan it with `make scan-demo`")
    return EXIT_PASS


def _ui(args: argparse.Namespace) -> int:
    from securegate.ui.server import serve  # Flask loads only when the dashboard is used

    return serve(Path(args.report), port=args.port, debug=args.debug, open_browser=args.open)


def _menu(runner: gitleaks.Runner) -> int:
    from securegate.menu.app import run_menu  # the menu loads only when it is used
    from securegate.menu.terminal import real_terminal

    return run_menu(
        real_terminal(),
        run_command=lambda argv: _run_for_menu(argv, runner),
        open_dashboard=_open_dashboard_for_menu,
        gitleaks_version=gitleaks.gitleaks_version(runner),
    )


def _run_for_menu(argv: Sequence[str], runner: gitleaks.Runner) -> int:
    """Run one command for the menu, exactly as if it had been typed."""
    try:
        return main(argv, runner=runner)
    except SystemExit as stopped:  # argparse refused the arguments, and said why
        return stopped.code if isinstance(stopped.code, int) else EXIT_ERROR


def _open_dashboard_for_menu(report: Path, wait: Callable[[], object]) -> int:
    from securegate.ui.server import serve

    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # no line for each page in the menu
    return serve(report, port=DASHBOARD_PORT, open_browser=True, wait=wait)


def _sample_report(args: argparse.Namespace, runner: gitleaks.Runner) -> int:
    from securegate.ui.sample import write_sample_report

    result = write_sample_report(
        Path(args.out),
        policy=load_policy(Path(args.policy)),
        policy_path=args.policy,
        key=load_hmac_key(os.environ, default_state_dir()),
        gitleaks_config=Path(args.gitleaks_config),
        runner=runner,
    )
    print(f"Wrote {args.out}: {result.findings} findings from a demo scan, values masked.")
    print(f"Open it with: securegate ui --report {args.out} --open")
    return EXIT_PASS


def _summary(args: argparse.Namespace) -> int:
    from securegate.summary import render_summary
    from securegate.ui.report_view import ReportProblem, load_report

    report = load_report(Path(args.report))
    print(render_summary(report), end="")
    return EXIT_ERROR if isinstance(report, ReportProblem) else EXIT_PASS


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
