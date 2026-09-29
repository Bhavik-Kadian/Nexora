"""Command-line entry point: `securegate <command>`.

The CLI only parses arguments and turns results into exit codes:
0 = pass, 1 = at least one finding is "block", 2 = tool error.
"""

import argparse
from collections.abc import Sequence

from securegate import __version__

EXIT_PASS = 0
EXIT_BLOCK = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securegate",
        description="Secret-scanning gate for Git repositories.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    commands.add_parser("version", help="print the SecureGate version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(f"securegate {__version__}")
        return EXIT_PASS
    return EXIT_ERROR
