"""argparse plumbing every tool shares.

Keeps the seven tools feeling like one set: same --version / --no-banner / --json
spelling, the same exit-code table in every --help epilog, and the same behaviour
when invoked bare (print help, exit 1).
"""

from __future__ import annotations

import argparse
import sys

from .banner import add_banner_flag
from .exits import (
    EXIT_INTERRUPTED,
    EXIT_NO_DATA,
    EXIT_OK,
    EXIT_UNAVAILABLE,
    EXIT_USAGE,
)

EXIT_TABLE = f"""exit codes:
  {EXIT_OK}    ok
  {EXIT_USAGE}    bad input or flags, or a step could not run
  {EXIT_NO_DATA}    ran fine, but there was nothing to report
  {EXIT_UNAVAILABLE}    something it needs is busy or unreachable
  {EXIT_INTERRUPTED}  interrupted
"""


class ToolParser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error (unknown flag, bad --choice, missing arg).

    In this suite 2 means "ran fine, nothing to report", so a typo in a flag would
    look like an empty result to anything checking the exit code. Every tool uses
    this parser so a usage error is always EXIT_USAGE. Subparsers inherit the class
    automatically, so `add_subparsers()` needs no extra wiring.
    """

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_epilog(examples: str) -> str:
    return f"{examples.rstrip()}\n\n{EXIT_TABLE}"


def add_global_flags(parser: argparse.ArgumentParser, prog: str, version: str) -> None:
    parser.add_argument("--version", action="version", version=f"{prog} {version}")
    add_banner_flag(parser)


def add_json_flag(parser: argparse.ArgumentParser, group_title: str = "output") -> None:
    group = parser.add_argument_group(group_title)
    group.add_argument(
        "--json", dest="json_out", metavar="FILE",
        help="write machine-readable JSON ('-' for stdout, which suppresses the table)",
    )


def make_parser(prog: str, description: str, examples: str) -> argparse.ArgumentParser:
    return ToolParser(
        prog=prog,
        description=description,
        epilog=build_epilog(examples),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
