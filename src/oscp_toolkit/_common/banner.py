"""Startup banner: per-tool sigil, wordmark, tagline.

Cosmetic, so it gets out of the way the moment output stops being for a human:
no TTY, no banner. That keeps `--json -` pipeable and keeps `| tee` files free of
escape sequences.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

from ._art import ART, SIGIL_WIDTH

SUITE = "oscp-toolkit"
_SIGIL = "\033[38;5;39m"    # blue, so the mark reads as separate from the name
_WORD = "\033[38;5;44m"     # cyan
_DIM = "\033[38;5;240m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_GAP = " "
_INDENT = " " * (SIGIL_WIDTH + len(_GAP))


def banner_suppressed(stream: TextIO = sys.stdout) -> bool:
    if os.environ.get("OSCP_NO_BANNER"):
        return True
    return not stream.isatty()


def _use_colour(stream: TextIO) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR")


def render_banner(
    tool: str,
    version: str,
    stream: TextIO = sys.stdout,
    force: bool = False,
) -> None:
    """Print `tool`'s banner unless the output isn't going to a human."""
    if not force and banner_suppressed(stream):
        return

    entry = ART.get(tool)
    if entry is None:
        # A tool with no art still gets the strapline rather than nothing.
        sigil, word, tagline = [], [], ""
    else:
        sigil, word, tagline = entry

    if force or _use_colour(stream):
        s, w, d, b, r = _SIGIL, _WORD, _DIM, _BOLD, _RESET
    else:
        s = w = d = b = r = ""

    rows = max(len(sigil), len(word))
    for i in range(rows):
        mark = sigil[i] if i < len(sigil) else " " * SIGIL_WIDTH
        name = word[i] if i < len(word) else ""
        stream.write(f"{s}{mark}{r}{_GAP}{w}{name}{r}\n")

    if tagline:
        stream.write(f"{d}{_INDENT}{tagline}{r}\n")
    stream.write(f"{d}{_INDENT}{SUITE} {b}v{version}{r}{d} · enumeration only{r}\n\n")
    stream.flush()


def add_banner_flag(parser) -> None:
    """Every tool takes --no-banner, so it's defined in exactly one place."""
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="skip the startup banner (also skipped automatically when piped)",
    )
