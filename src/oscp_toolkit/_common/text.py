"""Terminal-output helpers.

`scrub` is the important one. Most of these tools display text that ultimately
came off a target box - service banners, page titles, PEAS output, loot filenames,
LDAP attributes. That text is attacker-influenced, so a crafted value could
otherwise repaint or hijack the terminal. Everything displayed gets scrubbed on
the way IN, once, at the point it enters a dataclass - not at render time, so
there's no path that skips it.
"""

from __future__ import annotations

import os
import re
import sys

_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def scrub(text: str, limit: int = 300) -> str:
    """Strip escape sequences and control bytes, collapse whitespace, truncate."""
    text = _ANSI_OSC_RE.sub("", text)
    text = _ANSI_CSI_RE.sub("", text)
    text = text.replace("\x1b", "")
    text = _CTRL_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _colour_ok(stream=None) -> bool:
    stream = stream or sys.stdout
    return stream.isatty() and not os.environ.get("NO_COLOR")


def bold(text: str) -> str:
    """Only emit escapes at a real terminal - piped output stays clean."""
    return f"\033[1m{text}\033[0m" if _colour_ok() else text


def dim(text: str) -> str:
    return f"\033[2m{text}\033[0m" if _colour_ok() else text


def colour(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _colour_ok() else text


def fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins, secs = divmod(int(seconds), 60)
    if mins < 60:
        return f"{mins}m{secs:02d}s"
    hours, mins = divmod(mins, 60)
    return f"{hours}h{mins:02d}m"
