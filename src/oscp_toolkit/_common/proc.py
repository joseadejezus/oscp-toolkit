"""Subprocess helpers.

Two rules this enforces so no tool can quietly forget them: every call is an argv
list (there is no code path here that accepts a string), and every call has an
explicit timeout and explicit return-code handling. A timeout or a missing binary
raises rather than returning something that looks like an empty result.
"""

from __future__ import annotations

import subprocess
import sys
import time
from typing import Sequence

from .text import bold, fmt_duration


class StepError(RuntimeError):
    """A step could not run at all - missing binary, timeout, or a hard failure."""


def run(cmd: Sequence[str], timeout: int, capture: bool = True,
        echo: Sequence[str] | None = None) -> subprocess.CompletedProcess:
    """Run one command. `echo` overrides what's printed, for redacting credentials."""
    if isinstance(cmd, str):  # guard against a future refactor reintroducing a shell
        raise TypeError("commands must be an argv list, never a string")
    try:
        return subprocess.run(
            list(cmd), shell=False, check=False, timeout=timeout,
            capture_output=capture, text=True,
        )
    except subprocess.TimeoutExpired as exc:
        shown = " ".join(echo or cmd)
        raise StepError(f"timed out after {timeout}s: {shown}") from exc
    except FileNotFoundError as exc:
        raise StepError(f"command not found: {cmd[0]}") from exc


def run_streaming(cmd: Sequence[str], timeout: int,
                  echo: Sequence[str] | None = None) -> tuple[int, float]:
    """Run a command whose own output should stream straight to the terminal.

    Used where the wrapped tool already prints good progress (nmap, hashcat) - a
    spinner would only fight it, so the feedback is a header and the elapsed time.
    """
    started = time.monotonic()
    try:
        result = subprocess.run(list(cmd), shell=False, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise StepError(f"timed out after {timeout}s: {' '.join(echo or cmd)}") from exc
    except FileNotFoundError as exc:
        raise StepError(f"command not found: {cmd[0]}") from exc
    return result.returncode, time.monotonic() - started


def step_header(index: int, total: int, label: str, cmd: Sequence[str] | None = None) -> None:
    print(f"\n{bold(f'>> [{index}/{total}] {label}')}")
    if cmd:
        print(f"   {' '.join(cmd)}\n")


def step_done(elapsed: float, extra: str = "") -> None:
    tail = f" {extra}" if extra else ""
    print(f"   [done in {fmt_duration(elapsed)}]{tail}", file=sys.stderr)
