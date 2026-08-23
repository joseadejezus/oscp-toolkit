#!/usr/bin/env python3
"""
script-logger

Per-box terminal transcript, evidence tree, timeline and markers - a smarter
`script` plus `mkdir`. Wraps util-linux `script -q` so everything I type and
everything the box prints ends up in one file per target, alongside a
scans/loot/notes/exploits tree.

    script-logger start 10.10.10.10      # make the tree, drop into a recorded shell
    mark got a shell as www-data         # stamp a step (same tool, second command)
    script-logger stop 10.10.10.10       # rebuild + print the merged timeline
    script-logger status 10.10.10.10     # read-only: what's on disk

Documentation side only: this records my own terminal and organises my own
notes. It never connects to, scans, or interacts with a target. See the README.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from . import __version__
from ._common.banner import render_banner
from ._common.cli import ToolParser, add_global_flags, build_epilog
from ._common.exits import EXIT_INTERRUPTED, EXIT_NO_DATA, EXIT_OK, EXIT_USAGE
from ._common.jsonout import emit as emit_json
from ._common.jsonout import envelope
from ._common.text import scrub
from ._common.ui import RICH as _RICH
from ._common.ui import Console, Table

_console = Console() if _RICH else None

# --- config ---------------------------------------------------------------
DEFAULT_ROOT = "~/targets"
SUBDIRS = ("scans", "loot", "notes", "exploits")
SHELLS = ("bash", "zsh")
TS_FMT = "%Y-%m-%d %H:%M:%S"

# --- allow-lists (reject outright, never sanitize) ------------------------
# Target: an IPv4/hostname that's also safe as a directory/file component.
# No colons (rules out IPv6 — OSCP targets are v4), no slashes, no traversal.
_TARGET_RE = re.compile(r"^(?=.{1,64}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
# Root path may contain ~ / . _ - only (expanded later); never shell metachars.
_ROOT_RE = re.compile(r"^[A-Za-z0-9_./~-]+$")
# Generated temp rcfile path we embed in script's -c string. Tight allow-list.
_RCPATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")


def die(msg: str, code: int = EXIT_USAGE):
    """Fatal. Defaults to EXIT_USAGE - this used to default to 2, which in the
    suite now means "ran fine, nothing to report"."""
    print(f"[!] {msg}", file=sys.stderr)
    raise SystemExit(code)


def info(msg: str):
    print(f"[*] {msg}")


def validate_target(s: str) -> str:
    if ".." in s or not _TARGET_RE.match(s):
        die(f"refusing target {s!r}: not a plain IPv4/hostname "
            "(letters, digits, dot, hyphen; no slashes, no '..')")
    return s


def validate_root(s: str) -> Path:
    if ".." in s or not _ROOT_RE.match(s):
        die(f"refusing root {s!r}: unsafe characters or '..'")
    return Path(os.path.expanduser(s)).resolve()


def validate_shell(s: str) -> str:
    if s not in SHELLS:
        die(f"unsupported shell {s!r}; choose one of {', '.join(SHELLS)}")
    return s


def detect_shell() -> str:
    base = os.path.basename(os.environ.get("SHELL", "")).strip()
    return base if base in SHELLS else "bash"


def box_paths(root: Path, ip: str) -> dict[str, Path]:
    box = root / ip
    return {
        "box": box,
        "log": box / f"{ip}_session.log",
        "markers": box / f"{ip}_markers.log",
        "timeline": box / f"{ip}_timeline.log",
        "report": box / f"{ip}_timeline.txt",
    }


# --- shell rc (generic: reads session paths from the environment, so no
#     target/path string is ever baked into shell code) --------------------
_BASH_RC = r"""# script_logger session rc (bash) — auto-generated, safe to delete.
[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
# Per-command timeline hook: log each new history entry with a timestamp.
# Arm on the first fire (the pre-first-prompt fire) so a stale command left in
# ~/.bash_history by a previous session is used only as the baseline, never logged.
__sl_armed=""
__sl_last_num=""
__sl_log_cmd() {
  local h n c
  h=$(history 1)
  n=$(printf '%s' "$h" | awk '{print $1}')
  if [ -z "$__sl_armed" ]; then __sl_armed=1; __sl_last_num=$n; return; fi
  c=$(printf '%s' "$h" | sed 's/^ *[0-9]\+ *//')
  if [ "$n" != "$__sl_last_num" ] && [ -n "$c" ] && [ -n "$SCRIPT_LOGGER_TIMELINE" ]; then
    __sl_last_num=$n
    printf '%s\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$c" >> "$SCRIPT_LOGGER_TIMELINE"
  fi
}
case "$PROMPT_COMMAND" in
  *__sl_log_cmd*) : ;;
  *) PROMPT_COMMAND="__sl_log_cmd${PROMPT_COMMAND:+; $PROMPT_COMMAND}" ;;
esac
"""

_ZSH_RC = r"""# script_logger session rc (zsh) — auto-generated, safe to delete.
[ -f /etc/zsh/zshrc ] && . /etc/zsh/zshrc
[ -f "$HOME/.zshrc" ] && . "$HOME/.zshrc"
# preexec fires once per command with the full line in $1 — faithful timeline.
__sl_preexec() {
  [ -n "$SCRIPT_LOGGER_TIMELINE" ] || return
  printf '%s\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$SCRIPT_LOGGER_TIMELINE"
}
autoload -Uz add-zsh-hook 2>/dev/null && add-zsh-hook preexec __sl_preexec 2>/dev/null \
  || preexec_functions+=(__sl_preexec)
"""


def _session_env(p: dict[str, Path]) -> dict[str, str]:
    env = os.environ.copy()
    env["SCRIPT_LOGGER_IP"] = p["box"].name
    env["SCRIPT_LOGGER_DIR"] = str(p["box"])
    env["SCRIPT_LOGGER_MARKERS"] = str(p["markers"])
    env["SCRIPT_LOGGER_TIMELINE"] = str(p["timeline"])
    return env


# --- start ----------------------------------------------------------------
def cmd_start(args):
    ip = validate_target(args.ip)
    root = validate_root(args.root)
    shell = validate_shell(args.shell or detect_shell())
    p = box_paths(root, ip)

    for d in (p["box"], *(p["box"] / s for s in SUBDIRS)):
        d.mkdir(parents=True, exist_ok=True)

    env = _session_env(p)
    tmp_cleanup = []

    if shell == "bash":
        fd, rcpath = tempfile.mkstemp(prefix="sl_bashrc_", suffix=".sh")
        with os.fdopen(fd, "w") as fh:
            fh.write(_BASH_RC)
        if not _RCPATH_RE.match(rcpath):  # defense in depth on the embedded path
            os.unlink(rcpath)
            die(f"generated rc path looks unsafe: {rcpath!r}")
        tmp_cleanup.append(rcpath)
        inner = f"bash --rcfile '{rcpath}' -i"
    else:  # zsh — inject rc via a private ZDOTDIR, no path in the command string
        zdir = tempfile.mkdtemp(prefix="sl_zdot_")
        (Path(zdir) / ".zshrc").write_text(_ZSH_RC)
        env["ZDOTDIR"] = zdir
        tmp_cleanup.append(zdir)
        inner = "zsh -i"

    # `-a` appends, so reconnecting to a box continues the same transcript.
    script_argv = ["script", "-q", "-a", "-c", inner, str(p["log"])]

    if args.dry_run:
        info(f"shell        : {shell}")
        info(f"box dir      : {p['box']}  (+ {', '.join(SUBDIRS)}/)")
        info(f"transcript   : {p['log']}")
        info(f"timeline     : {p['timeline']}")
        info(f"markers      : {p['markers']}")
        info("session env  : " + " ".join(
            f"{k}={env[k]}" for k in
            ("SCRIPT_LOGGER_IP", "SCRIPT_LOGGER_DIR",
             "SCRIPT_LOGGER_MARKERS", "SCRIPT_LOGGER_TIMELINE")))
        info("script cmd   : " + " ".join(script_argv))
        _cleanup(tmp_cleanup)
        return 0

    if shutil.which("script") is None:
        _cleanup(tmp_cleanup)
        die("`script` (util-linux) not found on PATH")

    info(f"logging {ip} → {p['log']} (type `exit` to end; `mark <text>` to flag steps)")
    rc = 0
    try:
        # Interactive, user-driven session: deliberately NO timeout — the whole
        # point is that Jose holds it open for hours. rc handled below.
        proc = subprocess.run(script_argv, env=env)
        rc = proc.returncode
    except FileNotFoundError:
        _cleanup(tmp_cleanup)
        die("`script` (util-linux) not found on PATH")
    except KeyboardInterrupt:
        print()  # let the child see the Ctrl-C; fall through to timeline
    finally:
        _cleanup(tmp_cleanup)

    # `script` returns the child shell's exit status; a non-zero here just
    # means the last command in the session exited non-zero — not our error.
    if rc not in (0, None):
        info(f"session shell exited with status {rc} (last command's rc — normal)")

    _build_timeline(p, to_stdout=True)
    return 0


def _cleanup(paths):
    for pth in paths:
        try:
            if os.path.isdir(pth):
                shutil.rmtree(pth, ignore_errors=True)
            else:
                os.unlink(pth)
        except OSError:
            pass


# --- mark -----------------------------------------------------------------
def cmd_mark(args):
    markers = os.environ.get("SCRIPT_LOGGER_MARKERS")
    if not markers:
        die("not inside a logging session - run `script-logger start <ip>` first")
    if ".." in markers or not _RCPATH_RE.match(os.path.abspath(markers)):
        die("session markers path from the environment looks unsafe; refusing to write")
    text = " ".join(args.text).strip()
    if not text:
        die("mark needs some text, e.g. `mark got www-data shell`")
    # Marker text is only ever file content + stdout (never argv, never a shell),
    # so shell payloads are inert. scrub() is still the right call: it drops control
    # bytes and collapses the tab that would otherwise sit in a tab-separated field.
    text = scrub(text, limit=500)
    if not text:
        die("mark needs some text, e.g. `mark got www-data shell`")
    ts = datetime.now().strftime(TS_FMT)
    try:
        with open(markers, "a") as fh:
            fh.write(f"{ts}\t{text}\n")
    except OSError as e:
        die(f"could not write marker: {e}")
    # Echo so the marker also lands in the live transcript.
    print(f"[MARK {ts}] {text}")
    return 0


# --- stop / timeline ------------------------------------------------------
def _read_stamped(path: Path):
    out = []
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        if "\t" not in line:
            continue
        ts, _, text = line.partition("\t")
        ts, text = ts.strip(), text.strip()
        if ts and text:
            out.append((ts, text))
    return out


def _build_timeline(p: dict[str, Path], to_stdout: bool):
    cmds = [(ts, "CMD", t) for ts, t in _read_stamped(p["timeline"])]
    marks = [(ts, "MARK", t) for ts, t in _read_stamped(p["markers"])]
    rows = sorted(cmds + marks, key=lambda r: r[0])  # ISO timestamps sort lexically

    ip = p["box"].name
    header = f"Session timeline — {ip}   ({len(cmds)} commands, {len(marks)} markers)"

    # Plain-text report file (always written — this is the report artifact).
    lines = [header, "=" * len(header), ""]
    for ts, kind, text in rows:
        tag = ">>> MARK" if kind == "MARK" else "        "
        lines.append(f"{ts}  {tag}  {text}" if kind == "MARK"
                     else f"{ts}          {text}")
    report = "\n".join(lines) + "\n"
    try:
        p["report"].write_text(report)
    except OSError as e:
        info(f"could not write {p['report']}: {e}")

    if not to_stdout:
        return report

    if _console and rows:
        table = Table(title=header, show_lines=False)
        table.add_column("time", style="cyan", no_wrap=True)
        table.add_column("", no_wrap=True)
        table.add_column("entry")
        for ts, kind, text in rows:
            if kind == "MARK":
                table.add_row(ts, "[bold red]MARK[/]", f"[bold]{text}[/]")
            else:
                table.add_row(ts, "", text)
        _console.print(table)
    else:
        print(report, end="")
    info(f"timeline written → {p['report']}")
    return report


def cmd_stop(args):
    ip = validate_target(args.ip)
    root = validate_root(args.root)
    p = box_paths(root, ip)
    if not p["box"].exists():
        die(f"no session directory for {ip} under {root}")
    _build_timeline(p, to_stdout=True)
    return 0


# --- status (read-only) ---------------------------------------------------
def cmd_status(args):
    ip = validate_target(args.ip)
    root = validate_root(args.root)
    p = box_paths(root, ip)
    json_out = getattr(args, "json_out", None)

    if not p["box"].exists():
        if json_out:
            emit_json(_status_json(ip, p, exists=False, n_cmd=0, n_mark=0), json_out)
        else:
            info(f"no session directory yet for {ip} (would live at {p['box']})")
        return EXIT_NO_DATA

    if json_out:
        emit_json(
            _status_json(ip, p, exists=True,
                         n_cmd=len(_read_stamped(p["timeline"])),
                         n_mark=len(_read_stamped(p["markers"]))),
            json_out,
        )
        return EXIT_OK

    info(f"box dir: {p['box']}")
    for key in ("log", "timeline", "markers", "report"):
        f = p[key]
        if f.exists():
            print(f"    {f.name:<24} {f.stat().st_size:>10} bytes")
        else:
            print(f"    {f.name:<24} {'—':>10}")
    n_cmd = len(_read_stamped(p["timeline"]))
    n_mark = len(_read_stamped(p["markers"]))
    print(f"    {'commands logged':<24} {n_cmd:>10}")
    print(f"    {'markers':<24} {n_mark:>10}")
    return EXIT_OK


def _status_json(ip, p, exists, n_cmd, n_mark):
    return envelope(
        tool="script-logger",
        tool_version=__version__,
        subject=ip,
        summary=(f"{n_cmd} command(s), {n_mark} marker(s)" if exists
                 else "no session directory yet"),
        data={
            "target": ip,
            "box_dir": str(p["box"]),
            "exists": exists,
            "files": {
                key: {"path": str(p[key]),
                      "exists": p[key].exists(),
                      "bytes": p[key].stat().st_size if p[key].exists() else 0}
                for key in ("log", "timeline", "markers", "report")
            },
            "commands_logged": n_cmd,
            "markers": n_mark,
        },
    )


# --- cli ------------------------------------------------------------------
_EXAMPLES = """examples:
  script-logger start 10.10.10.10
      make the evidence tree and drop into a recorded shell

  script-logger start 10.10.10.10 --shell zsh
      the zsh timeline is the more faithful one (it catches `exit` too)

  mark got a shell as www-data
      stamp a major step - `mark` is this same tool under another name

  script-logger stop 10.10.10.10
      rebuild and print the merged command + marker timeline

  script-logger status 10.10.10.10 --json -
      what's on disk, machine-readable, without touching anything
"""


def build_parser() -> argparse.ArgumentParser:
    ap = ToolParser(
        prog="script-logger",
        description="Per-box terminal transcript, evidence tree, timeline and markers.\n"
                    "Documentation only: it records my own terminal and organises my own\n"
                    "notes. It never connects to, scans, or touches a target.",
        epilog=build_epilog(_EXAMPLES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_global_flags(ap, "script-logger", __version__)

    # Shared --root, accepted either before OR after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=DEFAULT_ROOT, metavar="DIR",
                        help=f"base directory for per-box folders (default: {DEFAULT_ROOT})")
    common.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--root", default=DEFAULT_ROOT, help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", metavar="<command>")

    sp = sub.add_parser("start", parents=[common], help="open a logged session for <ip>")
    sp.add_argument("ip")
    sp.add_argument("--shell", choices=SHELLS,
                    help="shell to log inside (default: $SHELL if bash/zsh, else bash)")
    sp.add_argument("--dry-run", action="store_true",
                    help="show the exact `script` command and paths, launch nothing")
    sp.set_defaults(func=cmd_start)

    sp = sub.add_parser("stop", parents=[common],
                        help="(re)build and print the timeline for <ip>")
    sp.add_argument("ip")
    sp.set_defaults(func=cmd_stop)

    sp = sub.add_parser("status", parents=[common], help="read-only: what's on disk for <ip>")
    sp.add_argument("ip")
    sp.add_argument("--json", dest="json_out", metavar="FILE",
                    help="write machine-readable JSON ('-' for stdout)")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("mark", parents=[common],
                        help="stamp a major-step marker (usually run as bare `mark`)")
    sp.add_argument("text", nargs="+")
    sp.set_defaults(func=cmd_mark)
    return ap


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # Still honour the old busybox-style symlink install, so an existing
    # `ln -s script_logger.py mark` keeps working alongside the new entry point.
    if os.path.basename(sys.argv[0]) == "mark":
        return main_mark(argv)

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.cmd:
        render_banner("script-logger", __version__)
        parser.print_help()
        return EXIT_USAGE

    # Never over JSON-to-stdout, and never in front of a recorded shell - the
    # banner would be the first thing in the transcript.
    if (not getattr(args, "no_banner", False)
            and getattr(args, "json_out", None) != "-"
            and args.cmd != "start"):
        render_banner("script-logger", __version__)

    try:
        rc = args.func(args)
        return EXIT_OK if rc is None else rc
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED


def main_mark(argv=None):
    """`mark <text...>` - everything after the command is marker text."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: mark <what you just did>", file=sys.stderr)
        return EXIT_USAGE
    ns = argparse.Namespace(text=argv, root=DEFAULT_ROOT)
    try:
        rc = cmd_mark(ns)
        return EXIT_OK if rc is None else rc
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


def main_cli():
    """Console-script entry point for `script-logger`."""
    return main()


def main_mark_cli():
    """Console-script entry point for the bare `mark` command."""
    return main_mark()


if __name__ == "__main__":
    sys.exit(main_cli())
