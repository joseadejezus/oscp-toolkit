#!/usr/bin/env python3
"""
ligolo-pivot

The repetitive Ligolo-ng tun + route dance, in one command.

    ligolo-pivot up                     # create/raise the tun, then land in the proxy console
    ligolo-pivot route 10.10.20.0/24    # add a route into the pivot subnet (2nd terminal)
    ligolo-pivot status                 # what's up, what's routed (read-only, no root)
    ligolo-pivot down                   # flush routes + delete the interface

Setup automation only: it wires the interface and routes packets, then hands you
the proxy TUI. You still pick the session, `start` the tunnel, and decide what to
route and what to run over it. See the README for detail.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

from . import __version__
from ._common.banner import render_banner
from ._common.cli import ToolParser, add_global_flags, build_epilog
from ._common.exits import EXIT_INTERRUPTED, EXIT_NO_DATA, EXIT_OK, EXIT_USAGE
from ._common.jsonout import emit as emit_json
from ._common.jsonout import envelope
from ._common.ui import RICH as _HAVE_RICH
from ._common.ui import Console, Table
from ._common.validate import (
    ValidationError,
    validate_iface as _shared_iface,
    validate_ip,
    validate_port,
    validate_subnet as _shared_subnet,
)

_console = Console() if _HAVE_RICH else None

IP = shutil.which("ip") or "ip"  # resolved once; a fake `ip` earlier on $PATH is picked up for tests
IP_TIMEOUT = 10  # seconds — ip(8) calls are local and instant; a hang means something is wrong

# --- allow-lists: reject outright, never sanitize (defense in depth on top of shell=False) -------
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")     # tun owner (root in Exegol)
BIN_RE = re.compile(r"^[A-Za-z0-9_./-]+$")          # proxy binary name or path
PROXY_ARG_RE = re.compile(r"^[A-Za-z0-9_.:/=-]+$")  # passthrough tokens for `proxy`

# The ligolo-ng proxy binary goes by different names depending on how it was installed:
# upstream releases ship it as `proxy`; Exegol symlinks it onto $PATH as `ligolo-ng`
# (/opt/tools/bin/ligolo-ng); Kali's package installs it as `ligolo-proxy`. When --proxy-bin
# isn't given we try these in order and take the first that resolves, instead of assuming one.
PROXY_BIN_CANDIDATES = ("proxy", "ligolo-ng", "ligolo-proxy")


def _die(msg):
    """Fatal, and always EXIT_USAGE. This used to exit 2, which in the suite now
    means "ran fine, nothing to report" - the wrong thing for a refused input."""
    (_console.print(f"[bold red]![/] {msg}") if _HAVE_RICH else print(f"! {msg}", file=sys.stderr))
    raise ValidationError(msg)


def _info(msg):
    (_console.print(f"[cyan]>[/] {msg}") if _HAVE_RICH else print(f"> {msg}"))


def _ok(msg):
    (_console.print(f"[green]+[/] {msg}") if _HAVE_RICH else print(f"+ {msg}"))


def _warn(msg):
    (_console.print(f"[yellow]~[/] {msg}") if _HAVE_RICH else print(f"~ {msg}"))


# --- validation ----------------------------------------------------------------------------------
def valid_iface(name):
    try:
        return _shared_iface(name)
    except ValidationError:
        _die(f"bad interface name {name!r} - allowed: letters/digits/_/.:- up to 15 chars")


def valid_user(name):
    if not USER_RE.match(name):
        _die(f"bad tun owner {name!r} - allowed: letters/digits/_/.- up to 32 chars")
    return name


def valid_subnet(text):
    # ipaddress is the real gate (rejects junk, normalises); a bare host becomes /32.
    try:
        return _shared_subnet(text)
    except ValidationError:
        _die(f"bad subnet {text!r} - not an IP or CIDR")


def valid_laddr(host, port):
    try:
        host = validate_ip(host)
    except ValidationError:
        _die(f"bad --laddr {host!r} - not an IP address")
    try:
        port = validate_port(port)
    except ValidationError:
        _die(f"bad --port {port} - must be 1-65535")
    return f"{host}:{port}"


def valid_proxy_bin(name):
    """Validate + resolve a single, explicitly-given proxy binary (name or path)."""
    if not BIN_RE.match(name):
        _die(f"bad --proxy-bin {name!r}")
    if "/" in name:  # an explicit path has to exist and be executable
        if not (os.path.isfile(name) and os.access(name, os.X_OK)):
            _die(f"--proxy-bin {name!r} is not an executable file")
        return name
    resolved = shutil.which(name)
    if not resolved:
        _die(f"--proxy-bin {name!r} not found on $PATH (Exegol ships it as `ligolo-ng`)")
    return resolved


def resolve_proxy_bin(name):
    """Resolve the proxy binary for `up`.

    name given -> honour it exactly (path or single name), erroring if it won't resolve.
    name None  -> auto-detect: try each known candidate name on $PATH, first hit wins.
    Auto-detect only searches $PATH names, never a path, so it can't be steered at a file.
    """
    if name is not None:
        return valid_proxy_bin(name)
    for cand in PROXY_BIN_CANDIDATES:
        resolved = shutil.which(cand)
        if resolved:
            return resolved
    tried = ", ".join(f"`{c}`" for c in PROXY_BIN_CANDIDATES)
    _die(f"no ligolo proxy binary found on $PATH (looked for {tried}); "
         "Exegol ships it as `ligolo-ng` — pass --proxy-bin to point at it explicitly")


def valid_proxy_args(args):
    for a in args:
        if not PROXY_ARG_RE.match(a):
            _die(f"bad --proxy-arg {a!r} - rejected by allow-list")
    return list(args)


# --- ip(8) wrapper: argv list, explicit timeout, explicit rc handling ----------------------------
def run_ip(args, check=True, capture=True):
    """Run `ip <args>` as an argv list. Returns CompletedProcess. On check=True a non-zero rc dies."""
    if shutil.which(IP) is None and not os.path.isabs(IP):
        _die("`ip` (iproute2) not found — this runs inside Exegol/Linux, not on the Mac host")
    cmd = [IP, *args]
    try:
        cp = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=IP_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _die(f"`{' '.join(cmd)}` timed out after {IP_TIMEOUT}s")
    except FileNotFoundError:
        _die(f"`{IP}` not found")
    if check and cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        _die(f"`{' '.join(cmd)}` failed (rc={cp.returncode}): {err}")
    return cp


def require_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        _die("needs root for ip tuntap/link/route (you're root in Exegol; use sudo otherwise)")


def iface_exists(iface):
    return run_ip(["link", "show", iface], check=False).returncode == 0


def route_exists(subnet, iface):
    cp = run_ip(["route", "show", subnet, "dev", iface], check=False)
    return cp.returncode == 0 and cp.stdout.strip() != ""


def iface_routes(iface):
    cp = run_ip(["-o", "route", "show", "dev", iface], check=False)
    if cp.returncode != 0:
        return []
    return [ln.split()[0] for ln in cp.stdout.splitlines() if ln.strip()]


# --- subcommands ---------------------------------------------------------------------------------
def cmd_up(args):
    require_root()
    iface = valid_iface(args.iface)
    user = valid_user(args.user)
    proxy_bin = resolve_proxy_bin(args.proxy_bin)  # resolve before touching the interface
    laddr = valid_laddr(args.laddr, args.port)
    extra = valid_proxy_args(args.proxy_arg)

    if iface_exists(iface):
        _warn(f"{iface} already exists — leaving it, just ensuring it's up")
    else:
        run_ip(["tuntap", "add", "user", user, "mode", "tun", iface])
        _ok(f"created tun {iface} (owner {user})")
    run_ip(["link", "set", iface, "up"])
    _ok(f"{iface} is up")

    proxy_cmd = [proxy_bin]
    if not args.no_selfcert:
        proxy_cmd.append("-selfcert")
    proxy_cmd += ["-laddr", laddr, *extra]

    if args.no_proxy:
        _info("interface ready. proxy not started (--no-proxy). run it yourself:")
        print("    " + " ".join(proxy_cmd))
        _info(f"tear down later with:  {os.path.basename(sys.argv[0])} down --iface {iface}")
        return
    _info("handing off to the proxy console — quit it, then run "
          f"`{os.path.basename(sys.argv[0])} down` to clean up")
    print("    " + " ".join(proxy_cmd))
    # exec: replace this process so the interactive TUI gets a clean TTY and our signals stay out.
    try:
        os.execv(proxy_bin, proxy_cmd)
    except OSError as e:
        _die(f"could not exec proxy: {e}")


def cmd_down(args):
    require_root()
    iface = valid_iface(args.iface)
    if not iface_exists(iface):
        _ok(f"{iface} already down — nothing to do")
        return
    routes = iface_routes(iface)
    # flush routes on the dev (rc!=0 just means none existed — don't treat as fatal)
    run_ip(["route", "flush", "dev", iface], check=False)
    if routes:
        _ok(f"flushed {len(routes)} route(s): {', '.join(routes)}")
    run_ip(["link", "set", iface, "down"], check=False)
    run_ip(["tuntap", "del", "mode", "tun", iface])
    _ok(f"deleted tun {iface}")


def cmd_route(args):
    require_root()
    iface = valid_iface(args.iface)
    subnet = valid_subnet(args.subnet)
    if not iface_exists(iface):
        _die(f"{iface} does not exist — run `up` first")
    if args.delete:
        if not route_exists(subnet, iface):
            _ok(f"no route {subnet} on {iface} — nothing to remove")
            return
        run_ip(["route", "del", subnet, "dev", iface])
        _ok(f"removed route {subnet} dev {iface}")
        return
    if route_exists(subnet, iface):
        _warn(f"route {subnet} dev {iface} already present — leaving it")
        return
    run_ip(["route", "add", subnet, "dev", iface])
    _ok(f"added route {subnet} dev {iface}")


def cmd_status(args):
    iface = valid_iface(args.iface)
    if not iface_exists(iface):
        if args.json_out:
            emit_json(_status_json(iface, "ABSENT", [], []), args.json_out)
        else:
            _warn(f"{iface}: down / does not exist")
        return EXIT_NO_DATA
    link = run_ip(["-o", "link", "show", iface], check=False).stdout.strip()
    state = "UP" if (" UP " in link or "state UP" in link) else "DOWN"
    addrs = run_ip(["-o", "-4", "addr", "show", iface], check=False).stdout
    addr_list = [ln.split()[3] for ln in addrs.splitlines() if len(ln.split()) > 3]
    routes = iface_routes(iface)

    if args.json_out:
        emit_json(_status_json(iface, state, addr_list, routes), args.json_out)
        return EXIT_OK

    if _HAVE_RICH:
        t = Table(title=f"ligolo pivot: {iface}", show_header=True, header_style="bold cyan")
        t.add_column("field")
        t.add_column("value")
        t.add_row("state", f"[green]{state}[/]" if state == "UP" else f"[red]{state}[/]")
        t.add_row("addrs", ", ".join(addr_list) or "-")
        t.add_row("routes", "\n".join(routes) or "-")
        _console.print(t)
    else:
        print(f"iface  : {iface}")
        print(f"state  : {state}")
        print(f"addrs  : {', '.join(addr_list) or '-'}")
        print(f"routes : {', '.join(routes) or '-'}")
    return EXIT_OK


def _status_json(iface, state, addrs, routes):
    return envelope(
        tool="ligolo-pivot",
        tool_version=__version__,
        subject=iface,
        summary=f"{iface} {state}, {len(routes)} route(s)",
        data={"iface": iface, "state": state, "addrs": addrs, "routes": routes},
    )


# --- cli ----------------------------------------------------------------------------------------
_EXAMPLES = """examples:
  sudo ligolo-pivot up
      create/raise the ligolo tun, then drop into the proxy console

  sudo ligolo-pivot route 10.10.20.0/24
      from a second terminal, route the pivot subnet you read off the agent

  ligolo-pivot status --json -
      what's up and what's routed, machine-readable (read-only, no root)

  sudo ligolo-pivot down
      flush the routes and delete the interface
"""


def build_parser():
    p = ToolParser(
        prog="ligolo-pivot",
        description="One-command Ligolo-ng tun and route setup/teardown.\n"
                    "Transport plumbing only - it wires the interface and routes packets,\n"
                    "it never selects or fires anything over the tunnel.",
        epilog=build_epilog(_EXAMPLES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_global_flags(p, "ligolo-pivot", __version__)
    p.add_argument("--iface", default="ligolo", metavar="NAME",
                   help="tun interface name (default: ligolo)")
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    up = sub.add_parser("up", help="create/raise the tun, then exec the proxy console")
    up.add_argument("--user", default="root",
                    help="tun owner for `ip tuntap add user` (default: root)")
    up.add_argument("--proxy-bin", default=None,
                    help="proxy binary name/path (default: auto-detect "
                         "proxy/ligolo-ng/ligolo-proxy on $PATH)")
    up.add_argument("--laddr", default="0.0.0.0", help="proxy listen host (default: 0.0.0.0)")
    up.add_argument("--port", type=int, default=11601, help="proxy listen port (default: 11601)")
    up.add_argument("--no-selfcert", action="store_true",
                    help="don't pass -selfcert (bring your own cert)")
    up.add_argument("--proxy-arg", action="append", default=[], metavar="ARG",
                    help="extra token passed to proxy (repeatable, allow-list validated)")
    up.add_argument("--no-proxy", action="store_true",
                    help="set up the interface only; print the proxy command")
    up.set_defaults(func=cmd_up)

    dn = sub.add_parser("down", help="flush routes + delete the interface (idempotent)")
    dn.set_defaults(func=cmd_down)

    rt = sub.add_parser("route", help="add/remove a subnet route into the tun")
    rt.add_argument("subnet", help="CIDR or host, e.g. 10.10.20.0/24 or 10.10.20.5")
    rt.add_argument("--del", dest="delete", action="store_true",
                    help="remove the route instead of adding it")
    rt.set_defaults(func=cmd_route)

    st = sub.add_parser("status", help="interface state, address and routes (read-only)")
    st.add_argument("--json", dest="json_out", metavar="FILE",
                    help="write machine-readable JSON ('-' for stdout)")
    st.set_defaults(func=cmd_status)

    for s_ in (up, dn, rt, st):
        s_.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.cmd:
        render_banner("ligolo-pivot", __version__)
        parser.print_help()
        return EXIT_USAGE

    # Never over JSON-to-stdout: that output is meant to be piped into something.
    if not args.no_banner and getattr(args, "json_out", None) != "-":
        render_banner("ligolo-pivot", __version__)

    try:
        rc = args.func(args)
        return EXIT_OK if rc is None else rc
    except ValidationError:
        return EXIT_USAGE          # _die already printed the message
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        _warn("interrupted")
        return EXIT_INTERRUPTED


def main_cli():
    """Console-script entry point (see pyproject [project.scripts])."""
    return main()


if __name__ == "__main__":
    sys.exit(main_cli())
