#!/usr/bin/env python3
"""
ad-enum

One credential, one DC, five read-only enumeration stages, merged into a single
report. What nmap-recon is for ports, this is for a domain.

Full writeup + usage examples: see the README. Short version:

    ad-enum sweep 10.10.10.5 -d corp.local -u jose -p 'Pass!'
    ad-enum sweep 10.10.10.5 -d corp.local -u jose -H :<nthash>
    ad-enum report 10.10.10.5 -d corp.local --markdown ad.md

Roasting collects hashes for OFFLINE cracking (feed them to hash-triage) - it
never cracks and then authenticates. bloodyAD is locked to get-only verbs, so
"writable" means rights worth confirming in BloodHound, not rights abused.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from ._common.banner import render_banner
from ._common.cli import ToolParser, add_global_flags, build_epilog
from ._common.exits import EXIT_INTERRUPTED, EXIT_NO_DATA, EXIT_OK, EXIT_USAGE
from ._common.jsonout import emit as emit_json
from ._common.jsonout import envelope
from ._common.text import bold, colour, dim, fmt_duration, scrub, scrub_line
from ._common.validate import (
    EMPTY_LM,
    ValidationError,
    safe_dir,
    safe_output_path,
    validate_domain,
    validate_host,
    validate_ntlm,
    validate_password,
)
from ._common.validate import validate_username as validate_user

# --- Optional rich rendering; degrades gracefully without it ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    _RICH = True
except ImportError:
    _RICH = False

DEFAULT_OUTDIR = "./ad-enum"
DEFAULT_STAGE_TIMEOUT = 600          # per-stage wall-clock cap (seconds)
SKEW_LDAP_TIMEOUT = 10               # connect/read cap for the preflight skew check
KERBEROS_SKEW_LIMIT = 300            # 5 minutes - past this Kerberos ops fail

_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"  # LM of the empty string

# Allow-list validators. Everything below is defense in depth on top of the
# shell=False / argv-list subprocess calls - a weird value here is a typo or a
# trap, so it's a hard reject, never a silent scrub.
STAGE_ORDER = ["enum", "kerberoast", "asreproast", "modules", "writable"]
STAGE_HELP = {
    "enum": "nxc ldap --users --groups --pass-pol",
    "kerberoast": "nxc ldap --kerberoasting (SPN hashes -> offline cracking)",
    "asreproast": "nxc ldap --asreproast (no-preauth hashes -> offline cracking)",
    "modules": "nxc ldap -M maq -M adcs (machine account quota + ADCS presence)",
    "writable": "bloodyAD get writable --detail (read-only ACL enum)",
}


@dataclass
class Ctx:
    dc: str
    domain: str
    user: str = ""
    password: Optional[str] = None
    lm: Optional[str] = None
    nt: Optional[str] = None
    outdir: Path = field(default_factory=lambda: Path(DEFAULT_OUTDIR))
    use_fallback: bool = True

    @property
    def by_hash(self) -> bool:
        return self.nt is not None

    @property
    def hashes_str(self) -> str:
        return f"{self.lm or _EMPTY_LM}:{self.nt}"

    def base_dn(self) -> str:
        parts = [p for p in self.domain.split(".") if p]
        return ",".join(f"DC={p}" for p in parts)

    def kerb_file(self) -> Path:
        return self.outdir / f"kerb.{self.dc}.txt"

    def asrep_file(self) -> Path:
        return self.outdir / f"asrep.{self.dc}.txt"

    def log_file(self, stage: str) -> Path:
        return self.outdir / f"{stage}.{self.dc}.log"


# --- input validation ------------------------------------------------------

def validate_hashes(value: str) -> tuple[Optional[str], str]:
    """Adapt the shared LM:NT validator to the (lm_or_None, nt) shape this uses."""
    lm, _, nt = validate_ntlm(value).partition(":")
    return (lm if lm != EMPTY_LM else None), nt


# --- little output helpers -------------------------------------------------

def _c(color: str, msg: str) -> None:
    if _RICH:
        Console().print(f"[{color}]{msg}[/{color}]")
    else:
        print(msg)


def _info(msg: str) -> None:
    _c("cyan", f"[*] {msg}")


def _warn(msg: str) -> None:
    _c("yellow", f"[!] {msg}")


def _err(msg: str) -> None:
    _c("bold red", f"[-] {msg}")


def redact(cmd: list[str], ctx: Ctx) -> str:
    """Command line for display/logging with the secret masked.

    The real argv still carries the true password/hash; this is only so the
    creds don't land in my terminal, the stage log, or a script_logger
    transcript.
    """
    secrets = set()
    if ctx.password:
        secrets.add(ctx.password)
    if ctx.nt:
        secrets.add(ctx.hashes_str)
        secrets.add(f":{ctx.nt}")
        secrets.add(ctx.nt)
        # The empty-LM constant isn't a secret, but leaving half a hash on screen
        # reads like a leak. Mask the LM half too so the echo is unambiguous.
        if ctx.lm:
            secrets.add(ctx.lm)
    out = []
    for tok in cmd:
        masked = tok
        for s in secrets:
            if s and s in masked:
                masked = masked.replace(s, "******")
        # also mask DOMAIN/USER:PASS impacket targets
        if ctx.password and f":{ctx.password}" in tok:
            masked = tok.split(":")[0] + ":******"
        out.append(masked)
    return " ".join(out)


# --- auth argument builders ------------------------------------------------

def nxc_auth(ctx: Ctx) -> list[str]:
    args = ["-u", ctx.user]
    if ctx.by_hash:
        args += ["-H", ctx.hashes_str]
    else:
        args += ["-p", ctx.password or ""]
    return args


def bloodyad_auth(ctx: Ctx) -> list[str]:
    args = ["-d", ctx.domain, "-u", ctx.user]
    if ctx.by_hash:
        args += ["-p", ctx.hashes_str]          # bloodyAD takes LM:NT for PtH
    else:
        args += ["-p", ctx.password or ""]
    return args


def impacket_target(ctx: Ctx) -> str:
    if ctx.by_hash:
        return f"{ctx.domain}/{ctx.user}"
    return f"{ctx.domain}/{ctx.user}:{ctx.password or ''}"


def impacket_hash_args(ctx: Ctx) -> list[str]:
    return ["-hashes", ctx.hashes_str, "-no-pass"] if ctx.by_hash else []


# --- stage command builders (primary = nxc, fallback = documented equivs) --

def primary_cmd(stage: str, ctx: Ctx) -> list[str]:
    a = nxc_auth(ctx)
    if stage == "enum":
        return ["nxc", "ldap", ctx.dc, *a, "--users", "--groups", "--pass-pol"]
    if stage == "kerberoast":
        return ["nxc", "ldap", ctx.dc, *a, "--kerberoasting", str(ctx.kerb_file())]
    if stage == "asreproast":
        return ["nxc", "ldap", ctx.dc, *a, "--asreproast", str(ctx.asrep_file())]
    if stage == "modules":
        return ["nxc", "ldap", ctx.dc, *a, "-M", "maq", "-M", "adcs"]
    if stage == "writable":
        # get-only, --detail. NEVER set/add/remove - those are write-abuse.
        return ["bloodyAD", "--host", ctx.dc, *bloodyad_auth(ctx),
                "get", "writable", "--detail"]
    raise ValidationError(f"Unknown stage: {stage}")


def fallback_cmds(stage: str, ctx: Ctx) -> list[tuple[str, list[str]]]:
    """Enumeration-equivalent fallbacks for when nxc is absent/fails.

    Every one of these is a read-only enumeration tool - the same *question*
    asked with a different client, never an exploit. Returns [(label, argv)].
    Password-only tools (ldapsearch) are skipped under -H with a note.
    """
    base = ctx.base_dn()
    if stage == "enum":
        cmds: list[tuple[str, list[str]]] = []
        idflag = ["-H", ctx.nt] if ctx.by_hash else ["-p", ctx.password or ""]
        cmds.append(("ldeep users", ["ldeep", "ldap", "-u", ctx.user, *idflag,
                                      "-d", ctx.domain, "-s", f"ldap://{ctx.dc}", "users"]))
        cmds.append(("ldeep groups", ["ldeep", "ldap", "-u", ctx.user, *idflag,
                                       "-d", ctx.domain, "-s", f"ldap://{ctx.dc}", "groups"]))
        if not ctx.by_hash:
            cmds.append(("ldapsearch pass-pol", [
                "ldapsearch", "-x", "-H", f"ldap://{ctx.dc}",
                "-D", f"{ctx.user}@{ctx.domain}", "-w", ctx.password or "",
                "-b", base, "-s", "base",
                "minPwdLength", "lockoutThreshold", "pwdProperties",
                "maxPwdAge", "pwdHistoryLength"]))
        return cmds
    if stage == "kerberoast":
        return [("GetUserSPNs", ["GetUserSPNs.py", impacket_target(ctx),
                                 *impacket_hash_args(ctx), "-dc-ip", ctx.dc,
                                 "-request", "-outputfile", str(ctx.kerb_file())])]
    if stage == "asreproast":
        return [("GetNPUsers", ["GetNPUsers.py", impacket_target(ctx),
                                *impacket_hash_args(ctx), "-dc-ip", ctx.dc,
                                "-request", "-outputfile", str(ctx.asrep_file())])]
    if stage == "modules":
        cmds = []
        if not ctx.by_hash:
            cmds.append(("ldapsearch maq", [
                "ldapsearch", "-x", "-H", f"ldap://{ctx.dc}",
                "-D", f"{ctx.user}@{ctx.domain}", "-w", ctx.password or "",
                "-b", base, "-s", "base", "ms-DS-MachineAccountQuota"]))
        certipy_auth = (["-hashes", ctx.hashes_str] if ctx.by_hash
                        else ["-p", ctx.password or ""])
        cmds.append(("certipy find (adcs)", [
            "certipy", "find", "-u", f"{ctx.user}@{ctx.domain}", *certipy_auth,
            "-dc-ip", ctx.dc, "-stdout"]))
        return cmds
    if stage == "writable":
        return []  # no clean 1:1 - handled with an honest note in the runner
    return []


# --- running a stage -------------------------------------------------------

@dataclass
class StageResult:
    stage: str
    output: str = ""
    ran: list[str] = field(default_factory=list)   # human labels of what ran
    rc: Optional[int] = None
    used_fallback: bool = False


# nxc and bloodyAD colour their own output, but only when they're talking to a
# terminal - we capture through a pipe so we can parse and save it, so what comes
# back is flat text. Rather than give that up, we re-add colour on the way out.
# Everything below is applied to text that came off the target box, so each line
# is scrubbed first and the escapes we add are our own.
_HASH_RE = re.compile(r"\$krb5[a-z]+\$\S+")
_HDR_ROW_RE = re.compile(r"^\s*-[A-Za-z]")


def _echo_tool_output(text: str) -> None:
    """Print a wrapped tool's output, scrubbed, with the noise turned down."""
    for raw in text.rstrip().splitlines():
        line = scrub_line(raw)
        if not line.strip():
            print()
            continue

        # The "LDAP  10.1.73.141  389  DC01" prefix repeats on every single line
        # and is the same every time - keep it (this should still look like nxc)
        # but dim it so it stops competing with the data beside it.
        m = _NXC_PREFIX_RE.match(line)
        prefix, body = (m.group(0), line[m.end():]) if m else ("", line)
        out = dim(prefix) if prefix else ""

        stripped = body.lstrip()
        if stripped.startswith("[+]"):
            body = colour(body, "32")            # success / creds confirmed
        elif stripped.startswith("[-]") or stripped.startswith("[!]"):
            body = colour(body, "31")            # failure - worth catching the eye
        elif stripped.startswith("[*]"):
            body = colour(body, "36")            # informational
        elif _HDR_ROW_RE.match(body):
            body = bold(body)                    # -Username- / -Group- header rows
        elif _HASH_RE.search(body):
            body = _HASH_RE.sub(lambda mm: colour(mm.group(0), "33"), body)

        print(out + body)


def run_cmd(cmd: list[str], ctx: Ctx, timeout: int) -> tuple[Optional[int], str]:
    """Run one argv (shell=False), capture combined output, echo it live-ish.

    Returns (rc, output). rc is None if the binary wasn't found (caller may then
    fall back). Timeout and rc are always surfaced - never a silent failure.
    """
    print(f"    $ {redact(cmd, ctx)}")
    try:
        proc = subprocess.run(cmd, shell=False, check=False,
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") + (exc.stderr or "")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        _warn(f"stage command timed out after {timeout}s - keeping partial output.")
        return None, out
    except FileNotFoundError:
        return None, ""   # binary missing - signal caller to consider fallback
    out = (proc.stdout or "") + (proc.stderr or "")
    if out.strip():
        _echo_tool_output(out)
    return proc.returncode, out


def stage_failed(rc: Optional[int], output: str) -> bool:
    """Did the primary stage fail hard enough to warrant the fallback?

    rc None = binary missing. Non-zero rc, or output that shows an auth/connect
    failure, counts as failed. A clean run with nothing found is NOT a failure.
    """
    if rc is None:
        return True
    if rc != 0:
        return True
    low = output.lower()
    for marker in ("logon_failure", "authentication failed", "[-] ",
                   "could not connect", "connection refused", "connection error"):
        if marker in low:
            return True
    return False


def run_stage(stage: str, ctx: Ctx, timeout: int) -> StageResult:
    res = StageResult(stage=stage)
    if shutil.which("nxc") is not None or stage == "writable":
        # writable's primary is bloodyAD, not nxc - let run_cmd report if absent.
        cmd = primary_cmd(stage, ctx)
        rc, out = run_cmd(cmd, ctx, timeout)
        res.output += out
        res.rc = rc
        primary_bin = cmd[0]
        if not stage_failed(rc, out):
            res.ran.append(primary_bin)
            return res
        if rc is None:
            _warn(f"{primary_bin} not found on PATH for stage '{stage}'.")
        else:
            _warn(f"stage '{stage}' primary ({primary_bin}) looks unhappy (rc={rc}).")
    else:
        _warn(f"nxc not found on PATH for stage '{stage}'.")

    if not ctx.use_fallback:
        _warn(f"--no-fallback set - not substituting a tool for '{stage}'.")
        return res

    fbs = fallback_cmds(stage, ctx)
    if not fbs:
        _warn(f"No auto-fallback for stage '{stage}'. Run it by hand "
              f"(writable-ACL enum: collect BloodHound then read with bh-quickwin).")
        return res

    _info(f"falling back to enumeration-equivalent tool(s) for '{stage}'.")
    for label, cmd in fbs:
        if shutil.which(cmd[0]) is None:
            _warn(f"fallback '{label}' unavailable ({cmd[0]} not on PATH).")
            continue
        rc, out = run_cmd(cmd, ctx, timeout)
        res.output += f"\n# fallback: {label}\n" + out
        res.used_fallback = True
        res.ran.append(label)
    return res


# --- parsing captured stage output into findings ---------------------------

# nxc column prefix, e.g. "LDAP  10.10.10.10  389  DC01  " or "MAQ ..." / "ADCS ..."
_NXC_PREFIX_RE = re.compile(r"^(LDAP|SMB|MAQ|ADCS|LDAPS)\s+\S+\s+\d+\s+\S+\s+")
_STATUS_RE = re.compile(r"^\s*\[[*+\-!]\]")
_KRB5TGS_RE = re.compile(r"\$krb5tgs\$\S+")
_KRB5ASREP_RE = re.compile(r"\$krb5asrep\$\S+")
_TGS_NAME_RE = re.compile(r"\$krb5tgs\$\d+\$\*([^*$]+)\$")
_ASREP_NAME_RE = re.compile(r"\$krb5asrep\$\d+\$([^@:]+)@")
_MAQ_RE = re.compile(r"MachineAccountQuota:\s*(\d+)", re.IGNORECASE)
_ENUM_COUNT_RE = re.compile(r"enumerated\s+(\d+)\s+domain\s+users", re.IGNORECASE)
# nxc column headers: "-Username-  -Last PW Set- …" and "-Group-  -Members- …".
# These are what actually delimit the two tables - the "Enumerated N" banner only
# opens the first one and nothing closes it, which is how group rows used to end
# up in the user list.
_USER_HDR_RE = re.compile(r"^-Username-", re.IGNORECASE)
_GROUP_HDR_RE = re.compile(r"^-Group-", re.IGNORECASE)
# "Remote Desktop Users      2      Members in this group are granted …"
# Two-or-more spaces is what separates nxc's columns; a single space is inside a
# group name. Only ever applied inside the groups section - a user row would
# otherwise match it via the BadPW column.
_GROUP_ROW_RE = re.compile(r"^(?P<name>\S.*?)\s{2,}(?P<n>\d+)(?:\s{2,}(?P<desc>.*))?$")
_SKEW_RE = re.compile(r"KRB_AP_ERR_SKEW|clock skew too great|clock skew", re.IGNORECASE)


def _strip_prefix(line: str) -> str:
    return _NXC_PREFIX_RE.sub("", line).rstrip()


@dataclass
class Findings:
    users: list[str] = field(default_factory=list)
    # What nxc's "Enumerated N domain users" banner claimed, so the render can
    # cross-check it against what we actually parsed instead of trusting the parse.
    users_expected: Optional[int] = None
    groups: list[tuple[str, str]] = field(default_factory=list)
    passpol: list[tuple[str, str]] = field(default_factory=list)
    kerberoastable: list[tuple[str, str]] = field(default_factory=list)
    asreproastable: list[tuple[str, str]] = field(default_factory=list)
    maq: Optional[str] = None
    adcs: list[str] = field(default_factory=list)
    writable: list[tuple[str, str]] = field(default_factory=list)
    skew_seen: bool = False
    notes: list[str] = field(default_factory=list)


_PASSPOL_KEYS = (
    "minimum password length", "password history length", "maximum password age",
    "minimum password age", "reset account lockout counter", "locked account duration",
    "account lockout threshold", "account lockout duration", "password complexity",
    "password properties", "minpwdlength", "pwdhistorylength", "maxpwdage",
    "lockoutthreshold", "pwdproperties", "ms-ds-machineaccountquota",
)


# run_stage tags each fallback block with "# fallback: <label>". The user list is
# the one thing whose shape is genuinely tool-specific: nxc announces it with an
# "Enumerated N domain users" banner, ldeep just prints bare names. Keying off the
# banner alone meant a fallback run reported zero users, which is exactly the run
# where you most need them.
_FALLBACK_MARK_RE = re.compile(r"^#\s*fallback:\s*(.+?)\s*$")


def parse_enum(text: str, f: Findings) -> None:
    """Parse the enum stage into users / groups / password policy.

    nxc prints the user table and the group table back to back with nothing
    between them but a header row, so this tracks which table it's inside.
    Getting that wrong is not a cosmetic problem: the first word of every group
    name ("Print Operators" -> "Print") used to land in the user list, and the
    real user count got buried in ~40 rows of junk.
    """
    section: Optional[str] = None   # None | "users" | "groups"
    for raw in text.splitlines():
        mark = _FALLBACK_MARK_RE.match(raw.strip())
        if mark:
            # A bare-list fallback section is users until the next section starts.
            section = "users" if mark.group(1).lower().endswith("users") else None
            continue

        body = _strip_prefix(raw)
        low = body.lower()

        # Column headers delimit the tables - and the group header is what closes
        # the user table.
        if _USER_HDR_RE.match(body):
            section = "users"
            continue
        if _GROUP_HDR_RE.match(body):
            section = "groups"
            continue

        # Any status line ends whichever table we were in: nxc emits "[+] Dumping
        # password info…" straight after the groups, with no blank line.
        if _STATUS_RE.match(body):
            m = _ENUM_COUNT_RE.search(body)
            if m:
                f.users_expected = int(m.group(1))
                section = "users"
            else:
                section = None
            continue

        # password policy: key: value lines (nxc or ldapsearch shapes)
        matched_pol = False
        for key in _PASSPOL_KEYS:
            if low.startswith(key) and ":" in body:
                k, _, v = body.partition(":")
                pair = (k.strip(), v.strip())
                if v.strip() and pair not in f.passpol:
                    f.passpol.append(pair)
                matched_pol = True
                break
        if matched_pol:
            section = None   # policy block means both tables are done
            continue

        # ldeep-style "GroupName   membercount: N" - shape is unambiguous, so it
        # doesn't need the section gate.
        m = re.search(r"^(.*?)\s+membercount:\s*(\d+)", body, re.IGNORECASE)
        if m:
            g = (m.group(1).strip(), m.group(2))
            if g[0] and g not in f.groups:
                f.groups.append(g)
            continue

        if not body.strip():
            continue

        if section == "groups":
            m = _GROUP_ROW_RE.match(body)
            if m:
                g = (m.group("name").strip(), m.group("n"))
                if g[0] and g not in f.groups:
                    f.groups.append(g)
            continue

        if section == "users":
            token = body.split()[0] if body.split() else ""
            if token and token not in f.users and not token.startswith("["):
                f.users.append(token)


def parse_roast(text: str, f: Findings, kind: str) -> None:
    if _SKEW_RE.search(text):
        f.skew_seen = True
    if kind == "tgs":
        for m in _KRB5TGS_RE.finditer(text):
            h = m.group(0)
            nm = _TGS_NAME_RE.search(h)
            name = nm.group(1) if nm else "?"
            if (name, h) not in f.kerberoastable:
                f.kerberoastable.append((name, h))
    else:
        for m in _KRB5ASREP_RE.finditer(text):
            h = m.group(0)
            nm = _ASREP_NAME_RE.search(h)
            name = nm.group(1) if nm else "?"
            if (name, h) not in f.asreproastable:
                f.asreproastable.append((name, h))


def parse_modules(text: str, f: Findings) -> None:
    if _SKEW_RE.search(text):
        f.skew_seen = True
    m = _MAQ_RE.search(text)
    if m:
        f.maq = m.group(1)
    for raw in text.splitlines():
        body = _strip_prefix(raw)
        low = body.lower()
        if any(k in low for k in ("found pki", "enrollment", "certificate authorit",
                                  "found cn", "ca name", "dnshostname", "web enrollment",
                                  "certificate templates")):
            if body and body not in f.adcs and not _STATUS_RE.match(body):
                f.adcs.append(body[:200])


def parse_writable(text: str, f: Findings) -> None:
    """bloodyAD get writable --detail prints per-object blocks with a
    distinguishedName and a permission/OWNER line. Pair them up."""
    dn = None
    for raw in text.splitlines():
        body = raw.strip()
        m = re.match(r"^distinguishedName:\s*(.+)$", body, re.IGNORECASE)
        if m:
            dn = m.group(1).strip()
            continue
        m = re.match(r"^(?:permission|OWNER|WRITE|rightsGuid)\w*:\s*(.+)$", body, re.IGNORECASE)
        if m and dn:
            perm = m.group(1).strip()
            entry = (dn, perm)
            if entry not in f.writable:
                f.writable.append(entry)


def _scrub_log(text: str) -> str:
    """AD output is remote-controlled text - a sAMAccountName or an LDAP attribute
    can carry escape sequences. Scrub per line (so line structure survives) before
    anything parses or displays it, the same way the other tools do."""
    return "\n".join(scrub(line, limit=1000) for line in text.splitlines())


def build_findings(logs: dict[str, str]) -> Findings:
    logs = {stage: _scrub_log(text) for stage, text in logs.items()}
    f = Findings()
    if "enum" in logs:
        parse_enum(logs["enum"], f)
    if "kerberoast" in logs:
        parse_roast(logs["kerberoast"], f, "tgs")
    if "asreproast" in logs:
        parse_roast(logs["asreproast"], f, "asrep")
    if "modules" in logs:
        parse_modules(logs["modules"], f)
    if "writable" in logs:
        parse_writable(logs["writable"], f)
    return f


# --- clock-skew preflight (optional ldap3) ---------------------------------

def _skew_from_currenttime(currenttime: str, now_utc: datetime) -> Optional[int]:
    """DC rootDSE currentTime is generalized time '20240814180000.0Z'.
    Return abs seconds of skew vs now_utc, or None if it won't parse."""
    m = re.match(r"^(\d{14})(?:\.\d+)?Z?$", currenttime.strip())
    if not m:
        return None
    try:
        dc_time = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(abs((now_utc - dc_time).total_seconds()))


def preflight_skew(ctx: Ctx) -> None:
    """Best-effort: read the DC's rootDSE currentTime and warn if we're more
    than ~5 min out, before any Kerberos stage runs. Needs ldap3; degrades to a
    one-line note if it's not installed or the read doesn't work out."""
    try:
        import ldap3  # type: ignore
    except ImportError:
        _warn("ldap3 not installed - skipping the up-front clock-skew check "
              "(the Kerberos stages still get scanned for skew errors). "
              "`pip install ldap3` to enable the preflight.")
        return
    try:
        server = ldap3.Server(ctx.dc, get_info=ldap3.DSA, connect_timeout=SKEW_LDAP_TIMEOUT)
        conn = ldap3.Connection(server, auto_bind=True, receive_timeout=SKEW_LDAP_TIMEOUT)
        ct = None
        if server.info and getattr(server.info, "other", None):
            vals = server.info.other.get("currentTime")
            if vals:
                ct = vals[0]
        if ct is None:
            conn.search("", "(objectClass=*)", search_scope=ldap3.BASE,
                        attributes=["currentTime"])
            if conn.entries:
                ct = str(conn.entries[0].currentTime.value)
        conn.unbind()
        if not ct:
            _warn("skew preflight: DC didn't return currentTime - relying on the "
                  "post-run output scan instead.")
            return
        skew = _skew_from_currenttime(str(ct), datetime.now(timezone.utc))
        if skew is None:
            _warn(f"skew preflight: couldn't parse DC time {ct!r}.")
            return
        if skew > KERBEROS_SKEW_LIMIT:
            _err(f"CLOCK SKEW ~{skew}s vs the DC (> {KERBEROS_SKEW_LIMIT}s) - Kerberos "
                 f"stages will likely fail. Sync first, e.g.:\n"
                 f"      sudo ntpdate {ctx.dc}    (or)    sudo timedatectl set-ntp true\n"
                 f"      faketime \"$(ntpdate -q {ctx.dc} | ...)\" <cmd>   # if you can't set the clock")
        else:
            _info(f"clock skew vs DC ~{skew}s (within {KERBEROS_SKEW_LIMIT}s - Kerberos OK).")
    except Exception as exc:  # noqa: BLE001 - preflight is best-effort by design
        _warn(f"skew preflight couldn't reach the DC over LDAP ({exc.__class__.__name__}) "
              f"- relying on the post-run output scan.")


# --- report rendering ------------------------------------------------------

def _post_process(ctx: Ctx, f: Findings) -> None:
    # If roasting only printed hashes to stdout (not the -outputfile), make sure
    # they still land on disk so hash-triage has something to eat.
    def ensure_file(path: Path, hashes: list[str]) -> None:
        if hashes and (not path.is_file() or path.stat().st_size == 0):
            path.write_text("\n".join(hashes) + "\n", encoding="utf-8")
    ensure_file(ctx.kerb_file(), [h for _, h in f.kerberoastable])
    ensure_file(ctx.asrep_file(), [h for _, h in f.asreproastable])


def render_report(ctx: Ctx, f: Findings) -> None:
    # nxc tells us how many users it found; if our parse disagrees, say so rather
    # than rendering a confident table built on a bad parse. This is exactly the
    # failure that shipped once - group rows leaking into the user list turned 6
    # users into 49, and nothing flagged it.
    if f.users_expected is not None and len(f.users) != f.users_expected:
        _warn(f"user count mismatch: nxc reported {f.users_expected}, parsed "
              f"{len(f.users)}. The Users table below is probably wrong - trust "
              f"the raw stage output above it and please report the format change.")

    if f.skew_seen:
        _err("Kerberos CLOCK SKEW error seen in stage output - roasting almost "
             "certainly came back empty because of it. Sync time to the DC "
             "(ntpdate/timedatectl/faketime) and re-run the Kerberos stages.")

    if _RICH:
        _render_rich(ctx, f)
    else:
        _render_plain(ctx, f)

    for note in f.notes:
        _warn(note)

    # actionable hand-offs to the other tools in the kit
    if f.kerberoastable:
        _info(f"{len(f.kerberoastable)} kerberoastable -> crack offline: "
              f"hash-triage {ctx.kerb_file()}")
    if f.asreproastable:
        _info(f"{len(f.asreproastable)} AS-REP-roastable -> crack offline: "
              f"hash-triage {ctx.asrep_file()}")
    if f.writable:
        _info("writable objects above are ACL leads - confirm the abuse path in "
              "BloodHound (bh-quickwin) before touching anything.")


def _sev_maq(maq: Optional[str]) -> tuple[str, str]:
    if maq is None:
        return "-", "dim"
    try:
        n = int(maq)
    except ValueError:
        return maq, "white"
    if n > 0:
        return f"{maq}  (>0: any user can join a machine - abuse-relevant)", "bold yellow"
    return f"{maq}  (0: locked down)", "green"


def _render_rich(ctx: Ctx, f: Findings) -> None:
    console = Console()
    console.rule(f"AD enumeration rollup - {ctx.domain} @ {ctx.dc}")

    if f.users:
        t = Table(title=f"Users ({len(f.users)})", show_lines=False)
        t.add_column("sAMAccountName", style="cyan")
        for u in f.users:
            t.add_row(u)
        console.print(t)

    if f.groups:
        t = Table(title=f"Groups ({len(f.groups)})")
        t.add_column("Group", style="cyan")
        t.add_column("Members", justify="right")
        for g, n in f.groups:
            t.add_row(g, n)
        console.print(t)

    if f.passpol:
        t = Table(title="Password policy")
        t.add_column("Setting", style="cyan")
        t.add_column("Value")
        for k, v in f.passpol:
            t.add_row(k, v)
        console.print(t)

    if f.kerberoastable or f.asreproastable:
        t = Table(title="Roastable accounts (offline crack only)")
        t.add_column("Vector", style="magenta")
        t.add_column("Account", style="green")
        t.add_column("Hash (head)")
        for name, h in f.kerberoastable:
            t.add_row("Kerberoast", name, h[:44] + "...")
        for name, h in f.asreproastable:
            t.add_row("AS-REP", name, h[:44] + "...")
        console.print(t)

    maq_val, maq_style = _sev_maq(f.maq)
    t = Table(title="Domain posture")
    t.add_column("Check", style="cyan")
    t.add_column("Result")
    t.add_row("MachineAccountQuota", Text(maq_val, style=maq_style))
    t.add_row("ADCS present", Text("yes" if f.adcs else "none seen",
                                   style="bold yellow" if f.adcs else "dim"))
    console.print(t)
    for line in f.adcs:
        console.print(f"    - ADCS: {line}")

    if f.writable:
        t = Table(title=f"Writable objects (read-only ACL enum, {len(f.writable)})")
        t.add_column("distinguishedName", style="green")
        t.add_column("Permission", style="bold yellow")
        for dn, perm in f.writable:
            t.add_row(dn, perm)
        console.print(t)


def _render_plain(ctx: Ctx, f: Findings) -> None:
    use_color = sys.stdout.isatty()

    def col(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if use_color else text

    print(f"\n===== AD enumeration rollup - {ctx.domain} @ {ctx.dc} =====")

    print(f"\n-- Users ({len(f.users)}) --")
    for u in f.users:
        print(f"  {u}")

    print(f"\n-- Groups ({len(f.groups)}) --")
    for g, n in f.groups:
        print(f"  {g:<40} {n}")

    if f.passpol:
        print("\n-- Password policy --")
        for k, v in f.passpol:
            print(f"  {k:<32} {v}")

    print("\n-- Roastable (offline crack only) --")
    for name, h in f.kerberoastable:
        print(f"  {col('KERBEROAST', '1;31')} {name:<24} {h[:44]}...")
    for name, h in f.asreproastable:
        print(f"  {col('AS-REP', '1;31')}     {name:<24} {h[:44]}...")
    if not (f.kerberoastable or f.asreproastable):
        print("  (none)")

    maq_val, _ = _sev_maq(f.maq)
    print("\n-- Domain posture --")
    print(f"  MachineAccountQuota : {maq_val}")
    print(f"  ADCS present        : {'yes' if f.adcs else 'none seen'}")
    for line in f.adcs:
        print(f"    - {line}")

    if f.writable:
        print(f"\n-- Writable objects (read-only ACL enum, {len(f.writable)}) --")
        for dn, perm in f.writable:
            print(f"  {col(dn, '1;33')}  [{perm}]")


def write_markdown(ctx: Ctx, f: Findings, out_path: Path) -> None:
    L = [f"# AD Enumeration Rollup - {ctx.domain} @ {ctx.dc}", ""]
    if f.skew_seen:
        L += ["> **CLOCK SKEW error seen** in Kerberos output - sync time to the "
              "DC and re-run the roasting stages.", ""]

    L.append(f"## Users ({len(f.users)})\n")
    L += [f"- `{u}`" for u in f.users] or ["_none parsed_"]

    L.append(f"\n## Groups ({len(f.groups)})\n")
    if f.groups:
        L += ["| Group | Members |", "|---|---|"]
        L += [f"| {g} | {n} |" for g, n in f.groups]
    else:
        L.append("_none parsed_")

    if f.passpol:
        L.append("\n## Password policy\n")
        L += ["| Setting | Value |", "|---|---|"]
        L += [f"| {k} | {v} |" for k, v in f.passpol]

    L.append("\n## Roastable accounts (offline crack only)\n")
    if f.kerberoastable or f.asreproastable:
        L += ["| Vector | Account | Hash (head) |", "|---|---|---|"]
        L += [f"| Kerberoast | {n} | `{h[:50]}...` |" for n, h in f.kerberoastable]
        L += [f"| AS-REP | {n} | `{h[:50]}...` |" for n, h in f.asreproastable]
        L.append(f"\nCrack offline: `hash-triage {ctx.kerb_file().name} "
                 f"{ctx.asrep_file().name}`")
    else:
        L.append("_none_")

    maq_val, _ = _sev_maq(f.maq)
    L.append("\n## Domain posture\n")
    L.append(f"- **MachineAccountQuota:** {maq_val}")
    L.append(f"- **ADCS present:** {'yes' if f.adcs else 'none seen'}")
    L += [f"  - {line}" for line in f.adcs]

    L.append(f"\n## Writable objects (read-only ACL enum, {len(f.writable)})\n")
    if f.writable:
        L += ["| distinguishedName | Permission |", "|---|---|"]
        L += [f"| {dn} | {perm} |" for dn, perm in f.writable]
        L.append("\nConfirm each abuse path in BloodHound (`bh-quickwin`) before acting.")
    else:
        L.append("_none parsed_")

    out_path.write_text("\n".join(L) + "\n", encoding="utf-8")
    _info(f"Markdown summary written to {out_path}")


# --- live / parse orchestration --------------------------------------------

def run_live(ctx: Ctx, stages: list[str], timeout: int, skew_check: bool) -> dict[str, str]:
    kerberos_stages = {"kerberoast", "asreproast"}
    if skew_check and (kerberos_stages & set(stages)):
        preflight_skew(ctx)

    logs: dict[str, str] = {}
    total = len(stages)
    started_all = time.monotonic()
    for index, stage in enumerate(stages, start=1):
        print(f"\n{bold(f'>> [{index}/{total}] {stage}')}")
        print(f"   {STAGE_HELP[stage]}")
        started = time.monotonic()
        res = run_stage(stage, ctx, timeout)
        elapsed = time.monotonic() - started
        logs[stage] = res.output
        ctx.log_file(stage).write_text(res.output, encoding="utf-8")
        if res.ran:
            tail = "  (fallback)" if res.used_fallback else ""
            print(f"   [done in {fmt_duration(elapsed)}] ran: {', '.join(res.ran)}{tail}")
        else:
            _warn(f"stage '{stage}' produced no output (nothing ran).")
    print(f"\n{bold('all stages done')} in {fmt_duration(time.monotonic() - started_all)}")
    return logs


def load_logs(ctx: Ctx, stages: list[str]) -> dict[str, str]:
    logs: dict[str, str] = {}
    for stage in stages:
        p = ctx.log_file(stage)
        if p.is_file():
            logs[stage] = p.read_text(encoding="utf-8", errors="replace")
        else:
            _warn(f"--parse: no saved log for stage '{stage}' at {p} (skipped).")
    if not logs:
        raise ValidationError(
            f"No stage logs found in {ctx.outdir} for {ctx.dc}. "
            "Run with --live first, or point --dir at the right folder.")
    return logs


# --- cli -------------------------------------------------------------------

_EXAMPLES = """examples:
  ad-enum sweep 10.10.10.5 -d corp.local -u jdoe -p 'Winter2026!'
      run all five stages, then print the merged report

  ad-enum sweep dc01.corp.local -d corp.local -u jdoe -H :31d6cfe0d16ae931b73c59d7e0c089c0
      same, authenticating with an NT hash instead of a password

  ad-enum sweep 10.10.10.5 -d corp.local -u jdoe -p pw --stages enum,kerberoast
      just the bits you need right now

  ad-enum report 10.10.10.5 -d corp.local --markdown notes.md
      re-render from stage logs already on disk - no DC contact at all

  ad-enum report 10.10.10.5 -d corp.local --json - | jq -r '.data.roastable[].sam'
      hand the roastable accounts to something else
"""


def add_common_options(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    sub.add_argument("-d", "--domain", required=True, metavar="DOMAIN",
                     help="AD domain, e.g. corp.local")

    out = sub.add_argument_group("output")
    out.add_argument("--dir", default=DEFAULT_OUTDIR, metavar="DIR",
                     help=f"where stage logs and roast files live (default: {DEFAULT_OUTDIR})")
    out.add_argument("--markdown", metavar="FILE", help="also write a Markdown rollup here")
    out.add_argument("--json", dest="json_out", metavar="FILE",
                     help="write machine-readable JSON ('-' for stdout, which hides the report)")
    out.add_argument("--stages", default=",".join(STAGE_ORDER), metavar="LIST",
                     help=f"subset/order to use (default: {','.join(STAGE_ORDER)})")


def build_parser() -> argparse.ArgumentParser:
    parser = ToolParser(
        prog="ad-enum",
        description="One-credential read-only AD enumeration sweep (nxc-first, with\n"
                    "documented fallbacks) merged into one report.\n"
                    "Enumeration only - it never fires an exploit, never cracks-then-authenticates,\n"
                    "and locks bloodyAD to get-only verbs.",
        epilog=build_epilog(_EXAMPLES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_global_flags(parser, "ad-enum", __version__)
    subs = parser.add_subparsers(dest="command", metavar="<command>")

    sweep = subs.add_parser(
        "sweep", help="run the enumeration stages against a DC, then report",
        description="Run the stages against a domain controller, then merge and print.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sweep.add_argument("dc", help="domain controller IP or hostname")
    add_common_options(sweep)
    sweep.add_argument("-u", "--user", required=True, metavar="USER", help="username")
    cred = sweep.add_mutually_exclusive_group(required=True)
    cred.add_argument("-p", "--password", metavar="PASS", help="password")
    cred.add_argument("-H", "--hashes", metavar="HASH",
                      help="NTLM hash for pass-the-hash: NT, LM:NT or :NT")
    run = sweep.add_argument_group("scan behaviour")
    run.add_argument("--no-fallback", action="store_true",
                     help="stay nxc-exact - don't auto-run a fallback tool if nxc is missing")
    run.add_argument("--no-skew-check", action="store_true",
                     help="skip the up-front ldap3 clock-skew preflight")
    run.add_argument("--timeout", type=int, default=DEFAULT_STAGE_TIMEOUT, metavar="SECS",
                     help=f"per-stage timeout (default: {DEFAULT_STAGE_TIMEOUT})")

    report = subs.add_parser(
        "report", help="re-render from stage logs you already have",
        description="Parse stage logs already on disk - no scanning, no DC contact.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    report.add_argument("dc", help="DC the stage logs are named after")
    add_common_options(report)

    return parser


def build_json(ctx: Ctx, f: Findings) -> dict:
    return envelope(
        tool="ad-enum",
        tool_version=__version__,
        subject=f"{ctx.domain} via {ctx.dc}",
        summary=summarise(f),
        notes=f.notes,
        data={
            "dc": ctx.dc,
            "domain": ctx.domain,
            "users": f.users,
            "groups": [{"name": n, "members": int(c)} for n, c in f.groups],
            "password_policy": [{"key": k, "value": v} for k, v in f.passpol],
            "roastable": (
                [{"sam": n, "kind": "kerberoast", "hash_preview": h[:40]}
                 for n, h in f.kerberoastable]
                + [{"sam": n, "kind": "asreproast", "hash_preview": h[:40]}
                   for n, h in f.asreproastable]
            ),
            "machine_account_quota": f.maq,
            "adcs": f.adcs,
            "writable": [{"object": o, "permission": p} for o, p in f.writable],
            "clock_skew_seen": f.skew_seen,
        },
    )


def summarise(f: Findings) -> str:
    bits = [f"{len(f.users)} users", f"{len(f.groups)} groups"]
    roast = len(f.kerberoastable) + len(f.asreproastable)
    if roast:
        bits.append(f"{roast} roastable")
    if f.writable:
        bits.append(f"{len(f.writable)} writable")
    if f.adcs:
        bits.append("ADCS present")
    return " \u00b7 ".join(bits)


def has_findings(f: Findings) -> bool:
    return bool(f.users or f.groups or f.passpol or f.kerberoastable
                or f.asreproastable or f.adcs or f.writable or f.maq)


def run_command(args: argparse.Namespace) -> int:
    quiet = args.json_out == "-"
    dc = validate_host(args.dc)
    domain = validate_domain(args.domain)
    outdir = safe_dir(args.dir)

    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    unknown = [s for s in stages if s not in STAGE_ORDER]
    if unknown:
        raise ValidationError(
            f"Unknown stage(s): {', '.join(unknown)}. Valid: {', '.join(STAGE_ORDER)}")

    ctx = Ctx(dc=dc, domain=domain, outdir=outdir,
              use_fallback=not getattr(args, "no_fallback", False))

    if args.command == "sweep":
        ctx.user = validate_user(args.user)
        if args.hashes:
            ctx.lm, ctx.nt = validate_hashes(args.hashes)
        else:
            ctx.password = validate_password(args.password)
        logs = run_live(ctx, stages, args.timeout, skew_check=not args.no_skew_check)
    else:
        logs = load_logs(ctx, stages)

    f = build_findings(logs)
    _post_process(ctx, f)

    if not quiet:
        render_report(ctx, f)

    if args.markdown:
        write_markdown(ctx, f, safe_output_path(args.markdown))
    if args.json_out:
        emit_json(build_json(ctx, f), args.json_out)

    return EXIT_OK if has_findings(f) else EXIT_NO_DATA


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        render_banner("ad-enum", __version__)
        parser.print_help()
        return EXIT_USAGE

    # Never over JSON-to-stdout: that output is meant to be piped into something.
    if not args.no_banner and args.json_out != "-":
        render_banner("ad-enum", __version__)

    try:
        return run_command(args)
    except (ValidationError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ninterrupted - partial output is still in the stage logs.", file=sys.stderr)
        return EXIT_INTERRUPTED


def main_cli() -> int:
    """Console-script entry point (see pyproject [project.scripts])."""
    return main()


if __name__ == "__main__":
    sys.exit(main_cli())
