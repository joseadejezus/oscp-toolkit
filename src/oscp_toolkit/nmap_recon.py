#!/usr/bin/env python3
"""
nmap-recon

Runs my usual 5-stage nmap flow (quick -> alltcp -> deep -> udp -> vuln)
and turns the output into a table I can actually read at 2am on exam day,
with the things worth looking at pulled to the top.

Can also just parse files from stages I already ran by hand - it doesn't
care whether nmap was invoked by this tool or by me typing it myself.

Full writeup + usage examples: see README.md. Short version:

    nmap-recon scan 10.10.10.10
    nmap-recon report 10.10.10.10 --dir ./nmap --markdown notes.md

Never picks or fires an exploit on its own - see README for why that
matters for the exam rules.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import __version__
from ._common.banner import render_banner
from ._common.cli import ToolParser, add_global_flags, build_epilog
from ._common.exits import EXIT_INTERRUPTED, EXIT_NO_DATA, EXIT_OK, EXIT_USAGE
from ._common.jsonout import emit as emit_json
from ._common.jsonout import envelope
from ._common.text import bold, colour, fmt_duration, scrub
from ._common.validate import (
    DANGEROUS_SUBSTRINGS as _DANGEROUS_SUBSTRINGS,
    ValidationError,
    safe_dir,
    safe_output_path,
    validate_extra_args,
    validate_port_list,
    validate_target,
)

# --- XML parsing (only used for the optional searchsploit cross-reference) ---
try:
    from defusedxml import ElementTree as ET  # type: ignore

    _XML_HARDENED = True
except ImportError:  # pragma: no cover - environment dependent
    from xml.etree import ElementTree as ET  # nosec B405 - locally-generated, trusted nmap output

    _XML_HARDENED = False

# Optional rich rendering; the shared module does the import dance for all the tools.
from ._common.ui import RICH as _RICH
from ._common.ui import Console, Table, Text  # noqa: E402

DEFAULT_NMAP_TIMEOUT_SECONDS = 5400  # -p- with --script vuln can run long
SEARCHSPLOIT_TIMEOUT_SECONDS = 120

STAGE_ORDER = ["quick", "alltcp", "deep", "udp", "vuln"]
STAGE_BASE_ARGS = {
    "quick": ["nmap", "-sC", "-sV", "-Pn"],
    "alltcp": ["nmap", "-p-", "--min-rate=5000", "-Pn"],
    "deep": ["nmap", "-sC", "-sV", "-Pn"],       # -p{ports} inserted at build time
    "udp": ["nmap", "-sU", "--top-ports", "100", "-Pn"],
    "vuln": ["nmap", "-sV", "--script", "vuln", "-Pn"],  # -p{ports} inserted at build time
}
STAGES_NEEDING_PORTS = {"deep", "vuln"}


@dataclass
class ScriptHit:
    script_id: str
    snippet: str


@dataclass
class ExploitHit:
    title: str
    path: str
    tier: str      # "exact" | "family" | "loose"
    term: str      # what we actually confirmed, so a weak hit is self-explaining
    source: str = "banner"   # banner | http-title | http-generator

    def display(self) -> str:
        if self.tier == "exact":
            tag = f"exact version {self.term}"
            if self.source != "banner":
                tag += f" (from {self.source})"
        elif self.tier == "family":
            tag = f"{self.term}.x family - NOT your version"
        elif self.source == "http-title":
            tag = f'page title match: "{self.term}"'
        elif self.source == "http-generator":
            tag = f'http-generator match: "{self.term}"'
        else:
            tag = f'name-only match on "{self.term}"'
        suffix = f"  ({self.path})" if self.path else ""
        return f"[{tag}] {self.title}{suffix}"


@dataclass
class Port:
    port: str
    protocol: str
    state: str = "open"
    service: str = ""
    raw_version: str = ""
    script_hits: list[ScriptHit] = field(default_factory=list)
    exploit_hits: list[ExploitHit] = field(default_factory=list)

    @property
    def version_str(self) -> str:
        return self.raw_version if self.raw_version else "-"

    @property
    def vuln_status(self) -> str:
        if any("vulnerable" in h.snippet.lower() for h in self.script_hits):
            return "VULNERABLE (NSE)"
        # vulners doesn't say "VULNERABLE" - it just lists CVE/exploit refs with
        # a CVSS score, e.g. "PACKETSTORM:179290  10.0  ...  *EXPLOIT*". Missing
        # this was a real bug: a 10.0 exploit match was showing as "no known hit"
        # just because it didn't use the same wording as the other NSE scripts.
        if any(h.script_id == "vulners" and h.snippet.strip() for h in self.script_hits):
            return "CVE MATCH (vulners)"
        if any(h.tier == "exact" for h in self.exploit_hits):
            return "LIKELY VULN (searchsploit)"
        if any(h.tier == "family" for h in self.exploit_hits):
            # Same major.minor, different patch - read it, then check whether it
            # actually applies to the version in front of you.
            return "CHECK EDB (version family)"
        if self.exploit_hits:
            # Only the product name matched. Could easily be a 20-year-old CVE.
            return "CHECK EDB (name only)"
        if not self.raw_version and not self.service:
            return "REVIEW (no version)"
        return "no known hit"


# --- running the actual stages ---

def build_stage_cmd(
    stage: str,
    ip: str,
    outdir: Path,
    ports: Optional[str],
    extra_args: list[str],
    use_sudo: bool,
    xml_sidecar: bool,
) -> tuple[list[str], Path]:
    cmd = list(STAGE_BASE_ARGS[stage])
    if stage in STAGES_NEEDING_PORTS:
        if not ports:
            raise ValidationError(f"Stage '{stage}' needs a port list but none was supplied.")
        cmd.append(f"-p{validate_port_list(ports)}")
    cmd.extend(extra_args)

    out_file = outdir / f"{stage}.{ip}"
    cmd.extend(["-oN", str(out_file)])
    if xml_sidecar:
        cmd.extend(["-oX", str(outdir / f"{stage}.{ip}.xml")])
    cmd.append(ip)

    if use_sudo:
        cmd = ["sudo", *cmd]
    return cmd, out_file


def run_stage(cmd: list[str], timeout: int, label: str = "") -> tuple[int, float]:
    """Run one nmap stage. nmap's own output streams straight through - a spinner
    would just fight it - so the feedback is a clear header and elapsed time."""
    if label:
        print(f"\n{bold('>> ' + label)}")
    print(f"   {' '.join(cmd)}\n")
    started = time.monotonic()
    try:
        result = subprocess.run(cmd, shell=False, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Stage timed out after {timeout}s: {' '.join(cmd)}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("nmap (or sudo) not found on PATH.") from exc
    elapsed = time.monotonic() - started
    status = "done" if result.returncode == 0 else f"exit {result.returncode}"
    print(f"   [{status} in {fmt_duration(elapsed)}]")
    return result.returncode, elapsed


def extract_ports(alltcp_file: Path) -> str:
    """Mirror: grep '^[0-9]' alltcp.$ip | cut -d/ -f1 | tr '\\n' ',' | sed s/,$//"""
    ports: list[str] = []
    for line in alltcp_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        if re.match(r"^\d", line):
            port = line.split("/", 1)[0].strip()
            if port.isdigit():
                ports.append(port)
    return ",".join(ports)


def backfill_alltcp_from_quick(
    alltcp_ports: str, quick_file: Path
) -> tuple[str, set[str]]:
    """alltcp's --min-rate=5000 full-range scan can outrun a slow/lab link and
    drop probes silently - nmap reports "filtered", not an error, so nothing
    else notices. If 'quick' already confirmed a port open (top ~1000, run
    first, much slower/safer rate) and alltcp's full-range pass missed it,
    that's not a real state change - it's packet loss. Union it back in so
    deep/vuln still get a shot at it.

    Returns (backfilled port list, the set of ports that had to be added).
    """
    alltcp_set = {p for p in alltcp_ports.split(",") if p} if alltcp_ports else set()
    if not quick_file.is_file():
        return alltcp_ports, set()

    quick_open = {
        port_num
        for (port_num, proto), port in parse_on_file(quick_file).items()
        if proto == "tcp" and port.state == "open"
    }
    missed = quick_open - alltcp_set
    if not missed:
        return alltcp_ports, set()

    alltcp_set |= missed
    return ",".join(sorted(alltcp_set, key=int)), missed


def run_live(
    ip: str,
    outdir: Path,
    stages: list[str],
    extra_args: list[str],
    use_sudo: bool,
    xml_sidecar: bool,
    timeout: int,
) -> None:
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap not found on PATH.")
    if use_sudo and shutil.which("sudo") is None:
        raise RuntimeError("sudo not found on PATH (pass --no-sudo if you're already root).")

    ports: Optional[str] = None
    total = len(stages)
    run_started = time.monotonic()

    for index, stage in enumerate(stages, start=1):
        if stage in STAGES_NEEDING_PORTS and ports is None:
            raise RuntimeError(
                f"Stage '{stage}' requires the port list from 'alltcp', "
                "which hasn't run yet. Include 'alltcp' before it in --stages."
            )
        cmd, out_file = build_stage_cmd(stage, ip, outdir, ports, extra_args, use_sudo, xml_sidecar)
        rc, _ = run_stage(cmd, timeout, label=f"[{index}/{total}] {stage}")
        if rc != 0:
            print(f"[!] Stage '{stage}' exited with status {rc} (continuing).", file=sys.stderr)

        if stage == "alltcp" and out_file.is_file():
            ports, missed = backfill_alltcp_from_quick(extract_ports(out_file), outdir / f"quick.{ip}")
            if missed:
                print(
                    f"[!] alltcp missed {len(missed)} port(s) 'quick' already found open: "
                    f"{','.join(sorted(missed, key=int))} - likely packet loss from --min-rate=5000 "
                    "outrunning this link, not that the ports closed. Adding them back for deep/vuln. "
                    "If this keeps happening, rerun alltcp with --extra-args '--min-rate=1000' (or lower).",
                    file=sys.stderr,
                )
            if ports:
                print(f"   open TCP ports: {ports}")
            else:
                print("[!] No open TCP ports parsed from alltcp output - deep/vuln stages will be skipped.")

    print(f"\n{bold('>> ' + str(total) + ' stage(s) finished in ' + fmt_duration(time.monotonic() - run_started))}")


# --- parsing -oN output (no XML needed for this part) ---

_HOST_RE = re.compile(r"^Nmap scan report for (?:(?P<name>\S+) \((?P<paren_ip>[^)]+)\)|(?P<bare_ip>\S+))$")
_PORT_RE = re.compile(r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<rest>.*))?$")
_SCRIPT_HEADER_RE = re.compile(r"^\|[ _]([A-Za-z0-9_.-]+):\s*(.*)$")


def parse_on_file(path: Path) -> dict[tuple[str, str], Port]:
    """Parse a normal-format (-oN) nmap output file into {(port, proto): Port}."""
    ports: dict[tuple[str, str], Port] = {}
    if not path.is_file():
        return ports

    current_key: Optional[tuple[str, str]] = None
    current_script_name: Optional[str] = None
    current_script_lines: list[str] = []

    def flush_script() -> None:
        nonlocal current_script_name, current_script_lines
        if current_key and current_script_name:
            snippet = scrub(" ".join(l for l in current_script_lines if l))
            ports[current_key].script_hits.append(ScriptHit(current_script_name, snippet))
        current_script_name = None
        current_script_lines = []

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        header_match = _SCRIPT_HEADER_RE.match(line)
        if header_match:
            flush_script()
            current_script_name = header_match.group(1)
            rest = header_match.group(2)
            current_script_lines = [rest] if rest else []
            continue

        if line.startswith("|"):
            if current_script_name is not None:
                current_script_lines.append(line.lstrip("|").strip())
            continue

        # Non-script line: close out any open script block first.
        flush_script()

        port_match = _PORT_RE.match(line)
        if port_match:
            port = port_match.group("port")
            proto = port_match.group("proto")
            key = (port, proto)
            current_key = key
            if key not in ports:
                ports[key] = Port(
                    port=port,
                    protocol=proto,
                    state=port_match.group("state"),
                    service=port_match.group("service"),
                    raw_version=(port_match.group("rest") or "").strip(),
                )
            else:
                # Later files (e.g. deep after quick) win on service/version detail.
                if port_match.group("rest"):
                    ports[key].raw_version = port_match.group("rest").strip()
                ports[key].service = port_match.group("service")
                ports[key].state = port_match.group("state")
        else:
            current_key = None

    flush_script()
    return ports


def get_host_label(any_stage_file: Path) -> str:
    if not any_stage_file.is_file():
        return ""
    for line in any_stage_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = _HOST_RE.match(line)
        if m:
            if m.group("name"):
                return f"{m.group('paren_ip')} ({m.group('name')})"
            return m.group("bare_ip") or ""
    return ""


def merge_stage_outputs(ip: str, outdir: Path) -> tuple[str, dict[tuple[str, str], Port], list[str]]:
    """Combine whichever of quick/alltcp/deep/udp/vuln exist for this ip."""
    notes: list[str] = []
    files = {stage: outdir / f"{stage}.{ip}" for stage in STAGE_ORDER}
    present = {stage: f for stage, f in files.items() if f.is_file()}
    missing = [stage for stage in STAGE_ORDER if stage not in present]
    if missing:
        notes.append(f"Stages not found in {outdir}: {', '.join(missing)} (skipped, not an error).")

    combined: dict[tuple[str, str], Port] = {}

    # Baseline from quick (top ~1000), then overlay deep's authoritative results.
    # deep is normally more trustworthy (targeted -sC/-sV on a known port), but
    # if it regresses a port from open -> filtered/closed while quick already
    # confirmed it open, that's almost always scan noise (packet loss, a rate
    # limit tripped by the alltcp burst) rather than a real state change -
    # keep quick's result and say so, instead of silently reporting a false
    # negative as if it were a clean "nothing here."
    for stage in ("quick", "deep"):
        if stage in present:
            for key, port in parse_on_file(present[stage]).items():
                existing = combined.get(key)
                if stage == "deep" and existing is not None:
                    if existing.state == "open" and port.state != "open":
                        existing.script_hits.extend(port.script_hits)
                        notes.append(
                            f"{key[0]}/{key[1]}: deep reported '{port.state}' but quick found it "
                            "open - kept quick's result (looks like scan noise, not a real state "
                            "change). Rerun 'deep' alone to confirm either way."
                        )
                        continue
                combined[key] = port

    # alltcp only tells us port numbers exist (no -sV) - fill in any TCP ports
    # missed by quick/deep so they're at least visible as "pending deep scan".
    if "alltcp" in present:
        for line in present["alltcp"].read_text(encoding="utf-8", errors="ignore").splitlines():
            if re.match(r"^\d", line):
                port_num = line.split("/", 1)[0].strip()
                key = (port_num, "tcp")
                if port_num.isdigit() and key not in combined:
                    combined[key] = Port(port=port_num, protocol="tcp", state="open")

    # UDP results are always their own rows.
    if "udp" in present:
        for key, port in parse_on_file(present["udp"]).items():
            combined[key] = port

    # vuln stage: merge its NSE script hits (and version, as a fallback) into
    # the matching TCP port rather than overwriting the deep-scan entry wholesale.
    if "vuln" in present:
        for key, vuln_port in parse_on_file(present["vuln"]).items():
            if key in combined:
                combined[key].script_hits.extend(vuln_port.script_hits)
                if not combined[key].raw_version and vuln_port.raw_version:
                    combined[key].raw_version = vuln_port.raw_version
            else:
                combined[key] = vuln_port

    host_label = ""
    for stage in STAGE_ORDER:
        if stage in present:
            host_label = get_host_label(present[stage]) or host_label
            if host_label:
                break

    return host_label or ip, combined, notes


# --- searchsploit cross-ref, only runs if we have an xml sidecar ---
#
# Was using `searchsploit --nmap <xml>`, which turned out to be a dead end: its
# output never says which port a result came from, and it searches the full
# product+version string with -t, so anything nmap labels with an extra token
# (e.g. "FreeSWITCH mod_event_socket") silently matches nothing. Now we read the
# sidecar ourselves and run one lookup per port, narrowest term first.

_SS_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/:-]*$")
_VERSION_MM_RE = re.compile(r"^(\d+)\.(\d+)")


def _version_re(version: str) -> "re.Pattern":
    """Match this version in a title without matching 1.2.4 as 2.4."""
    return re.compile(r"(?<![\w.])" + re.escape(version), re.IGNORECASE)


def _word_re(word: str) -> "re.Pattern":
    """Whole-word-ish: Samba yes, GoSamba no."""
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])", re.IGNORECASE)
_SS_MAX_TOKENS = 8
_MAX_LOOSE_HITS = 10


def find_xml_sidecar(ip: str, outdir: Path) -> Optional[Path]:
    for stage in ("vuln", "deep", "quick"):
        candidate = outdir / f"{stage}.{ip}.xml"
        if candidate.is_file():
            return candidate
    return None


@dataclass
class SearchTerm:
    text: str
    tier: str             # "exact" | "family" | "loose"
    verify: list           # regexes the returned title must ALL match
    label: str            # the bit we actually confirmed - a version or a name
    source: str = "banner"  # banner | http-title | http-generator


def safe_search_tokens(term: str) -> Optional[list[str]]:
    """Split a term into argv tokens, or None if anything looks off.

    nmap's own XML is about as trusted as input gets, but a service banner is
    still remote-controlled text, so a term that doesn't pass gets dropped
    whole rather than cleaned up and used anyway.
    """
    tokens = term.split()
    if not tokens or len(tokens) > _SS_MAX_TOKENS:
        return None
    for tok in tokens:
        if len(tok) > 64 or not _SS_TOKEN_RE.match(tok):
            return None
    return tokens


# NSE scripts that name the *application* rather than the server it rides on.
# Port 3000 on a real box was "Thin httpd" to nmap and "Cassandra Web" in the
# page title - the exploitable name only ever existed in the script output.
_APP_HINT_SCRIPTS = ("http-title", "http-generator")
_APP_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)+[a-z0-9.+-]*$", re.IGNORECASE)
_JUNK_TITLE_RE = re.compile(
    r"^(?:\d{3}\b"                              # "403 Forbidden"
    r"|site doesn't have a title"
    r"|index of\b"
    r"|welcome to\b"
    r"|it works"
    r"|test page\b"
    r"|apache\d?\b|nginx\b|iis\b"
    r"|home|login|log in|sign in|dashboard|admin|error|untitled)",
    re.IGNORECASE,
)
# A title made only of these tells you nothing worth searching.
_GENERIC_TITLE_WORDS = {
    "home", "login", "index", "welcome", "page", "dashboard", "admin", "portal",
    "test", "default", "server", "error", "site", "web", "app", "main", "start",
}


def clean_app_hint(raw: str) -> str:
    """Turn an http-title / http-generator value into a searchable app name, or ''."""
    hint = scrub(raw, 120).strip(".").strip()
    hint = re.sub(r"\s*\((?:text/html|application/[^)]*)\)\s*$", "", hint, flags=re.IGNORECASE)
    hint = re.sub(r"\s+", " ", hint)
    if not hint or _JUNK_TITLE_RE.match(hint):
        return ""
    words = hint.split()
    if len(words) > 4:  # a sentence, not a product name
        return ""
    meaningful = [w for w in words if w.lower().strip("-_") not in _GENERIC_TITLE_WORDS]
    if not meaningful:
        return ""
    if not any(len(w) >= 3 and any(c.isalpha() for c in w) for w in meaningful):
        return ""
    return hint


def build_search_ladder(
    product: str,
    version: str,
    app_hints: Optional[list[tuple[str, str]]] = None,
    allow_loose: bool = True,
) -> list[SearchTerm]:
    """Most specific term first, widening only if nothing hits (and verifies).

    Each rung carries regexes we re-check the returned titles against.
    searchsploit's default search is fuzzy - asking it for "Apache httpd 2.4"
    happily returns 2.4.23 and 2.4.49 - so the tier a hit gets is decided here,
    on the title, not on which rung happened to return it.

    app_hints are (script_id, value) pairs from NSE - the application name, which
    is often the only place the exploitable software is actually named.
    """
    product = product.strip()
    version = version.strip()
    app_hints = app_hints or []

    versioned: list[SearchTerm] = []   # anchored to a version number
    family: list[SearchTerm] = []      # same major.minor
    named: list[SearchTerm] = []       # name only

    seen: set[str] = set()

    def push(bucket: list, text: str, tier: str, verify: list, label: str, source: str) -> None:
        if text and text not in seen:
            seen.add(text)
            bucket.append(SearchTerm(text, tier, verify, label, source))

    if product:
        name = product.split()[0]
        if version:
            head = version.split()[0]  # "7.9p1 Debian 10+deb10u2" -> "7.9p1"
            push(versioned, f"{product} {version}", "exact", [_version_re(head)], head, "banner")
            mm = _VERSION_MM_RE.match(version)
            if mm:
                fam = f"{mm.group(1)}.{mm.group(2)}"
                # An Apache 2.4.49 RCE is worth knowing about on 2.4.38, but it
                # is NOT your version and must never be labelled as if it were.
                push(family, f"{product} {fam}", "family", [_version_re(fam)], fam, "banner")
        elif allow_loose:
            push(named, product, "loose", [_word_re(name)], name, "banner")
        if allow_loose:
            # Word-boundary checked, otherwise "Thin" drags in every
            # Thinfinity/ThinClientServer title in the database.
            push(named, name, "loose", [_word_re(name)], name, "banner")

    for script_id, raw in app_hints:
        hint = clean_app_hint(raw)
        if not hint:
            continue
        words = hint.split()
        if len(words) > 1 and _APP_VERSION_RE.match(words[-1]):
            app_name, app_ver = " ".join(words[:-1]), words[-1].lstrip("vV")
            push(versioned, hint, "exact", [_version_re(app_ver)], app_ver, script_id)
            if allow_loose:
                push(named, app_name, "loose", [_word_re(w) for w in app_name.split()],
                     app_name, script_id)
        elif allow_loose:
            # Every word must appear as a whole word, so "Cassandra Web" keeps
            # "Cassandra Web 0.5.0 - Remote File Read" and drops the unrelated
            # "Atrium Software Cassandra NNTP Server".
            push(named, hint, "loose", [_word_re(w) for w in words], hint, script_id)

    # App names beat the bare service name: "Cassandra Web" is the thing running,
    # "Thin" is only what it rides on.
    named.sort(key=lambda t: t.source == "banner")
    return versioned + family + named


_json_warned = False


def parse_searchsploit_json(raw: str) -> list[tuple[str, str]]:
    """-> [(title, path)]. Tolerant about field spelling across edb versions."""
    global _json_warned
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        # An old searchsploit without --json would land here and silently report
        # nothing - which is the exact bug this rewrite existed to kill, so say so.
        if raw.strip() and not _json_warned:
            _json_warned = True
            print("[!] searchsploit didn't return JSON - too old for --json? "
                  "Exploit-db cross-reference will come back empty.")
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("RESULTS_EXPLOIT") or []
    if not isinstance(results, list):
        return []

    out: list[tuple[str, str]] = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        title = entry.get("Title") or entry.get("Exploit Title") or ""
        path = entry.get("Path") or entry.get("path") or ""
        if isinstance(title, str) and title.strip():
            out.append((scrub(title, 200), scrub(str(path), 200)))
    return out


def run_searchsploit(tokens: list[str]) -> Optional[list[tuple[str, str]]]:
    """One lookup against the local exploit-db mirror. Nothing gets run."""
    cmd = ["searchsploit", "--json"] + tokens
    try:
        result = subprocess.run(
            cmd, shell=False, check=False, capture_output=True, text=True,
            timeout=SEARCHSPLOIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] searchsploit timed out on {' '.join(tokens)!r} - skipping that term.")
        return None
    except OSError as exc:
        print(f"[!] searchsploit failed to run ({exc}) - skipping vuln lookup.")
        return None

    # searchsploit exits non-zero on "no results" in some builds, which isn't an
    # error worth shouting about - only stderr with no stdout is a real problem.
    if result.returncode != 0 and not result.stdout.strip():
        if result.stderr.strip():
            print(f"[!] searchsploit exited {result.returncode} on {' '.join(tokens)!r}: "
                  f"{result.stderr.strip().splitlines()[0][:120]}")
        return []
    return parse_searchsploit_json(result.stdout)


def services_from_xml(xml_path: Path) -> dict[tuple[str, str], tuple[str, str]]:
    """-> {(port, proto): (product, version)} from an nmap -oX sidecar."""
    services: dict[tuple[str, str], tuple[str, str]] = {}
    try:
        root = ET.parse(str(xml_path)).getroot()
    except Exception as exc:  # noqa: BLE001 - malformed sidecar shouldn't kill the run
        print(f"[!] Couldn't parse {xml_path} ({exc}) - skipping vuln lookup.")
        return services

    for port_el in root.iter("port"):
        portid = (port_el.get("portid") or "").strip()
        proto = (port_el.get("protocol") or "").strip()
        if not portid.isdigit() or proto not in ("tcp", "udp"):
            continue
        state_el = port_el.find("state")
        if state_el is not None and (state_el.get("state") or "").split("|")[0] != "open":
            continue
        svc = port_el.find("service")
        if svc is None:
            continue
        services[(portid, proto)] = (svc.get("product") or "", svc.get("version") or "")
    return services


def enrich_with_searchsploit(
    xml_path: Path,
    ports: dict[tuple[str, str], Port],
    allow_loose: bool = True,
) -> None:
    """Attach exploit-db titles per port. Lookup only - nothing is executed."""
    if shutil.which("searchsploit") is None:
        print("[!] searchsploit not found on PATH - skipping vuln lookup.")
        return

    services = services_from_xml(xml_path)
    if not services:
        return

    # Same product/version on two ports (e.g. 139/445) shouldn't cost two runs.
    cache: dict[str, list[tuple[str, str]]] = {}

    for key, (product, version) in services.items():
        port_obj = ports.get(key)
        if port_obj is None:
            continue

        app_hints = [
            (h.script_id, h.snippet)
            for h in port_obj.script_hits
            if h.script_id in _APP_HINT_SCRIPTS and h.snippet.strip()
        ]

        for term in build_search_ladder(product, version, app_hints, allow_loose):
            tokens = safe_search_tokens(term.text)
            if tokens is None:
                # Plenty of banners are just unsearchable ("Samba smbd 3.X - 4.X"),
                # which is a dud term, not an incident - only shout about the ones
                # that look like someone's having a go at us.
                if any(bad in term.text for bad in _DANGEROUS_SUBSTRINGS):
                    print(f"[!] Refusing searchsploit term for {key[0]}/{key[1]} - "
                          f"shell metacharacters in {term.source} value {term.text!r}.")
                continue

            if term.text in cache:
                results = cache[term.text]
            else:
                fetched = run_searchsploit(tokens)
                if fetched is None:
                    break  # timed out / couldn't run; don't hammer the rest of the ladder
                results = fetched
                cache[term.text] = results

            # searchsploit's default search is fuzzy, so a rung can come back
            # with titles that don't actually contain what we asked for. Re-check
            # every title here; if nothing survives, widen to the next rung.
            kept = [(t, path) for t, path in results
                    if all(rx.search(t) for rx in term.verify)]
            if kept:
                if term.tier != "exact":
                    kept = kept[:_MAX_LOOSE_HITS]
                port_obj.exploit_hits = [
                    ExploitHit(title=t, path=path, tier=term.tier, term=term.label,
                               source=term.source)
                    for t, path in kept
                ]
                break


# --- output ---

def sorted_ports(ports: dict[tuple[str, str], Port]) -> list[Port]:
    return sorted(ports.values(), key=lambda p: (p.protocol, int(p.port)))


def render_rich(host_label: str, ports: dict[tuple[str, str], Port], notes: list[str],
                console: Optional["Console"] = None, details: bool = True) -> None:
    console = console or Console()
    for note in notes:
        console.print(f"[dim]{note}[/dim]")

    table = Table(title=host_label, show_lines=False)
    table.add_column("Port", style="cyan", no_wrap=True)
    table.add_column("Proto", no_wrap=True)
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Status")

    if not ports:
        console.print(f"[dim]{host_label}: no port data parsed yet[/dim]")
        return

    for p in sorted_ports(ports):
        status = p.vuln_status
        if status.startswith("VULNERABLE"):
            styled = Text(status, style="bold red")
        elif status.startswith("CVE MATCH"):
            styled = Text(status, style="bold red")
        elif status.startswith("LIKELY VULN"):
            styled = Text(status, style="bold red")
        elif status.startswith("REVIEW") or status.startswith("CHECK EDB"):
            styled = Text(status, style="bold yellow")
        else:
            styled = Text(status, style="green")
        table.add_row(p.port, p.protocol, p.service or "-", p.version_str, styled)

    console.print(table)

    if not details:
        return

    for p in sorted_ports(ports):
        if p.script_hits or p.exploit_hits:
            console.print(f"  [bold red]{host_label}:{p.port}/{p.protocol}[/bold red] details:")
            # markup=False: nmap/edb text is full of [brackets] and rich would
            # eat them as style tags - "[exact]" vanished from the output once.
            for hit in p.script_hits:
                console.print(f"    - NSE {hit.script_id}: {hit.snippet[:150]}", markup=False, highlight=False)
            for hit in p.exploit_hits[:5]:
                console.print(f"    - exploit-db: {hit.display()}", markup=False, highlight=False)
            if len(p.exploit_hits) > 5:
                console.print(f"    - exploit-db: (+{len(p.exploit_hits) - 5} more, see --markdown)")


def render_plain(host_label: str, ports: dict[tuple[str, str], Port], notes: list[str],
                 details: bool = True) -> None:
    for note in notes:
        print(note)

    print(f"\n=== {host_label} ===")
    if not ports:
        print("  (no port data parsed yet)")
        return

    header = f"{'PORT':<8}{'PROTO':<7}{'SERVICE':<15}{'VERSION':<40}{'STATUS'}"
    print(header)
    print("-" * len(header))
    for p in sorted_ports(ports):
        status = p.vuln_status
        if status.startswith("VULNERABLE") or status.startswith("CVE MATCH") or status.startswith("LIKELY VULN"):
            styled = colour(status, "1;31")
        elif status.startswith("REVIEW") or status.startswith("CHECK EDB"):
            styled = colour(status, "1;33")
        else:
            styled = colour(status, "1;32")
        service = (p.service or "-")[:14]
        print(f"{p.port:<8}{p.protocol:<7}{service:<15}{p.version_str[:38]:<40}{styled}")

    if not details:
        return

    for p in sorted_ports(ports):
        if p.script_hits or p.exploit_hits:
            print(f"  {host_label}:{p.port}/{p.protocol} details:")
            for hit in p.script_hits:
                print(f"    - NSE {hit.script_id}: {hit.snippet[:150]}")
            for hit in p.exploit_hits[:5]:
                print(f"    - exploit-db: {hit.display()}")
            if len(p.exploit_hits) > 5:
                print(f"    - exploit-db: (+{len(p.exploit_hits) - 5} more, see --markdown)")


def write_markdown(host_label: str, ports: dict[tuple[str, str], Port], out_path: Path) -> None:
    lines = [f"# Nmap Enumeration Summary - {host_label}", ""]
    if not ports:
        lines.append("_No port data parsed yet._")
    else:
        lines.append("| Port | Proto | Service | Version | Status |")
        lines.append("|---|---|---|---|---|")
        for p in sorted_ports(ports):
            status = p.vuln_status
            status_md = f"**{status}**" if status != "no known hit" else status
            lines.append(f"| {p.port} | {p.protocol} | {p.service or '-'} | {p.version_str} | {status_md} |")
        for p in sorted_ports(ports):
            if p.script_hits or p.exploit_hits:
                lines.append(f"\n**{p.port}/{p.protocol}** details to review manually:")
                for hit in p.script_hits:
                    lines.append(f"- NSE `{hit.script_id}`: {hit.snippet}")
                for hit in p.exploit_hits:
                    lines.append(f"- exploit-db: {hit.display()}")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[*] Markdown summary written to {out_path}")


def summarise(ports: dict[tuple[str, str], Port]) -> str:
    """The one line worth reading if you scrolled past everything else."""
    if not ports:
        return "no ports parsed"
    buckets = {"vuln": 0, "check": 0, "review": 0}
    for p in ports.values():
        status = p.vuln_status
        if status.startswith(("VULNERABLE", "CVE MATCH", "LIKELY VULN")):
            buckets["vuln"] += 1
        elif status.startswith("CHECK EDB"):
            buckets["check"] += 1
        elif status.startswith("REVIEW"):
            buckets["review"] += 1
    bits = [f"{len(ports)} open"]
    if buckets["vuln"]:
        bits.append(f"{buckets['vuln']} flagged")
    if buckets["check"]:
        bits.append(f"{buckets['check']} worth checking")
    if buckets["review"]:
        bits.append(f"{buckets['review']} needs a version")
    return " \u00b7 ".join(bits)


def build_json(host_label: str, ports: dict[tuple[str, str], Port], notes: list[str]) -> dict:
    return envelope(
        tool="nmap-recon",
        tool_version=__version__,
        subject=host_label,
        summary=summarise(ports),
        notes=notes,
        data={
        "ports": [
            {
                "port": int(p.port),
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service or None,
                "version": p.raw_version or None,
                "status": p.vuln_status,
                "nse": [{"script": h.script_id, "output": h.snippet} for h in p.script_hits],
                "exploitdb": [
                    {
                        "title": h.title,
                        "path": h.path,
                        "tier": h.tier,
                        "matched": h.term,
                        "matched_from": h.source,
                    }
                    for h in p.exploit_hits
                ],
            }
            for p in sorted_ports(ports)
        ],
        },
    )


def write_json(host_label: str, ports: dict, notes: list[str], target: str) -> None:
    emit_json(build_json(host_label, ports, notes), target)


# --- cli ---

_EXAMPLES = """examples:
  nmap-recon scan 10.10.10.10
      run all five stages, then print the merged table

  nmap-recon scan 10.10.10.10 --stages quick,alltcp,deep --no-sudo
      skip UDP and the vuln scripts when you're short on time

  nmap-recon report 10.10.10.10 --dir ./nmap --markdown notes.md
      re-render from files you already have, and save notes

  nmap-recon report 10.10.10.10 --json - | jq '.data.ports[] | select(.status != "no known hit")'
      pipe the findings somewhere else
"""


def add_common_options(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    out = sub.add_argument_group("output")
    out.add_argument("--dir", default="nmap", metavar="DIR",
                     help="where the stage files live / are written (default: ./nmap)")
    out.add_argument("--markdown", metavar="FILE", help="also write a Markdown summary here")
    out.add_argument("--no-details", action="store_true",
                     help="just the table - skip the per-port NSE/exploit-db detail block")
    out.add_argument("--json", metavar="FILE", dest="json_out",
                     help="write machine-readable JSON here ('-' for stdout, which hides the table)")

    edb = sub.add_argument_group("exploit-db cross-reference")
    edb.add_argument("--no-searchsploit", action="store_true",
                     help="skip the exploit-db lookup entirely")
    edb.add_argument("--no-loose-edb", action="store_true",
                     help="only accept hits anchored to a version number (quieter, misses "
                          "oddly-labelled services like FreeSWITCH)")


def build_parser() -> argparse.ArgumentParser:
    parser = ToolParser(
        prog="nmap-recon",
        description="Runs a 5-stage nmap enumeration flow and merges it into one readable table.\n"
                    "Enumeration only - it flags things to look at, it never selects or fires an exploit.",
        epilog=build_epilog(_EXAMPLES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_global_flags(parser, "nmap-recon", __version__)
    subs = parser.add_subparsers(dest="command", metavar="<command>")

    scan = subs.add_parser(
        "scan", help="run the nmap stages against a target, then report",
        description="Run the stages against a target, then merge and print the results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("target", help="IP, CIDR or hostname to scan")
    add_common_options(scan)
    run = scan.add_argument_group("scan behaviour")
    run.add_argument("--stages", default=",".join(STAGE_ORDER), metavar="LIST",
                     help=f"subset/order to run (default: {','.join(STAGE_ORDER)})")
    run.add_argument("--no-sudo", action="store_true", help="don't prefix nmap with sudo")
    run.add_argument("--no-xml-sidecar", action="store_true",
                     help="don't write the -oX sidecar (this also disables the exploit-db lookup)")
    run.add_argument("--extra-args", default="", metavar="ARGS",
                     help='extra nmap flags for every stage, e.g. "-T4" (validated first)')
    run.add_argument("--timeout", type=int, default=DEFAULT_NMAP_TIMEOUT_SECONDS, metavar="SECS",
                     help=f"per-stage timeout (default: {DEFAULT_NMAP_TIMEOUT_SECONDS})")

    report = subs.add_parser(
        "report", help="re-render from stage files you already have",
        description="Parse stage files already on disk - no scanning, no target contact.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    report.add_argument("target", help="IP or hostname the stage files are named after")
    add_common_options(report)

    return parser


def run_command(args: argparse.Namespace) -> int:
    quiet = args.json_out == "-"
    target = validate_target(args.target)
    outdir = safe_dir(args.dir)

    if args.command == "scan":
        if not quiet:
            print(f"target: {target}")
        stages = [s.strip() for s in args.stages.split(",") if s.strip()]
        unknown = [s for s in stages if s not in STAGE_ORDER]
        if unknown:
            raise ValidationError(
                f"Unknown stage(s): {', '.join(unknown)}. Valid: {', '.join(STAGE_ORDER)}"
            )
        run_live(
            ip=target,
            outdir=outdir,
            stages=stages,
            extra_args=validate_extra_args(args.extra_args),
            use_sudo=not args.no_sudo,
            xml_sidecar=not args.no_xml_sidecar,
            timeout=args.timeout,
        )

    host_label, ports, notes = merge_stage_outputs(target, outdir)

    if not args.no_searchsploit:
        sidecar = find_xml_sidecar(target, outdir)
        if sidecar:
            enrich_with_searchsploit(sidecar, ports, allow_loose=not args.no_loose_edb)
        else:
            notes.append(
                "No -oX sidecar found for the exploit-db cross-reference "
                "(scan without --no-xml-sidecar, or pass --no-searchsploit to silence this)."
            )

    if not quiet:
        if _RICH:
            render_rich(host_label, ports, notes, details=not args.no_details)
        else:
            render_plain(host_label, ports, notes, details=not args.no_details)
        print(f"\n{summarise(ports)}")

    if args.markdown:
        write_markdown(host_label, ports, safe_output_path(args.markdown))
    if args.json_out:
        write_json(host_label, ports, notes, args.json_out)

    return EXIT_OK if ports else EXIT_NO_DATA


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        render_banner("nmap-recon", __version__)
        parser.print_help()
        return EXIT_USAGE

    # Never over JSON-to-stdout: that output is meant to be piped into something.
    if not args.no_banner and args.json_out != "-":
        render_banner("nmap-recon", __version__)

    if not _XML_HARDENED and not args.no_searchsploit:
        print(
            "[!] defusedxml not installed - falling back to the stdlib XML parser for the "
            "sidecar. Low risk against nmap's own output, but `pip install defusedxml` is "
            "recommended for defense in depth.",
            file=sys.stderr,
        )

    try:
        return run_command(args)
    except (ValidationError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ninterrupted - partial output is still in the stage files.", file=sys.stderr)
        return EXIT_INTERRUPTED


def main_cli() -> int:
    """Console-script entry point (see pyproject [project.scripts])."""
    return main()


if __name__ == "__main__":
    sys.exit(main_cli())
