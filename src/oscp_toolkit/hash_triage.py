#!/usr/bin/env python3
"""
hash-triage

Classify a pile of found hashes by type, split them into the right per-mode
files, and run a rockyou pass with Hashcat (John as the fallback) - then report
which ones cracked and to what. The "I just dumped a bunch of hashes, now what
are they and which fall to rockyou" step, automated.

It never picks or fires an exploit. It identifies hash types, cracks locally
against a wordlist, and prints the recovered passwords for me to use by hand.

Full writeup + the exam-rule reasoning: see the README. Short version:

    hash-triage crack dump.txt
    hash-triage crack dump.txt --rules best64
    hash-triage classify dump.txt
    secretsdump ... | hash-triage crack -
    hash-triage crack ntds.txt --only-mode 1000

Cracking is local, on my own machine - which is fine. Just don't point the
wordlist step at an external or distributed cracking service on the exam.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import __version__
from ._common.banner import render_banner
from ._common.cli import ToolParser, add_global_flags, build_epilog
from ._common.exits import EXIT_INTERRUPTED, EXIT_NO_DATA, EXIT_OK, EXIT_USAGE
from ._common.jsonout import emit as emit_json
from ._common.jsonout import envelope
from ._common.text import bold, fmt_duration, scrub
from ._common.ui import RICH as _RICH
from ._common.ui import Console, Table
from ._common.validate import ValidationError, checked_path

# Kali/Exegol ship rockyou here (sometimes gzipped - handled with a hint).
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
DEFAULT_OUTDIR = "./hash-triage"
# Where Hashcat ships its .rule files in Kali/Exegol, so `--rules best64`
# resolves to a bare name instead of a full path.
DEFAULT_RULES_DIR = "/usr/share/hashcat/rules"
# Wall-clock cap on a single crack so a slow mode (bcrypt, sha512crypt) can't
# wedge the run forever. Anything already cracked when it trips is still saved
# in the potfile and reported. Override with --timeout; 0 disables the cap.
DEFAULT_TIMEOUT = 3600

# A single hash line: printable, no control chars, no embedded newline. This is
# the file *content*, never an argv value, but a control char in here is either
# a corrupt dump or someone being cute - hard stop either way.
_HASHLINE_RE = re.compile(r"^[\x20-\x7e]{1,4096}$")
# John rule section names (become `--rules=<name>` argv); keep it to a clean tag.
_RULENAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class HashType:
    def __init__(self, name, mode, john, pattern, note=""):
        self.name = name
        self.mode = mode          # hashcat -m value
        self.john = john          # john --format value (None = let john autodetect)
        self.re = re.compile(pattern)
        self.note = note


CURATED = [
    # Kerberos - the roasting outputs. RC4 (etype 23) is the common OSCP case.
    HashType("Kerberos TGS-REP (RC4)", 13100, "krb5tgs", r"^\$krb5tgs\$23\$"),
    HashType("Kerberos TGS-REP (AES256)", 19700, "krb5tgs-aes256", r"^\$krb5tgs\$18\$"),
    HashType("Kerberos TGS-REP (AES128)", 19600, "krb5tgs-aes128", r"^\$krb5tgs\$17\$"),
    HashType("Kerberos AS-REP (RC4)", 18200, "krb5asrep", r"^\$krb5asrep\$23\$"),
    HashType("Kerberos AS-REQ PA (RC4)", 7500, "krb5pa-md5", r"^\$krb5pa\$23\$"),
    # NetNTLM (Responder / relay captures).
    HashType("NetNTLMv2", 5600, "netntlmv2",
             r"^[^:]*::[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]+$"),
    HashType("NetNTLMv1", 5500, "netntlm",
             r"^[^:]*::[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}$"),
    # Domain cached creds v2 (mscash2).
    HashType("Domain Cached Creds 2 (DCC2)", 2100, "mscash2", r"^\$DCC2\$\d+#"),
    HashType("Domain Cached Creds (mscash)", 1100, "mscash", r"^M\$"),
    # Unix crypt families.
    HashType("md5crypt", 500, "md5crypt", r"^\$1\$"),
    HashType("bcrypt", 3200, "bcrypt", r"^\$2[abxy]\$"),
    HashType("sha256crypt", 7400, "sha256crypt", r"^\$5\$"),
    HashType("sha512crypt", 1800, "sha512crypt", r"^\$6\$"),
    HashType("apache apr1", 1600, "md5crypt-long", r"^\$apr1\$"),
    HashType("phpass (WP/phpBB)", 400, "phpass", r"^\$[PH]\$"),
    # MySQL.
    HashType("MySQL 4.1+ (SHA1)", 300, "mysql-sha1", r"^\*[0-9A-Fa-f]{40}$"),
]

# secretsdump / pwdump line: user:rid:lm:nt:::  -> pull the NT hash out and
# treat it as NTLM. Kept apart from CURATED because it needs field extraction,
# not just a mode tag.
_PWDUMP_RE = re.compile(
    r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::\s*$"
)
_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"  # LM of the empty string

# Bare-hex fallbacks - genuinely ambiguous, so they don't auto-classify to one
# mode. In an AD-heavy OSCP context a lone 32-hex is usually NTLM, so that's the
# default guess (--ambiguous flips it), but it's always flagged as a guess.
NTLM = HashType("NTLM", 1000, "nt", r"^[0-9a-fA-F]{32}$")
RAW_MD5 = HashType("raw MD5", 0, "raw-md5", r"^[0-9a-fA-F]{32}$")
RAW_SHA1 = HashType("raw SHA1", 100, "raw-sha1", r"^[0-9a-fA-F]{40}$")
RAW_SHA256 = HashType("raw SHA256", 1400, "raw-sha256", r"^[0-9a-fA-F]{64}$")

# Everything the map knows about, by mode, so --only-mode can validate.
_KNOWN_MODES = {ht.mode: ht for ht in CURATED}
for ht in (NTLM, RAW_MD5, RAW_SHA1, RAW_SHA256):
    _KNOWN_MODES.setdefault(ht.mode, ht)


# --- validation (allow-list, reject don't sanitize) ------------------------

def safe_path(path_str, must_exist=False, kind="path"):
    """Shared allow-list, plus the must-exist check this tool needs for wordlists
    and rule files. The resolved path becomes an argv value to hashcat/john."""
    path = checked_path(str(path_str))
    if must_exist and not path.exists():
        raise ValidationError(f"{kind} does not exist: {path}")
    return path


def validate_mode(raw):
    """A hashcat -m value we actually know how to handle."""
    raw = str(raw).strip()
    if not raw.isdigit():
        raise ValidationError(f"Refusing non-numeric mode: {raw!r}")
    mode = int(raw)
    if mode not in _KNOWN_MODES:
        known = ", ".join(str(m) for m in sorted(_KNOWN_MODES))
        raise ValidationError(f"Mode {mode} isn't in the curated map. Known: {known}")
    return mode


def clean_hash_line(raw):
    """Validate + normalize one input line. Returns None for blank/comment.

    Rejects control chars / absurdly long lines outright - the line goes into a
    file the cracker reads, so a NUL or newline sneaking through is a corrupt
    dump, not a hash.
    """
    line = raw.rstrip("\n").rstrip("\r")
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if not _HASHLINE_RE.match(line):
        raise ValidationError(
            f"Refusing hash line with control chars / over-length: {line[:40]!r}..."
        )
    return line.strip()


# --- classification --------------------------------------------------------

class Item:
    """One input hash and what we decided it is."""

    def __init__(self, raw, user=None):
        self.raw = raw            # what we write to the mode file (the hash itself)
        self.user = user          # username if the input carried one (pwdump), else None
        self.tag = None           # stable per-hash id (t0, t1, ...) for john mapping
        self.htype = None         # HashType, or None if unknown
        self.ambiguous = False    # True when the type is a best-guess, not certain
        self.candidates = []      # other plausible HashTypes (for the report)


def classify_line(line, ambiguous_pref):
    """Turn one cleaned line into an Item (or None to skip)."""
    # pwdump / secretsdump first - it's a superset shape that would otherwise
    # trip the bare-hex branch on its NT field.
    m = _PWDUMP_RE.match(line)
    if m:
        item = Item(m.group("nt"), user=m.group("user"))
        item.htype = NTLM
        if m.group("lm").lower() != _EMPTY_LM:
            item.candidates.append(HashType("LM present", 3000, "lm", r".", "LM hash is set too"))
        return item

    for ht in CURATED:
        if ht.re.match(line):
            return _typed(line, ht)

    # Bare hex - ambiguous. Pick a default by length, record the alternates.
    if RAW_MD5.re.match(line):  # 32 hex
        primary, alt = (NTLM, RAW_MD5) if ambiguous_pref == "ntlm" else (RAW_MD5, NTLM)
        item = _typed(line, primary)
        item.ambiguous = True
        item.candidates = [alt]
        return item
    if RAW_SHA1.re.match(line):  # 40 hex
        item = _typed(line, RAW_SHA1)
        item.ambiguous = True
        return item
    if RAW_SHA256.re.match(line):  # 64 hex
        item = _typed(line, RAW_SHA256)
        item.ambiguous = True
        return item

    return Item(line)  # unknown - htype stays None


def _typed(line, ht):
    item = Item(line)
    item.htype = ht
    return item


def classify(lines, ambiguous_pref, only_mode=None):
    """Classify every line. only_mode forces one known mode for all of them."""
    items = []
    for i, line in enumerate(lines):
        if only_mode is not None:
            it = Item(line)
            it.htype = _KNOWN_MODES[only_mode]
        else:
            it = classify_line(line, ambiguous_pref)
        it.tag = f"t{i}"
        items.append(it)
    return items


# --- optional external identify (curated map + a second opinion) -----------

def identify_suggestions(hashes):
    """Ask hashcat --identify for candidate modes on hashes we're unsure about.

    Best-effort: hashcat is the primary cracker so it's almost certainly here,
    but if --identify isn't supported or errors we just skip the second opinion
    rather than failing the run.
    """
    if shutil.which("hashcat") is None or not hashes:
        return {}
    suggestions = {}
    for h in hashes:
        # hashcat --identify only reads a file (stdin returns nothing), so drop
        # each hash into a short-lived temp file and read it back.
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".hash", delete=True) as tf:
                tf.write(h + "\n")
                tf.flush()
                r = subprocess.run(
                    ["hashcat", "--identify", tf.name],
                    shell=False, check=False,
                    capture_output=True, text=True, timeout=60,
                )
        except (OSError, subprocess.TimeoutExpired):
            return suggestions  # give up quietly on the whole batch
        modes = re.findall(r"^\s*(\d+)\s*\|", r.stdout, re.MULTILINE)
        if modes:
            suggestions[h] = sorted(set(int(x) for x in modes))
    return suggestions


# --- writing the per-mode files --------------------------------------------

def group_by_mode(items):
    """{mode: (HashType, [Item, ...])} for everything that got a type."""
    groups = {}
    for it in items:
        if it.htype is None:
            continue
        groups.setdefault(it.htype.mode, (it.htype, []))[1].append(it)
    return groups


def write_mode_files(groups, outdir, cracker):
    """One file per mode: hashes.m<mode>.<slug>.txt. Returns {mode: Path}.

    Hashcat wants bare hashes (results map back by hash via --show). John's
    --show drops the hash and only prints login:password, so for John we write
    `<tag>:<hash>` and map results back by the tag instead.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for mode, (ht, items) in sorted(groups.items()):
        slug = re.sub(r"[^a-z0-9]+", "-", ht.name.lower()).strip("-")
        path = outdir / f"hashes.m{mode}.{slug}.txt"
        if cracker == "john":
            body = "\n".join(f"{it.tag}:{it.raw}" for it in items)
        else:
            body = "\n".join(it.raw for it in items)
        path.write_text(body + "\n")
        paths[mode] = path
    return paths


# --- running the crackers --------------------------------------------------

def hashcat_crack_cmd(mode, hashfile, wordlist, potfile, rules=None):
    cmd = [
        "hashcat", "-m", str(mode), "-a", "0",
        str(hashfile), str(wordlist),
        "--potfile-path", str(potfile),
        "-w", "3", "--force",
    ]
    if rules:
        cmd += ["-r", str(rules)]
    return cmd


def hashcat_show(mode, hashfile, potfile, hashes):
    """`--show` is the authoritative 'what cracked' read - includes potfile hits
    from earlier runs, not just this one.

    Output is `hash:plain`, but several hash *types* (NetNTLMv2, Kerberos, DCC2)
    contain colons themselves, so a plain first-colon split would slice the hash
    in half. Match each line against the known hash strings instead and take
    everything after `hash:` as the password.
    """
    r = subprocess.run(
        ["hashcat", "-m", str(mode), "--show", str(hashfile),
         "--potfile-path", str(potfile)],
        shell=False, check=False, capture_output=True, text=True, timeout=120,
    )
    cracked = {}
    for line in r.stdout.splitlines():
        for h in hashes:
            if line.startswith(h + ":"):
                cracked[h] = line[len(h) + 1:]
                break
    return cracked


def john_crack_cmd(john_format, hashfile, wordlist, rules=None):
    # Uses John's default potfile (~/.john/john.pot). The --pot flag is
    # jumbo-only, and Exegol's John is jumbo, but sticking to the default keeps
    # this working on a plain John too.
    cmd = ["john", f"--wordlist={wordlist}", str(hashfile)]
    if john_format:
        cmd.insert(1, f"--format={john_format}")
    if rules:
        cmd.insert(1, f"--rules={rules}")
    return cmd


def john_show(john_format, hashfile):
    cmd = ["john", "--show", str(hashfile)]
    if john_format:
        cmd.insert(1, f"--format={john_format}")
    r = subprocess.run(cmd, shell=False, check=False,
                       capture_output=True, text=True, timeout=120)
    cracked = {}
    for line in r.stdout.splitlines():
        # john --show prints `login:password`; summary lines ("N password hashes
        # cracked, ...") carry no colon, so requiring one filters them out.
        if ":" not in line:
            continue
        login, _, plain = line.partition(":")
        if login:
            cracked[login] = plain
    return cracked


def run_stream(cmd, timeout):
    """Run a crack, streaming its progress straight to my terminal. Returns the
    return code, or None if the wall-clock timeout tripped (partial results are
    still in the potfile). Ctrl-C stops just this one crack and moves on."""
    to = None if not timeout else timeout
    try:
        return subprocess.run(cmd, shell=False, check=False, timeout=to).returncode
    except subprocess.TimeoutExpired:
        _warn(f"crack hit the {timeout}s timeout - reporting what cracked so far.")
        return None
    except KeyboardInterrupt:
        _warn("Ctrl-C - stopping this crack, keeping what's cracked.")
        return None


def crack_group(cracker, ht, items, hashfile, wordlist, potfile, timeout,
                dry_run, rules=None, step=1, total_steps=1):
    """Crack one mode's file and return [(type, user, hash, password), ...].

    Straight wordlist pass first; then, if --rules is set and anything is still
    uncracked, a second pass applying the rules to only the leftovers (the
    potfile means the already-cracked are skipped, and we skip phase 2 entirely
    when the wordlist got everything).
    """
    def build(with_rules):
        if cracker == "hashcat":
            return hashcat_crack_cmd(ht.mode, hashfile, wordlist, potfile,
                                     rules if with_rules else None)
        return john_crack_cmd(ht.john, hashfile, wordlist,
                              rules if with_rules else None)

    if cracker == "hashcat":
        show = lambda: hashcat_show(ht.mode, hashfile, potfile, [it.raw for it in items])
        key = lambda it: it.raw
    else:
        show = lambda: john_show(ht.john, hashfile)
        key = lambda it: it.tag

    if dry_run:
        print("    " + " ".join(build(False)))
        if rules:
            print("    " + " ".join(build(True)) + "    # second pass, leftovers only")
        return []

    # phase 1 - straight wordlist
    print(f"\n{bold(f'>> [{step}/{total_steps}] {ht.name} (mode {ht.mode})')}")
    print(f"   {len(items)} hash(es) <- {hashfile.name}")
    started = time.monotonic()
    _rc_warn(cracker, run_stream(build(False), timeout), ht)
    cracked = show()
    print(f"   [done in {fmt_duration(time.monotonic() - started)}] "
          f"{len(cracked)}/{len(items)} cracked")

    # phase 2 - rules on whatever the wordlist left behind
    if rules:
        remaining = [it for it in items if key(it) not in cracked]
        if remaining:
            _info(f"{len(remaining)}/{len(items)} still uncracked - rules pass "
                  f"({_rules_label(rules)})")
            _rc_warn(cracker, run_stream(build(True), timeout), ht)
            cracked = show()
        else:
            _info(f"wordlist got all {len(items)} - skipping the rules pass")

    return [(ht.name, it.user, it.raw, cracked[key(it)])
            for it in items if key(it) in cracked]


def _rules_label(rules):
    return Path(str(rules)).name if "/" in str(rules) else str(rules)


# --- output ----------------------------------------------------------------

def _c(color, msg):
    if _RICH:
        Console().print(f"[{color}]{msg}[/{color}]")
    else:
        print(msg)


def _info(msg):
    _c("cyan", f"[*] {msg}")


def _warn(msg):
    _c("yellow", f"[!] {msg}")


def print_classification(items, suggestions):
    known = [it for it in items if it.htype is not None]
    unknown = [it for it in items if it.htype is None]

    if known and _RICH:
        console = Console()
        table = Table(title="Classified hashes", show_lines=False)
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Mode", style="magenta", no_wrap=True)
        table.add_column("User", style="green")
        table.add_column("Hash (head)", style="white")
        table.add_column("Note", style="yellow")
        for it in known:
            note = ""
            if it.ambiguous:
                alts = ", ".join(f"{c.name}/m{c.mode}" for c in it.candidates)
                note = "GUESS" + (f" (or {alts})" if alts else "")
            elif it.candidates:
                note = "; ".join(c.note for c in it.candidates)
            table.add_row(it.htype.name, str(it.htype.mode), it.user or "-",
                          it.raw[:32] + ("..." if len(it.raw) > 32 else ""), note)
        console.print(table)
    elif known:
        print("[*] Classified:")
        for it in known:
            if it.ambiguous:
                alts = ", ".join(f"{c.name}/m{c.mode}" for c in it.candidates)
                tag = "  (GUESS" + (f", or {alts}" if alts else "") + ")"
            elif it.candidates:
                tag = "  (" + "; ".join(c.note for c in it.candidates) + ")"
            else:
                tag = ""
            print(f"    m{it.htype.mode:<6} {it.htype.name:<28} {it.user or '-':<12} "
                  f"{it.raw[:32]}{tag}")

    for it in unknown:
        head = it.raw[:48] + ("..." if len(it.raw) > 48 else "")
        hint = ""
        if it.raw in suggestions:
            hint = "  hashcat --identify suggests: -m " + \
                   ", -m ".join(str(m) for m in suggestions[it.raw])
        _warn(f"unrecognized: {head}{hint}")


def print_results(cracked_rows, total_known):
    if not cracked_rows:
        _warn("Nothing cracked against this wordlist. Not a dead end - try "
              "rules (--rules best64), a bigger list, or a targeted mask by hand.")
        return

    if _RICH:
        console = Console()
        table = Table(title=f"CRACKED  ({len(cracked_rows)}/{total_known})",
                      show_lines=False)
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("User", style="green")
        table.add_column("Hash (head)", style="white")
        table.add_column("Password", style="bold red")
        for typ, user, h, pw in cracked_rows:
            table.add_row(typ, user or "-", h[:24] + ("..." if len(h) > 24 else ""), pw)
        console.print(table)
    else:
        print(f"[*] CRACKED ({len(cracked_rows)}/{total_known}):")
        for typ, user, h, pw in cracked_rows:
            print(f"    {typ:<26} {user or '-':<14} {h[:24]:<24}  {pw}")


# --- cli -------------------------------------------------------------------

def read_inputs(args):
    """Gather raw hash strings from -H, files, and/or stdin ('-')."""
    raw = []
    for h in args.hash or []:
        raw.append(h)
    for src in args.inputs or []:
        if src == "-":
            raw.extend(sys.stdin.read().splitlines())
        else:
            path = safe_path(src, must_exist=True, kind="input file")
            raw.extend(path.read_text(errors="replace").splitlines())
    lines = []
    for r in raw:
        cleaned = clean_hash_line(r)
        if cleaned is not None:
            lines.append(cleaned)
    if not lines:
        raise ValidationError("No hashes to work with (empty input).")
    return lines


def resolve_rules(name, cracker):
    """Resolve --rules for the chosen cracker.

    Hashcat wants a .rule *file*: an explicit path if it exists, otherwise a
    bare name resolved under /usr/share/hashcat/rules (with .rule appended).
    John wants a *section name* from john.conf (Wordlist, Jumbo, KoreLogic, ...),
    passed through as `--rules=<name>` - allow-list validated, not a file.
    """
    if name is None:
        return None
    if cracker == "hashcat":
        p = Path(name).expanduser()
        if not p.exists():
            fname = name if name.endswith(".rule") else name + ".rule"
            p = Path(DEFAULT_RULES_DIR) / fname
        return safe_path(str(p), must_exist=True, kind="rules file")
    # john
    if not _RULENAME_RE.match(name):
        raise ValidationError(f"Refusing suspicious john rules name: {name!r}")
    return name


def _rc_warn(cracker, rc, ht):
    # hashcat: 0=cracked, 1=exhausted (both normal). Anything else (bad hash
    # file, nothing loaded) is a real problem worth flagging, not swallowing.
    # john returns 0 on a normal finish. rc is None on timeout/Ctrl-C (already
    # warned) - don't double-warn there.
    if rc is not None and ((cracker == "hashcat" and rc not in (0, 1))
                           or (cracker == "john" and rc != 0)):
        _warn(f"{cracker} exited rc={rc} on {ht.name} - results below may be incomplete.")


def resolve_cracker(name):
    if name == "hashcat":
        if shutil.which("hashcat") is None:
            if shutil.which("john") is not None:
                _warn("hashcat not found - falling back to John.")
                return "john"
            raise ValidationError("Neither hashcat nor john is on PATH.")
        return "hashcat"
    if name == "john":
        if shutil.which("john") is None:
            raise ValidationError("john not found on PATH - install it or use --cracker hashcat.")
        return "john"
    raise ValidationError(f"Unknown cracker: {name!r}")


_EXAMPLES = """examples:
  hash-triage crack dump.txt
      classify everything in the file, then run rockyou against each mode

  hash-triage crack secretsdump.out --rules best64
      wordlist first, then a rules pass on whatever is left

  cat hashes | hash-triage crack - --cracker john
      read from stdin and use John instead of Hashcat

  hash-triage classify dump.txt
      just say what each hash is - crack nothing, write nothing

  hash-triage crack dump.txt --json - | jq -r '.data.cracked[] | "\\(.user)  \\(.password)"'
      hand the recovered creds to something else
"""


def add_input_options(sub):
    sub.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    sub.add_argument("inputs", nargs="*",
                     help="hash file(s), or '-' for stdin (combine with -H)")
    sub.add_argument("-H", "--hash", action="append", metavar="HASH",
                     help="a single hash on the command line (repeatable)")
    sub.add_argument("--only-mode", type=int, default=None, metavar="N",
                     help="skip detection - treat every line as this hashcat mode")
    sub.add_argument("--ambiguous", choices=("ntlm", "md5"), default="ntlm",
                     help="what a bare 32-hex hash is assumed to be (default: ntlm)")
    sub.add_argument("--no-identify", action="store_true",
                     help="don't ask hashcat --identify for a second opinion on unknowns")
    sub.add_argument("--json", dest="json_out", metavar="FILE",
                     help="write machine-readable JSON ('-' for stdout, which hides the tables)")


def build_parser():
    parser = ToolParser(
        prog="hash-triage",
        description="Classify found hashes by type, split them per Hashcat mode, run a\n"
                    "local wordlist pass (Hashcat first, John fallback), and report what\n"
                    "cracked. Triage only: it identifies and cracks locally, it never\n"
                    "fires an exploit and never reuses a recovered password.",
        epilog=build_epilog(_EXAMPLES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_global_flags(parser, "hash-triage", __version__)
    subs = parser.add_subparsers(dest="command", metavar="<command>")

    crack = subs.add_parser(
        "crack", help="classify, then run the wordlist against each mode",
        description="Classify the input, write one file per hashcat mode, and crack each.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_input_options(crack)
    run = crack.add_argument_group("cracking")
    run.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, metavar="FILE",
                     help=f"wordlist for the -a 0 run (default: {DEFAULT_WORDLIST})")
    run.add_argument("-o", "--outdir", default=DEFAULT_OUTDIR, metavar="DIR",
                     help=f"where per-mode files and the potfile go (default: {DEFAULT_OUTDIR})")
    run.add_argument("--cracker", choices=("hashcat", "john"), default="hashcat",
                     help="cracker to use (default: hashcat)")
    run.add_argument("--rules", default=None, metavar="NAME",
                     help="second pass with rules on the leftovers - hashcat: a .rule "
                          f"name resolved under {DEFAULT_RULES_DIR}, or a path; "
                          "john: a john.conf section name")
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SECS",
                     help=f"per-mode wall-clock cap (default: {DEFAULT_TIMEOUT}; 0 = none)")
    run.add_argument("--dry-run", action="store_true",
                     help="write the per-mode files and print the exact crack commands, "
                          "but run nothing")

    classify_p = subs.add_parser(
        "classify", help="say what each hash is - crack nothing, write nothing",
        description="Identify each hash's type, hashcat mode and John format, then stop.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_input_options(classify_p)

    return parser


def build_json(items, suggestions, cracked_rows):
    return envelope(
        tool="hash-triage",
        tool_version=__version__,
        subject=f"{len(items)} hash(es)",
        summary=summarise(items, cracked_rows),
        data={
            "hashes": [
                {
                    "hash": scrub(it.raw, limit=200),
                    "user": it.user,
                    "type": it.htype.name if it.htype else None,
                    "hashcat_mode": it.htype.mode if it.htype else None,
                    "john_format": it.htype.john if it.htype else None,
                    "guess": bool(it.ambiguous),
                    "identify_suggestion": suggestions.get(it.raw),
                }
                for it in items
            ],
            "cracked": [
                {"type": t, "user": u, "hash": scrub(h, limit=200), "password": pw}
                for t, u, h, pw in cracked_rows
            ],
        },
    )


def summarise(items, cracked_rows):
    known = sum(1 for it in items if it.htype)
    bits = [f"{len(items)} hash(es)", f"{known} identified"]
    if cracked_rows:
        bits.append(f"{len(cracked_rows)} cracked")
    unknown = len(items) - known
    if unknown:
        bits.append(f"{unknown} unrecognised")
    return " \u00b7 ".join(bits)


def run_command(args):
    quiet = args.json_out == "-"
    only_mode = validate_mode(args.only_mode) if args.only_mode is not None else None

    # Validate everything that can be rejected BEFORE doing any work - failing
    # after printing a full classification table just makes the error easy to miss.
    outdir = wordlist = cracker = rules = None
    if args.command == "crack":
        outdir = safe_path(args.outdir, kind="outdir")
        wordlist = safe_path(args.wordlist, kind="wordlist")
        cracker = resolve_cracker(args.cracker)
        rules = resolve_rules(args.rules, cracker)
        if not args.dry_run and not wordlist.exists():
            raise ValidationError(
                f"Wordlist not found: {wordlist} "
                f"(rockyou is often gzipped - `gunzip {wordlist}.gz`).")

    lines = read_inputs(args)
    items = classify(lines, args.ambiguous, only_mode=only_mode)

    unknown_hashes = [it.raw for it in items if it.htype is None]
    suggestions = {} if args.no_identify else identify_suggestions(unknown_hashes)
    if not quiet:
        print_classification(items, suggestions)

    groups = group_by_mode(items)

    if args.command == "classify":
        if args.json_out:
            emit_json(build_json(items, suggestions, []), args.json_out)
        return EXIT_OK if groups else EXIT_NO_DATA

    if not groups:
        _warn("Nothing recognized to crack. See the unrecognized lines above.")
        if args.json_out:
            emit_json(build_json(items, suggestions, []), args.json_out)
        return EXIT_NO_DATA

    outdir.mkdir(parents=True, exist_ok=True)
    paths = write_mode_files(groups, outdir, cracker)
    _info(f"wrote {len(paths)} per-mode file(s) to {outdir}")

    potfile = outdir / "triage.potfile"
    if args.dry_run:
        _info("dry run - commands only, nothing executed:")

    cracked_rows = []
    total_known = sum(len(v[1]) for v in groups.values())
    ordered = sorted(groups.items())
    started_all = time.monotonic()
    for step, (mode, (ht, group_items)) in enumerate(ordered, start=1):
        cracked_rows.extend(
            crack_group(cracker, ht, group_items, paths[mode], wordlist,
                        potfile, args.timeout, args.dry_run, rules,
                        step=step, total_steps=len(ordered)))

    if not args.dry_run:
        print(f"\n{bold('all modes done')} in {fmt_duration(time.monotonic() - started_all)}")
        if not quiet:
            print_results(cracked_rows, total_known)
        if cracked_rows:
            creds = outdir / "cracked.txt"
            creds.write_text(
                "\n".join(f"{typ}\t{user or '-'}\t{h}\t{pw}"
                          for typ, user, h, pw in cracked_rows) + "\n")
            _info(f"cracked creds also written to {creds}")

    if args.json_out:
        emit_json(build_json(items, suggestions, cracked_rows), args.json_out)

    return EXIT_OK


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        render_banner("hash-triage", __version__)
        parser.print_help()
        return EXIT_USAGE

    # Never over JSON-to-stdout: that output is meant to be piped into something.
    if not args.no_banner and args.json_out != "-":
        render_banner("hash-triage", __version__)

    try:
        return run_command(args)
    except (ValidationError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ninterrupted - anything already cracked is in the potfile.", file=sys.stderr)
        return EXIT_INTERRUPTED


def main_cli():
    """Console-script entry point (see pyproject [project.scripts])."""
    return main()


if __name__ == "__main__":
    sys.exit(main_cli())
