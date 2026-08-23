"""Input validation, shared across the suite.

The rule everywhere: **reject, don't sanitise.** Nothing here quietly strips a bad
character and carries on - a value that doesn't match its allow-list raises and the
tool exits 1 without a subprocess ever being built.

None of these tools use `shell=True`, so injection is already dead at the argv
boundary. This layer sits on top of that, not instead of it: a target with a `;` in
it is someone poking at me, and I'd rather find out at the front door.

The one deliberate exception is `password` - a real credential can legitimately
contain any punctuation, so an allow-list there would reject valid logins. It's
checked for control characters and length only, which is safe precisely because
`shell=False` makes its content inert.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from pathlib import Path


class ValidationError(ValueError):
    """Raised when input fails its allow-list. Always fatal, always exit 1."""


# --- patterns -------------------------------------------------------------

_PATH_RE = re.compile(r"^[A-Za-z0-9_./~ +=@:-]+$")
_TARGET_RE = re.compile(r"^[A-Za-z0-9.:/_-]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")
_USER_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")          # $ for machine accounts
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")          # IFNAMSIZ
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")             # session / rule names
_TOKEN_RE = re.compile(r"^[A-Za-z0-9.,:/_=@-]+$")           # one extra CLI arg
_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")

DANGEROUS_SUBSTRINGS = (";", "|", "&", "$(", "`", "\n", "\r", "&&", "||", ">", "<")
_DANGEROUS = DANGEROUS_SUBSTRINGS  # older spelling, kept so nothing breaks mid-port

MAX_PASSWORD_LEN = 1024
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


# --- paths ----------------------------------------------------------------

def checked_path(path_str: str) -> Path:
    """Allow-list a path, then expand and resolve it. Creates nothing."""
    if not path_str or not path_str.strip() or not _PATH_RE.match(path_str):
        raise ValidationError(f"Refusing suspicious path: {path_str!r}")
    if ".." in Path(path_str).parts:
        raise ValidationError(f"Refusing path with '..': {path_str!r}")
    return Path(path_str).expanduser().resolve()


def safe_dir(path_str: str) -> Path:
    """Validated directory, created if missing."""
    path = checked_path(path_str)
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_output_path(path_str: str) -> Path:
    """Validated file path; its parent directory is created if missing."""
    path = checked_path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


# --- network identifiers --------------------------------------------------

def validate_target(target: str) -> str:
    """IP, CIDR or hostname. Scan targets, which may legitimately be a range."""
    target = target.strip()
    if not target or not _TARGET_RE.match(target):
        raise ValidationError(f"Refusing suspicious target value: {target!r}")
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        pass  # fine - a hostname, and it already passed the regex
    return target


def validate_host(host: str) -> str:
    """A single host: no CIDR, no slashes. Used for DCs and bolt endpoints."""
    host = host.strip()
    if not host or not _HOST_RE.match(host):
        raise ValidationError(f"Refusing suspicious host value: {host!r}")
    return host


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValidationError(f"Not a valid IP address: {value!r}") from exc


def validate_subnet(value: str) -> str:
    """CIDR or bare host; a bare host normalises to /32 (or /128)."""
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValidationError(f"Not a valid subnet or host: {value!r}") from exc


def validate_iface(name: str) -> str:
    name = name.strip()
    if not name or not _IFACE_RE.match(name):
        raise ValidationError(f"Refusing suspicious interface name: {name!r}")
    return name


def validate_port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Not a valid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValidationError(f"Port out of range 1-65535: {port}")
    return port


def validate_port_list(ports: str) -> str:
    """Comma-separated ports, as handed to nmap's -p."""
    if not re.match(r"^\d+(,\d+)*$", ports):
        raise ValidationError(f"Refusing suspicious port list: {ports!r}")
    for part in ports.split(","):
        validate_port(part)
    return ports


# --- credentials ----------------------------------------------------------

def validate_username(user: str) -> str:
    user = user.strip()
    if not user or not _USER_RE.match(user):
        raise ValidationError(f"Refusing suspicious username: {user!r}")
    return user


def validate_domain(domain: str) -> str:
    domain = domain.strip()
    if not domain or not _DOMAIN_RE.match(domain):
        raise ValidationError(f"Refusing suspicious domain: {domain!r}")
    return domain


def validate_password(password: str) -> str:
    """The documented exception: content isn't allow-listed, because a real password
    can contain anything. Control characters and absurd length are still refused -
    those aren't passwords, they're someone probing the argv boundary."""
    if any(ch in password for ch in ("\x00", "\n", "\r")):
        raise ValidationError("Password contains control characters.")
    if len(password) > MAX_PASSWORD_LEN:
        raise ValidationError(f"Password longer than {MAX_PASSWORD_LEN} characters.")
    return password


def validate_ntlm(value: str) -> str:
    """Accepts NT, LM:NT or :NT, each half 32 hex. Returns LM:NT for pass-the-hash."""
    raw = value.strip()
    if ":" in raw:
        lm, _, nt = raw.partition(":")
        lm = lm or EMPTY_LM
    else:
        lm, nt = EMPTY_LM, raw
    if not _HEX32_RE.match(lm) or not _HEX32_RE.match(nt):
        raise ValidationError("NTLM hash must be 32 hex chars (NT, LM:NT or :NT).")
    return f"{lm.lower()}:{nt.lower()}"


def redact(value: str) -> str:
    """What goes in an echoed command line and a saved log instead of a secret."""
    return "******" if value else ""


# --- free-form extra arguments -------------------------------------------

def validate_extra_args(raw: str) -> list[str]:
    """Split user-supplied passthrough flags and allow-list every token."""
    if not raw:
        return []
    if any(bad in raw for bad in _DANGEROUS):
        raise ValidationError("Extra args contain disallowed shell metacharacters.")
    tokens = shlex.split(raw)
    for tok in tokens:
        if not _TOKEN_RE.match(tok):
            raise ValidationError(f"Refusing suspicious argument: {tok!r}")
    return tokens


def validate_name(name: str, what: str = "name") -> str:
    """Short identifier: tmux session, hashcat rule section, and friends."""
    name = name.strip()
    if not name or not _NAME_RE.match(name):
        raise ValidationError(f"Refusing suspicious {what}: {name!r}")
    return name
