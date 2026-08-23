#!/usr/bin/env python3
"""Regenerate the README images from real tool output.

    python3 docs/make_demo.py                      # self-contained, uses a built-in fixture
    python3 docs/make_demo.py 10.10.10.10 ./nmap   # render YOUR actual stage files instead

Renders through rich's SVG recorder, so the pictures in the README are captured
output rather than a hand-drawn approximation. If the renderer changes and the
image isn't regenerated, the README is wrong in a way you can see.

Writes docs/demo.svg - a real nmap-recon run.

Needs `searchsploit` on PATH for the exploit-db column to populate; without it the
Status column degrades to NSE findings only, which is duller but still honest.

Deliberately NOT included: the startup banner. rich's SVG export uses a font whose
`_` and `|` don't tile, so figlet art fragments into something illegible - it looks
correct in a real terminal and wrong in the picture. The README shows the banners as
a fenced code block instead, which GitHub renders in a real monospace font.
"""
import sys
import tempfile
from pathlib import Path

from rich.console import Console

from oscp_toolkit import nmap_recon as nr

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

# Mirrors a real box (192.168.177.240) - the one that exposed the Cassandra Web
# miss, so the demo shows the exploit-db tiering doing something worth seeing.
FIXTURE_QUICK = """\
Nmap scan report for target.oscp.local (192.168.177.240)
Host is up (0.031s latency).
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-title: 403 Forbidden
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3000/tcp open  http        Thin httpd
|_http-title: Cassandra Web
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
"""

FIXTURE_VULN = """\
Nmap scan report for target.oscp.local (192.168.177.240)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| vulners:
|   cpe:/a:openbsd:openssh:7.9p1:
|_      CVE-2021-41617  7.0     https://vulners.com/cve/CVE-2021-41617
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
| http-slowloris-check:
|   VULNERABLE:
|_    Slowloris DOS attack
"""


# The -oX sidecar is what drives the exploit-db cross-reference. Without it the
# Status column is all "no known hit" and the demo shows nothing interesting.
FIXTURE_SERVICES = [
    (22, "ssh", "OpenSSH", "7.9p1"),
    (80, "http", "Apache httpd", "2.4.38"),
    (139, "netbios-ssn", "Samba smbd", "3.X - 4.X"),
    (445, "netbios-ssn", "Samba smbd", "3.X - 4.X"),
    (3000, "http", "Thin httpd", ""),
    (8021, "freeswitch-event", "FreeSWITCH mod_event_socket", ""),
]


def write_fixture(directory: Path, target: str) -> None:
    (directory / f"quick.{target}").write_text(FIXTURE_QUICK, encoding="utf-8")
    (directory / f"vuln.{target}").write_text(FIXTURE_VULN, encoding="utf-8")
    rows = "".join(
        f'<port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="{name}" product="{product}" version="{version}"/></port>'
        for port, name, product, version in FIXTURE_SERVICES
    )
    (directory / f"quick.{target}.xml").write_text(
        f'<?xml version="1.0"?><nmaprun><host><address addr="{target}"/>'
        f'<ports>{rows}</ports></host></nmaprun>',
        encoding="utf-8",
    )


def make_demo_svg(target: str, outdir: Path) -> Path:
    host_label, ports, _notes = nr.merge_stage_outputs(target, outdir)
    sidecar = nr.find_xml_sidecar(target, outdir)
    if sidecar:
        nr.enrich_with_searchsploit(sidecar, ports)

    console = Console(record=True, width=104)
    console.print(f"[dim]$ nmap-recon report {target}[/dim]\n")
    # details=True: the per-port lines are the interesting part - they're where
    # a name-only match is labelled as such instead of passing for a real finding.
    nr.render_rich(host_label, ports, [], console=console, details=True)
    console.print(f"\n{nr.summarise(ports)}")

    out = DOCS / "demo.svg"
    console.save_svg(str(out), title="nmap-recon")
    return out


def main() -> int:
    DOCS.mkdir(exist_ok=True)

    if len(sys.argv) > 2:
        target, outdir = sys.argv[1], Path(sys.argv[2])
        print(f"wrote {make_demo_svg(target, outdir)}")
        return 0

    target = "192.168.177.240"
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        write_fixture(directory, target)
        print(f"wrote {make_demo_svg(target, directory)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
