"""oscp-toolkit - read-only enumeration helpers for OSCP+ prep and exam day.

Seven commands, one install, one shared core:

    nmap-recon     five-stage nmap flow merged into one readable table
    http-serve     loot server + paste-ready target download commands
    ad-enum        one-credential read-only AD enumeration sweep
    hash-triage    classify found hashes, run a local wordlist pass, report
    bh-quickwin    read quick wins straight out of the BloodHound graph
    ligolo-pivot   bring the ligolo tun interface and its routes up and down
    script-logger  record the terminal session and organise per-target evidence

Everything here stays on the enumeration side of the OSCP exam rules: these tools
scan, parse, aggregate, transfer and report. None of them selects or fires an
exploit, and none of them chains one finding into the next attack. See the README
for where that line sits and why each tool stops where it does.
"""

__version__ = "2.1.0"
