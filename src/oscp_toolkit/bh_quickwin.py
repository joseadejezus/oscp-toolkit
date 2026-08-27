#!/usr/bin/env python3
"""
bh-quickwin

Reads the AD quick wins straight out of the Neo4j graph BloodHound already
built, so I don't have to click through the GUI on exam day:

  * kerberoastable users        (hasspn)
  * AS-REP-roastable users      (dontreqpreauth)
  * unconstrained-delegation hosts
  * shortest paths from owned principals -> Domain Admins

Give it the nodes you've popped with --own and it marks them owned=true first
(the same thing the GUI does on right-click), then walks the paths. It only ever
*reads* attack paths - you still run every hop by hand. See the README.

    bh-quickwin wins --password 'bloodhoundcommunityedition'
    bh-quickwin wins --own 'JDOE@CORP.LOCAL' --markdown quickwins.md
    bh-quickwin check
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

from . import __version__
from ._common.banner import render_banner
from ._common.cli import ToolParser, add_global_flags, build_epilog
from ._common.exits import (
    EXIT_INTERRUPTED,
    EXIT_NO_DATA,
    EXIT_OK,
    EXIT_UNAVAILABLE,
    EXIT_USAGE,
)
from ._common.jsonout import emit as emit_json
from ._common.jsonout import envelope
from ._common.text import scrub
from ._common.validate import ValidationError, safe_output_path
from ._common.validate import validate_domain as _shared_domain

# The neo4j driver is this tool's one hard dependency - it IS a bolt client. But
# failing at import time also kills --help and --version, which is unhelpful when
# you're trying to find out how to install it. Fail when a connection is actually
# attempted instead.
try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable

    _HAVE_NEO4J = True
except ImportError:  # pragma: no cover - environment dependent
    _HAVE_NEO4J = False
    GraphDatabase = None

    class _MissingDriverError(Exception):
        pass

    AuthError = Neo4jError = ServiceUnavailable = _MissingDriverError


def _require_driver() -> None:
    if not _HAVE_NEO4J:
        raise RuntimeError(
            "the 'neo4j' driver isn't installed - this tool is a bolt client and "
            "needs it.\n       pipx inject oscp-toolkit neo4j   (or: pip install neo4j)"
        )

# --- Optional rich rendering; degrades to plain ANSI without it ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    _RICH = True
except ImportError:
    _RICH = False

DEFAULT_URI = "bolt://localhost:7687"
DEFAULT_USER = "neo4j"
CONNECT_TIMEOUT_SECONDS = 15
QUERY_TIMEOUT_SECONDS = 120  # server-side per-transaction cap

# BloodHound names are uppercase FQDNs (JDOE@CORP.LOCAL) or SIDs (S-1-5-21-...-1104).
# shell=False isn't in play here - the risk is Cypher injection - but I still
# reject anything that isn't a plausible name/SID outright before it goes near a
# query, even though every query below is parameterised. Defense in depth.
_NAME_RE = re.compile(r"^[A-Za-z0-9._@$-]+$")
_URI_RE = re.compile(r"^(?:bolt|neo4j)(?:\+s|\+ssc)?://[A-Za-z0-9._:\[\]-]+$")
_RID_RE = re.compile(r"^\d+$")
# GPO display names are the one place real AD data has spaces and braces
# ("Default Domain Policy@CORP.LOCAL", "{31B2F340-016D-11D2-945F-00C04FB984F9}"),
# so _NAME_RE is too tight for them. Deliberately still excludes $ & ( ) ' - a
# first cut allowed those for names like "Sales & Marketing (2024)" and it let
# "$(whoami)" and "&& reboot" straight through the validator. Nothing here shells
# out and every query is parameterised, so that was only theoretical - but a
# validator that accepts a command substitution isn't one. A GPO whose real name
# needs those characters is still reachable by its objectid GUID, which the
# lookup below accepts alongside the name.
_GPO_NAME_RE = re.compile(r"^[A-Za-z0-9._@ {}-]+$")


def validate_uri(uri: str) -> str:
    uri = uri.strip()
    if not _URI_RE.match(uri):
        raise ValidationError(f"Refusing suspicious Neo4j URI: {uri!r}")
    return uri


def validate_names(raw: str) -> list[str]:
    """Split/validate the --own list. Names are upper-cased to match BH's schema."""
    names: list[str] = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not _NAME_RE.match(tok):
            raise ValidationError(f"Refusing suspicious node identifier: {tok!r}")
        names.append(tok.upper())
    if not names:
        raise ValidationError("--own was given but no valid names were parsed from it.")
    return names


def validate_domain(domain: Optional[str]) -> Optional[str]:
    """BloodHound domains are UPPERCASE FQDNs; the shared validator is the same shape."""
    if domain is None:
        return None
    return _shared_domain(domain).upper()


def validate_rids(raw: str) -> list[str]:
    """'512,519' -> ['-512', '-519'] suffixes for objectid matching."""
    suffixes: list[str] = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not _RID_RE.match(tok):
            raise ValidationError(f"Refusing non-numeric target RID: {tok!r}")
        suffixes.append(f"-{tok}")
    if not suffixes:
        raise ValidationError("No valid target RIDs parsed (expected e.g. '512').")
    return suffixes


def validate_gpo_name(name: Optional[str]) -> Optional[str]:
    """Upper-cased to match BloodHound's schema, same as --own."""
    if name is None:
        return None
    name = name.strip()
    if not name:
        raise ValidationError("GPO name was empty.")
    if not _GPO_NAME_RE.match(name):
        raise ValidationError(
            f"Refusing suspicious GPO name: {name!r}\n"
            "       (letters, digits, space and . _ - @ { } only - if the real name "
            "needs other\n       characters, pass the GPO's objectid GUID instead)"
        )
    if not any(ch.isalnum() for ch in name):
        raise ValidationError(f"GPO name has no alphanumeric content: {name!r}")
    return name.upper()


def validate_max_hops(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if value < 1:
        raise ValidationError("--max-hops must be a positive integer.")
    return value


# --- queries (every user value travels as a bound parameter) ---

Q_KERBEROASTABLE = """
MATCH (u:User)
WHERE u.hasspn = true AND NOT coalesce(u.name, '') STARTS WITH 'KRBTGT@'
  AND ($domain IS NULL OR u.domain = $domain)
RETURN u.name AS name, u.enabled AS enabled, u.admincount AS admincount,
       u.pwdlastset AS pwdlastset, u.serviceprincipalnames AS spns
ORDER BY coalesce(u.admincount, false) DESC, u.name
"""

Q_ASREP = """
MATCH (u:User)
WHERE u.dontreqpreauth = true
  AND ($domain IS NULL OR u.domain = $domain)
RETURN u.name AS name, u.enabled AS enabled, u.admincount AS admincount
ORDER BY coalesce(u.admincount, false) DESC, u.name
"""

# OPTIONAL MATCH + count instead of an exists{} subquery so this runs on the
# Neo4j 4.4 that older BloodHound CE ships as well as 5.x.
Q_UNCONSTRAINED = """
MATCH (c:Computer)
WHERE c.unconstraineddelegation = true
  AND ($domain IS NULL OR c.domain = $domain)
OPTIONAL MATCH (c)-[:MemberOf*1..3]->(g:Group)
WHERE g.objectid ENDS WITH '-516'
WITH c, count(g) AS dc_hits
RETURN c.name AS name, c.enabled AS enabled, dc_hits > 0 AS is_dc
ORDER BY is_dc, c.name
"""

Q_MARK_OWNED = """
UNWIND $names AS n
MATCH (x)
WHERE x.name = n OR x.objectid = n
SET x.owned = true
RETURN collect(DISTINCT x.name) AS matched
"""

Q_OWNED_COUNT = "MATCH (o) WHERE o.owned = true RETURN count(o) AS c"

# Contains/GPLink describe AD *structure* (this OU holds that computer, this GPO is
# linked there) - not control. shortestPath() below has no type filter, so it'll
# happily walk WriteOwner(gpo) -[GPLink]-> ou -[Contains]-> some unrelated Group and
# report that as a path to Domain Admins. That's wrong: containment never grants
# control over the contained object. Neo4j 4.4 (what BloodHound CE ships) can't
# exclude relationship types inside a variable-length pattern without APOC, so this
# is enforced as a post-query filter in gather() instead of in the Cypher itself -
# meaning a rejected path isn't replaced by the next-best real one, it's just
# dropped and reported as "no path found" via a note. False negative over false
# positive, on purpose: GPO-based attack paths still need manual "what does this
# GPO apply to" verification (BloodHound GUI or `bloodyAD ... get object <gpo>`),
# they are not something this query can safely automate.
_STRUCTURAL_EDGE_TYPES = {"Contains", "GPLink"}

# shortestPath length limit is substituted from a validated int (or '' = unbounded).
Q_PATHS_TMPL = """
MATCH (o) WHERE o.owned = true
MATCH (g:Group) WHERE any(r IN $rids WHERE g.objectid ENDS WITH r)
MATCH p = shortestPath((o)-[*1..{maxhops}]->(g))
WHERE o <> g
RETURN o.name AS source, g.name AS target,
       [n IN nodes(p) | n.name] AS node_names,
       [r IN relationships(p) | type(r)] AS edge_types,
       length(p) AS hops
ORDER BY hops, source
"""

# Who can rewrite a GPO. Deliberately only *control* edges - this is the same
# distinction the path filter above enforces, applied at the GPO itself.
Q_GPO_CONTROLLERS = """
MATCH (p)-[r:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights]->(g:GPO)
WHERE ($name IS NULL OR toUpper(g.name) = $name OR toUpper(g.objectid) = $name)
OPTIONAL MATCH (m)-[:MemberOf*1..5]->(p)
WHERE m:User OR m:Computer
RETURN g.name AS gpo, p.name AS principal, labels(p) AS principal_labels,
       type(r) AS edge, coalesce(p.owned, false) AS owned,
       collect(DISTINCT {name: m.name, owned: coalesce(m.owned, false)}) AS members
ORDER BY gpo, principal
"""

# THE scope walk. Contains/GPLink are exactly the right edges for this question
# ("what does this policy apply to") even though they're exactly the wrong ones
# for "what did I compromise" - see _STRUCTURAL_EDGE_TYPES. blocksinheritance and
# the link's enforced flag come back raw; the precedence rule between them is
# applied in Python, not here.
Q_GPO_SCOPE = """
MATCH (g:GPO) WHERE toUpper(g.name) = $name OR toUpper(g.objectid) = $name
MATCH (g)-[l:GPLink]->(scope)
OPTIONAL MATCH path = (scope)-[:Contains*0..10]->(t)
WHERE t:Computer OR t:User
OPTIONAL MATCH (t)-[:MemberOf*1..3]->(dcg:Group)
WHERE dcg.objectid ENDS WITH '-516'
RETURN g.name AS gpo, scope.name AS scope_name, labels(scope) AS scope_labels,
       coalesce(l.enforced, false) AS enforced,
       t.name AS target_name, labels(t) AS target_labels,
       count(dcg) > 0 AS is_dc,
       [n IN nodes(path) | n.name] AS chain,
       [n IN nodes(path) | coalesce(n.blocksinheritance, false)] AS blocks
ORDER BY scope_name, target_name
"""


# --- neo4j plumbing ---

@dataclass
class Neo4jClient:
    driver: object

    @classmethod
    def connect(cls, uri: str, user: str, password: str) -> "Neo4jClient":
        _require_driver()
        try:
            driver = GraphDatabase.driver(
                uri, auth=(user, password), connection_timeout=CONNECT_TIMEOUT_SECONDS
            )
            driver.verify_connectivity()
        except AuthError as exc:
            raise RuntimeError(f"Neo4j auth failed for user {user!r}: {exc}") from exc
        except ServiceUnavailable as exc:
            raise RuntimeError(
                f"Couldn't reach Neo4j at {uri}: {exc}\n"
                "       (running inside Exegol? the graph is on your Mac host - try "
                "--uri bolt://host.docker.internal:7687)"
            ) from exc
        except Neo4jError as exc:
            raise RuntimeError(f"Neo4j connection error: {exc}") from exc
        return cls(driver=driver)

    def _run(self, query: str, params: dict, write: bool) -> list[dict]:
        """One explicit transaction with a server-side timeout - no silent hangs."""
        try:
            with self.driver.session() as session:
                tx = session.begin_transaction(timeout=QUERY_TIMEOUT_SECONDS)
                try:
                    records = [rec.data() for rec in tx.run(query, **params)]
                    tx.commit()
                    return records
                except BaseException:
                    tx.rollback()
                    raise
        except Neo4jError as exc:
            # ClientError / CypherSyntaxError / ConstraintError all subclass this.
            raise RuntimeError(f"Neo4j query failed: {exc}") from exc

    def read(self, query: str, **params) -> list[dict]:
        return self._run(query, params, write=False)

    def write(self, query: str, **params) -> list[dict]:
        return self._run(query, params, write=True)

    def close(self) -> None:
        try:
            self.driver.close()
        except Exception:
            pass


# --- collecting the results ---

@dataclass
class QuickWins:
    kerberoastable: list[dict] = field(default_factory=list)
    asrep: list[dict] = field(default_factory=list)
    unconstrained: list[dict] = field(default_factory=list)
    paths: list[dict] = field(default_factory=list)
    owned_count: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class GpoScope:
    gpo_name: str = ""
    links: list[dict] = field(default_factory=list)
    in_scope: list[dict] = field(default_factory=list)
    excluded: list[dict] = field(default_factory=list)
    controllers: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _scrub_rows(rows: list[dict]) -> list[dict]:
    """Node names, SPNs and edge types are domain data - in a domain you don't
    control, a sAMAccountName can carry escape sequences. Scrub on the way IN, so
    the rich table, the plain render, the Markdown and the JSON are all covered by
    one call instead of four that can drift apart."""
    cleaned = []
    for row in rows:
        out = {}
        for key, value in row.items():
            if isinstance(value, str):
                out[key] = scrub(value, limit=300)
            elif isinstance(value, list):
                out[key] = [scrub(v, limit=300) if isinstance(v, str) else v for v in value]
            else:
                out[key] = value
        cleaned.append(out)
    return cleaned


def _drop_structural_paths(rows: list[dict]) -> tuple[list[dict], int]:
    """Reject any candidate path that leans on a structural edge anywhere in the
    chain, not just at the end - a Contains/GPLink hop in the *middle* is just as
    bogus as one at the tail. See the _STRUCTURAL_EDGE_TYPES comment above."""
    kept, dropped = [], 0
    for row in rows:
        edges = row.get("edge_types") or []
        if any(e in _STRUCTURAL_EDGE_TYPES for e in edges):
            dropped += 1
        else:
            kept.append(row)
    return kept, dropped


def gather(client: Neo4jClient, domain: Optional[str], rids: list[str],
           own: Optional[list[str]], max_hops: Optional[int]) -> QuickWins:
    wins = QuickWins()

    if own:
        matched = client.write(Q_MARK_OWNED, names=own)
        names_set = [scrub(n, limit=300) for n in (matched[0]["matched"] if matched else [])]
        wins.notes.append(f"Marked owned=true on {len(names_set)} node(s): {', '.join(names_set) or '(none)'}")
        missing = [n for n in own if n not in names_set]
        if missing:
            wins.notes.append(
                f"No graph node matched: {', '.join(missing)} "
                "(check the exact BloodHound name/SID - names are UPPERCASE FQDNs)."
            )

    wins.kerberoastable = _scrub_rows(client.read(Q_KERBEROASTABLE, domain=domain))
    wins.asrep = _scrub_rows(client.read(Q_ASREP, domain=domain))
    wins.unconstrained = _scrub_rows(client.read(Q_UNCONSTRAINED, domain=domain))

    wins.owned_count = client.read(Q_OWNED_COUNT)[0]["c"]
    if wins.owned_count == 0:
        wins.notes.append(
            "No nodes are marked owned yet - path-to-DA section will be empty. "
            "Pass --own 'NAME@DOMAIN,...' or mark them owned in the BloodHound GUI."
        )
    else:
        maxhops = str(max_hops) if max_hops else ""
        query = Q_PATHS_TMPL.format(maxhops=maxhops)
        raw_paths = _scrub_rows(client.read(query, rids=rids))
        wins.paths, dropped = _drop_structural_paths(raw_paths)
        if dropped:
            wins.notes.append(
                f"Dropped {dropped} candidate path(s) that only reached the target via "
                f"structural edges ({', '.join(sorted(_STRUCTURAL_EDGE_TYPES))}) rather than "
                "real control - containment isn't compromise. If a GenericAll/WriteOwner/"
                "GenericWrite hit on a GPO looked promising, resolve what it actually "
                "reaches with: bh-quickwin gpo-scope '<GPO NAME>'"
            )

    return wins


def _resolve_inheritance(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Apply the one AD rule that decides whether a linked GPO actually reaches an
    object: an OU with blockInheritance set cuts off GPOs linked above it, unless
    that link is Enforced, which wins over the block.

    nodes[0] of each chain is the link target itself - a block flag there is about
    what it inherits from *above*, not about a GPO linked directly to it, so only
    nodes[1:] can cut this path off.
    """
    in_scope, excluded = [], []
    for row in rows:
        if not row.get("target_name"):
            continue  # link target has no User/Computer under it
        chain = row.get("chain") or []
        blocks = row.get("blocks") or []
        blocking = [
            chain[i] for i in range(1, len(blocks))
            if blocks[i] and i < len(chain)
        ]
        entry = {
            "name": row["target_name"],
            "kind": "Computer" if "Computer" in (row.get("target_labels") or []) else "User",
            "is_dc": bool(row.get("is_dc")),
            "scope_name": row.get("scope_name"),
            "enforced": bool(row.get("enforced")),
            "chain": chain,
        }
        if blocking and not row.get("enforced"):
            entry["blocked_by"] = blocking
            excluded.append(entry)
        else:
            if blocking:
                entry["enforced_over_block"] = blocking
            in_scope.append(entry)
    return in_scope, excluded


def _dedupe_by_name(rows: list[dict]) -> list[dict]:
    """The same object can be reached through more than one link; report it once,
    preferring the entry that actually lands in scope."""
    best: dict[str, dict] = {}
    for row in rows:
        cur = best.get(row["name"])
        if cur is None:
            best[row["name"]] = row
    return sorted(best.values(), key=lambda r: (r["kind"] != "Computer", not r["is_dc"], r["name"]))


def gather_gpo_scope(client: Neo4jClient, name: Optional[str]) -> GpoScope:
    """name=None lists every GPO someone holds a control edge on; a name resolves
    that one GPO's applied scope."""
    scope = GpoScope(gpo_name=name or "")

    raw_ctl = _scrub_rows(client.read(Q_GPO_CONTROLLERS, name=name))
    for row in raw_ctl:
        members = [m for m in (row.get("members") or [])
                   if isinstance(m, dict) and m.get("name")]
        row["members"] = members
        row["owned_members"] = [m["name"] for m in members if m.get("owned")]
        row["is_group"] = "Group" in (row.get("principal_labels") or [])
    scope.controllers = raw_ctl

    if name is None:
        if not scope.controllers:
            scope.notes.append(
                "No GPO in this graph has an inbound control edge (Owns/GenericAll/"
                "GenericWrite/WriteOwner/WriteDacl/AllExtendedRights)."
            )
        else:
            scope.notes.append(
                "Listing GPOs with a control edge. Re-run with a GPO name to see what "
                "that policy actually applies to."
            )
        return scope

    rows = _scrub_rows(client.read(Q_GPO_SCOPE, name=name))
    if not rows:
        scope.notes.append(
            f"No GPO named {name!r} is linked anywhere in this graph. Names are "
            "UPPERCASE and usually FQDN-suffixed, e.g. 'DEFAULT DOMAIN POLICY@CORP.LOCAL'; "
            "the objectid GUID works too. Run `bh-quickwin gpo-scope` with no name to "
            "list the GPOs that have a control edge."
        )
        return scope

    seen_links = set()
    for row in rows:
        key = (row.get("scope_name"), bool(row.get("enforced")))
        if key in seen_links:
            continue
        seen_links.add(key)
        labels = row.get("scope_labels") or []
        scope.links.append({
            "scope_name": row.get("scope_name"),
            "kind": ("Domain" if "Domain" in labels
                     else "OU" if "OU" in labels
                     else (labels[0] if labels else "?")),
            "enforced": bool(row.get("enforced")),
        })

    raw_in, raw_out = _resolve_inheritance(rows)
    scope.in_scope = _dedupe_by_name(raw_in)
    in_names = {r["name"] for r in scope.in_scope}
    scope.excluded = _dedupe_by_name([r for r in raw_out if r["name"] not in in_names])

    dcs = [r for r in scope.in_scope if r["is_dc"]]
    if dcs:
        scope.notes.append(
            f"This GPO applies to {len(dcs)} domain controller(s): "
            f"{', '.join(r['name'] for r in dcs)}. Code pushed through it runs as SYSTEM there."
        )
    else:
        scope.notes.append(
            "No domain controller falls in this GPO's applied scope - it reaches "
            "member objects only."
        )
    scope.notes.append(
        "Scope here is link + inheritance only. BloodHound does NOT collect GPO "
        "security filtering or WMI filters, so an object listed below can still be "
        "filtered out in reality - confirm on the box before relying on it."
    )
    return scope


# --- rendering ---

def _fmt_bool(v) -> str:
    if v is True:
        return "yes"
    if v is False:
        return "no"
    return "?"


def _path_str(row: dict) -> str:
    nodes = row.get("node_names") or []
    edges = row.get("edge_types") or []
    parts = [str(nodes[0]) if nodes else "?"]
    for i, edge in enumerate(edges):
        nxt = nodes[i + 1] if i + 1 < len(nodes) else "?"
        parts.append(f"-[{edge}]-> {nxt}")
    return " ".join(parts)


def render_rich(wins: QuickWins) -> None:
    console = Console()
    for note in wins.notes:
        console.print(f"[dim]{note}[/dim]")

    kt = Table(title=f"Kerberoastable users ({len(wins.kerberoastable)})", show_lines=False)
    for col in ("Name", "Enabled", "AdminCount", "SPNs"):
        kt.add_column(col)
    for r in wins.kerberoastable:
        spns = r.get("spns") or []
        name = Text(r["name"], style="bold red" if r.get("admincount") else "yellow")
        kt.add_row(name, _fmt_bool(r.get("enabled")), _fmt_bool(r.get("admincount")),
                   str(len(spns)) if isinstance(spns, list) else "-")
    console.print(kt)

    at = Table(title=f"AS-REP-roastable users ({len(wins.asrep)})")
    for col in ("Name", "Enabled", "AdminCount"):
        at.add_column(col)
    for r in wins.asrep:
        name = Text(r["name"], style="bold red" if r.get("admincount") else "yellow")
        at.add_row(name, _fmt_bool(r.get("enabled")), _fmt_bool(r.get("admincount")))
    console.print(at)

    ut = Table(title=f"Unconstrained-delegation hosts ({len(wins.unconstrained)})")
    for col in ("Host", "Enabled", "Domain Controller?"):
        ut.add_column(col)
    for r in wins.unconstrained:
        is_dc = r.get("is_dc")
        note = "yes (expected)" if is_dc else "NO - juicy"
        style = "dim" if is_dc else "bold red"
        ut.add_row(Text(r["name"], style=style), _fmt_bool(r.get("enabled")), note)
    console.print(ut)

    pt = Table(title=f"Shortest paths owned -> Domain Admins ({len(wins.paths)})", show_lines=True)
    for col in ("Hops", "Path"):
        pt.add_column(col)
    for r in wins.paths:
        pt.add_row(str(r.get("hops")), _path_str(r))
    console.print(pt)


def render_plain(wins: QuickWins) -> None:
    use_color = sys.stdout.isatty()

    def c(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if use_color else text

    for note in wins.notes:
        print(note)

    print(f"\n=== Kerberoastable users ({len(wins.kerberoastable)}) ===")
    if not wins.kerberoastable:
        print("  (none)")
    for r in wins.kerberoastable:
        spns = r.get("spns") or []
        flag = c("[admin]", "1;31") if r.get("admincount") else ""
        n = c(r["name"], "1;31") if r.get("admincount") else c(r["name"], "1;33")
        print(f"  {n}  enabled={_fmt_bool(r.get('enabled'))} spns={len(spns) if isinstance(spns, list) else '-'} {flag}")

    print(f"\n=== AS-REP-roastable users ({len(wins.asrep)}) ===")
    if not wins.asrep:
        print("  (none)")
    for r in wins.asrep:
        flag = c("[admin]", "1;31") if r.get("admincount") else ""
        n = c(r["name"], "1;31") if r.get("admincount") else c(r["name"], "1;33")
        print(f"  {n}  enabled={_fmt_bool(r.get('enabled'))} {flag}")

    print(f"\n=== Unconstrained-delegation hosts ({len(wins.unconstrained)}) ===")
    if not wins.unconstrained:
        print("  (none)")
    for r in wins.unconstrained:
        if r.get("is_dc"):
            print(f"  {r['name']}  enabled={_fmt_bool(r.get('enabled'))}  (domain controller - expected)")
        else:
            print(f"  {c(r['name'], '1;31')}  enabled={_fmt_bool(r.get('enabled'))}  {c('<- not a DC, worth a look', '1;31')}")

    print(f"\n=== Shortest paths owned -> Domain Admins ({len(wins.paths)}) ===")
    if not wins.paths:
        print("  (none)")
    for r in wins.paths:
        print(f"  [{r.get('hops')} hops] {_path_str(r)}")


def _ctl_label(row: dict) -> str:
    tag = ""
    if row.get("owned"):
        tag = "  [owned]"
    elif row.get("owned_members"):
        tag = f"  [owned member: {', '.join(row['owned_members'])}]"
    return tag


def render_gpo_scope_rich(scope: GpoScope) -> None:
    console = Console()
    for note in scope.notes:
        console.print(f"[dim]{note}[/dim]")

    if scope.controllers:
        title = ("GPOs with a control edge" if not scope.gpo_name
                 else f"Who can rewrite this GPO ({len(scope.controllers)})")
        ct = Table(title=f"{title}")
        for col in ("GPO", "Principal", "Edge", "Via"):
            ct.add_column(col, overflow="fold")
        for r in scope.controllers:
            owned = r.get("owned") or r.get("owned_members")
            principal = Text(str(r.get("principal")), style="bold red" if owned else "yellow")
            via = ""
            if r.get("is_group"):
                names = [m["name"] for m in r.get("members", [])]
                via = f"group, {len(names)} member(s)"
                if r.get("owned_members"):
                    via += f" - owned: {', '.join(r['owned_members'])}"
            elif r.get("owned"):
                via = "owned"
            ct.add_row(str(r.get("gpo")), principal, str(r.get("edge")), via)
        console.print(ct)

    if not scope.gpo_name:
        return

    lt = Table(title=f"Linked at ({len(scope.links)})")
    for col in ("Scope", "Kind", "Enforced"):
        lt.add_column(col)
    for l in scope.links:
        lt.add_row(str(l["scope_name"]), l["kind"], "yes" if l["enforced"] else "no")
    console.print(lt)

    st = Table(title=f"Objects this GPO applies to ({len(scope.in_scope)})")
    for col in ("Object", "Type", "Domain Controller?"):
        st.add_column(col)
    for r in scope.in_scope:
        style = "bold red" if r["is_dc"] else ("cyan" if r["kind"] == "Computer" else "")
        st.add_row(Text(r["name"], style=style), r["kind"],
                   "YES - SYSTEM on the DC" if r["is_dc"] else "no")
    console.print(st)

    if scope.excluded:
        xt = Table(title=f"Cut off by blocked inheritance ({len(scope.excluded)})")
        for col in ("Object", "Type", "Blocked at"):
            xt.add_column(col, overflow="fold")
        for r in scope.excluded:
            xt.add_row(r["name"], r["kind"], ", ".join(r.get("blocked_by") or []))
        console.print(xt)


def render_gpo_scope_plain(scope: GpoScope) -> None:
    use_color = sys.stdout.isatty()

    def c(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if use_color else text

    for note in scope.notes:
        print(note)

    if scope.controllers:
        header = ("GPOs with a control edge" if not scope.gpo_name
                  else "Who can rewrite this GPO")
        print(f"\n=== {header} ({len(scope.controllers)}) ===")
        for r in scope.controllers:
            owned = r.get("owned") or r.get("owned_members")
            nm = c(str(r.get("principal")), "1;31") if owned else str(r.get("principal"))
            extra = ""
            if r.get("is_group"):
                extra = f"  (group, {len(r.get('members', []))} member(s))"
            print(f"  {r.get('gpo')}  <-[{r.get('edge')}]-  {nm}{extra}{_ctl_label(r)}")

    if not scope.gpo_name:
        return

    print(f"\n=== Linked at ({len(scope.links)}) ===")
    if not scope.links:
        print("  (none)")
    for l in scope.links:
        enf = "  [ENFORCED]" if l["enforced"] else ""
        print(f"  {l['scope_name']}  ({l['kind']}){enf}")

    print(f"\n=== Objects this GPO applies to ({len(scope.in_scope)}) ===")
    if not scope.in_scope:
        print("  (none)")
    for r in scope.in_scope:
        if r["is_dc"]:
            print(f"  {c(r['name'], '1;31')}  {r['kind']}  {c('<- domain controller, SYSTEM', '1;31')}")
        else:
            print(f"  {r['name']}  {r['kind']}")

    if scope.excluded:
        print(f"\n=== Cut off by blocked inheritance ({len(scope.excluded)}) ===")
        for r in scope.excluded:
            print(f"  {r['name']}  {r['kind']}  blocked at {', '.join(r.get('blocked_by') or [])}")


def build_gpo_json(scope: GpoScope, uri: str) -> dict:
    if scope.gpo_name:
        summary = (f"{len(scope.in_scope)} object(s) in scope, "
                   f"{sum(1 for r in scope.in_scope if r['is_dc'])} DC(s), "
                   f"{len(scope.controllers)} controller edge(s)")
    else:
        summary = f"{len(scope.controllers)} GPO control edge(s)"
    return envelope(
        tool="bh-quickwin",
        tool_version=__version__,
        subject=scope.gpo_name or uri,
        summary=summary,
        notes=[scrub(n, limit=500) for n in scope.notes],
        data={
            "gpo": scope.gpo_name,
            "links": scope.links,
            "controllers": scope.controllers,
            "in_scope": scope.in_scope,
            "excluded_by_blocked_inheritance": scope.excluded,
        },
    )


def write_markdown(wins: QuickWins, out_path) -> None:
    L = ["# BloodHound Quick-Wins", ""]
    for note in wins.notes:
        L.append(f"> {note}")
    L.append("")

    L.append(f"## Kerberoastable users ({len(wins.kerberoastable)})")
    if wins.kerberoastable:
        L += ["", "| Name | Enabled | AdminCount | SPNs |", "|---|---|---|---|"]
        for r in wins.kerberoastable:
            spns = r.get("spns") or []
            nm = f"**{r['name']}**" if r.get("admincount") else r["name"]
            L.append(f"| {nm} | {_fmt_bool(r.get('enabled'))} | {_fmt_bool(r.get('admincount'))} | "
                     f"{len(spns) if isinstance(spns, list) else '-'} |")
    else:
        L.append("\n_None._")

    L += ["", f"## AS-REP-roastable users ({len(wins.asrep)})"]
    if wins.asrep:
        L += ["", "| Name | Enabled | AdminCount |", "|---|---|---|"]
        for r in wins.asrep:
            nm = f"**{r['name']}**" if r.get("admincount") else r["name"]
            L.append(f"| {nm} | {_fmt_bool(r.get('enabled'))} | {_fmt_bool(r.get('admincount'))} |")
    else:
        L.append("\n_None._")

    L += ["", f"## Unconstrained-delegation hosts ({len(wins.unconstrained)})"]
    if wins.unconstrained:
        L += ["", "| Host | Enabled | Domain Controller? |", "|---|---|---|"]
        for r in wins.unconstrained:
            dc = "yes (expected)" if r.get("is_dc") else "**no - worth a look**"
            L.append(f"| {r['name']} | {_fmt_bool(r.get('enabled'))} | {dc} |")
    else:
        L.append("\n_None._")

    L += ["", f"## Shortest paths owned -> Domain Admins ({len(wins.paths)})"]
    if wins.paths:
        L.append("")
        for r in wins.paths:
            L.append(f"- **{r.get('hops')} hops:** `{_path_str(r)}`")
    else:
        L.append("\n_None (mark owned nodes first)._")

    out_path.write_text("\n".join(L), encoding="utf-8")
    print(f"[*] Markdown summary written to {out_path}")


# --- cli ---

_EXAMPLES = """examples:
  bh-quickwin wins
      kerberoastable, AS-REP-roastable and unconstrained-delegation objects

  bh-quickwin wins --own 'JDOE@CORP.LOCAL,WS01.CORP.LOCAL'
      mark those principals owned first, then walk the paths to Domain Admins

  bh-quickwin wins --uri bolt://host.docker.internal:7687
      from inside Exegol, where the graph is on the Mac host

  bh-quickwin wins --json - | jq -r '.data.kerberoastable[].name'
      hand the roastable accounts to hash-triage

  bh-quickwin check
      just prove the bolt connection works

  bh-quickwin gpo-scope
      which GPOs anyone holds a control edge on, and who holds it

  bh-quickwin gpo-scope 'DEFAULT DOMAIN POLICY@CORP.LOCAL'
      what that policy actually applies to - the question `wins` can't answer
"""


def add_connection_options(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    conn = sub.add_argument_group("connection")
    conn.add_argument("--uri", default=DEFAULT_URI, metavar="URI",
                      help=f"Neo4j bolt URI (default: {DEFAULT_URI})")
    conn.add_argument("--user", default=DEFAULT_USER, metavar="USER",
                      help=f"Neo4j username (default: {DEFAULT_USER})")
    conn.add_argument("--password", metavar="PASS",
                      help="Neo4j password; also read from $NEO4J_PASSWORD, else prompted")


def build_parser() -> argparse.ArgumentParser:
    parser = ToolParser(
        prog="bh-quickwin",
        description="Reads quick wins straight out of a BloodHound CE graph over bolt.\n"
                    "Read-only analysis: --own annotates the graph the same way the GUI\n"
                    "right-click does, and nothing here exploits a path it finds.",
        epilog=build_epilog(_EXAMPLES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_global_flags(parser, "bh-quickwin", __version__)
    subs = parser.add_subparsers(dest="command", metavar="<command>")

    wins = subs.add_parser(
        "wins", help="read the quick wins and the paths to Domain Admins",
        description="Query the graph for roastable/delegation objects and owned->DA paths.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_options(wins)
    q = wins.add_argument_group("query")
    q.add_argument("--own", metavar="NAMES",
                   help="comma list of node names/SIDs to SET owned=true before pathing")
    q.add_argument("--domain", metavar="DOMAIN",
                   help="only report objects in this domain (e.g. CORP.LOCAL)")
    q.add_argument("--target-rids", default="512", metavar="RIDS",
                   help="group RIDs treated as crown jewels (default: 512 = Domain Admins)")
    q.add_argument("--max-hops", type=int, metavar="N",
                   help="cap shortest-path length (default: unbounded)")
    out = wins.add_argument_group("output")
    out.add_argument("--markdown", metavar="FILE", help="also write a Markdown report here")
    out.add_argument("--json", dest="json_out", metavar="FILE",
                     help="write machine-readable JSON ('-' for stdout, which hides the tables)")

    gpo = subs.add_parser(
        "gpo-scope", help="what a GPO applies to, and who can rewrite it",
        description="Resolve a GPO's applied scope (links + inheritance) and its\n"
                    "controllers. This is the deliberate counterpart to `wins`:\n"
                    "Contains/GPLink are the wrong edges for 'what did I compromise'\n"
                    "and the right ones for 'what does this policy reach'.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_options(gpo)
    gpo.add_argument("gpo_name", nargs="?", metavar="GPO",
                     help="GPO name (e.g. 'DEFAULT DOMAIN POLICY@CORP.LOCAL'); "
                          "omit to list every GPO with a control edge")
    gpo.add_argument("--json", dest="json_out", metavar="FILE",
                     help="write machine-readable JSON ('-' for stdout)")

    check = subs.add_parser(
        "check", help="prove the bolt connection works, then stop",
        description="Connect, count the nodes, and report - no analysis, no writes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_options(check)
    check.add_argument("--json", dest="json_out", metavar="FILE",
                       help="write machine-readable JSON ('-' for stdout)")

    return parser


def resolve_password(args) -> str:
    if args.password:
        return args.password
    env = os.environ.get("NEO4J_PASSWORD")
    if env:
        return env
    return getpass.getpass(f"Neo4j password for {args.user}: ")


def summarise(wins: QuickWins) -> str:
    bits = [f"{len(wins.kerberoastable)} kerberoastable",
            f"{len(wins.asrep)} AS-REP",
            f"{len(wins.unconstrained)} unconstrained"]
    if wins.paths:
        bits.append(f"{len(wins.paths)} path(s) to DA")
    return " \u00b7 ".join(bits)


def build_json(wins: QuickWins, uri: str) -> dict:
    def rows(items):
        return [{k: (scrub(str(v), limit=300) if isinstance(v, str) else v)
                 for k, v in row.items()} for row in items]

    return envelope(
        tool="bh-quickwin",
        tool_version=__version__,
        subject=uri,
        summary=summarise(wins),
        notes=[scrub(n, limit=500) for n in wins.notes],
        data={
            "kerberoastable": rows(wins.kerberoastable),
            "asrep": rows(wins.asrep),
            "unconstrained": rows(wins.unconstrained),
            "owned_count": wins.owned_count,
            "paths": [
                {"summary": scrub(_path_str(p), limit=500),
                 "nodes": [scrub(str(n), limit=200) for n in (p.get("node_names") or [])],
                 "edges": [scrub(str(e), limit=100) for e in (p.get("edge_types") or [])]}
                for p in wins.paths
            ],
        },
    )


def has_findings(wins: QuickWins) -> bool:
    return bool(wins.kerberoastable or wins.asrep or wins.unconstrained or wins.paths)


def run_command(args: argparse.Namespace) -> int:
    quiet = args.json_out == "-"
    uri = validate_uri(args.uri)
    password = resolve_password(args)

    client = None
    try:
        client = Neo4jClient.connect(uri, args.user, password)

        if args.command == "check":
            count = client.read("MATCH (n) RETURN count(n) AS c")[0]["c"]
            if args.json_out:
                emit_json(envelope(
                    tool="bh-quickwin", tool_version=__version__, subject=uri,
                    summary=f"connected, {count} node(s) in the graph",
                    data={"uri": uri, "reachable": True, "node_count": count},
                ), args.json_out)
            elif not quiet:
                print(f"connected to {uri} - {count} node(s) in the graph")
            return EXIT_OK if count else EXIT_NO_DATA

        if args.command == "gpo-scope":
            scope = gather_gpo_scope(client, validate_gpo_name(args.gpo_name))
            if not quiet:
                if _RICH:
                    render_gpo_scope_rich(scope)
                else:
                    render_gpo_scope_plain(scope)
            if args.json_out:
                emit_json(build_gpo_json(scope, uri), args.json_out)
            return EXIT_OK if (scope.in_scope or scope.controllers) else EXIT_NO_DATA

        domain = validate_domain(args.domain)
        rids = validate_rids(args.target_rids)
        max_hops = validate_max_hops(args.max_hops)
        own = validate_names(args.own) if args.own else None
        wins = gather(client, domain, rids, own, max_hops)
    finally:
        if client is not None:
            client.close()

    if not quiet:
        if _RICH:
            render_rich(wins)
        else:
            render_plain(wins)

    if args.markdown:
        write_markdown(wins, safe_output_path(args.markdown))
    if args.json_out:
        emit_json(build_json(wins, uri), args.json_out)

    return EXIT_OK if has_findings(wins) else EXIT_NO_DATA


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        render_banner("bh-quickwin", __version__)
        parser.print_help()
        return EXIT_USAGE

    # Never over JSON-to-stdout: that output is meant to be piped into something.
    if not args.no_banner and args.json_out != "-":
        render_banner("bh-quickwin", __version__)

    try:
        return run_command(args)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except RuntimeError as exc:
        # Almost always "the graph isn't reachable" - its own code so a wrapper
        # can tell "Neo4j is down" apart from "you typed the flag wrong".
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED


def main_cli() -> int:
    """Console-script entry point (see pyproject [project.scripts])."""
    return main()


if __name__ == "__main__":
    sys.exit(main_cli())
