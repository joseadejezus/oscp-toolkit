"""Shared fixture: a synthetic AD graph + a fake bolt client that computes what each of
bh-quickwin's three GPO queries is SPECIFIED to return, by really walking the
graph in Python. This exercises every line of the tool's own logic; it does NOT
execute the literal Cypher (no Neo4j reachable here - flagged in the report).
"""

NODES = {
    "SYSCO.LOCAL":                        {"labels": ["Domain"]},
    "DOMAIN CONTROLLERS@SYSCO.LOCAL":     {"labels": ["OU"]},
    "USERS@SYSCO.LOCAL":                  {"labels": ["Container"]},
    "WORKSTATIONS@SYSCO.LOCAL":           {"labels": ["OU"], "blocksinheritance": True},
    "DC01@SYSCO.LOCAL":                   {"labels": ["Computer"]},
    "WS01@SYSCO.LOCAL":                   {"labels": ["Computer"]},
    "JACK.DOWLAND@SYSCO.LOCAL":           {"labels": ["User"]},
    "GREG.SHIELDS@SYSCO.LOCAL":           {"labels": ["User"], "owned": True},
    "LAINEY.MOORE@SYSCO.LOCAL":           {"labels": ["User"]},
    "GROUP POLICY CREATOR OWNERS@SYSCO.LOCAL": {"labels": ["Group"]},
    "DOMAIN CONTROLLERS GROUP@SYSCO.LOCAL": {"labels": ["Group"], "objectid": "S-1-5-21-1-516"},
    "DEFAULT DOMAIN POLICY@SYSCO.LOCAL":  {"labels": ["GPO"], "objectid": "{31B2F340-016D-11D2-945F-00C04FB984F9}"},
    "ENFORCED POLICY@SYSCO.LOCAL":        {"labels": ["GPO"]},
    "ORPHAN POLICY@SYSCO.LOCAL":          {"labels": ["GPO"]},
}

# (src, type, dst, props)
EDGES = [
    ("DEFAULT DOMAIN POLICY@SYSCO.LOCAL", "GPLink", "SYSCO.LOCAL", {"enforced": False}),
    ("ENFORCED POLICY@SYSCO.LOCAL", "GPLink", "SYSCO.LOCAL", {"enforced": True}),
    ("SYSCO.LOCAL", "Contains", "DOMAIN CONTROLLERS@SYSCO.LOCAL", {}),
    ("SYSCO.LOCAL", "Contains", "USERS@SYSCO.LOCAL", {}),
    ("SYSCO.LOCAL", "Contains", "WORKSTATIONS@SYSCO.LOCAL", {}),
    ("DOMAIN CONTROLLERS@SYSCO.LOCAL", "Contains", "DC01@SYSCO.LOCAL", {}),
    ("WORKSTATIONS@SYSCO.LOCAL", "Contains", "WS01@SYSCO.LOCAL", {}),
    ("USERS@SYSCO.LOCAL", "Contains", "JACK.DOWLAND@SYSCO.LOCAL", {}),
    ("USERS@SYSCO.LOCAL", "Contains", "GREG.SHIELDS@SYSCO.LOCAL", {}),
    ("USERS@SYSCO.LOCAL", "Contains", "LAINEY.MOORE@SYSCO.LOCAL", {}),
    ("DC01@SYSCO.LOCAL", "MemberOf", "DOMAIN CONTROLLERS GROUP@SYSCO.LOCAL", {}),
    ("GREG.SHIELDS@SYSCO.LOCAL", "MemberOf", "GROUP POLICY CREATOR OWNERS@SYSCO.LOCAL", {}),
    ("LAINEY.MOORE@SYSCO.LOCAL", "MemberOf", "GROUP POLICY CREATOR OWNERS@SYSCO.LOCAL", {}),
    ("GROUP POLICY CREATOR OWNERS@SYSCO.LOCAL", "WriteOwner",
     "DEFAULT DOMAIN POLICY@SYSCO.LOCAL", {}),
    ("JACK.DOWLAND@SYSCO.LOCAL", "GenericWrite", "ORPHAN POLICY@SYSCO.LOCAL", {}),
]

CONTROL = {"Owns", "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
           "AllExtendedRights"}


def _out(src, etype):
    return [(d, pr) for (s, t, d, pr) in EDGES if s == src and t == etype]


def _contains_paths(root):
    """Every (chain) reachable via Contains*0..10, chain[0] == root."""
    out, stack = [], [[root]]
    while stack:
        chain = stack.pop()
        out.append(chain)
        if len(chain) > 10:
            continue
        for dst, _ in _out(chain[-1], "Contains"):
            if dst not in chain:
                stack.append(chain + [dst])
    return out


def _members_of(group):
    """Transitive MemberOf*1..5 inbound, User/Computer only."""
    found, frontier = set(), {group}
    for _ in range(5):
        nxt = set()
        for (s, t, d, _p) in EDGES:
            if t == "MemberOf" and d in frontier:
                nxt.add(s)
        frontier = nxt - found
        found |= nxt
        if not frontier:
            break
    return [n for n in found
            if set(NODES[n]["labels"]) & {"User", "Computer"}]


def _is_dc(name):
    for _ in range(1):
        for (s, t, d, _p) in EDGES:
            if t == "MemberOf" and s == name:
                if str(NODES.get(d, {}).get("objectid", "")).endswith("-516"):
                    return True
    return False


class FakeClient:
    """Stands in for Neo4jClient. Only .read() is used by the GPO paths."""
    calls: list = []

    def read(self, query, **params):
        FakeClient.calls.append(query)
        if "Q_GPO_CONTROLLERS" in query or "-[r:Owns|GenericAll" in query:
            return self._controllers(params.get("name"))
        if "MATCH (g:GPO) WHERE toUpper(g.name) = $name" in query:
            return self._scope(params.get("name"))
        raise AssertionError("unexpected query: " + query[:80])

    @staticmethod
    def _gpo_matches(node, name):
        return (node.upper() == name
                or str(NODES.get(node, {}).get("objectid", "")).upper() == name)

    def _controllers(self, name):
        rows = []
        for (s, t, d, _p) in EDGES:
            if t not in CONTROL or "GPO" not in NODES[d]["labels"]:
                continue
            if name is not None and not self._gpo_matches(d, name):
                continue
            members = [{"name": m, "owned": bool(NODES[m].get("owned"))}
                       for m in _members_of(s)] or [{"name": None, "owned": False}]
            rows.append({
                "gpo": d, "principal": s, "principal_labels": NODES[s]["labels"],
                "edge": t, "owned": bool(NODES[s].get("owned")), "members": members,
            })
        return sorted(rows, key=lambda r: (r["gpo"], r["principal"]))

    def _scope(self, name):
        rows = []
        for (s, t, d, pr) in EDGES:
            if t != "GPLink" or not self._gpo_matches(s, name):
                continue
            for chain in _contains_paths(d):
                tail = chain[-1]
                labels = NODES[tail]["labels"]
                is_target = bool(set(labels) & {"User", "Computer"})
                rows.append({
                    "gpo": s, "scope_name": d, "scope_labels": NODES[d]["labels"],
                    "enforced": bool(pr.get("enforced")),
                    "target_name": tail if is_target else None,
                    "target_labels": labels if is_target else [],
                    "is_dc": _is_dc(tail) if is_target else False,
                    "chain": chain,
                    "blocks": [bool(NODES[n].get("blocksinheritance")) for n in chain],
                })
        return rows

    def close(self):
        pass
