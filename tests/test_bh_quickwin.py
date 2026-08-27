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
