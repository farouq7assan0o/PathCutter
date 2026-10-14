"""Assume-breach: from one compromised object, what Tier 0 is reachable and by which route."""
from pathcutter.breach import analyse_breach, resolve_principals
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType


def _g():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP, "CORP.LOCAL"))
    g.add_node(ADNode("bob", "BOB@CORP.LOCAL", NodeType.USER, "CORP.LOCAL"))
    g.add_node(ADNode("ws", "WS01@CORP.LOCAL", NodeType.COMPUTER, "CORP.LOCAL"))
    g.add_node(ADNode("svc", "SVC@CORP.LOCAL", NodeType.USER, "CORP.LOCAL"))
    g.add_node(ADNode("idle", "IDLE@CORP.LOCAL", NodeType.USER, "CORP.LOCAL"))
    # bob -> ws (AdminTo) -> svc (HasSession) -> da (GenericAll); and a direct loud bob -> da (WriteDacl)
    g.add_edge(ADEdge("bob", "ws", "AdminTo"))
    g.add_edge(ADEdge("ws", "svc", "HasSession"))
    g.add_edge(ADEdge("svc", "da", "GenericAll"))
    g.add_edge(ADEdge("bob", "da", "WriteDacl"))
    g.classify_tiers()
    return g


def test_reaches_tier0_and_picks_cheapest_route():
    g = _g()
    rep = analyse_breach(g, "BOB")
    assert len(rep.reachable_tier0) == 1
    it = rep.reachable_tier0[0]
    assert it["name"] == "DOMAIN ADMINS"
    # the 1-hop WriteDacl is cheaper than the 3-hop route
    assert it["cheapest"]["cost"]["steps"] == 1
    assert it["cheapest"]["route"][-1]["name"] == "DOMAIN ADMINS"


def test_isolated_object_reaches_nothing():
    g = _g()
    rep = analyse_breach(g, "IDLE")
    assert rep.reachable_tier0 == []
    assert rep.blast_nodes == 0


def test_blast_radius_counts_reachable_actors():
    g = _g()
    rep = analyse_breach(g, "BOB")
    # bob reaches ws, svc, da
    assert rep.blast_nodes == 3
    assert rep.blast_actors == 2       # ws (computer) and svc (user); da is a group


def test_unknown_object_is_reported_not_crashed():
    g = _g()
    rep = analyse_breach(g, "NOBODY")
    assert rep.start == [] and rep.candidates == []


def test_ambiguous_name_lists_candidates():
    g = _g()
    g.add_node(ADNode("bob2", "BOBBY@CORP.LOCAL", NodeType.USER, "CORP.LOCAL"))
    ids, cands = resolve_principals(g, "OB")   # substring of both BOB and BOBBY, exact of neither
    assert len(ids) == 2
    rep = analyse_breach(g, "OB")
    assert rep.start == [] and len(rep.candidates) == 2


def test_exact_name_wins_over_substring():
    g = _g()
    g.add_node(ADNode("bob2", "BOBBY@CORP.LOCAL", NodeType.USER, "CORP.LOCAL"))
    ids, _ = resolve_principals(g, "BOB@CORP.LOCAL")
    assert ids == ["bob"]


def test_downstream_tier0_is_separated():
    g = _g()
    # add a second Tier 0 group reachable only THROUGH domain admins
    g.add_node(ADNode("ea", "ENTERPRISE ADMINS@CORP.LOCAL", NodeType.GROUP, "CORP.LOCAL"))
    g.add_edge(ADEdge("da", "ea", "GenericAll"))
    g.classify_tiers()
    rep = analyse_breach(g, "BOB")
    direct = {it["name"] for it in rep.reachable_tier0}
    downstream = {it["name"] for it in rep.downstream_tier0}
    assert "DOMAIN ADMINS" in direct
    assert "ENTERPRISE ADMINS" in downstream        # only reachable past DOMAIN ADMINS


def test_object_that_is_itself_tier0_is_flagged():
    g = _g()
    rep = analyse_breach(g, "DOMAIN ADMINS")
    assert rep.already_tier0 and rep.already_tier0[0]["name"] == "DOMAIN ADMINS"
