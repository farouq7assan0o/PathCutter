"""Blocked GPO inheritance in the GPO-rights scope, and the recently-created-privileged-object finding."""
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.gpo_rights import _scope
from pathcutter.hygiene import audit


def _gpo_tree(enforced, block=True, link_to="dom"):
    g = AttackGraph()
    g.add_node(ADNode("gpo", "GPO1@C.L", NodeType.GPO, "C.L"))
    g.add_node(ADNode("dom", "C.L", NodeType.DOMAIN, "C.L"))
    g.add_node(ADNode("ou", "OU-BLOCK@C.L", NodeType.OU, "C.L", properties={"blocksinheritance": block}))
    g.add_node(ADNode("comp", "WS01@C.L", NodeType.COMPUTER, "C.L"))
    g.add_edge(ADEdge("gpo", link_to, "GPOControlsObject", properties={"enforced": enforced}))
    g.add_edge(ADEdge("dom", "ou", "Contains"))
    g.add_edge(ADEdge("ou", "comp", "Contains"))
    return g


def test_blocked_inheritance_stops_non_enforced_gpo():
    # GPO linked at the domain, not enforced, OU below blocks inheritance -> does not reach the computer
    assert _scope(_gpo_tree(enforced=False, block=True), "gpo") == set()


def test_enforced_link_pierces_the_block():
    assert _scope(_gpo_tree(enforced=True, block=True), "gpo") == {"comp"}


def test_no_block_reaches_the_computer():
    assert _scope(_gpo_tree(enforced=False, block=False), "gpo") == {"comp"}


def test_direct_link_to_blocking_ou_still_applies():
    # the block stops inheritance FROM ABOVE; a GPO linked directly to the blocking OU still applies below it
    assert _scope(_gpo_tree(enforced=False, block=True, link_to="ou"), "gpo") == {"comp"}


def test_recent_privileged_object_flagged():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@C.L", NodeType.GROUP, "C.L"))
    # ctx.now is the newest timestamp in the collection; give both accounts a recent pwdlastset so 'now' is set
    now = 1_760_000_000
    g.add_node(ADNode("new", "NEW-ADMIN@C.L", NodeType.USER, "C.L", admin_count=True,
                      properties={"pwdlastset": now, "whencreated": now - 5 * 86400}))        # 5 days old
    g.add_node(ADNode("old", "OLD-ADMIN@C.L", NodeType.USER, "C.L", admin_count=True,
                      properties={"pwdlastset": now, "whencreated": now - 400 * 86400}))       # ~1 year old
    g.add_node(ADNode("joe", "JOE@C.L", NodeType.USER, "C.L",
                      properties={"pwdlastset": now, "whencreated": now - 2 * 86400}))          # recent but not privileged
    g.classify_tiers()
    f = next((x for x in audit(g) if x.rule == "recent-privileged-object"), None)
    assert f and "NEW-ADMIN" in f.objects
    assert "OLD-ADMIN" not in f.objects and "JOE" not in f.objects
