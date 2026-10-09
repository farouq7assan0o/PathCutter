"""Graph primitives the change gate relies on: clone, remove_edge, retier."""
from pathcutter.graph import ADEdge


def _tiers(g):
    return {n.object_id: n.tier for n in g.all_nodes()}


def test_clone_is_independent(corp):
    c = corp.clone()
    c.add_edge(ADEdge("u-alice", "g-help", "MemberOf"))
    c.get_node("u-alice").tier = 0
    assert not corp.has_edge_type("u-alice", "g-help", "MemberOf")
    assert corp.get_node("u-alice").tier == 2
    assert c.node_count == corp.node_count


def test_clone_preserves_edges_and_tiers(corp):
    c = corp.clone()
    assert sorted((u, v, d["edge_type"]) for u, v, d in c.all_edges()) == \
        sorted((u, v, d["edge_type"]) for u, v, d in corp.all_edges())
    assert _tiers(c) == _tiers(corp)
    assert c.tier0_nodes == corp.tier0_nodes


def test_retier_reproduces_ingest_classification(corp):
    before = _tiers(corp)
    t0 = set(corp.tier0_nodes)
    corp.retier()
    assert _tiers(corp) == before
    assert corp.tier0_nodes == t0


def test_retier_demotes_after_membership_removed(corp):
    assert corp.get_node("u-svc").tier == 0
    assert corp.remove_edge("u-svc", "g-da", "MemberOf") == 1
    # classify_tiers alone would leave the stale Tier 0; retier fixes it
    corp.retier()
    assert corp.get_node("u-svc").tier == 2
    assert "u-svc" not in corp.tier0_nodes


def test_retier_promotes_new_member(corp):
    corp.add_edge(ADEdge("u-alice", "g-da", "MemberOf"))
    corp.retier()
    assert corp.get_node("u-alice").tier == 0


def test_retier_honours_extra_tier0(corp):
    corp.retier(extra_tier0={"c-srv01"})
    assert corp.get_node("c-srv01").tier == 0
    assert "c-srv01" in corp.tier0_nodes


def test_remove_edge_only_removes_that_type(corp):
    corp.add_edge(ADEdge("g-help", "u-svc", "WriteSPN"))
    assert corp.remove_edge("g-help", "u-svc", "GenericAll") == 1
    assert corp.has_edge_type("g-help", "u-svc", "WriteSPN")
    assert not corp.has_edge_type("g-help", "u-svc", "GenericAll")
    assert corp.remove_edge("g-help", "u-svc", "GenericAll") == 0


def test_remove_memberof_updates_group_members(corp):
    corp.remove_edge("u-bob", "g-it", "MemberOf")
    assert "u-bob" not in corp._group_members.get("g-it", set())
