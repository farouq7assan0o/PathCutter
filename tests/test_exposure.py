"""Exact reachability to Tier 0 (exposure.py)."""
from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge


def test_only_the_helpdesk_group_is_exposed(corp):
    exp = compute_exposure(corp)
    assert exp.exposed() == {"g-help"}
    assert exp.hops("g-help") == 1


def test_tier0_objects_are_never_exposed(corp):
    exp = compute_exposure(corp)
    assert not (exp.exposed() & corp.tier0_nodes)
    assert "u-svc" in corp.tier0_nodes


def test_membership_only_route_is_not_an_attack_path(corp):
    # alice -> TEAM has no attack edge anywhere, so she is not exposed
    corp.add_edge(ADEdge("u-alice", "g-team", "MemberOf"))
    assert "u-alice" not in compute_exposure(corp).exposed()


def test_membership_in_exposed_group_exposes_the_member(corp):
    corp.add_edge(ADEdge("u-alice", "g-help", "MemberOf"))
    exp = compute_exposure(corp)
    assert "u-alice" in exp.exposed()
    assert exp.hops("u-alice") == 2


def test_path_reconstruction_lists_every_hop(corp):
    corp.add_edge(ADEdge("u-alice", "g-help", "MemberOf"))
    steps = compute_exposure(corp).path("u-alice")
    assert [(s.node_id, s.edge_type) for s in steps] == [
        ("u-alice", "MemberOf"), ("g-help", "GenericAll"), ("u-svc", None)]


def test_path_of_unexposed_node_is_empty(corp):
    assert compute_exposure(corp).path("u-dave") == []


def test_shortest_attack_path_wins(corp):
    corp.add_edge(ADEdge("u-alice", "g-team", "MemberOf"))
    corp.add_edge(ADEdge("g-team", "g-help", "MemberOf"))
    corp.add_edge(ADEdge("u-alice", "u-svc", "ForceChangePassword"))   # direct, 1 hop
    exp = compute_exposure(corp)
    assert exp.hops("u-alice") == 1


def test_path_with_attack_edge_is_found_even_if_membership_route_is_shorter(corp):
    # alice -MemberOf-> TEAM (no attack) and alice -AdminTo-> SRV; SRV -GenericAll-> DA
    corp.add_edge(ADEdge("u-alice", "g-team", "MemberOf"))
    corp.add_edge(ADEdge("u-alice", "c-srv01", "AdminTo"))
    corp.add_edge(ADEdge("c-srv01", "g-da", "GenericAll"))
    exp = compute_exposure(corp)
    assert exp.hops("u-alice") == 2 and "c-srv01" in exp.exposed()


def test_graph_without_tier0_has_no_exposure():
    from pathcutter.graph import AttackGraph, ADNode, NodeType
    g = AttackGraph()
    g.add_node(ADNode("a", "a@x", NodeType.USER))
    g.add_node(ADNode("b", "b@x", NodeType.GROUP))
    g.add_edge(ADEdge("a", "b", "GenericAll"))
    assert compute_exposure(g).exposed() == set()
