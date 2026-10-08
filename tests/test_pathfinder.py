"""Tests for path finding algorithms."""
from pathcutter.pathfinder import (
    find_all_paths, shortest_path, reachable_from, reachable_tier0,
    nodes_reaching_targets, shortest_paths_to_targets,
)


def test_find_paths_to_da(tiny_graph):
    """Should find paths from jsmith to Domain Admins through HelpDesk."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    assert report.total_paths > 0
    # jsmith should be a source
    assert any(p.source == "S-1-5-21-1234-1001" for p in report.paths)


def test_path_through_helpdesk(tiny_graph):
    """Path from jsmith should go through HelpDesk (the chokepoint)."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    helpdesk_id = "S-1-5-21-1234-1100"
    paths_via_helpdesk = report.paths_through_node(helpdesk_id)
    assert len(paths_via_helpdesk) > 0


def test_path_edge_types(tiny_graph):
    """Paths should contain real attack edge types."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    for path in report.paths:
        assert path.length > 0
        assert all(isinstance(e, dict) for e in path.edges)
        assert all("edge_type" in e for e in path.edges)


def test_path_has_attack_edge(tiny_graph):
    """Every reported path must include at least one attack edge (not just MemberOf)."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    attack_types = {"GenericAll", "GenericWrite", "ForceChangePassword", "WriteDacl",
                    "WriteOwner", "AddMember", "AdminTo", "DCSync", "AllowedToDelegate"}
    for path in report.paths:
        edge_types = set(path.edge_types)
        assert edge_types & attack_types, f"Path has no attack edges: {path.edge_types}"


def test_tier0_not_source(tiny_graph):
    """Tier 0 nodes should never be the source of an attack path."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    for path in report.paths:
        source_node = tiny_graph.get_node(path.source)
        assert source_node is None or source_node.tier != 0


def test_max_depth_limit(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    # max_depth=2 should return shorter paths than max_depth=20
    report_short = find_all_paths(tiny_graph, {da_id}, max_depth=2)
    report_long = find_all_paths(tiny_graph, {da_id}, max_depth=20)
    for path in report_short.paths:
        assert path.length <= 2
    assert report_long.total_paths >= report_short.total_paths


def test_max_paths_limit(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id}, max_paths=1)
    assert report.total_paths <= 1


def test_shortest_path(tiny_graph):
    """Shortest path from HelpDesk to svc_backup should be 1 hop (GenericAll)."""
    path = shortest_path(tiny_graph, "S-1-5-21-1234-1100", "S-1-5-21-1234-1003")
    assert path is not None
    assert path.length >= 1
    assert "GenericAll" in path.edge_types


def test_shortest_path_no_path(tiny_graph):
    """No path should exist from DC01 to jsmith (wrong direction)."""
    path = shortest_path(tiny_graph, "S-1-5-21-1234-2003", "S-1-5-21-1234-1001")
    assert path is None


def test_shortest_paths_to_targets(tiny_graph):
    targets = {"S-1-5-21-1234-512", "S-1-5-21-1234-2003"}  # DA + DC01
    paths = shortest_paths_to_targets(tiny_graph, "S-1-5-21-1234-1001", targets)
    # Should find at least one path to one of the targets
    assert len(paths) >= 1
    # Results should be sorted by weight
    for i in range(len(paths) - 1):
        assert paths[i].total_weight <= paths[i + 1].total_weight


def test_reachable_from(tiny_graph):
    """From jsmith, should be able to reach HelpDesk, svc_backup, bwayne, etc."""
    reachable = reachable_from(tiny_graph, "S-1-5-21-1234-1001")
    assert "S-1-5-21-1234-1100" in reachable  # HelpDesk
    assert "S-1-5-21-1234-1003" in reachable  # svc_backup (via HelpDesk->GenericAll)
    assert "S-1-5-21-1234-2001" in reachable  # WS01 (HasSession)


def test_reachable_tier0(tiny_graph):
    """jsmith should be able to reach Tier 0 (DA, svc_backup)."""
    t0 = reachable_tier0(tiny_graph, "S-1-5-21-1234-1001")
    assert len(t0) > 0
    assert "S-1-5-21-1234-512" in t0  # DA


def test_reachable_tier0_from_isolated():
    """Node with no edges should not reach Tier 0."""
    from pathcutter.graph import AttackGraph, ADNode, NodeType
    g = AttackGraph()
    g.add_node(ADNode("S-isolated", "isolated@corp.local", NodeType.USER))
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    t0 = reachable_tier0(g, "S-isolated")
    assert len(t0) == 0


def test_nodes_reaching_targets(tiny_graph):
    """Should find nodes that can reach DA."""
    da_id = "S-1-5-21-1234-512"
    reaching = nodes_reaching_targets(tiny_graph, {da_id})
    # svc_backup -> MemberOf -> DA, so svc_backup reaches DA
    assert "S-1-5-21-1234-1003" in reaching
    # HelpDesk -> GenericAll -> svc_backup -> MemberOf -> DA
    assert "S-1-5-21-1234-1100" in reaching


def test_nested_group_path(nested_groups):
    """Path through 5-level nested groups should be found."""
    da_id = "S-da"
    report = find_all_paths(nested_groups, {da_id}, max_depth=10)
    # user1 should have a path to DA through G1->G2->G3->G4->G5->GenericAll->DA
    user1_paths = [p for p in report.paths if p.source == "S-user1"]
    assert len(user1_paths) > 0
    path = user1_paths[0]
    assert "GenericAll" in path.edge_types


def test_path_report_stats(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    assert report.unique_sources > 0
    assert report.shortest_length > 0
    assert report.longest_length >= report.shortest_length
    assert report.avg_length > 0


def test_delegation_paths(delegation_graph):
    """Delegation edges should create paths to DC."""
    dc_id = "S-1-5-21-9999-2001"
    report = find_all_paths(delegation_graph, {dc_id})
    # web_svc -> AllowedToDelegate -> DC01
    web_paths = [p for p in report.paths if p.source == "S-1-5-21-9999-1001"]
    assert len(web_paths) > 0
    assert any("AllowedToDelegate" in p.edge_types for p in web_paths)
