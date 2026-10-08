"""Tests for attack graph construction."""
from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType


def test_add_nodes_and_edges(tiny_graph):
    assert tiny_graph.node_count == 10
    assert tiny_graph.edge_count > 0


def test_tier0_detected(tiny_graph):
    """Domain Admins group and its members should be Tier 0."""
    da_id = "S-1-5-21-1234-512"
    assert da_id in tiny_graph.tier0_nodes
    # svc_backup is MemberOf Domain Admins -> should be Tier 0
    svc_id = "S-1-5-21-1234-1003"
    assert svc_id in tiny_graph.tier0_nodes


def test_tier0_by_sid(tiny_graph):
    """Domain Admins SID ends in -512, should be auto-classified."""
    node = tiny_graph.get_node("S-1-5-21-1234-512")
    assert node is not None
    assert node.tier == 0


def test_regular_user_is_tier2(tiny_graph):
    node = tiny_graph.get_node("S-1-5-21-1234-1001")
    assert node is not None
    assert node.tier == 2


def test_successors(tiny_graph):
    # jsmith should have successors: HelpDesk (MemberOf), WS01 (HasSession)
    succs = tiny_graph.successors("S-1-5-21-1234-1001")
    assert "S-1-5-21-1234-1100" in succs  # HelpDesk
    assert "S-1-5-21-1234-2001" in succs  # WS01


def test_predecessors(tiny_graph):
    # HelpDesk should have predecessor: jsmith
    preds = tiny_graph.predecessors("S-1-5-21-1234-1100")
    assert "S-1-5-21-1234-1001" in preds


def test_transitive_group_membership(nested_groups):
    """user1 -> G1 -> G2 -> G3 -> G4 -> G5, should be member of all."""
    groups = nested_groups.transitive_group_memberships("S-user1")
    assert "S-g1" in groups
    assert "S-g2" in groups
    assert "S-g3" in groups
    assert "S-g4" in groups
    assert "S-g5" in groups
    assert len(groups) == 5


def test_transitive_no_self(nested_groups):
    """Node should not appear in its own transitive memberships."""
    groups = nested_groups.transitive_group_memberships("S-user1")
    assert "S-user1" not in groups


def test_out_edges(tiny_graph):
    edges = tiny_graph.out_edges("S-1-5-21-1234-1100")  # HelpDesk
    edge_types = [d["edge_type"] for _, _, d in edges]
    assert "GenericAll" in edge_types
    assert "ForceChangePassword" in edge_types


def test_summary(tiny_graph):
    s = tiny_graph.summary()
    assert s["total_nodes"] == 10
    assert s["total_edges"] > 0
    assert "User" in s["node_types"]
    assert "Group" in s["node_types"]
    assert s["tier_0_count"] > 0


def test_subgraph(tiny_graph):
    ids = {"S-1-5-21-1234-1001", "S-1-5-21-1234-1100", "S-1-5-21-1234-1003"}
    sub = tiny_graph.subgraph(ids)
    assert sub.node_count == 3
    # jsmith -> HelpDesk edge should be preserved
    assert "S-1-5-21-1234-1100" in sub.successors("S-1-5-21-1234-1001")


def test_get_node_name(tiny_graph):
    assert tiny_graph.get_node_name("S-1-5-21-1234-1001") == "jsmith@corp.local"
    assert tiny_graph.get_node_name("nonexistent") == "nonexistent"


def test_delegation_edges(delegation_graph):
    """Delegation edges should be in the graph."""
    edges = delegation_graph.out_edges("S-1-5-21-9999-1001")  # web_svc
    edge_types = [d["edge_type"] for _, _, d in edges]
    assert "AllowedToDelegate" in edge_types


def test_circular_group_membership():
    """AD allows circular group membership - transitive expansion must not infinite loop."""
    g = AttackGraph()
    g.add_node(ADNode("S-a", "GroupA@CORP.LOCAL", NodeType.GROUP))
    g.add_node(ADNode("S-b", "GroupB@CORP.LOCAL", NodeType.GROUP))
    g.add_node(ADNode("S-c", "GroupC@CORP.LOCAL", NodeType.GROUP))
    g.add_node(ADNode("S-u", "user@corp.local", NodeType.USER))

    # Circular: A -> B -> C -> A
    g.add_edge(ADEdge("S-a", "S-b", "MemberOf"))
    g.add_edge(ADEdge("S-b", "S-c", "MemberOf"))
    g.add_edge(ADEdge("S-c", "S-a", "MemberOf"))
    g.add_edge(ADEdge("S-u", "S-a", "MemberOf"))

    # Should not hang, should return all groups
    groups = g.transitive_group_memberships("S-u")
    assert "S-a" in groups
    assert "S-b" in groups
    assert "S-c" in groups


def test_effective_permissions(tiny_graph):
    """jsmith via HelpDesk should have GenericAll on svc_backup."""
    perms = tiny_graph.effective_permissions("S-1-5-21-1234-1001")
    # svc_backup should be reachable through HelpDesk
    svc_id = "S-1-5-21-1234-1003"
    assert svc_id in perms
    perm_strs = perms[svc_id]
    assert any("GenericAll" in p for p in perm_strs)
