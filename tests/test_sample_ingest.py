"""Integration tests using GOAD lab sample exports (BloodHound.py CE format).

Source: m4lwhere/Bloodhound-CE-Sample-Data (MIT license)
Three domains from the GOAD lab: NORTH, ESSOS, SEVENKINGDOMS
"""
import pytest
from pathlib import Path

from pathcutter.graph import NodeType
from pathcutter.ingest import load_sharphound

EXPORTS = Path(__file__).parent / "data" / "sample-exports"
ZIPS = sorted(EXPORTS.glob("ce_branch_*.zip"))


@pytest.fixture(params=ZIPS, ids=[z.stem.split("_")[3] for z in ZIPS])
def goad_graph(request):
    return load_sharphound(request.param)


def test_ingest_produces_nodes(goad_graph):
    nodes = list(goad_graph.all_nodes())
    assert len(nodes) >= 50, f"Expected 50+ nodes, got {len(nodes)}"


def test_ingest_produces_edges(goad_graph):
    edges = list(goad_graph.all_edges())
    assert len(edges) >= 100, f"Expected 100+ edges, got {len(edges)}"


def test_has_domain_node(goad_graph):
    domains = list(goad_graph.nodes_by_type(NodeType.DOMAIN))
    assert len(domains) >= 1


def test_has_users_and_computers(goad_graph):
    users = list(goad_graph.nodes_by_type(NodeType.USER))
    computers = list(goad_graph.nodes_by_type(NodeType.COMPUTER))
    assert len(users) >= 1, "Should have at least one user"
    assert len(computers) >= 1, "Should have at least one computer"


def test_has_group_memberships(goad_graph):
    member_edges = [(s, t) for s, t, d in goad_graph.all_edges()
                    if d.get("edge_type") == "MemberOf"]
    assert len(member_edges) >= 20, "Should have group membership edges"


def test_tier_classification_runs(goad_graph):
    goad_graph.classify_tiers()


def test_exposure_computes(goad_graph):
    from pathcutter.exposure import compute_exposure
    goad_graph.classify_tiers()
    exp = compute_exposure(goad_graph)
    assert isinstance(exp.exposed(), (set, frozenset, list))
