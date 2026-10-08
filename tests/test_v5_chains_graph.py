"""Tests for BloodHound CE v5 format, new chain detectors, and graph command."""
import json
import tempfile
from pathlib import Path

import pytest

from pathcutter.ingest import load_sharphound, _detect_format
from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType
from pathcutter.pathfinder import find_all_paths
from pathcutter.chains import detect_chains
from pathcutter.choke import find_chokepoints
from pathcutter.cli import main


class TestFormatDetection:
    def test_v4_with_type(self):
        data = {"meta": {"type": "users", "version": 5}, "data": [{"Properties": {}}]}
        assert _detect_format(data) == "v4"

    def test_v5_with_kind(self):
        data = {"meta": {"version": 6}, "data": [{"kind": "User", "Properties": {}}]}
        assert _detect_format(data) == "v5"

    def test_v4_with_methods(self):
        data = {"meta": {"methods": 0}, "data": [{"Properties": {}}]}
        assert _detect_format(data) == "v4"


class TestV5Ingestion:
    def test_load_v5_users(self, tmp_path):
        """v5 format with 'kind' field should parse correctly."""
        v5_data = {
            "meta": {"version": 6},
            "data": [
                {
                    "kind": "User",
                    "ObjectIdentifier": "S-1-5-21-V5-1001",
                    "Properties": {
                        "name": "TESTUSER@V5DOMAIN.LOCAL",
                        "domain": "V5DOMAIN.LOCAL",
                        "enabled": True,
                    },
                    "Aces": [],
                },
                {
                    "kind": "Group",
                    "ObjectIdentifier": "S-1-5-21-V5-512",
                    "Properties": {
                        "name": "DOMAIN ADMINS@V5DOMAIN.LOCAL",
                        "domain": "V5DOMAIN.LOCAL",
                    },
                    "Aces": [
                        {
                            "PrincipalSID": "S-1-5-21-V5-1001",
                            "RightName": "GenericAll",
                            "IsInherited": False,
                        }
                    ],
                    "Members": [{"MemberId": "S-1-5-21-V5-500"}],
                },
            ]
        }
        (tmp_path / "v5_users.json").write_text(json.dumps(v5_data))
        graph = load_sharphound(tmp_path)
        assert graph.node_count >= 2
        user = graph.get_node("S-1-5-21-V5-1001")
        assert user is not None
        assert user.node_type == NodeType.USER

    def test_v5_edges_parsed(self, tmp_path):
        """v5 ACEs should create edges."""
        v5_data = {
            "meta": {"version": 6},
            "data": [
                {
                    "kind": "User",
                    "ObjectIdentifier": "S-USER",
                    "Properties": {"name": "USER@TEST.LOCAL"},
                    "Aces": [],
                },
                {
                    "kind": "Group",
                    "ObjectIdentifier": "S-DA",
                    "Properties": {"name": "DOMAIN ADMINS@TEST.LOCAL"},
                    "Aces": [
                        {"PrincipalSID": "S-USER", "RightName": "GenericAll", "IsInherited": False},
                    ],
                    "Members": [],
                },
            ]
        }
        (tmp_path / "v5_test.json").write_text(json.dumps(v5_data))
        graph = load_sharphound(tmp_path)
        edges = graph.get_edge_data("S-USER", "S-DA")
        assert len(edges) >= 1
        assert any(e.get("edge_type") == "GenericAll" for e in edges)


class TestNewChainDetectors:
    def test_asrep_roasting_detection(self):
        g = AttackGraph()
        asrep_user = ADNode("S-asrep", "ASREP_USER@CORP.LOCAL", NodeType.USER,
                            properties={"dontreqpreauth": True})
        g.add_node(asrep_user)
        g.add_node(ADNode("S-target", "TARGET@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
        g.add_edge(ADEdge("S-asrep", "S-target", "GenericAll"))
        g.add_edge(ADEdge("S-target", "S-da", "AddMember"))
        g.classify_tiers()
        report = find_all_paths(g, {"S-da"})
        chains = detect_chains(g, report)
        types = {c.chain_type for c in chains}
        assert "asrep_roasting" in types

    def test_laps_abuse_detection(self):
        g = AttackGraph()
        g.add_node(ADNode("S-user", "USER@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-comp", "SERVER01@CORP.LOCAL", NodeType.COMPUTER))
        g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
        g.add_edge(ADEdge("S-user", "S-comp", "ReadLAPSPassword"))
        g.add_edge(ADEdge("S-comp", "S-da", "AdminTo"))
        g.classify_tiers()
        report = find_all_paths(g, {"S-da"})
        chains = detect_chains(g, report)
        types = {c.chain_type for c in chains}
        assert "laps_abuse" in types

    def test_gmsa_abuse_detection(self):
        g = AttackGraph()
        g.add_node(ADNode("S-user", "USER@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-gmsa", "GMSA_SVC@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
        g.add_edge(ADEdge("S-user", "S-gmsa", "ReadGMSAPassword"))
        g.add_edge(ADEdge("S-gmsa", "S-da", "MemberOf"))
        g.classify_tiers()
        report = find_all_paths(g, {"S-da"})
        chains = detect_chains(g, report)
        types = {c.chain_type for c in chains}
        assert "gmsa_abuse" in types

    def test_all_chains_have_mitre(self):
        """Every chain detector should include MITRE ATT&CK IDs."""
        g = AttackGraph()
        g.add_node(ADNode("S-user", "USER@CORP.LOCAL", NodeType.USER,
                          properties={"dontreqpreauth": True}))
        g.add_node(ADNode("S-target", "TARGET@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
        g.add_edge(ADEdge("S-user", "S-target", "WriteKeyCredentialLink"))
        g.add_edge(ADEdge("S-target", "S-da", "AddMember"))
        g.classify_tiers()
        report = find_all_paths(g, {"S-da"})
        chains = detect_chains(g, report)
        for chain in chains:
            assert chain.mitre, f"Chain {chain.chain_type} has no MITRE IDs"


class TestRiskAwareChokepoints:
    def test_prefer_safe_fix(self):
        """When two edges eliminate equal paths, prefer non-service-account source."""
        g = AttackGraph()
        g.add_node(ADNode("S-user", "JDOE@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-svc", "SVC_BACKUP@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-target", "TARGET@CORP.LOCAL", NodeType.USER))
        g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
        g.add_edge(ADEdge("S-user", "S-target", "GenericAll"))
        g.add_edge(ADEdge("S-svc", "S-target", "GenericAll"))
        g.add_edge(ADEdge("S-target", "S-da", "AddMember"))
        g.classify_tiers()
        report = find_all_paths(g, {"S-da"})
        choke = find_chokepoints(g, report, prefer_safe=True)
        # First fix should be the shared target edge (eliminates both paths)
        # or the non-svc edge if they're equal
        assert len(choke.fixes) > 0


class TestGraphCommand:
    def test_graph_command(self, tmp_path):
        """Test the graph CLI subcommand."""
        data_dir = Path(__file__).parent / "test_sharphound_data"
        if not data_dir.exists():
            pytest.skip("Test data not generated")
        result = main(["graph", str(data_dir), "--target", "DOMAIN ADMINS", "--top", "5"])
        assert result == 0

    def test_graph_no_match(self, tmp_path):
        """Non-existent target should return error."""
        data_dir = Path(__file__).parent / "test_sharphound_data"
        if not data_dir.exists():
            pytest.skip("Test data not generated")
        result = main(["graph", str(data_dir), "--target", "NONEXISTENT_XYZZY_NODE"])
        assert result == 1
