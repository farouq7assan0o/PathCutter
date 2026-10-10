"""GPO user-rights assignments (SeBackupPrivilege and friends) from the SYSVOL sidecar."""
import json
import zipfile

from pathcutter.exposure import compute_exposure
from pathcutter.gpo_rights import capture, derive_gpo_privileges
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.ingest import load_sharphound

GUID = "AAAAAAAA-0000-0000-0000-000000000001"


def _g():
    g = AttackGraph()
    g.add_node(ADNode("dom", "X.LOCAL", NodeType.DOMAIN, "X.LOCAL"))
    g.add_node(ADNode("ou-dc", "DOMAIN CONTROLLERS@X.LOCAL", NodeType.OU, "X.LOCAL"))
    g.add_node(ADNode("ou-ws", "WORKSTATIONS@X.LOCAL", NodeType.OU, "X.LOCAL"))
    g.add_node(ADNode("dc1", "DC1.X.LOCAL", NodeType.COMPUTER, "X.LOCAL", properties={"isdc": True}))
    g.add_node(ADNode("ws1", "WS1.X.LOCAL", NodeType.COMPUTER, "X.LOCAL"))
    g.add_node(ADNode(GUID, "DC POLICY@X.LOCAL", NodeType.GPO, "X.LOCAL"))
    g.add_node(ADNode("u-alice", "ALICE@X.LOCAL", NodeType.USER, "X.LOCAL"))
    g.add_node(ADNode("S-1-5-21-1-2-3-516", "DOMAIN CONTROLLERS@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.add_edge(ADEdge("dc1", "S-1-5-21-1-2-3-516", "MemberOf"))
    g.add_node(ADNode("S-1-5-21-1-2-3-1500", "HELPDESK@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.add_edge(ADEdge("dom", "ou-dc", "Contains"))
    g.add_edge(ADEdge("dom", "ou-ws", "Contains"))
    g.add_edge(ADEdge("ou-dc", "dc1", "Contains"))
    g.add_edge(ADEdge("ou-ws", "ws1", "Contains"))
    g.add_edge(ADEdge(GUID, "ou-dc", "GPOControlsObject"))
    g.add_edge(ADEdge("u-alice", "S-1-5-21-1-2-3-1500", "MemberOf"))
    return g


def _rec(right="SeBackupPrivilege", who="S-1-5-21-1-2-3-1500"):
    return {"meta": {"type": "gporights", "version": 1}, "data": [{"GPO": "{" + GUID.lower() + "}", "Rights": {right: [who]}}]}


def test_privilege_reaches_only_computers_the_gpo_applies_to():
    g = _g()
    capture(_rec(), g)
    assert derive_gpo_privileges(g) == 1
    assert g.has_edge_type("S-1-5-21-1-2-3-1500", "dc1", "GPOUserRight")
    assert not g.has_edge_type("S-1-5-21-1-2-3-1500", "ws1", "GPOUserRight")


def test_a_privilege_on_a_domain_controller_is_a_path_to_tier0():
    g = _g()
    capture(_rec(), g)
    derive_gpo_privileges(g)
    g.classify_tiers()
    exp = compute_exposure(g)
    assert "u-alice" in exp.exposed()


def test_harmless_rights_are_ignored():
    g = _g()
    capture(_rec(right="SeInteractiveLogonRight"), g)
    assert derive_gpo_privileges(g) == 0


def test_unknown_gpo_or_principal_adds_nothing():
    g = _g()
    capture(_rec(who="S-1-5-21-9-9-9-1234"), g)
    assert derive_gpo_privileges(g) == 0


def test_sidecar_loads_from_an_export(tmp_path):
    z = tmp_path / "e.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("1_domains.json", json.dumps({"meta": {"type": "domains", "version": 4}, "data": []}))
        zf.writestr("2_gporights.json", json.dumps(_rec()))
    g = load_sharphound(z)
    assert g.meta["gpo_rights"][0]["gpo"] == GUID
