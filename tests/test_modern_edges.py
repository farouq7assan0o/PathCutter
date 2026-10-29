"""Modern BloodHound CE edges (SharpHound v6/v7): ingested so current collections are not under-reported."""
from pathcutter.edges import NON_TRAVERSABLE, get_edge_type
from pathcutter.evidence import edge_confidence
from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.ingest import _parse_one_file
from pathcutter.pathfinder import _ATTACK_EDGES


def test_registry_and_traversability():
    for e in ("CoerceToTGT", "WriteOwnerLimitedRights", "OwnsLimitedRights", "SpoofSIDHistory", "AbuseTGTDelegation"):
        assert get_edge_type(e) is not None and e in _ATTACK_EDGES and e not in NON_TRAVERSABLE
    cft = get_edge_type("CrossForestTrust")
    assert cft is not None and cft.exploitability == 0
    assert "CrossForestTrust" in NON_TRAVERSABLE and "CrossForestTrust" not in _ATTACK_EDGES


def _v6(kinds):
    g = AttackGraph()
    g.add_node(ADNode("ud", "WS-UD@C.L", NodeType.COMPUTER, "C.L"))
    g.add_node(ADNode("dom", "C.L", NodeType.DOMAIN, "C.L"))
    g.add_node(ADNode("d2", "PARTNER.L", NodeType.DOMAIN, "PARTNER.L"))
    data = {"meta": {"type": "edges", "version": 6, "count": len(kinds)},
            "data": [{"kind": k, "SourceSID": s, "TargetSID": t} for k, s, t in kinds]}
    _parse_one_file(data, g, "edges")
    return g


def test_v6_edge_kinds_map_correctly():
    g = _v6([("CoerceToTGT", "ud", "dom"), ("SameForestTrust", "dom", "d2"),
             ("CrossForestTrust", "dom", "d2"), ("SpoofSIDHistory", "dom", "d2"),
             ("AbuseTGTDelegation", "dom", "d2")])
    edges = {(u, v, d.get("edge_type")) for u, v, d in g.all_edges()}
    assert ("ud", "dom", "CoerceToTGT") in edges
    assert ("dom", "d2", "TrustedBy") in edges              # SameForestTrust -> TrustedBy
    assert ("dom", "d2", "CrossForestTrust") in edges       # kept as the trust fact
    assert ("dom", "d2", "SpoofSIDHistory") in edges
    assert ("dom", "d2", "AbuseTGTDelegation") in edges


def test_coerce_to_tgt_creates_exposure_to_domain():
    g = _v6([("CoerceToTGT", "ud", "dom")])
    g.add_node(ADNode("joe", "JOE@C.L", NodeType.USER, "C.L"))
    g.add_edge(ADEdge("joe", "ud", "AdminTo"))              # an admin of the UD host reaches the domain
    g.classify_tiers()
    exposed = compute_exposure(g).exposed()
    assert "joe" in exposed and "ud" in exposed


def test_cross_forest_trust_alone_is_not_traversed():
    g = _v6([("CrossForestTrust", "dom", "d2")])
    g.add_node(ADNode("joe", "JOE@PARTNER.L", NodeType.USER, "PARTNER.L"))
    g.add_edge(ADEdge("joe", "d2", "GenericAll"))           # joe controls the OTHER domain
    g.classify_tiers()
    # joe can reach d2 (its own domain) but CrossForestTrust must NOT carry it onward to dom
    exposed = compute_exposure(g).exposed()
    # no traversable edge from d2 to dom exists (only the non-traversable CrossForestTrust), so joe does not reach dom via it
    assert all(get_edge_type(d.get("edge_type")) for _u, _v, d in g.all_edges())   # sanity: types resolve
    # the only path to dom would require crossing CrossForestTrust, which is non-traversable
    paths = [p for p in __import__("pathcutter.pathfinder", fromlist=["find_all_paths"]).find_all_paths(g, {"dom"}).paths]
    assert not any(p.source == "joe" for p in paths)


def test_owner_limited_rights_as_ace():
    # BloodHound CE emits these as ACEs on the target object
    g = AttackGraph()
    g.add_node(ADNode("grp", "HELPDESK@C.L", NodeType.GROUP, "C.L"))
    g.add_node(ADNode("da", "DOMAIN ADMINS@C.L", NodeType.GROUP, "C.L"))
    data = {"meta": {"type": "groups", "version": 4},
            "data": [{"ObjectIdentifier": "da", "Properties": {"name": "DOMAIN ADMINS@C.L"},
                      "Aces": [{"PrincipalSID": "grp", "RightName": "WriteOwnerLimitedRights", "IsInherited": False}]}]}
    _parse_one_file(data, g, "groups")
    assert any(d.get("edge_type") == "WriteOwnerLimitedRights" for _u, _v, d in g.all_edges())


def test_evidence_labels():
    assert edge_confidence("CoerceToTGT", {})[0] == "low"
    assert edge_confidence("SpoofSIDHistory", {}) == ("medium", "derived:trust",
                                                       "a cross-forest trust with SID filtering disabled (collected by SharpHound v7.4+)")
