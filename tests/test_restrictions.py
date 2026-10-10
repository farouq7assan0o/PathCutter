"""Restrictions: Protected Users / sensitive accounts make delegation edges unusable, and it is reported, not silent."""
from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.hygiene import audit
from pathcutter.restrictions import apply_restrictions, protected_accounts
from pathcutter.snapshot import load_snapshot, save_snapshot


def _g(protect_admin=True, sensitive_flag=False, unconstrained=False):
    g = AttackGraph()
    g.add_node(ADNode("DA", "DA@C.L", NodeType.GROUP))
    g.add_node(ADNode("PU", "PROTECTED USERS@C.L", NodeType.GROUP))
    g.add_node(ADNode("admin", "ADMIN@C.L", NodeType.USER, properties={"sensitive": True} if sensitive_flag else {}))
    g.add_node(ADNode("web", "WEB.C.L", NodeType.COMPUTER, properties={"unconstraineddelegation": True} if unconstrained else {}))
    g.add_node(ADNode("srv", "SRV.C.L", NodeType.COMPUTER))
    g.add_edge(ADEdge("admin", "DA", "MemberOf"))
    g.add_edge(ADEdge("DA", "srv", "AdminTo"))
    g.add_edge(ADEdge("web", "srv", "AllowedToDelegate"))
    if protect_admin:
        g.add_edge(ADEdge("admin", "PU", "MemberOf"))
    return g


def test_edge_removed_when_every_admin_is_protected():
    g = _g()
    assert "admin" in protected_accounts(g)
    apply_restrictions(g)
    assert not g.has_edge_type("web", "srv", "AllowedToDelegate")
    assert g.meta["restrictions"][0]["count"] == 1


def test_sensitive_flag_counts_as_protection():
    g = _g(protect_admin=False, sensitive_flag=True)
    apply_restrictions(g)
    assert not g.has_edge_type("web", "srv", "AllowedToDelegate")


def test_one_unprotected_admin_keeps_the_edge():
    g = _g()
    g.add_node(ADNode("bob", "BOB@C.L", NodeType.USER))
    g.add_edge(ADEdge("bob", "srv", "AdminTo"))
    apply_restrictions(g)
    assert g.has_edge_type("web", "srv", "AllowedToDelegate") and "restrictions" not in g.meta


def test_unconstrained_hosts_are_not_affected():
    g = _g(unconstrained=True)
    apply_restrictions(g)
    assert g.has_edge_type("web", "srv", "AllowedToDelegate")


def test_no_admins_known_keeps_the_edge():
    g = _g()
    g.remove_edge("DA", "srv", "AdminTo")
    apply_restrictions(g)
    assert g.has_edge_type("web", "srv", "AllowedToDelegate")


def test_harness_protect_admin_groups():
    """Validate BloodHound's ProtectAdminGroups harness models SDProp protection we recognize."""
    import json
    from pathlib import Path
    harness = json.loads((Path(__file__).parent / "data" / "harnesses" / "ProtectAdminGroupsHarness.json").read_text())
    nodes = {n["id"]: n for n in harness["nodes"]}
    rels = harness["relationships"]

    protect_rels = [r for r in rels if r["type"] == "ProtectAdminGroups"]
    assert len(protect_rels) >= 2, "Harness should have ProtectAdminGroups relationships"

    protected_targets = set()
    for r in protect_rels:
        target = nodes[r["toId"]]
        protected_targets.add(target["id"])
        assert target["properties"].get("adminsdholderprotected", "").upper() in ("TRUE", "BOOL:TRUE"), \
            f"Protected target {target['caption']} should have adminsdholderprotected=True"

    unprotected = [n for n in harness["nodes"]
                   if n["properties"].get("adminsdholderprotected", "").upper() in ("FALSE", "BOOL:FALSE")]
    assert len(unprotected) >= 1, "Harness should have at least one unprotected user"
    assert not any(u["id"] in protected_targets for u in unprotected), \
        "Unprotected users should not be ProtectAdminGroups targets"

    # The harness models cross-domain AdminSDHolder containers
    containers = [n for n in harness["nodes"] if "Container" in n.get("labels", [])]
    domain_sids = {n["properties"].get("domainsid") for n in containers}
    assert len(domain_sids) >= 2, "Harness should have AdminSDHolder containers in multiple domains"


def test_audit_and_snapshot_carry_it(tmp_path):
    g = _g()
    apply_restrictions(g)
    assert any(f.rule == "protected-users-neutralizes-delegation" for f in audit(g))
    save_snapshot(g, tmp_path / "s.pcsnap")
    g2, _ = load_snapshot(tmp_path / "s.pcsnap")
    assert g2.meta["restrictions"][0]["count"] == 1
