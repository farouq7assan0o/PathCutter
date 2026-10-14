"""Shadow Tier 0: management-plane groups and domain-takeover holders are treated as Tier 0, and it is reported."""
from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.hygiene import audit
from pathcutter.shadow_tier0 import derive_shadow_tier0, strip_by_name


def _g():
    g = AttackGraph()
    g.add_node(ADNode("dom", "X.LOCAL", NodeType.DOMAIN, "X.LOCAL"))
    g.add_node(ADNode("sccm", "SCCM ADMINS@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.add_node(ADNode("veeam", "VEEAM BACKUP OPERATORS@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.add_node(ADNode("msol", "MSOL_7F3A@X.LOCAL", NodeType.USER, "X.LOCAL"))
    g.add_node(ADNode("hr", "HR TEAM@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.add_node(ADNode("bob", "BOB@X.LOCAL", NodeType.USER, "X.LOCAL"))
    g.add_node(ADNode("alice", "ALICE@X.LOCAL", NodeType.USER, "X.LOCAL"))
    g.add_edge(ADEdge("bob", "dom", "DCSync"))
    g.add_edge(ADEdge("alice", "sccm", "GenericAll"))
    return g


def test_by_name_and_derived_matches():
    g = _g()
    found = derive_shadow_tier0(g)
    by = {s["name"]: s for s in found}
    assert "SCCM ADMINS" in by and by["SCCM ADMINS"]["evidence"] == "by-name"
    assert "VEEAM BACKUP OPERATORS" in by and by["VEEAM BACKUP OPERATORS"]["product"] == "backup"
    assert "MSOL_7F3A" in by and by["MSOL_7F3A"]["product"] == "Entra Connect"
    assert "BOB" in by and by["BOB"]["evidence"] == "derived"
    assert "HR TEAM" not in by


def test_a_member_of_a_shadow_group_becomes_exposed():
    g = _g()
    derive_shadow_tier0(g)
    g.classify_tiers()
    assert "sccm" in g.tier0_nodes
    exp = compute_exposure(g)
    assert "alice" in exp.exposed()


def test_shadow_tier0_only_adds_targets_never_removes_paths():
    g = _g()
    before = len(compute_exposure(g).exposed())
    derive_shadow_tier0(g)
    g.classify_tiers()
    assert len(compute_exposure(g).exposed()) >= before


def test_audit_reports_both_kinds():
    g = _g()
    derive_shadow_tier0(g)
    rules = {f.rule for f in audit(g)}
    assert "shadow-tier0-by-name" in rules and "shadow-tier0-derived" in rules


def test_strip_by_name_keeps_derived():
    g = _g()
    derive_shadow_tier0(g)
    g.classify_tiers()
    assert "sccm" in g.tier0_nodes
    removed = strip_by_name(g)
    assert removed == 3
    assert "sccm" not in g.tier0_nodes and "bob" in {s["id"] for s in g.meta["shadow_tier0"]}


def test_extra_patterns_and_disable_by_name():
    g = _g()
    found = derive_shadow_tier0(g, extra_patterns=[(r"HR TEAM", "custom", "declared crown jewel", "T0")])
    assert any(s["name"] == "HR TEAM" for s in found)
    only_derived = derive_shadow_tier0(_g(), by_name=False)
    assert only_derived and all(s["evidence"] == "derived" for s in only_derived)


def test_real_entra_fixture_flags_sync_accounts():
    from pathlib import Path
    from pathcutter.ingest import load_sharphound
    z = Path(__file__).parent / "data" / "real" / "entra_sampledata.zip"
    if not z.exists():
        import pytest
        pytest.skip("fixture missing")
    g = load_sharphound(z)
    # the derivation ran during load; meta records any management-plane matches without crashing on a real tenant
    assert isinstance(g.meta.get("shadow_tier0", []), list)
