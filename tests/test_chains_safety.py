"""Tests for attack chain detection and fix safety analysis."""
from pathcutter.pathfinder import find_all_paths
from pathcutter.choke import find_chokepoints
from pathcutter.chains import detect_chains
from pathcutter.safety import assess_fixes, summarize_safety, RiskLevel
from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType


def test_detect_chains_returns_list(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    chains = detect_chains(tiny_graph, report)
    assert isinstance(chains, list)


def test_chains_sorted_by_severity(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    chains = detect_chains(tiny_graph, report)
    if len(chains) >= 2:
        severity_order = {"critical": 0, "high": 1, "medium": 2}
        for i in range(len(chains) - 1):
            assert severity_order.get(chains[i].severity, 3) <= severity_order.get(chains[i+1].severity, 3)


def test_shadow_credential_detection():
    """WriteKeyCredentialLink should trigger shadow credentials chain."""
    g = AttackGraph()
    g.add_node(ADNode("S-user1", "USER1@CORP.LOCAL", NodeType.USER))
    g.add_node(ADNode("S-target", "TARGET@CORP.LOCAL", NodeType.USER))
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    g.add_edge(ADEdge("S-user1", "S-target", "WriteKeyCredentialLink"))
    g.add_edge(ADEdge("S-target", "S-da", "MemberOf"))
    g.classify_tiers()
    report = find_all_paths(g, {"S-da"})
    chains = detect_chains(g, report)
    chain_types = [c.chain_type for c in chains]
    assert "shadow_credentials" in chain_types


def test_dcsync_detection():
    """DCSync edges should trigger dcsync chain."""
    g = AttackGraph()
    g.add_node(ADNode("S-user1", "USER1@CORP.LOCAL", NodeType.USER))
    g.add_node(ADNode("S-svc", "SVC_SYNC@CORP.LOCAL", NodeType.USER))
    g.add_node(ADNode("S-domain", "CORP.LOCAL", NodeType.DOMAIN))
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    g.add_edge(ADEdge("S-user1", "S-svc", "GenericAll"))
    g.add_edge(ADEdge("S-svc", "S-domain", "DCSync"))
    g.add_edge(ADEdge("S-svc", "S-da", "MemberOf"))
    g.classify_tiers()
    report = find_all_paths(g, {"S-da"})
    chains = detect_chains(g, report)
    chain_types = [c.chain_type for c in chains]
    assert "dcsync" in chain_types


def test_disabled_account_detection():
    """Disabled accounts in attack paths should be flagged."""
    g = AttackGraph()
    g.add_node(ADNode("S-user1", "USER1@CORP.LOCAL", NodeType.USER))
    disabled = ADNode("S-disabled", "OLD_ADMIN@CORP.LOCAL", NodeType.USER, enabled=False)
    g.add_node(disabled)
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    g.add_edge(ADEdge("S-user1", "S-disabled", "GenericAll"))
    g.add_edge(ADEdge("S-disabled", "S-da", "AddMember"))
    g.classify_tiers()
    report = find_all_paths(g, {"S-da"})
    chains = detect_chains(g, report)
    chain_types = [c.chain_type for c in chains]
    assert "disabled_account" in chain_types


# ---- Safety tests ----

def test_safety_assessment(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    assessments = assess_fixes(tiny_graph, choke.fixes)
    assert len(assessments) == len(choke.fixes)
    for a in assessments:
        assert a.risk_level in (RiskLevel.SAFE, RiskLevel.CAUTION, RiskLevel.DANGEROUS)


def test_service_account_flagged():
    """Fixes involving service accounts should be flagged as caution."""
    g = AttackGraph()
    g.add_node(ADNode("S-svc", "SVC_BACKUP@CORP.LOCAL", NodeType.USER))
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    g.add_edge(ADEdge("S-svc", "S-da", "GenericAll"))
    g.classify_tiers()
    report = find_all_paths(g, {"S-da"})
    choke = find_chokepoints(g, report)
    assessments = assess_fixes(g, choke.fixes)
    svc_assessments = [a for a in assessments if "SVC_" in a.fix.source_name.upper()]
    assert len(svc_assessments) > 0
    assert svc_assessments[0].risk_level in (RiskLevel.CAUTION, RiskLevel.DANGEROUS)


def test_disabled_source_safe():
    """Fixes on disabled source accounts should be safe."""
    g = AttackGraph()
    disabled = ADNode("S-disabled", "OLD_SVC@CORP.LOCAL", NodeType.USER, enabled=False)
    g.add_node(disabled)
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    g.add_edge(ADEdge("S-disabled", "S-da", "GenericAll"))
    g.classify_tiers()
    report = find_all_paths(g, {"S-da"})
    choke = find_chokepoints(g, report)
    assessments = assess_fixes(g, choke.fixes)
    assert len(assessments) > 0
    assert assessments[0].risk_level == RiskLevel.SAFE


def test_summarize_safety(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    assessments = assess_fixes(tiny_graph, choke.fixes)
    summary = summarize_safety(assessments)
    assert summary["total"] == len(choke.fixes)
    assert summary["safe"] + summary["caution"] + summary["dangerous"] == summary["total"]


def test_chain_has_remediation():
    """Every detected chain should have remediation advice."""
    g = AttackGraph()
    g.add_node(ADNode("S-user1", "USER1@CORP.LOCAL", NodeType.USER))
    g.add_node(ADNode("S-target", "TARGET@CORP.LOCAL", NodeType.USER))
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    g.add_edge(ADEdge("S-user1", "S-target", "WriteKeyCredentialLink"))
    g.add_edge(ADEdge("S-target", "S-da", "MemberOf"))
    g.classify_tiers()
    report = find_all_paths(g, {"S-da"})
    chains = detect_chains(g, report)
    for chain in chains:
        assert chain.remediation, f"Chain {chain.chain_type} has no remediation"
        assert len(chain.remediation) > 10
