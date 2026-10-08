"""Tests for edge type registry."""
from pathcutter.edges import (
    get_edge_type, exploitability_weight, is_tier0,
    GenericAll, DCSync, MemberOf, Contains, EDGE_REGISTRY,
)


def test_registry_populated():
    assert len(EDGE_REGISTRY) > 0
    assert "GenericAll" in EDGE_REGISTRY
    assert "DCSync" in EDGE_REGISTRY
    assert "MemberOf" in EDGE_REGISTRY


def test_get_edge_type():
    et = get_edge_type("GenericAll")
    assert et is not None
    assert et.name == "GenericAll"
    assert et.exploitability == 9
    assert et.mitre == "T1222.001"


def test_get_edge_type_unknown():
    assert get_edge_type("NonExistentEdge") is None


def test_exploitability_weight_high():
    # DCSync has exploitability 10 -> weight should be low (easy to exploit = preferred path)
    w = exploitability_weight("DCSync")
    assert w == 1.0  # 10/10


def test_exploitability_weight_low():
    # CanRDP has exploitability 5 -> weight 2.0
    w = exploitability_weight("CanRDP")
    assert w == 2.0  # 10/5


def test_exploitability_weight_nonexploitable():
    # MemberOf has exploitability 0 -> high weight (not directly exploitable)
    w = exploitability_weight("MemberOf")
    assert w == 100.0


def test_exploitability_weight_unknown():
    w = exploitability_weight("FakeEdge")
    assert w == 100.0


def test_is_tier0_domain_admins():
    assert is_tier0("Domain Admins") is True
    assert is_tier0("DOMAIN ADMINS") is True
    assert is_tier0("DOMAIN ADMINS@CORP.LOCAL") is True


def test_is_tier0_by_sid():
    assert is_tier0("SomeGroup", "S-1-5-21-123456-512") is True  # DA SID
    assert is_tier0("SomeGroup", "S-1-5-21-123456-519") is True  # EA SID
    assert is_tier0("SomeGroup", "S-1-5-21-123456-500") is True  # Administrator
    assert is_tier0("SomeGroup", "S-1-5-21-123456-502") is True  # KRBTGT


def test_is_tier0_regular_user():
    assert is_tier0("jsmith", "S-1-5-21-123456-1234") is False
    assert is_tier0("Regular Group", "S-1-5-21-123456-5555") is False


def test_fix_template_has_placeholders():
    et = get_edge_type("GenericAll")
    assert "{target_dn}" in et.fix_template
    assert "{source_name}" in et.fix_template


def test_all_edges_have_required_fields():
    for name, et in EDGE_REGISTRY.items():
        assert et.name, f"{name} missing name"
        assert et.category, f"{name} missing category"
        assert et.abuse, f"{name} missing abuse description"
        assert et.detection_difficulty in ("low", "medium", "high"), f"{name} bad detection_difficulty"
        assert 0 <= et.exploitability <= 10, f"{name} exploitability out of range"
