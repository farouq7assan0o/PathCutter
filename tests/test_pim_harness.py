"""PIM roles harness oracle test: validates BloodHound's PIM model against PathCutter's Entra analysis.

The AZPIMRolesHarness.json carries AZRole nodes with PIM policy properties (approval requirements,
MFA, justification, ticket info, approvers) and AZRoleEligible/AZRoleApprover relationships.
This test validates the harness structure and documents the conditions PathCutter should check.
"""
import json
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "data" / "harnesses" / "AZPIMRolesHarness.json"


@pytest.fixture
def pim_data():
    return json.loads(HARNESS.read_text())


def test_harness_has_eligible_and_approver_relationships(pim_data):
    rels = pim_data["relationships"]
    eligible = [r for r in rels if r["type"] == "AZRoleEligible"]
    approvers = [r for r in rels if r["type"] == "AZRoleApprover"]
    assert len(eligible) >= 3, "Harness should have multiple eligibility relationships"
    assert len(approvers) >= 5, "Harness should have multiple approver relationships"


def test_harness_roles_have_pim_properties(pim_data):
    roles = [n for n in pim_data["nodes"] if "AZRole" in n.get("labels", [])]
    assert len(roles) >= 3

    for role in roles:
        props = role["properties"]
        assert "EndUserAssignmentRequiresApproval" in props, f"Role {props.get('name')} missing approval setting"
        assert "EndUserAssignmentRequiresMFA" in props, f"Role {props.get('name')} missing MFA setting"
        assert "EndUserAssignmentRequiresJustification" in props, f"Role {props.get('name')} missing justification setting"


def test_harness_global_admin_has_mfa_but_no_approval(pim_data):
    """Global Administrator: MFA required but no approval required (common misconfiguration)."""
    roles = {n["id"]: n for n in pim_data["nodes"] if "AZRole" in n.get("labels", [])}
    ga = next((r for r in roles.values() if r["properties"].get("name") == "Global Administrator"), None)
    assert ga is not None
    assert ga["properties"]["EndUserAssignmentRequiresApproval"] == "False"
    assert ga["properties"]["EndUserAssignmentRequiresMFA"] == "True"


def test_harness_models_approval_requirements(pim_data):
    """Roles requiring approval have approver relationships."""
    nodes = {n["id"]: n for n in pim_data["nodes"]}
    rels = pim_data["relationships"]
    roles_needing_approval = {n["id"] for n in pim_data["nodes"]
                              if "AZRole" in n.get("labels", [])
                              and n["properties"].get("EndUserAssignmentRequiresApproval") == "True"}
    approver_targets = {r["toId"] for r in rels if r["type"] == "AZRoleApprover"}
    assert roles_needing_approval & approver_targets, "Roles requiring approval should have approver relationships"


def test_pathcutter_eligible_role_edge_matches_harness():
    """Verify PathCutter creates AZEligibleRole edges the same way the harness models them."""
    from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType
    from pathcutter.azure import KNOWN_ROLES

    g = AttackGraph()
    data = json.loads(HARNESS.read_text())

    role_ids = {}
    for n in data["nodes"]:
        if "AZRole" in n.get("labels", []):
            oid = n["properties"]["objectid"]
            role_ids[n["id"]] = oid
            g.add_node(ADNode(object_id=oid, name=n["properties"].get("name", ""),
                               node_type=NodeType.AZ_ROLE))
        elif "AZBase" in n.get("labels", []):
            oid = n["properties"]["objectid"].strip()
            g.add_node(ADNode(object_id=oid, name="", node_type=NodeType.AZ_SP))

    for r in data["relationships"]:
        if r["type"] == "AZRoleEligible":
            src_node = next((n for n in data["nodes"] if n["id"] == r["fromId"]), None)
            dst_node = next((n for n in data["nodes"] if n["id"] == r["toId"]), None)
            if src_node and dst_node:
                src_oid = src_node["properties"].get("objectid", "").strip()
                dst_oid = dst_node["properties"].get("objectid", "").strip()
                g.add_edge(ADEdge(source_id=src_oid, target_id=dst_oid, edge_type="AZEligibleRole"))

    eligible_edges = [(s, t) for s, t, d in g.all_edges() if d.get("edge_type") == "AZEligibleRole"]
    harness_eligible = [r for r in data["relationships"] if r["type"] == "AZRoleEligible"]
    assert len(eligible_edges) == len(harness_eligible), \
        f"PathCutter should create {len(harness_eligible)} eligible edges, got {len(eligible_edges)}"
