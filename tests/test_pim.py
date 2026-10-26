"""PIM enforcement: AzureHound role-management-policy assignments turn an eligible-role edge from an assumption into a
verdict about what activation actually requires (MFA / approval / neither)."""
from pathcutter import azure, cost
from pathcutter.evidence import edge_confidence
from pathcutter.graph import AttackGraph

_ROLE = "62E90394-69F5-4237-9190-012177145E10"     # Global Administrator (a real template id)
_USER = "11111111-1111-1111-1111-111111111111"


def _enablement(mfa, justification=False):
    enabled = []
    if mfa:
        enabled.append("MultiFactorAuthentication")
    if justification:
        enabled.append("Justification")
    return {"id": "Enablement_EndUser_Assignment",
            "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
            "enabledRules": enabled, "target": {"caller": "EndUser", "level": "Assignment"}}


def _approval(required):
    return {"id": "Approval_EndUser_Assignment",
            "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule",
            "setting": {"isApprovalRequired": required}, "target": {"caller": "EndUser", "level": "Assignment"}}


def _graph(policy_rules=None):
    items = [
        {"kind": "AZRole", "data": {"id": _ROLE, "displayName": "Global Administrator"}},
        {"kind": "AZUser", "data": {"id": _USER, "userPrincipalName": "alice@contoso.com"}},
        {"kind": "AZRoleEligibilityScheduleInstance",
         "data": {"principalId": _USER, "roleDefinitionId": _ROLE, "directoryScopeId": "/"}},
    ]
    if policy_rules is not None:
        items.append({"kind": "AZRoleManagementPolicyAssignment",
                      "data": {"roleDefinitionId": _ROLE, "scopeType": "Directory",
                               "policy": {"rules": policy_rules}}})
    g = AttackGraph()
    azure.parse_azure_file({"data": items}, g)
    azure.finalize_azure(g)
    return g


def _eligible_edge(g):
    for _u, _v, d in g.all_edges():
        if d.get("edge_type") == "AZEligibleRole":
            return d
    raise AssertionError("no AZEligibleRole edge")


def test_no_policy_collected_stays_an_assumption():
    e = _eligible_edge(_graph(policy_rules=None))
    assert not e.get("pim_collected")
    lvl, src, _ = edge_confidence("AZEligibleRole", e)
    assert lvl == "low" and src == "assumption:pim-policy"
    assert cost.edge_cost("AZEligibleRole", e)["fragile"] is True


def test_approval_required_is_low_and_fragile():
    e = _eligible_edge(_graph([_enablement(mfa=True), _approval(required=True)]))
    assert e["pim_collected"] and e["pim_approval"] is True
    lvl, src, _ = edge_confidence("AZEligibleRole", e)
    assert lvl == "low" and src == "assumption:pim-approval"
    assert cost.edge_cost("AZEligibleRole", e)["fragile"] is True      # approval may be denied


def test_mfa_only_is_medium_and_not_fragile():
    e = _eligible_edge(_graph([_enablement(mfa=True), _approval(required=False)]))
    assert e["pim_mfa"] is True and e["pim_approval"] is False
    lvl, src, _ = edge_confidence("AZEligibleRole", e)
    assert lvl == "medium" and src == "derived:pim-policy"
    assert cost.edge_cost("AZEligibleRole", e)["fragile"] is False     # the holder can activate on their own


def test_no_mfa_no_approval_is_high_standing_assignment():
    e = _eligible_edge(_graph([_enablement(mfa=False), _approval(required=False)]))
    assert e["pim_mfa"] is False and e["pim_approval"] is False
    lvl, src, why = edge_confidence("AZEligibleRole", e)
    assert lvl == "high" and src == "derived:pim-policy" and "standing" in why
    assert cost.edge_cost("AZEligibleRole", e)["fragile"] is False


def test_audit_flags_weak_activation():
    from pathcutter.hygiene import audit
    rules_ids = {f.rule for f in audit(_graph([_enablement(mfa=False), _approval(required=False)]))}
    assert "pim-activation-no-mfa" in rules_ids
    rules_ids2 = {f.rule for f in audit(_graph([_enablement(mfa=True), _approval(required=False)]))}
    assert "pim-activation-no-approval" in rules_ids2
    # MFA + approval required: no weak-activation finding
    rules_ids3 = {f.rule for f in audit(_graph([_enablement(mfa=True), _approval(required=True)]))}
    assert "pim-activation-no-mfa" not in rules_ids3 and "pim-activation-no-approval" not in rules_ids3


def test_flags_parsed_without_odata_type_via_rule_id():
    # some exports omit @odata.type; the rule id must still classify it
    rules = [{"id": "Enablement_EndUser_Assignment", "enabledRules": ["MultiFactorAuthentication"],
              "target": {"caller": "EndUser", "level": "Assignment"}},
             {"id": "Approval_EndUser_Assignment", "setting": {"isApprovalRequired": True},
              "target": {"caller": "EndUser", "level": "Assignment"}}]
    e = _eligible_edge(_graph(rules))
    assert e["pim_mfa"] is True and e["pim_approval"] is True
