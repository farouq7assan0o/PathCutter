"""Entra ID / hybrid identity from AzureHound-shaped data (the schema comes from the AzureHound source models)."""
import json
import zipfile

import pytest

from pathcutter.azure import RESET_ROLES, SECRET_ROLES, TIER0_ROLES
from pathcutter.exposure import compute_exposure
from pathcutter.graph import NodeType
from pathcutter.ingest import load_sharphound

GA = "62E90394-69F5-4237-9190-012177145E10"
PRA = "E8611AB8-C189-46E8-94E1-60213AB1F814"
HELPDESK = "729827E3-9C14-49F7-BB1B-9608F156BBB8"
APPADMIN = "9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3"
TENANT = "11111111-1111-1111-1111-111111111111"
SID = "S-1-5-21-1-2-3"


def user(i, upn, **kw):
    return {"kind": "AZUser", "data": {"id": i.lower(), "userPrincipalName": upn, "displayName": upn.split("@")[0], "tenantId": TENANT, "accountEnabled": True, **kw}}


def azure_file(*items):
    return {"meta": {"type": "azure", "version": 2, "count": len(items)}, "data": list(items)}


def assignment(role, *principals):
    return {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": role.lower(), "tenantId": TENANT,
            "roleAssignments": [{"principalId": p.lower(), "roleDefinitionId": role.lower()} for p in principals]}}


def build(tmp_path, azure_items, ad_users=(), ad_groups=()):
    z = tmp_path / "e.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("1_azure.json", json.dumps(azure_file(*azure_items)))
        if ad_users or ad_groups:
            zf.writestr("1_users.json", json.dumps({"meta": {"type": "users", "version": 4}, "data": list(ad_users)}))
            zf.writestr("1_groups.json", json.dumps({"meta": {"type": "groups", "version": 4}, "data": list(ad_groups)}))
    return load_sharphound(z)


def names(g, steps):
    return [g.get_node(s.node_id).display_name for s in steps]


def test_global_admin_membership_is_tier0(tmp_path):
    g = build(tmp_path, [user("A1", "ada@x.com"), user("B2", "bob@x.com"), assignment(GA, "A1")])
    assert "A1" in g.tier0_nodes and "B2" not in g.tier0_nodes and GA in g.tier0_nodes


def test_group_ownership_and_membership_chain(tmp_path):
    g = build(tmp_path, [user("A1", "ada@x.com"), user("B2", "bob@x.com"),
                         {"kind": "AZGroup", "data": {"id": "g1", "displayName": "Cloud Admins", "tenantId": TENANT, "isAssignableToRole": True}},
                         {"kind": "AZGroupMember", "data": {"groupId": "g1", "members": [{"member": {"id": "a1"}, "groupId": "g1"}]}},
                         {"kind": "AZGroupOwner", "data": {"groupId": "g1", "owners": [{"owner": {"id": "b2"}, "groupId": "g1"}]}},
                         assignment(PRA, "G1")])
    e = compute_exposure(g)
    assert "B2" in e.exposed(), "the owner of a role-assignable group can add themselves"
    assert [s.edge_type for s in e.path("B2")] == ["AZOwns", None]      # the group itself is Tier 0 (a member of the role)


def test_app_owner_to_service_principal_to_global_admin(tmp_path):
    g = build(tmp_path, [user("B2", "bob@x.com"),
                         {"kind": "AZApp", "data": {"id": "app1", "appId": "aaaa", "displayName": "Deploy"}},
                         {"kind": "AZServicePrincipal", "data": {"id": "sp1", "appId": "AAAA", "displayName": "Deploy SP"}},
                         {"kind": "AZAppOwner", "data": {"appId": "app1", "owners": [{"owner": {"id": "b2"}, "appId": "app1"}]}},
                         assignment(GA, "SP1")])
    e = compute_exposure(g)
    assert names(g, e.path("B2"))[0] == "BOB" and e.hops("B2") == 2
    assert [s.edge_type for s in e.path("B2")] == ["AZOwns", "AZRunsAs", None]


def test_pim_eligibility_is_an_attack_edge(tmp_path):
    g = build(tmp_path, [user("C3", "cy@x.com"), {"kind": "AZRoleEligibilityScheduleInstance", "data": {"principalId": "c3", "roleDefinitionId": GA.lower()}}])
    e = compute_exposure(g)
    assert "C3" in e.exposed() and e.path("C3")[0].edge_type == "AZEligibleRole"


def test_helpdesk_admin_reaches_tier0_through_an_unprivileged_app_owner(tmp_path):
    g = build(tmp_path, [user("D4", "dee@x.com"), user("B2", "bob@x.com"), user("A1", "ada@x.com"),
                         assignment(HELPDESK, "D4"), assignment(GA, "A1"),
                         {"kind": "AZApp", "data": {"id": "app1", "appId": "aaaa", "displayName": "Deploy"}},
                         {"kind": "AZServicePrincipal", "data": {"id": "sp1", "appId": "aaaa", "displayName": "Deploy SP"}},
                         {"kind": "AZAppOwner", "data": {"appId": "app1", "owners": [{"owner": {"id": "b2"}, "appId": "app1"}]}},
                         assignment(GA, "SP1")])
    e = compute_exposure(g)
    assert [s.edge_type for s in e.path("D4")] == ["MemberOf", "AZResetPassword", "AZOwns", "AZRunsAs", None]
    # privileged users cannot be reset by a helpdesk admin, and unconnected users get no edge at all
    assert not g.has_edge_type(HELPDESK, "A1", "AZResetPassword")
    assert g.edge_count < 40


def test_application_administrator_can_add_a_secret(tmp_path):
    g = build(tmp_path, [user("E5", "eve@x.com"), assignment(APPADMIN, "E5"),
                         {"kind": "AZServicePrincipal", "data": {"id": "sp1", "appId": "aaaa", "displayName": "Powerful SP"}},
                         assignment(GA, "SP1")])
    e = compute_exposure(g)
    assert [s.edge_type for s in e.path("E5")] == ["MemberOf", "AZAddSecret", None]


def test_hybrid_path_from_on_premises_control_to_a_cloud_global_admin(tmp_path):
    ad_users = [{"ObjectIdentifier": f"{SID}-1105", "Properties": {"name": "JDOE@CORP.LOCAL", "domain": "CORP.LOCAL"}}]
    ad_groups = [{"ObjectIdentifier": f"{SID}-1200", "Properties": {"name": "HELPDESK@CORP.LOCAL", "domain": "CORP.LOCAL"},
                  "Members": [{"ObjectIdentifier": f"{SID}-1106", "ObjectType": "User"}]}]
    ad_users.append({"ObjectIdentifier": f"{SID}-1106", "Properties": {"name": "TIM@CORP.LOCAL", "domain": "CORP.LOCAL"}})
    ad_users[0]["Aces"] = [{"PrincipalSID": f"{SID}-1200", "PrincipalType": "Group", "RightName": "ForceChangePassword", "IsInherited": False}]
    g = build(tmp_path, [user("A1", "jdoe@x.com", onPremisesSecurityIdentifier=f"{SID}-1105", onPremisesSyncEnabled=True), assignment(GA, "A1")],
              ad_users, ad_groups)
    e = compute_exposure(g)
    tim = f"{SID}-1106"
    assert tim in e.exposed()
    assert [s.edge_type for s in e.path(tim)] == ["MemberOf", "ForceChangePassword", "SyncedTo", None]


def test_cloud_only_user_is_not_linked_and_unsynced_flag_is_respected(tmp_path):
    g = build(tmp_path, [user("A1", "jdoe@x.com", onPremisesSecurityIdentifier=f"{SID}-1105", onPremisesSyncEnabled=False)],
              [{"ObjectIdentifier": f"{SID}-1105", "Properties": {"name": "JDOE@CORP.LOCAL", "domain": "CORP.LOCAL"}}], [])
    assert not [1 for _, _, d in g.all_edges() if d["edge_type"] == "SyncedTo"]


def test_role_tables_are_consistent():
    assert not set(TIER0_ROLES) & set(RESET_ROLES) and not set(TIER0_ROLES) & set(SECRET_ROLES)
    from pathcutter.edges import TIER0_AZ_ROLE_IDS
    assert TIER0_AZ_ROLE_IDS == set(TIER0_ROLES)


def test_anonymized_hybrid_export_has_the_same_paths_and_no_identities(tmp_path):
    from pathcutter.toolkit import anonymize, iter_raw
    items = [user("A1", "jdoe@contoso.com", onPremisesSecurityIdentifier=f"{SID}-1105", onPremisesSyncEnabled=True, mail="jdoe@contoso.com",
                  givenName="John", surname="Doe", jobTitle="CFO", otherMails=["j@gmail.com"]),
             {"kind": "AZGroup", "data": {"id": "g1", "displayName": "Finance Admins", "tenantId": TENANT}}, assignment(GA, "A1")]
    ad_users = [{"ObjectIdentifier": f"{SID}-1105", "Properties": {"name": "JDOE@CORP.LOCAL", "domain": "CORP.LOCAL"}}]
    z = tmp_path / "e.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("1_azure.json", json.dumps(azure_file(*items)))
        zf.writestr("1_users.json", json.dumps({"meta": {"type": "users", "version": 4}, "data": ad_users}))
        zf.writestr("1_groups.json", json.dumps({"meta": {"type": "groups", "version": 4}, "data": []}))
    out = tmp_path / "anon.zip"
    anonymize(z, out, "salt")
    blob = "".join(json.dumps(d) for _, d in iter_raw(out)).upper()
    for secret in ("JDOE", "CONTOSO", "JOHN", "CFO", "GMAIL", "FINANCE", TENANT.upper(), SID):
        assert secret not in blob, secret
    a, b = load_sharphound(z), load_sharphound(out)
    fp = lambda g: sorted((g.get_node(u).node_type.value, d["edge_type"], g.get_node(v).node_type.value) for u, v, d in g.all_edges())  # noqa: E731
    assert fp(a) == fp(b) and len(b.tier0_nodes) == len(a.tier0_nodes)


def test_doctor_understands_azure_files(tmp_path):
    from pathcutter.toolkit import diagnose
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("1_azure.json", json.dumps(azure_file(user("A1", "a@x.com"), assignment(GA, "A1"))))
    r = diagnose(z)
    assert r["files"] == {"azure": 1} and not [f for f in r["findings"] if "no users file" in f[1]]


# ---------------------------------------------------------------- Azure resource RBAC

SUB = "SUB-0001"
RG = f"/SUBSCRIPTIONS/{SUB}/RESOURCEGROUPS/RG1"
VM = f"{RG}/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM1"


def arm(*extra):
    return [{"kind": "AZSubscription", "data": {"id": f"/subscriptions/{SUB}", "subscriptionId": SUB, "displayName": "Prod", "tenantId": TENANT}},
            {"kind": "AZResourceGroup", "data": {"id": RG.lower(), "name": "rg1", "subscriptionId": f"/subscriptions/{SUB}".lower(), "tenantId": TENANT}},
            {"kind": "AZVM", "data": {"id": VM.lower(), "name": "vm1", "resourceGroupId": RG.lower(), "subscriptionId": SUB, "tenantId": TENANT,
                                      "identity": {"type": "SystemAssigned", "principalId": "sp-vm", "tenantId": TENANT}}},
            {"kind": "AZServicePrincipal", "data": {"id": "sp-vm", "appId": "vvvv", "displayName": "vm1 identity"}}, *extra]


def wrap(key, principal, role_def=""):
    return {key: {"id": "x", "properties": {"principalId": principal, "roleDefinitionId": role_def, "scope": "/s"}}}


def test_vm_contributor_reaches_tier0_through_the_managed_identity(tmp_path):
    g = build(tmp_path, arm(user("C3", "cy@x.com"), assignment(GA, "SP-VM"),
                            {"kind": "AZVMContributor", "data": {"virtualMachineId": VM.lower(), "contributors": [dict(wrap("contributor", "c3"), virtualMachineId=VM.lower())]}}))
    e = compute_exposure(g)
    assert [s.edge_type for s in e.path("C3")] == ["AZContributor", "AZManagedIdentity", None]


def test_subscription_owner_flows_down_the_hierarchy(tmp_path):
    g = build(tmp_path, arm(user("C3", "cy@x.com"), assignment(GA, "SP-VM"),
                            {"kind": "AZSubscriptionOwner", "data": {"subscriptionId": SUB, "owners": [dict(wrap("owner", "c3"), subscriptionId=SUB)]}}))
    e = compute_exposure(g)
    assert [s.edge_type for s in e.path("C3")] == ["AZOwner", "AZContains", "AZContains", "AZManagedIdentity", None]


def test_generic_role_assignment_uses_the_builtin_role_ids(tmp_path):
    contributor = "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
    reader = "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
    g = build(tmp_path, arm(user("C3", "cy@x.com"), user("D4", "dee@x.com"), assignment(GA, "SP-VM"),
                            {"kind": "AZResourceGroupRoleAssignment", "data": {"resourceGroupId": RG.lower(), "roleAssignments": [
                                dict(wrap("roleAssignment", "c3", contributor), resourceGroupId=RG.lower()),
                                dict(wrap("roleAssignment", "d4", reader), resourceGroupId=RG.lower())]}}))
    e = compute_exposure(g)
    assert "C3" in e.exposed() and "D4" not in e.exposed(), "Reader must not count"


def test_a_vm_without_a_managed_identity_leads_nowhere(tmp_path):
    items = arm(user("C3", "cy@x.com"), {"kind": "AZVMOwner", "data": {"virtualMachineId": VM.lower(), "owners": [dict(wrap("owner", "c3"), virtualMachineId=VM.lower())]}})
    items[2]["data"]["identity"] = None
    assert "C3" not in compute_exposure(build(tmp_path, items + [assignment(GA, "SP-VM")])).exposed()


def test_subscriptions_become_targets_through_policy_extra_tier0(tmp_path):
    g = build(tmp_path, arm(user("C3", "cy@x.com"), {"kind": "AZSubscriptionOwner", "data": {"subscriptionId": SUB, "owners": [dict(wrap("owner", "c3"), subscriptionId=SUB)]}}))
    assert "C3" not in compute_exposure(g).exposed()
    sub = next(n for n in g.nodes_by_type(NodeType.AZ_SUBSCRIPTION))
    g.retier({sub.object_id})
    assert "C3" in compute_exposure(g).exposed()


# ---------------------------------------------------------------- Microsoft Graph application permissions

def perm(principal, role_id, resource="Microsoft Graph"):
    return {"kind": "AZAppRoleAssignment", "data": {"principalId": principal.lower(), "appRoleId": role_id.lower(), "resourceDisplayName": resource, "appId": "x"}}


def test_service_principal_with_role_management_permission_is_one_step_from_global_admin(tmp_path):
    g = build(tmp_path, [{"kind": "AZServicePrincipal", "data": {"id": "sp9", "appId": "9999", "displayName": "Automation"}},
                         user("A1", "ada@x.com"), assignment(GA, "A1"),
                         perm("SP9", "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8")])
    e = compute_exposure(g)
    assert [s.edge_type for s in e.path("SP9")] == ["AZMGGrantRole", None]


def test_application_readwrite_lets_a_service_principal_take_over_a_privileged_one(tmp_path):
    g = build(tmp_path, [{"kind": "AZServicePrincipal", "data": {"id": "sp9", "appId": "9999", "displayName": "Automation"}},
                         {"kind": "AZServicePrincipal", "data": {"id": "sp1", "appId": "1111", "displayName": "Privileged"}},
                         {"kind": "AZServicePrincipal", "data": {"id": "sp2", "appId": "2222", "displayName": "Harmless"}},
                         assignment(GA, "SP1"), perm("SP9", "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9")])
    e = compute_exposure(g)
    assert [s.edge_type for s in e.path("SP9")] == ["AZMGAddSecret", None]
    assert not g.has_edge_type("SP9", "SP2", "AZMGAddSecret"), "edges only to targets that lead somewhere"


def test_harmless_and_non_graph_permissions_do_nothing(tmp_path):
    g = build(tmp_path, [{"kind": "AZServicePrincipal", "data": {"id": "sp9", "appId": "9999", "displayName": "Automation"}},
                         user("A1", "ada@x.com"), assignment(GA, "A1"),
                         perm("SP9", "df021288-bdef-4463-88db-98f22de89214"),                       # User.Read.All
                         perm("SP9", "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", resource="Contoso API")])   # same GUID on someone else's API
    assert "SP9" not in compute_exposure(g).exposed()


def test_group_and_user_write_permissions_reach_only_what_they_can_change(tmp_path):
    g = build(tmp_path, [{"kind": "AZServicePrincipal", "data": {"id": "sp9", "appId": "9999", "displayName": "Automation"}},
                         user("A1", "ada@x.com"), user("B2", "bob@x.com"), user("C3", "cy@x.com"),
                         assignment(GA, "A1"),
                         {"kind": "AZGroup", "data": {"id": "gplain", "displayName": "Plain", "tenantId": TENANT}},
                         {"kind": "AZGroup", "data": {"id": "grole", "displayName": "Roles", "tenantId": TENANT, "isAssignableToRole": True}},
                         assignment(PRA, "GPLAIN", "GROLE"),
                         {"kind": "AZGroupOwner", "data": {"groupId": "gplain", "owners": [{"owner": {"id": "b2"}, "groupId": "gplain"}]}},
                         perm("SP9", "62a82d76-70ea-41e2-9197-370581804d09"), perm("SP9", "741f803b-c850-494e-b5df-cde7c675a1ca")])
    # gplain holds a role (so it is Tier 0) only because we granted it above; Group.ReadWrite.All reaches the non-role-assignable one
    assert g.has_edge_type("SP9", "GPLAIN", "AZMGAddMember") and not g.has_edge_type("SP9", "GROLE", "AZMGAddMember")
    assert not g.has_edge_type("SP9", "A1", "AZMGResetPassword"), "a Global Administrator cannot be reset by these permissions"


# ---------------------------------------------------------------- scoped role assignments

def scoped(role, principal, scope):
    return {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": role.lower(), "tenantId": TENANT,
            "roleAssignments": [{"principalId": principal.lower(), "roleDefinitionId": role.lower(), "directoryScopeId": scope}]}}


def au(i, *members):
    return {"kind": "AZAdministrativeUnit", "data": {"id": i, "displayName": i, "members": [{"id": m.lower()} for m in members]}}


def _tenant(extra):
    return [user("H1", "help@x.com"), user("V1", "vic@x.com"), user("V2", "other@x.com"), user("G1", "ga@x.com"),
            assignment(GA, "G1"),
            {"kind": "AZGroup", "data": {"id": "grp", "displayName": "Admins", "tenantId": TENANT}},
            {"kind": "AZGroupMember", "data": {"groupId": "grp", "members": [{"member": {"id": "v1"}}, {"member": {"id": "v2"}}]}},
            assignment(PRA, "GRP")] + extra


def test_unit_scoped_helpdesk_reaches_only_unit_members(tmp_path):
    g = build(tmp_path, _tenant([scoped(HELPDESK, "H1", "/administrativeUnits/AU1"), au("AU1", "V1")]))
    assert g.has_edge_type("H1", "V1", "AZResetPassword")
    assert not g.has_edge_type("H1", "V2", "AZResetPassword")
    assert not g.has_edge_type("H1", HELPDESK, "MemberOf")
    assert g.meta["scoped_roles_unresolved"] == 0


def test_tenant_wide_helpdesk_is_unchanged(tmp_path):
    g = build(tmp_path, _tenant([scoped(HELPDESK, "H1", "/")]))
    assert g.has_edge_type("H1", HELPDESK, "MemberOf")


def test_unit_without_members_is_reported_not_guessed(tmp_path):
    from pathcutter.hygiene import audit
    g = build(tmp_path, _tenant([scoped(HELPDESK, "H1", "/administrativeUnits/AU9")]))
    assert not g.has_edge_type("H1", HELPDESK, "MemberOf")
    assert g.meta["scoped_roles_unresolved"] == 1
    assert any(f.rule == "entra-scoped-roles-unresolved" for f in audit(g))


def test_role_scoped_to_one_object(tmp_path):
    g = build(tmp_path, _tenant([scoped(HELPDESK, "H1", "/V1")]))
    assert g.has_edge_type("H1", "V1", "AZResetPassword") and not g.has_edge_type("H1", "V2", "AZResetPassword")


def test_scoped_eligibility_is_scoped_too(tmp_path):
    g = build(tmp_path, _tenant([{"kind": "AZRoleEligibilityScheduleInstance", "data": {
        "principalId": "h1", "roleDefinitionId": HELPDESK.lower(), "directoryScopeId": "/administrativeUnits/AU1"}}, au("AU1", "V2")]))
    assert g.has_edge_type("H1", "V2", "AZResetPassword") and not g.has_edge_type("H1", HELPDESK, "AZEligibleRole")


def test_unknown_azure_role_definitions_are_reported(tmp_path):
    from pathcutter.hygiene import audit
    item = {"kind": "AZSubscriptionRoleAssignment", "data": {"subscriptionId": "S1", "roleAssignments": [
        {"roleAssignment": {"properties": {"principalId": "h1", "roleDefinitionId": "/subscriptions/S1/providers/x/roleDefinitions/CUSTOM-1"}}}]}}
    g = build(tmp_path, [user("H1", "help@x.com"), assignment(GA, "H1"), item])
    assert g.meta.get("azure_unevaluated_roles") == ["CUSTOM-1"]
    assert any(f.rule == "azure-roles-unevaluated" for f in audit(g))
