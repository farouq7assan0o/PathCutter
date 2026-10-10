"""Conditional Access evaluation against the collected Entra tenant (rules in `pathcutter audit`)."""
import json
import zipfile

import pytest

from pathcutter.hygiene import audit
from pathcutter.ingest import load_sharphound
from pathcutter.snapshot import load_snapshot, save_snapshot

from test_azure import GA, PRA, TENANT, assignment, azure_file, user

CA_IDS = {"admins": "ab000000-0000-0000-0000-000000000001"}


def policy(name, *, state="enabled", include_users=None, exclude_users=(), include_roles=(), exclude_roles=(), include_groups=(),
           exclude_groups=(), controls=("mfa",), operator="OR", apps=("All",), clients=("all",), extra=None):
    p = {"id": f"p-{name}", "displayName": name, "state": state,
         "conditions": {"users": {"includeUsers": list(include_users or []), "excludeUsers": list(exclude_users),
                                  "includeRoles": list(include_roles), "excludeRoles": list(exclude_roles),
                                  "includeGroups": list(include_groups), "excludeGroups": list(exclude_groups)},
                        "applications": {"includeApplications": list(apps)}, "clientAppTypes": list(clients)},
         "grantControls": {"operator": operator, "builtInControls": list(controls)}}
    if extra:
        p["conditions"].update(extra)
    return p


def build(tmp_path, policies, *, ga=("A1",), extra_items=()):
    z = tmp_path / "e.zip"
    items = [user("A1", "ada@x.com"), user("B2", "bob@x.com"), user("C3", "cy@x.com"), assignment(GA, *ga), *extra_items]
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("1_azure.json", json.dumps(azure_file(*items)))
        if policies is not None:
            zf.writestr("2_ca.json", json.dumps({"value": policies}))
    return load_sharphound(z)


def rules(g):
    return {f.rule: f for f in audit(g)}


def test_missing_policies_are_reported_as_unknown_not_as_good(tmp_path):
    r = rules(build(tmp_path, None))
    assert r["ca-not-collected"].severity == "info" and "ca-no-admin-mfa" not in r


def test_no_policies_at_all_means_admins_have_no_mfa_and_legacy_is_open(tmp_path):
    r = rules(build(tmp_path, []))      # an empty list is "collected, none exist"?  (treated as not collected: falsy)
    assert "ca-not-collected" in r


def test_enforced_mfa_for_the_admin_role_covers_the_admin(tmp_path):
    g = build(tmp_path, [policy("admins mfa", include_roles=[GA]), policy("legacy", include_users=["All"], controls=("block",),
                                                                            clients=("exchangeActiveSync", "other"))])
    r = rules(g)
    assert not [k for k in r if k.startswith("ca-")], r.keys()


def test_nobody_covered_is_critical(tmp_path):
    r = rules(build(tmp_path, [policy("only bob", include_users=["B2"])]))
    assert r["ca-no-admin-mfa"].severity == "critical" and r["ca-no-admin-mfa"].objects == ["ADA"]


def test_some_admins_uncovered_is_high(tmp_path):
    g = build(tmp_path, [policy("ga only", include_roles=[GA])], ga=("A1", "C3"), extra_items=[assignment(PRA, "B2")])
    r = rules(g)
    assert r["ca-admin-uncovered"].objects == ["BOB"] and r["ca-admin-uncovered"].severity == "high"


def test_exclusion_of_an_admin_is_reported_by_policy_name(tmp_path):
    r = rules(build(tmp_path, [policy("all users mfa", include_users=["All"], exclude_users=["A1"])]))
    assert r["ca-admin-excluded"].objects == ["ADA"] and "all users mfa" in r["ca-admin-excluded"].title
    assert "ca-no-admin-mfa" in r, "an excluded admin is also simply uncovered"


def test_exclusion_through_a_group_and_a_role(tmp_path):
    g = build(tmp_path, [policy("mfa", include_users=["All"], exclude_roles=[GA])])
    assert "ca-admin-excluded" in rules(g)
    g = build(tmp_path, [policy("mfa", include_users=["All"], exclude_groups=["G1"])],
              extra_items=[{"kind": "AZGroup", "data": {"id": "g1", "displayName": "Break glass", "tenantId": TENANT}},
                           {"kind": "AZGroupMember", "data": {"groupId": "g1", "members": [{"member": {"id": "a1"}, "groupId": "g1"}]}}])
    assert "ca-admin-excluded" in rules(g)


def test_report_only_and_disabled_do_not_count(tmp_path):
    r = rules(build(tmp_path, [policy("ro", include_roles=[GA], state="enabledForReportingButNotEnforced")]))
    assert r["ca-report-only"].objects == ["ADA"] and "ca-no-admin-mfa" in r
    r = rules(build(tmp_path, [policy("off", include_roles=[GA], state="disabled")]))
    assert "ca-report-only" not in r and "ca-no-admin-mfa" in r


@pytest.mark.parametrize("kw,covered", [
    ({"controls": ("mfa", "compliantDevice"), "operator": "OR"}, False),      # either control satisfies it: MFA is not required
    ({"controls": ("mfa", "compliantDevice"), "operator": "AND"}, True),
    ({"controls": ("compliantDevice",)}, False),
    ({"apps": ("Office365",)}, False),                                         # not all cloud apps
    ({"extra": {"locations": {"includeLocations": ["office"]}}}, False),       # narrowed by a condition we do not evaluate
    ({"extra": {"signInRiskLevels": ["high"]}}, False),
])
def test_what_counts_as_mfa_coverage(tmp_path, kw, covered):
    r = rules(build(tmp_path, [policy("p", include_roles=[GA], **kw)]))
    assert ("ca-no-admin-mfa" not in r) is covered


def test_authentication_strength_counts_as_mfa(tmp_path):
    p = policy("strength", include_roles=[GA], controls=())
    p["grantControls"]["authenticationStrength"] = {"id": "x"}
    assert "ca-no-admin-mfa" not in rules(build(tmp_path, [p]))


def test_legacy_auth_block_needs_both_client_types_and_all_users(tmp_path):
    base = policy("admins", include_roles=[GA])
    partial = policy("legacy", include_users=["All"], controls=("block",), clients=("exchangeActiveSync",))
    assert "ca-legacy-auth" in rules(build(tmp_path, [base, partial]))
    scoped = policy("legacy", include_users=["B2"], controls=("block",), clients=("exchangeActiveSync", "other"))
    assert "ca-legacy-auth" in rules(build(tmp_path, [base, scoped]))


def test_eligible_admins_are_privileged_too(tmp_path):
    g = build(tmp_path, [policy("nobody", include_users=["C3"])], ga=(),
              extra_items=[{"kind": "AZRoleEligibilityScheduleInstance", "data": {"principalId": "b2", "roleDefinitionId": GA.lower()}}])
    r = rules(g)
    assert r["ca-no-admin-mfa"].objects == ["BOB"]


def test_policies_survive_a_snapshot(tmp_path):
    g = build(tmp_path, [policy("p", include_roles=[GA])])
    save_snapshot(g, tmp_path / "s.pcsnap")
    g2, _ = load_snapshot(tmp_path / "s.pcsnap")
    assert [p["displayName"] for p in g2.meta["conditional_access"]] == ["p"]


# ---- what Windows PowerShell 5.1 and the Graph SDK actually write ------------------------------------------------------------

def test_sdk_pascalcase_bare_list_with_bom_is_read_from_a_directory(tmp_path):
    import json as _json
    from pathcutter.ingest import load_sharphound
    pol = [{"Id": "p1", "DisplayName": "Require MFA for admins", "State": "enabled",
            "Conditions": {"Users": {"IncludeUsers": ["All"], "ExcludeUsers": []}, "Applications": {"IncludeApplications": ["All"]}},
            "GrantControls": {"BuiltInControls": ["mfa"], "Operator": "OR"}}]
    (tmp_path / "conditional_access.json").write_bytes(b"\xef\xbb\xbf" + _json.dumps(pol).encode())
    (tmp_path / "20260101_azure.json").write_text(_json.dumps({"meta": {"type": "azure", "version": 5}, "data": [
        {"kind": "AZUser", "data": {"id": "u1", "userPrincipalName": "a@x.com", "displayName": "a", "tenantId": "t", "accountEnabled": True}}]}))
    g = load_sharphound(tmp_path)
    assert len(g.meta.get("conditional_access", [])) == 1
    assert g.meta["conditional_access"][0]["displayName"] == "Require MFA for admins"
