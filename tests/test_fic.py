"""Workload identity federation: federated credentials become AZAuthenticatesTo edges, checked against BloodHound's own output."""
import json
from pathlib import Path

from pathcutter.hygiene import audit
from pathcutter.ingest import load_sharphound

V = Path(__file__).parent / "data" / "vendor"


def _load(tmp_path, items):
    (tmp_path / "azure.json").write_text(json.dumps({"meta": {"type": "azure", "version": 5}, "data": items}))
    return load_sharphound(tmp_path)


def _raw_with_apps(raw):
    items = list(raw["data"])
    for a in sorted({fe["appId"].upper() for it in raw["data"] for fe in it["data"]["fics"]}):
        items.append({"kind": "AZApp", "data": {"id": "obj-" + a, "appId": a, "displayName": a, "tenantId": "t"}})
    return items


def test_edges_match_bloodhounds_derived_edges(tmp_path):
    raw = json.loads((V / "fic_raw.json").read_text())
    expected = {tuple(e) for e in json.loads((V / "fic_expected.json").read_text())["AZAuthenticatesTo"]}
    g = _load(tmp_path, _raw_with_apps(raw))
    got = {(u, v.replace("OBJ-", "")) for u, v, d in g.all_edges() if d["edge_type"] == "AZAuthenticatesTo"}
    assert expected and got == expected


def test_wildcard_subject_and_outside_issuer_are_findings(tmp_path):
    raw = json.loads((V / "fic_raw.json").read_text())
    g = _load(tmp_path, _raw_with_apps(raw))
    rules = {f.rule: f for f in audit(g)}
    assert "fic-wildcard-subject" in rules and "fic-external-issuer" in rules
    assert any("*" in str(n.properties.get("subject")) for n in g.all_nodes() if n.display_name in rules["fic-wildcard-subject"].objects)


def test_a_federated_credential_on_a_privileged_app_is_a_path_to_tier0(tmp_path):
    from pathcutter.exposure import compute_exposure
    items = [
        {"kind": "AZApp", "data": {"id": "app-obj", "appId": "AAAA0000-0000-0000-0000-000000000001", "displayName": "Deploy", "tenantId": "t"}},
        {"kind": "AZServicePrincipal", "data": {"id": "sp-obj", "appId": "AAAA0000-0000-0000-0000-000000000001", "displayName": "Deploy", "tenantId": "t"}},
        {"kind": "AZUser", "data": {"id": "ga", "userPrincipalName": "ga@x.com", "displayName": "ga", "tenantId": "t", "accountEnabled": True}},
        {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "roleAssignments": [
            {"principalId": "sp-obj", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "directoryScopeId": "/"}]}},
        {"kind": "AZFederatedIdentityCredential", "data": {"appId": "AAAA0000-0000-0000-0000-000000000001", "fics": [
            {"appId": "AAAA0000-0000-0000-0000-000000000001", "fic": {"id": "fic-1", "name": "gh-main", "issuer": "https://token.actions.githubusercontent.com",
                                                                        "subject": "repo:org/repo:ref:refs/heads/main", "audiences": ["api://AzureADTokenExchange"]}}]}},
    ]
    g = _load(tmp_path, items)
    exp = compute_exposure(g)
    assert "FIC-1" in exp.exposed()
    assert [x.edge_type for x in exp.path("FIC-1")] == ["AZAuthenticatesTo", "AZRunsAs", None]     # token -> app -> its service principal (a Global Administrator)
