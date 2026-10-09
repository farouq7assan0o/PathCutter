"""AD CS escalation edges: every condition on its own, then real collections against an independent re-derivation."""
from pathlib import Path

import pytest

from pathcutter.adcs import derive_adcs_edges
from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.ingest import load_sharphound
from pathcutter.toolkit import iter_raw

REAL = Path(__file__).parent / "data" / "real" / "specterops_ad_sampledata.zip"


def lab(template=None, ca=None, enroll_t=("u-grp",), enroll_ca=("u-grp",), ntauth=("AA",), control=(), manage=()):
    """users -> GROUP; GROUP can enroll (configurable); one CA publishing one template; domain X.LOCAL."""
    g = AttackGraph()
    g.add_node(ADNode("dom", "X.LOCAL", NodeType.DOMAIN, "X.LOCAL"))
    g.add_node(ADNode("u-alice", "ALICE@X.LOCAL", NodeType.USER, "X.LOCAL"))
    g.add_node(ADNode("u-grp", "STAFF@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.add_node(ADNode("u-other", "OTHER@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.add_edge(ADEdge("u-alice", "u-grp", "MemberOf"))
    tprops = {"enrolleesuppliessubject": True, "authenticationenabled": True, "requiresmanagerapproval": False, "authorizedsignatures": 0}
    tprops.update(template or {})
    cprops = {"certthumbprint": "AA", "_enabled_templates": ["tpl"], "_san_enabled": False, "_san_collected": True}
    cprops.update(ca or {})
    g.add_node(ADNode("tpl", "ESC@X.LOCAL", NodeType.CERT_TEMPLATE, "X.LOCAL", properties=tprops))
    g.add_node(ADNode("ca", "CA@X.LOCAL", NodeType.ENTERPRISE_CA, "X.LOCAL", properties=cprops))
    g.add_node(ADNode("nt", "NTAUTH@X.LOCAL", NodeType.NTAUTH_STORE, "X.LOCAL", properties={"certthumbprints": list(ntauth)}))
    for p in enroll_t:
        g.add_edge(ADEdge(p, "tpl", "Enroll"))
    for p in enroll_ca:
        g.add_edge(ADEdge(p, "ca", "Enroll"))
    for p in control:
        g.add_edge(ADEdge(p, "tpl", "WriteDacl"))
    for p in manage:
        g.add_edge(ADEdge(p, "ca", "ManageCA"))
    g.classify_tiers()
    return g


def kinds(g):
    return {(u, d["edge_type"]) for u, v, d in g.all_edges() if d["edge_type"].startswith("ADCSESC") and v == "dom"}


def test_esc1_edge_and_path_to_tier0():
    g = lab()
    assert derive_adcs_edges(g) == {"ADCSESC1": 1, "ADCSESC4": 0, "ADCSESC6": 0, "ADCSESC7": 0}
    assert kinds(g) == {("u-grp", "ADCSESC1")}
    exp = compute_exposure(g)
    assert exp.hops("u-alice") == 2 and "u-alice" in exp.exposed()
    assert [s.node_id for s in exp.path("u-alice")] == ["u-alice", "u-grp", "dom"]


@pytest.mark.parametrize("what,kw", [
    ("requester cannot name the subject", {"template": {"enrolleesuppliessubject": False}}),
    ("template cannot authenticate", {"template": {"authenticationenabled": False}}),
    ("manager approval required", {"template": {"requiresmanagerapproval": True}}),
    ("authorized signatures required", {"template": {"authorizedsignatures": 1}}),
    ("template not published", {"ca": {"_enabled_templates": []}}),
    ("CA not in NTAuth", {"ntauth": ("BB",)}),
    ("nobody can enroll on the template", {"enroll_t": ()}),
    ("nobody can enroll on the CA", {"enroll_ca": ()}),
    ("template and CA enrollers are unrelated", {"enroll_t": ("u-other",)}),
])
def test_esc1_needs_every_condition(what, kw):
    g = lab(**kw)
    derive_adcs_edges(g)
    assert not [k for k in kinds(g) if k[1] == "ADCSESC1"], what


def test_enrollment_through_nested_groups_is_found():
    g = lab(enroll_t=("u-grp",), enroll_ca=("u-other",))
    g.add_edge(ADEdge("u-grp", "u-other", "MemberOf"))      # STAFF is nested in OTHER: STAFF holds both rights
    derive_adcs_edges(g)
    assert ("u-grp", "ADCSESC1") in kinds(g)


def test_user_in_two_unrelated_groups_gets_the_edge_from_the_user():
    g = lab(enroll_t=("u-grp",), enroll_ca=("u-other",))
    g.add_edge(ADEdge("u-alice", "u-other", "MemberOf"))    # alice is in both groups; the groups are unrelated
    derive_adcs_edges(g)
    assert ("u-alice", "ADCSESC1") in kinds(g)
    assert ("u-grp", "ADCSESC1") not in kinds(g)


def test_esc6_needs_the_san_flag_and_ignores_the_subject_flag():
    g = lab(template={"enrolleesuppliessubject": False}, ca={"_san_enabled": True})
    derive_adcs_edges(g)
    assert kinds(g) == {("u-grp", "ADCSESC6")}
    g = lab(template={"enrolleesuppliessubject": False}, ca={"_san_enabled": True, "_san_collected": False})
    derive_adcs_edges(g)
    assert not kinds(g), "an uncollected flag is not evidence"


def test_esc4_template_control_and_esc7_manage_ca():
    g = lab(template={"enrolleesuppliessubject": False}, enroll_t=(), enroll_ca=(), control=("u-grp",), manage=("u-other",))
    derive_adcs_edges(g)
    assert ("u-other", "ADCSESC7") in kinds(g)
    assert kinds(g) >= {("u-other", "ADCSESC7")} and ("u-grp", "ADCSESC4") not in kinds(g)   # controller cannot enroll on the CA...
    g = lab(template={"enrolleesuppliessubject": False}, enroll_t=(), control=("u-grp",))
    derive_adcs_edges(g)
    assert ("u-grp", "ADCSESC4") in kinds(g)                                                  # ...unless it can


def test_tier0_sources_are_not_reported():
    g = lab(enroll_t=("u-grp", "da"), enroll_ca=("u-grp", "da"))
    g.add_node(ADNode("da", "DOMAIN ADMINS@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    g.classify_tiers()
    derive_adcs_edges(g)
    assert all(src != "da" for src, _ in kinds(g))


def test_no_ntauth_store_means_assume_trusted():
    g = lab()
    g.remove_edge("u-grp", "ca", "Enroll")
    g.add_edge(ADEdge("u-grp", "ca", "Enroll"))
    g._nodes.pop("nt")
    g.graph.remove_node("nt")
    derive_adcs_edges(g)
    assert ("u-grp", "ADCSESC1") in kinds(g)


# ------------------------------------------------------------ real collection vs independent re-derivation

@pytest.mark.skipif(not REAL.exists(), reason="real dataset missing")
def test_real_collection_matches_an_independent_derivation_from_the_raw_json():
    """Re-derive which templates are ESC1-vulnerable straight from the raw JSON (no graph, no shared code) and check
    that the graph carries an ADCSESC1 edge for exactly those templates' non-Tier-0 enrollers' groups."""
    raw = {}
    cas, ntauth = [], set()
    for entry, data in iter_raw(REAL):
        e = entry.lower()
        for o in data["data"]:
            if "certtemplates" in e:
                raw[o["ObjectIdentifier"]] = o
            elif "enterprisecas" in e:
                cas.append(o)
            elif "ntauth" in e:
                ntauth |= {t.upper() for t in o["Properties"].get("certthumbprints", [])}
    vulnerable = set()
    for ca in cas:
        if ca["Properties"].get("certthumbprint", "").upper() not in ntauth:
            continue
        ca_enrollers = {a["PrincipalSID"] for a in ca["Aces"] if a["RightName"] in ("Enroll", "GenericAll", "AllExtendedRights")}
        for ref in ca.get("EnabledCertTemplates") or []:
            t = raw.get(ref["ObjectIdentifier"])
            if not t:
                continue
            p = t["Properties"]
            if p["enrolleesuppliessubject"] and p["authenticationenabled"] and not p["requiresmanagerapproval"] \
                    and p["authorizedsignatures"] == 0:
                t_enrollers = {a["PrincipalSID"] for a in t["Aces"] if a["RightName"] in ("Enroll", "GenericAll", "AllExtendedRights")}
                if t_enrollers & ca_enrollers:
                    vulnerable.add(t["ObjectIdentifier"])
    assert vulnerable, "the sample is expected to contain published ESC1-shaped templates"
    g = load_sharphound(REAL)
    edge_sources = {u for u, v, d in g.all_edges() if d["edge_type"] == "ADCSESC1"}
    assert edge_sources, "no ADCSESC1 edge was derived although vulnerable templates exist"
    # every edge source must hold Enroll on at least one of the independently found vulnerable templates (or be nested under such a holder)
    holders = {a["PrincipalSID"] for tid in vulnerable for a in raw[tid]["Aces"] if a["RightName"] in ("Enroll", "GenericAll", "AllExtendedRights")}
    for src in edge_sources:
        assert src in holders or any(g.has_edge_type(src, h, "MemberOf") for h in holders), g.get_node(src).name


# ------------------------------------------------------------ implicit memberships and the domain object

def _ace_to_everyone(right="GenericAll"):
    import json, zipfile, tempfile
    sid = "S-1-5-21-1-2-3"
    mk = lambda i, n: {"ObjectIdentifier": f"{sid}-{i}", "Properties": {"name": n, "domain": "X.LOCAL"}}   # noqa: E731
    users = {"meta": {"type": "users", "version": 4}, "data": [dict(mk(1105, "ALICE@X.LOCAL"), PrimaryGroupSID=f"{sid}-513"),
             dict(mk(1106, "VICTIM@X.LOCAL"), Aces=[{"PrincipalSID": "X.LOCAL-S-1-5-11", "PrincipalType": "Group", "RightName": right, "IsInherited": False}])]}
    groups = {"meta": {"type": "groups", "version": 4}, "data": [mk(513, "DOMAIN USERS@X.LOCAL"), mk(512, "DOMAIN ADMINS@X.LOCAL")]}
    groups["data"][1]["Members"] = [{"ObjectIdentifier": f"{sid}-1106", "ObjectType": "User"}]
    domains = {"meta": {"type": "domains", "version": 4}, "data": [{"ObjectIdentifier": sid, "Properties": {"name": "X.LOCAL", "domain": "X.LOCAL"}}]}
    f = Path(tempfile.mkdtemp()) / "e.zip"
    with zipfile.ZipFile(f, "w") as zf:
        for n, d in (("users", users), ("groups", groups), ("domains", domains)):
            zf.writestr(f"1_{n}.json", json.dumps(d))
    return f


def test_an_ace_granted_to_authenticated_users_is_a_right_everyone_holds():
    g = load_sharphound(_ace_to_everyone())
    exp = compute_exposure(g)
    assert "S-1-5-21-1-2-3-1105" in exp.exposed(), "ALICE is an authenticated user, so she holds Authenticated Users' GenericAll"
    names = [g.get_node(s.node_id).display_name for s in exp.path("S-1-5-21-1-2-3-1105")]
    assert names[:3] == ["ALICE", "DOMAIN USERS", "AUTHENTICATED USERS"]


def test_the_domain_object_is_tier0():
    g = load_sharphound(_ace_to_everyone())
    assert "S-1-5-21-1-2-3" in g.tier0_nodes
