"""Ground-truth proof on a rebuilt GOAD (sevenkingdoms.local) lab, loaded through the real SharpHound ingest.

The expected hop counts below were derived BY HAND from the published lab definition (users, nested
groups, the 12 ACLs, DC local-group rights, OU containment), not copied from program output.
"""
import pytest

from oracle import oracle_hops
from pathcutter.changes import load_changes, resolve_changes
from pathcutter.exposure import compute_exposure
from pathcutter.impact import analyze_impact
from pathcutter.ingest import load_sharphound
from pathcutter.labs import lab_ids, write_lab
from pathcutter.policy import Policy, evaluate

IDS = lab_ids("goad-sevenkingdoms")

# Hand-derived minimum hops to Tier 0 (domain controller kingslanding is Tier 0 via Domain Controllers).
EXPECTED_HOPS = {
    "lord.varys": 1,            # GenericAll on Domain Admins
    "stannis.baratheon": 1,     # GenericAll on the DC
    "Baratheon": 1,             # CanRDP to the DC (local group of dc01)
    "Small Council": 1,         # CanRDP to the DC
    "DragonRider": 1,           # local Administrators of the DC (AdminTo)
    "AcrossTheNarrowSea": 1,    # GenericAll on the DC
    "daenerys.targaryen": 2,    # essos.local user in AcrossTheNarrowSea (cross-domain)
    "joffrey.baratheon": 2,     # member of Baratheon -> CanRDP
    "renly.baratheon": 2,       # member of Baratheon / Small Council
    "petyer.baelish": 2,        # member of Small Council
    "maester.pycelle": 2,
    "tyron.lannister": 2,       # AddSelf on Small Council, which has CanRDP
    "KingsGuard": 2,            # GenericAll on stannis
    "OU Crownlands": 2,         # Contains Small Council (structural), then CanRDP
    "DragonStone": 3,           # WriteOwner on KingsGuard
    "jaime.lannister": 3,       # GenericWrite on joffrey
    "tywin.lannister": 4,       # ForceChangePassword on jaime
}
NOT_EXPOSED = ["Lannister"]     # a group nobody gave any rights


@pytest.fixture(scope="module")
def _lab_loaded(tmp_path_factory):
    d = tmp_path_factory.mktemp("goad")
    write_lab("goad-sevenkingdoms", d)
    return load_sharphound(d)


@pytest.fixture
def lab(_lab_loaded):
    """A private copy per test, so tests that edit the graph cannot leak into each other."""
    return _lab_loaded.clone()


def test_lab_loads_through_the_real_ingest(lab):
    assert lab.node_count == 26
    names = {n.name for n in lab.all_nodes()}
    assert {"TYWIN.LANNISTER@SEVENKINGDOMS.LOCAL", "KINGSLANDING.SEVENKINGDOMS.LOCAL",
            "ADMINSDHOLDER@SEVENKINGDOMS.LOCAL"} <= names


def test_tier0_matches_the_lab(lab):
    t0 = {lab.get_node_name(i).split("@")[0] for i in lab.tier0_nodes}
    assert t0 == {"ADMINISTRATOR", "ADMINSDHOLDER", "CERSEI.LANNISTER", "DOMAIN ADMINS", "DOMAIN CONTROLLERS",
                  "KINGSLANDING.SEVENKINGDOMS.LOCAL", "ROBERT.BARATHEON"}


def test_the_documented_acl_chain_is_present(lab):
    chain = [("tywin.lannister", "ForceChangePassword", "jaime.lannister"),
             ("jaime.lannister", "GenericWrite", "joffrey.baratheon"),
             ("joffrey.baratheon", "WriteDacl", "tyron.lannister"),
             ("tyron.lannister", "AddMember", "Small Council"),
             ("Small Council", "AddMember", "DragonStone"),
             ("DragonStone", "WriteOwner", "KingsGuard"),
             ("KingsGuard", "GenericAll", "stannis.baratheon"),
             ("stannis.baratheon", "GenericAll", "kingslanding")]
    for src, right, dst in chain:
        assert lab.has_edge_type(IDS[src], IDS[dst], right), (src, right, dst)


def test_hop_counts_match_hand_derived_ground_truth(lab):
    exp = compute_exposure(lab)
    for name, hops in EXPECTED_HOPS.items():
        assert exp.hops(IDS[name]) == hops, f"{name}: expected {hops}, got {exp.hops(IDS[name])}"
    for name in NOT_EXPOSED:
        assert IDS[name] not in exp.exposed(), name
    assert len(exp.exposed()) == len(EXPECTED_HOPS)         # nothing exposed that we did not predict


def test_engine_agrees_with_the_independent_oracle(lab):
    exp = compute_exposure(lab)
    oracle = oracle_hops(lab, max_depth=12)
    assert {n: exp.hops(n) for n in exp.exposed()} == oracle


def test_cross_domain_principal_is_reported(lab):
    assert IDS["daenerys.targaryen"] in compute_exposure(lab).exposed()


def test_shortest_route_is_not_the_famous_chain(lab):
    steps = compute_exposure(lab).path(IDS["tywin.lannister"])
    assert [s.edge_type for s in steps[:-1]] == ["ForceChangePassword", "GenericWrite", "MemberOf", "CanRDP"]


# ----------------------------------------------------------------- the gate on this lab

def gate(lab, lines, policy=None):
    specs, _ = load_changes(inline=lines)
    resolved, errors = resolve_changes(lab, specs)
    assert not errors, errors
    report = analyze_impact(lab, resolved)
    evaluate(report, policy or Policy(), resolved)
    return report


def test_new_account_in_dragonstone_is_blocked_and_the_fix_works(lab):
    r = gate(lab, ["create user newhire", "add-member newhire DragonStone"])
    f = next(x for x in r.findings if x.kind == "NEW_EXPOSURE")
    assert r.verdict == "block" and f.principals[0]["hops_after"] == 4
    assert [s["name"] for s in f.paths[0]] == ["newhire", "DragonStone", "KingsGuard", "stannis.baratheon"] \
        or f.paths[0][0]["name"].lower() == "newhire"
    assert f.fix_first, "the gate must say what to fix first"
    # apply the suggested fix to the baseline, then the same change must pass
    ids = {n.display_name.lower(): n.object_id for n in lab.all_nodes()}
    for fx in f.fix_first:
        lab.remove_edge(ids[fx["source"].split("@")[0].lower()], ids[fx["target"].split("@")[0].lower()], fx["edge_type"])
    lab.retier()
    r2 = gate(lab, ["create user newhire", "add-member newhire DragonStone"])
    assert r2.verdict == "pass", r2.verdict_reason


def test_promotion_into_domain_admins_is_critical(lab):
    r = gate(lab, ['add-member petyer.baelish "Domain Admins"'])
    f = next(x for x in r.findings if x.kind == "TIER0_PROMOTION")
    assert f.severity == "critical" and r.verdict == "block" and f.principals[0]["name"].lower() == "petyer.baelish"


def test_adding_to_a_harmless_group_passes(lab):
    r = gate(lab, ["create user newhire", "add-member newhire Lannister"])
    assert r.verdict == "pass" and r.totals["newly_exposed"] == 0


def test_removing_the_documented_acl_does_not_secure_stannis(lab):
    """Revoking stannis' GenericAll on the DC looks like the fix, but stannis is still in Baratheon,
    which can RDP to the DC. A naive reading of the ACL list would call this fixed; the gate does not."""
    r = gate(lab, ["revoke stannis.baratheon GenericAll kingslanding"])
    assert r.totals["newly_secured"] == 0 and not [f for f in r.findings if f.kind == "RISK_REDUCTION"]


def test_removing_the_rdp_rights_only_secures_the_group_not_its_members(lab):
    r = gate(lab, ["revoke Baratheon CanRDP kingslanding", 'revoke "Small Council" CanRDP kingslanding'])
    secured = {p["name"] for f in r.findings if f.kind == "RISK_REDUCTION" for p in f.principals}
    # Baratheon (the group) loses its only route, but every Baratheon member keeps one through the
    # Small Council -> DragonStone -> KingsGuard -> stannis chain, so no user account is secured.
    assert secured == {"BARATHEON"} and r.totals["newly_secured_actors"] == 0
    assert r.verdict == "pass"


def test_varys_adminsdholder_control_is_tier0_control(lab):
    exp = compute_exposure(lab)
    path = exp.path(IDS["lord.varys"])
    assert path[0].edge_type == "GenericAll" and exp.hops(IDS["lord.varys"]) == 1


def test_unconstrained_delegation_host_is_linked_to_the_dc(tmp_path):
    """Regression: the DC lookup used to match computers by the Domain Controllers *group* RID, so the
    unconstrained-delegation edge was never created and such hosts were invisible to every analysis."""
    import json
    write_lab("goad-sevenkingdoms", tmp_path)
    web = {"meta": {"type": "computers", "version": 4, "count": 1, "methods": 0}, "data": [{
        "ObjectIdentifier": "S-1-5-21-1101001-2202002-3303003-2001", "Aces": [],
        "Properties": {"name": "WEB01.SEVENKINGDOMS.LOCAL", "domain": "SEVENKINGDOMS.LOCAL", "enabled": True,
                       "unconstraineddelegation": True}}]}
    (tmp_path / "20240601000000_computers_web.json").write_text(json.dumps(web))
    g = load_sharphound(tmp_path)
    web_id, dc_id = "S-1-5-21-1101001-2202002-3303003-2001", IDS["kingslanding"]
    assert g.has_edge_type(web_id, dc_id, "AllowedToDelegate")
    assert not g.has_edge_type(dc_id, dc_id, "AllowedToDelegate")            # the DC itself is not linked to itself
    assert compute_exposure(g).hops(web_id) == 1
