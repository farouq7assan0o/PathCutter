"""PathCutter's ingest against BloodHound CE's own computed graph.

tests/data/vendor holds two SpecterOps test fixtures (Apache-2.0): the raw collector output of an AD lab in the version 5 and
version 6 formats, and the edges BloodHound derived from it. For every edge type both sides model, BloodHound's edges must all
be present here; the only edges we draw that BloodHound does not are listed (with the reason) below. This oracle found, among
other things: self-referential ACEs kept, DCSync built from either right instead of both, sessions in their own file
ignored, containment stated only on the child, SQL admin rights, and trust directions.
"""
import json
from pathlib import Path

import pytest

from pathcutter.ingest import load_sharphound

V = Path(__file__).parent / "data" / "vendor"
pytestmark = pytest.mark.skipif(not (V / "expected_ad.json").exists(), reason="vendor fixtures missing")

# edges we draw that BloodHound does not, per edge type, and why
EXPECTED_EXTRA = {
    "AllowedToDelegate": "unconstrained delegation is drawn as host -> domain controller (BloodHound uses CoerceToTGT)",
    "DCSync": "AllExtendedRights on the domain object by a principal that is already Tier 0",
    "MemberOf": "Domain Users / Domain Computers -> Everyone stand in for every user and computer (one edge per domain, not per object)",
}
# BloodHound edges we do not draw, per edge type, and why
EXPECTED_MISSING = {
    "MemberOf": "Guest -> Everyone (Guest is not in Domain Users; the account is disabled by default)",
}


@pytest.fixture(scope="module", params=["v5", "v6"])
def sides(request):
    g = load_sharphound(V / f"ad_{request.param}.zip")
    exp = json.loads((V / "expected_ad.json").read_text(encoding="utf-8"))[request.param]
    return g, exp


def mine_by_kind(g):
    out = {}
    for u, v, d in g.all_edges():
        out.setdefault(d["edge_type"], set()).add((u, v))
    return out


def test_every_edge_bloodhound_draws_is_drawn_here(sides):
    g, exp = sides
    mine = mine_by_kind(g)
    problems = []
    for kind, pairs in exp["edges"].items():
        missing = {tuple(p) for p in pairs} - mine.get(kind, set())
        if missing and kind not in EXPECTED_MISSING:
            problems.append((kind, sorted(g.get_node_name(s) + " -> " + g.get_node_name(t) for s, t in missing)[:3], len(missing)))
        elif missing and kind in EXPECTED_MISSING:
            assert len(missing) <= 1, f"{kind}: more than the documented gap is missing"
    assert not problems, problems


def test_we_draw_nothing_extra_beyond_the_documented_differences(sides):
    g, exp = sides
    mine = mine_by_kind(g)
    problems = []
    for kind, pairs in exp["edges"].items():
        extra = mine.get(kind, set()) - {tuple(p) for p in pairs}
        if extra and kind not in EXPECTED_EXTRA:
            problems.append((kind, sorted(g.get_node_name(s) + " -> " + g.get_node_name(t) for s, t in extra)[:3], len(extra)))
    assert not problems, problems


def test_tier_zero_agrees_with_bloodhound(sides):
    g, exp = sides
    theirs, mine = set(exp["tier_zero_ids"]), set(g.tier0_nodes)
    missing = theirs - mine
    assert not missing, f"BloodHound tags these Tier Zero and we do not: {sorted(g.get_node_name(i) for i in missing)}"
    extra = {g.get_node_name(i) for i in mine - theirs}
    # Tier 0 here that BloodHound's fixture does not tag: the read-only DC groups, the Domain Controllers group and the GPO linked to
    # the Domain Controllers OU (both are Tier 0 in BloodHound's other fixture, so this is its data, not a disagreement of principle)
    allowed = {"READ-ONLY DOMAIN CONTROLLERS@TESTLAB.LOCAL", "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@TESTLAB.LOCAL",
               "DOMAIN CONTROLLERS@TESTLAB.LOCAL", "DEFAULT DOMAIN CONTROLLERS POLICY@TESTLAB.LOCAL"}
    assert extra <= allowed, sorted(extra - allowed)


def test_trust_directions_follow_bloodhound(sides):
    g, exp = sides
    theirs = {tuple(p) for p in exp["edges"]["TrustedBy"]}
    mine = mine_by_kind(g)["TrustedBy"]
    assert theirs <= mine and len(mine) == len(theirs), (len(theirs), len(mine))


@pytest.mark.parametrize("zip_name", ["adcs_fixture.zip", "ad_v6.zip"])
def test_a_snapshot_has_exactly_the_tier_zero_of_a_fresh_load(tmp_path, zip_name):
    """Structural Tier 0 (GPOs linked to the domain, published templates, PKI objects, domains) must survive save/load."""
    from pathcutter.snapshot import load_snapshot, save_snapshot
    g = load_sharphound(V / zip_name)
    save_snapshot(g, tmp_path / "s.pcsnap")
    g2, _ = load_snapshot(tmp_path / "s.pcsnap")
    assert g2.tier0_nodes == g.tier0_nodes
    assert {(u, v, d["edge_type"]) for u, v, d in g2.all_edges()} == {(u, v, d["edge_type"]) for u, v, d in g.all_edges()}
