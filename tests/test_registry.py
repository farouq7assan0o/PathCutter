"""Registry completeness: knowledge about an edge type lives in several modules; this test fails when they drift.

Adding a right means touching the places below. If one is forgotten, a test here names it. The explicit allow-lists
are the honest list of known gaps: they may only shrink.
"""
import re
from pathlib import Path

from pathcutter import changes, ingest, ps_rules
from pathcutter.edges import EDGE_REGISTRY
from pathcutter.pathfinder import _ATTACK_EDGES

NAMES = sorted({e.name for e in EDGE_REGISTRY.values()})

# Edges that are not attack steps by themselves (plumbing)
STRUCTURAL = {"MemberOf", "Contains", "AZContains"}
# Known gap: AD CS rights are ingested and typed but only become attack steps once the ESC conditions are modeled.
PENDING_ADCS = {"Enroll", "AutoEnroll", "ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag", "WritePKINameFlag"}


def test_every_edge_is_an_attack_step_or_explicitly_not():
    missing = [n for n in NAMES if n not in _ATTACK_EDGES and n not in STRUCTURAL and n not in PENDING_ADCS]
    assert not missing, f"edge types that are neither attack steps nor declared structural/pending: {missing}"
    assert not (PENDING_ADCS & _ATTACK_EDGES), "an allow-list entry became an attack edge: remove it from PENDING_ADCS"


def test_attack_edges_exist_in_the_registry():
    assert not [n for n in _ATTACK_EDGES if n not in NAMES]


def test_attack_edges_explain_themselves():
    for n in NAMES:
        et = EDGE_REGISTRY[n]
        if n in _ATTACK_EDGES:
            assert et.abuse and et.exploitability, f"{n}: an attack edge needs abuse text and an exploitability score"
            assert et.mitre, f"{n}: an attack edge needs a MITRE technique"


def test_collector_maps_only_produce_known_edges():
    for table in (ingest._ACE_MAP, ingest._CE_EDGE_MAP, ingest._LOCAL_GROUP_EDGE, ingest._GPO_CHANGE_EDGE):
        assert not [v for v in table.values() if v not in NAMES], table


def test_powershell_rules_only_produce_known_edges():
    for table in (ps_rules._WRITE_PROP, ps_rules._EXT_RIGHT, ps_rules._READ_PROP):
        assert not [v for v in table.values() if v not in NAMES], table


def test_user_grantable_edges_have_endpoint_rules_or_are_generic():
    """`grant X Right Y` works for any edge; the typed verbs (add-member, local-admin, ...) need endpoint types."""
    for verb, (op, edge, _) in changes._VERBS.items():
        assert edge in (None, "*") or edge in NAMES, f"{verb} -> {edge}"


def test_collector_script_guids_match_the_powershell_rules():
    """tools/Export-AdDenyAces.ps1 carries its own GUID table; it must agree with ps_rules.PROP_GUIDS."""
    ps1 = (Path(__file__).parent.parent / "tools" / "Export-AdDenyAces.ps1").read_text(encoding="utf-8")
    script = {m.group(1).lower() for m in re.finditer(r"'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'", ps1)}
    known = set(ps_rules.PROP_GUIDS)
    assert script <= known, f"the collector uses GUIDs the rules do not know: {sorted(script - known)}"
    needed = {g for g, n in ps_rules.PROP_GUIDS.items() if n in ("member", "serviceprincipalname", "user-force-change-password",
              "msds-allowedtoactonbehalfofotheridentity", "msds-keycredentiallink", "ds-replication-get-changes",
              "ds-replication-get-changes-all", "ds-replication-get-changes-in-filtered-set")}
    assert needed <= script, f"the collector cannot see denies for: {sorted(needed - script)}"


def test_help_lists_every_edge():
    from pathcutter.syntax_help import edges
    text = edges()
    assert not [n for n in NAMES if n not in text]


# ------------------------------------------------------------------ data/rights.json is the single source

def test_rights_json_is_well_formed():
    from pathcutter import rights
    doc = rights.load()
    names = [p["name"] for p in doc["properties"]]
    guids = [p["guid"] for p in doc["properties"] if p.get("guid")]
    assert len(names) == len(set(names)) and len(guids) == len(set(guids))
    for p in doc["properties"]:
        assert p["kind"] in ("write_property", "extended_right", "read_property", "none")
        assert (p["kind"] == "none") == (not p.get("edge")), p
        if p.get("guid"):
            assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", p["guid"]), p
        if p.get("edge"):
            assert p["edge"] in NAMES, p
    for table in ("collector_ace", "collector_edge", "local_group_rid", "gpo_changes"):
        assert not [v for v in doc[table].values() if v not in NAMES], table


def test_collector_script_table_is_generated_from_rights_json():
    import subprocess, sys
    r = subprocess.run([sys.executable, str(Path(__file__).parent.parent / "tools" / "gen_collector_table.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_modules_use_the_json_not_private_copies():
    from pathcutter import rights
    assert ingest._ACE_MAP == rights.collector_ace() and ingest._CE_EDGE_MAP == rights.collector_edge()
    assert ps_rules.PROP_GUIDS == rights.property_guids()
