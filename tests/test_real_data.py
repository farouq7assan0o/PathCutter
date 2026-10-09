"""Real collector output (see tests/data/real/README.md): the ingest must understand what SharpHound 2.x emits.

A synthetic generator can only test what its author already knew. These datasets found: shadow-credential rights
named AddKeyCredentialLink, local admin/RDP data in LocalGroups keyed by RID, session edges in the wrong direction,
domain controllers that are members of their group only through PrimaryGroupSID, ADCS objects typed Unknown,
and GPO links pointing the wrong way.
"""
import time
from pathlib import Path

import pytest

from pathcutter.exposure import compute_exposure
from pathcutter.graph import NodeType
from pathcutter.ingest import load_sharphound
from pathcutter.labs import write_lab

DATA = Path(__file__).parent / "data" / "real"
GOAD = sorted(DATA.glob("*_BloodHound-2.3.3.zip"))
SPECTER = DATA / "specterops_ad_sampledata.zip"
pytestmark = pytest.mark.skipif(not GOAD, reason="real datasets not present")


@pytest.fixture(scope="module")
def graphs():
    return {p.name.split("_")[0]: load_sharphound(p) for p in GOAD}


@pytest.fixture(scope="module")
def specter():
    return load_sharphound(SPECTER)


def edges_of(g, edge_type):
    return [(u, v) for u, v, d in g.all_edges() if d.get("edge_type") == edge_type]


def test_every_real_collection_loads_fast_and_nothing_is_untyped(graphs, specter):
    t = time.time()
    for g in list(graphs.values()) + [specter]:
        assert g.node_count > 90 and g.edge_count > 500
        assert not g.nodes_by_type(NodeType.UNKNOWN), "principals referenced by ACEs must be named and typed"
    assert time.time() - t < 15


def test_adcs_objects_are_typed(graphs, specter):
    for g in list(graphs.values()) + [specter]:
        assert g.nodes_by_type(NodeType.CERT_TEMPLATE) and g.nodes_by_type(NodeType.ENTERPRISE_CA)
        assert g.nodes_by_type(NodeType.ROOT_CA)
    assert len(specter.nodes_by_type(NodeType.CERT_TEMPLATE)) > 50


def test_adcs_rights_survive_ingest(specter):
    types = {d.get("edge_type") for _, _, d in specter.all_edges()}
    assert {"Enroll", "ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag", "WritePKINameFlag"} <= types


def test_shadow_credential_rights_are_not_dropped(graphs, specter):
    """Collectors name it AddKeyCredentialLink; this used to be ignored (hundreds of ACEs)."""
    for g in list(graphs.values()) + [specter]:
        assert edges_of(g, "WriteKeyCredentialLink"), "AddKeyCredentialLink ACEs were dropped"


def test_local_groups_become_admin_rdp_edges(graphs, specter):
    assert any(edges_of(g, "AdminTo") for g in graphs.values())
    assert edges_of(specter, "AdminTo") and edges_of(specter, "CanRDP")


def test_sessions_run_from_the_computer_to_the_user(graphs, specter):
    found = 0
    for g in list(graphs.values()) + [specter]:
        for u, v in edges_of(g, "HasSession"):
            assert g.get_node(u).node_type == NodeType.COMPUTER and g.get_node(v).node_type == NodeType.USER
            found += 1
    assert found > 10


def test_gpo_links_run_from_the_gpo_to_what_it_applies_to(graphs, specter):
    found = 0
    for g in list(graphs.values()) + [specter]:
        for u, v in edges_of(g, "GPOControlsObject"):
            assert g.get_node(u).node_type == NodeType.GPO
            assert g.get_node(v).node_type in (NodeType.OU, NodeType.DOMAIN)
            found += 1
    assert found >= 5


def test_domain_controllers_are_tier0_via_primary_group_and_isdc(graphs, specter):
    for g in list(graphs.values()) + [specter]:
        dcs = [n for n in g.nodes_by_type(NodeType.COMPUTER) if n.properties.get("isdc")]
        assert dcs, "IsDC flags were not read"
        for dc in dcs:
            assert dc.object_id in g.tier0_nodes, f"{dc.name} must be Tier 0"


def test_well_known_principals_are_named_not_unknown(specter):
    names = {n.name.split("@")[0] for n in specter.all_nodes()}
    assert {"SYSTEM", "ADMINISTRATORS", "DOMAIN ADMINS"} <= names


# --------------------------------- cross-validation against the independent GOAD reconstruction

def hop_table(g):
    e = compute_exposure(g)
    return {g.get_node_name(n).split("@")[0].replace(".SEVENKINGDOMS.LOCAL", "").upper(): e.hops(n) for n in e.exposed()}


def test_real_collection_agrees_with_the_hand_built_lab_model(graphs, tmp_path):
    """Two independent encodings of the same public lab (a real SharpHound run and our reconstruction from the
    published lab definition) must give identical attack-path lengths for every shared object."""
    write_lab("goad-sevenkingdoms", tmp_path)
    model = hop_table(load_sharphound(tmp_path))
    real = hop_table(graphs["SEVENKINGDOMS"])
    shared = set(real) & set(model)
    assert len(shared) >= 13
    for name in shared:
        assert real[name] == model[name], f"{name}: real {real[name]} vs model {model[name]}"
    assert real["TYWIN.LANNISTER"] == 4 and real["LORD.VARYS"] == 1 and real["KINGSGUARD"] == 2


def test_the_documented_acl_chain_exists_in_the_real_collection(graphs):
    g = graphs["SEVENKINGDOMS"]
    ids = {n.display_name.upper().replace(".SEVENKINGDOMS.LOCAL", ""): n.object_id
           for n in sorted(g.all_nodes(), key=lambda n: n.node_type == NodeType.COMPUTER)}  # a container shares the DC's name
    chain = [("TYWIN.LANNISTER", "ForceChangePassword", "JAIME.LANNISTER"), ("JAIME.LANNISTER", "GenericWrite", "JOFFREY.BARATHEON"),
             ("JOFFREY.BARATHEON", "WriteDacl", "TYRON.LANNISTER"), ("TYRON.LANNISTER", "AddMember", "SMALL COUNCIL"),
             ("SMALL COUNCIL", "AddMember", "DRAGONSTONE"), ("DRAGONSTONE", "WriteOwner", "KINGSGUARD"),
             ("KINGSGUARD", "GenericAll", "STANNIS.BARATHEON"), ("STANNIS.BARATHEON", "GenericAll", "KINGSLANDING"),
             ("LORD.VARYS", "GenericAll", "DOMAIN ADMINS")]
    for src, right, dst in chain:
        assert g.has_edge_type(ids[src], ids[dst], right), (src, right, dst)


def test_specterops_sample_has_cross_domain_paths_and_exposure(specter):
    assert len(edges_of(specter, "TrustedBy")) >= 4
    exp = compute_exposure(specter)
    assert len(exp.exposed()) >= 30 and not exp.unverified
    domains = {n.domain for n in specter.all_nodes() if n.domain}
    assert len(domains) >= 3
