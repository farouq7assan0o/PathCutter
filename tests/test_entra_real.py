"""A real AzureHound collection (SpecterOps' PhantomCorp demo tenant) through the Entra / Azure model."""
from collections import Counter
from pathlib import Path

import pytest

from pathcutter.exposure import compute_exposure
from pathcutter.graph import NodeType
from pathcutter.hygiene import audit
from pathcutter.ingest import load_sharphound
from pathcutter.toolkit import diagnose

DATA = Path(__file__).parent / "data" / "real"
ENTRA = DATA / "entra_sampledata.zip"
AD = DATA / "specterops_ad_sampledata.zip"
pytestmark = pytest.mark.skipif(not ENTRA.exists(), reason="fixture missing")


@pytest.fixture(scope="module")
def g():
    return load_sharphound(ENTRA)


def test_every_object_kind_that_matters_is_loaded(g):
    c = Counter(n.node_type for n in g.all_nodes())
    assert c[NodeType.AZ_USER] == 230 and c[NodeType.AZ_ROLE] == 116 and c[NodeType.AZ_SUBSCRIPTION] == 3
    assert c[NodeType.AZ_VM] == 66 and c[NodeType.AZ_RESOURCE] == 16 and c[NodeType.AZ_KEYVAULT] == 3
    assert c[NodeType.AZ_SP] >= 6269 and c[NodeType.AZ_APP] == 6064


def test_tier0_is_the_privileged_roles_and_their_holders(g):
    roles = {g.get_node(n).display_name for n in g.tier0_nodes if g.get_node(n).node_type == NodeType.AZ_ROLE}
    assert {"GLOBAL ADMINISTRATOR", "PRIVILEGED ROLE ADMINISTRATOR", "PRIVILEGED AUTHENTICATION ADMINISTRATOR"} <= roles
    ga = g.get_node("62E90394-69F5-4237-9190-012177145E10")
    holders = {u for u, _, d in g.in_edges(ga.object_id) if d["edge_type"] == "MemberOf"}
    assert holders and holders <= g.tier0_nodes


def test_a_role_scoped_to_one_object_reaches_only_that_object(g):
    """The tenant's 'All Phantom users' group holds Cloud Application Administrator scoped to a single service principal."""
    grp = next(n for n in g.all_nodes() if n.display_name == "ALL PHANTOM USERS")
    targets = {g.get_node(t).display_name for _, t, d in g.out_edges(grp.object_id) if d["edge_type"] == "AZAddSecret"}
    assert targets == {"THISSPOWNSTHEGAGROUP"}


def test_resource_managed_identities_link_to_service_principals(g):
    assert Counter(d["edge_type"] for _, _, d in g.all_edges())["AZManagedIdentity"] >= 20
    res = [n for n in g.nodes_by_type(NodeType.AZ_RESOURCE) if n.display_name == "PHANTOMDEMOWEBAPP"]
    assert res and any(d["edge_type"] == "AZManagedIdentity" for _, _, d in g.out_edges(res[0].object_id))


def test_graph_permissions_become_edges(g):
    c = Counter(d["edge_type"] for _, _, d in g.all_edges())
    assert c["AZMGAddSecret"] > 1000 and c["AZMGGrantRole"] > 0


def test_exposure_finds_paths_and_every_path_ends_at_tier0(g):
    exp = compute_exposure(g)
    assert len(exp.exposed()) > 500
    for n in list(exp.exposed())[:25]:
        assert exp.path(n)[-1].node_id in g.tier0_nodes


def test_doctor_does_not_ask_an_entra_export_for_domain_controllers():
    r = diagnose(str(ENTRA))
    assert not [f for f in r["findings"] if f[0] in ("ERROR", "WARN")], r["findings"]


def test_audit_reports_unevaluated_roles(g):
    assert any(f.rule == "azure-roles-unevaluated" for f in audit(g))


@pytest.mark.skipif(not AD.exists(), reason="AD fixture missing")
def test_synced_users_link_the_two_directories():
    h = load_sharphound([AD, ENTRA])
    assert Counter(d["edge_type"] for _, _, d in h.all_edges())["SyncedTo"] >= 5
