"""The hybrid lab: AD (GOAD sevenkingdoms) plus an Entra tenant, with the chains known in advance."""
from pathcutter.exposure import compute_exposure
from pathcutter.ingest import load_sharphound
from pathcutter.labs import lab_ids, write_lab

CLOUD = "C0000001-0000-4000-8000-00000000000"


def _lab(tmp_path):
    g = load_sharphound(write_lab("hybrid-sevenkingdoms", tmp_path))
    return g, compute_exposure(g)


def _names(g, steps):
    return [(g.get_node(s.node_id).display_name, s.edge_type) for s in steps]


def test_synced_users_link_ad_to_the_cloud(tmp_path):
    g, _ = _lab(tmp_path)
    ids = lab_ids()
    assert g.has_edge_type(ids["jaime.lannister"], CLOUD + "1", "SyncedTo")
    assert g.has_edge_type(ids["tyron.lannister"], CLOUD + "2", "SyncedTo")


def test_app_admin_chain_to_global_administrator(tmp_path):
    g, e = _lab(tmp_path)
    assert e.hops(CLOUD + "1") == 3
    assert _names(g, e.path(CLOUD + "1")) == [("JAIME.LANNISTER", "MemberOf"), ("APPLICATION ADMINISTRATOR", "AZAddSecret"),
                                              ("DEPLOY", "AZMGGrantRole"), ("GLOBAL ADMINISTRATOR", None)]


def test_scoped_helpdesk_reaches_only_the_units_members(tmp_path):
    g, e = _lab(tmp_path)
    assert g.has_edge_type(CLOUD + "4", CLOUD + "5", "AZResetPassword")           # sales.rep is in the unit
    assert not g.has_edge_type(CLOUD + "4", CLOUD + "6", "AZResetPassword")       # other.rep is not
    assert not any(d["edge_type"] == "MemberOf" and g.get_node(t).display_name == "HELPDESK ADMINISTRATOR" for _, t, d in g.out_edges(CLOUD + "4"))
    assert CLOUD + "4" in e.exposed() and e.hops(CLOUD + "4") == 4
