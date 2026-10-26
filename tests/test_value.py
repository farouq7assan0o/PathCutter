"""Crown jewels and business value: parsing, resolving (by name and OU), and the per-jewel reachability analysis."""
import pytest

from pathcutter import value
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType


def _g():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@C.L", NodeType.GROUP, "C.L"))
    g.add_node(ADNode("sis", "SQL-SIS@C.L", NodeType.COMPUTER, "C.L",
                      properties={"distinguishedname": "CN=SQL-SIS,OU=Servers,OU=IT,DC=c,DC=l"}))
    g.add_node(ADNode("erp", "ERP-FIN@C.L", NodeType.COMPUTER, "C.L",
                      properties={"distinguishedname": "CN=ERP-FIN,OU=Finance,DC=c,DC=l"}))
    g.add_node(ADNode("bob", "BOB@C.L", NodeType.USER, "C.L",
                      properties={"distinguishedname": "CN=BOB,OU=Staff,DC=c,DC=l"}))
    g.add_edge(ADEdge("bob", "sis", "AdminTo"))      # bob can reach the SIS server
    g.classify_tiers()
    return g


def test_parse_rejects_bad_value_and_empty_entry():
    with pytest.raises(value.ValueError_):
        value.parse({"crown_jewels": [{"match": "X", "value": "supercritical"}]})
    with pytest.raises(value.ValueError_):
        value.parse({"crown_jewels": [{"value": "high"}]})     # no match or ou


def test_parse_accepts_bare_list_and_object():
    a = value.parse([{"match": "X"}])
    b = value.parse({"crown_jewels": [{"match": "X"}]})
    assert len(a) == len(b) == 1 and a[0].value == "high"       # default value


def test_resolve_by_name_and_ou_highest_value_wins():
    g = _g()
    specs = value.parse({"crown_jewels": [
        {"match": "SQL-SIS", "value": "critical", "label": "Student records"},
        {"ou": "OU=IT,DC=c,DC=l", "value": "high", "label": "IT"},       # also matches SQL-SIS, lower value
        {"ou": "OU=Finance,DC=c,DC=l", "value": "high", "label": "Finance"},
    ]})
    vb, errs = value.resolve(g, specs)
    assert errs == []
    assert vb["sis"]["value"] == "critical"          # critical (name) beats high (OU)
    assert vb["sis"]["label"] == "Student records"
    assert vb["erp"]["value"] == "high"
    assert "bob" not in vb                            # BOB is under OU=Staff, not a crown jewel


def test_resolve_reports_unmatched():
    g = _g()
    vb, errs = value.resolve(g, value.parse([{"match": "NOPE"}]))
    assert vb == {} and errs and "NOPE" in errs[0]


def test_analyse_marks_reachable_and_cheapest_route():
    g = _g()
    vb, _ = value.resolve(g, value.parse([
        {"match": "SQL-SIS", "value": "critical", "label": "SIS"},
        {"match": "ERP-FIN", "value": "high", "label": "ERP"},
    ]))
    g.retier(extra_tier0=set(vb))
    rep = value.analyse(g, vb)
    by = {r["name"]: r for r in rep}
    assert by["SQL-SIS"]["reachable"] and by["SQL-SIS"]["reachers"] >= 1
    assert by["SQL-SIS"]["cheapest"] and by["SQL-SIS"]["cheapest"]["route"][0]["name"] == "BOB"
    assert by["ERP-FIN"]["reachable"] is False       # nothing reaches ERP
    # ranking: critical first
    assert rep[0]["value"] == "critical"


def test_ou_path_and_grouping():
    assert value.ou_path("CN=BOB,OU=Staff,OU=People,DC=c,DC=l") == "People/Staff"
    assert value.ou_path("CN=X,DC=c,DC=l") == ""
    g = _g()
    groups = value.group_by_ou(g, ["sis", "bob"])
    assert set(groups) == {"IT/Servers", "Staff"}
