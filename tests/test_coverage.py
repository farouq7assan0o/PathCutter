"""Detection coverage per path: detected / visible / blind, what to switch on, and what the generated pack would add."""
import json

import pytest

from pathcutter.coverage import Inventory, OBSERVABLE, PACK_EDGES, TELEMETRY, analyse, path_coverage, step_status
from pathcutter.cli import main
from pathcutter.edges import EDGE_REGISTRY
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType


def _lab():
    """alice -AddMember-> HELPDESK(group) ... bob -HasSession path: two independent paths to Tier 0."""
    g = AttackGraph()
    g.add_node(ADNode("DA", "DOMAIN ADMINS@X.L", NodeType.GROUP, "X.L"))
    g.add_node(ADNode("alice", "ALICE@X.L", NodeType.USER, "X.L"))
    g.add_node(ADNode("bob", "BOB@X.L", NodeType.USER, "X.L"))
    g.add_node(ADNode("ws", "WS1.X.L", NodeType.COMPUTER, "X.L"))
    g.add_node(ADNode("admin", "ADMIN1@X.L", NodeType.USER, "X.L"))
    g.add_edge(ADEdge("admin", "DA", "MemberOf"))
    g.add_edge(ADEdge("alice", "DA", "AddMember"))
    g.add_edge(ADEdge("bob", "ws", "CanRDP"))
    g.add_edge(ADEdge("ws", "admin", "HasSession"))
    g.classify_tiers()
    return g


def test_no_telemetry_means_blind():
    inv = Inventory()
    assert step_status("AddMember", inv)["status"] == "blind"
    assert step_status("AddMember", inv)["missing"] == ["group-mgmt"]


def test_telemetry_without_a_rule_is_visible_and_with_a_rule_is_detected():
    inv = Inventory.from_dict({"telemetry": ["group-mgmt"]})
    assert step_status("AddMember", inv)["status"] == "visible"
    inv = Inventory.from_dict({"telemetry": ["group-mgmt"], "rules": [{"edges": ["AddMember"]}]})
    assert step_status("AddMember", inv)["status"] == "detected"


def test_a_technique_id_covers_its_subtechniques():
    inv = Inventory.from_dict({"telemetry": ["group-mgmt"], "rules": [{"techniques": ["T1098"]}]})
    assert step_status("AddMember", inv)["status"] == "detected"        # AddMember is T1098


def test_any_of_options_and_quality_pick_the_best_available():
    inv = Inventory.from_dict({"telemetry": ["sysmon"]})
    s = step_status("HasSession", inv)
    assert s["status"] == "visible" and s["via"] == ["sysmon"] and s["quality"] == "medium"
    inv = Inventory.from_dict({"telemetry": ["sysmon", "edr"]})
    assert step_status("HasSession", inv)["quality"] == "high"


def test_path_takes_its_best_step_and_reports_the_first_detecting_hop():
    inv = Inventory.from_dict({"telemetry": ["logon", "edr"], "rules": [{"edges": ["HasSession"]}]})
    c = path_coverage(["CanRDP", "HasSession"], inv)
    assert c["status"] == "detected" and c["first_detected"] == 2 and c["hops"] == 2
    assert path_coverage(["MemberOf", "MemberOf"], inv)["steps"] == []        # structure is not an attack step


def test_unknown_telemetry_names_are_reported_not_ignored_silently():
    inv = Inventory.from_dict({"telemetry": ["group-mgmt", "splunk-forwarder"]})
    assert inv.unknown_telemetry == ["splunk-forwarder"] and inv.telemetry == {"group-mgmt"}


def test_analysis_counts_and_recommends_what_to_enable():
    rep = analyse(_lab(), Inventory.from_dict({"telemetry": ["logon"]}))
    # alice -AddMember-> DA is blind; ws -HasSession-> admin is blind; bob -CanRDP-> ws -HasSession-> admin is visible (the logon is collected)
    assert rep.paths_total == 3 and rep.counts == {"detected": 0, "visible": 1, "blind": 2}
    assert {e["telemetry"] for e in rep.enable} >= {"group-mgmt", "edr"}
    assert any(r["edge"] == "CanRDP" for r in rep.write_rules)


def test_pack_assumption_turns_visible_into_detected():
    base = Inventory.from_dict({"telemetry": ["group-mgmt", "logon", "edr"]})
    assert analyse(_lab(), base).counts["detected"] == 0
    rep = analyse(_lab(), base.with_pack())
    assert rep.counts["detected"] >= 1 and "AddMember" in PACK_EDGES


def test_every_edge_with_a_telemetry_requirement_names_real_telemetry():
    for edge, options in OBSERVABLE.items():
        assert edge in EDGE_REGISTRY or edge in ("AZOwner",), edge
        for keys, q, _why in options:
            assert q in ("high", "medium", "low") and keys and all(k in TELEMETRY for k in keys), (edge, keys)


def test_cli_template_and_fail_on_blind(tmp_path, capsys):
    assert main(["coverage", "--template"]) == 0
    assert "available_telemetry" in capsys.readouterr().out
    from pathcutter.snapshot import save_snapshot
    snap = tmp_path / "s.pcsnap"
    save_snapshot(_lab(), snap)
    tel = tmp_path / "t.json"
    tel.write_text(json.dumps({"telemetry": ["group-mgmt"]}))
    assert main(["coverage", str(snap), "--telemetry", str(tel), "--json", str(tmp_path / "o.json")]) == 0
    assert json.loads((tmp_path / "o.json").read_text())["counts"]["blind"] == 2
    assert main(["coverage", str(snap), "--telemetry", str(tel), "--fail-on-blind"]) == 2
    capsys.readouterr()
