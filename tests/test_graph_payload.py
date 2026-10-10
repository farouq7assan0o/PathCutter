"""Tests for the large-graph payload builder and report hardening."""
import json
import re

from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType
from pathcutter.pathfinder import find_all_paths
from pathcutter.scoring import score_nodes, score_posture
from pathcutter.choke import find_chokepoints
from pathcutter.report import (
    _build_graph_json, _safe_json, _e, generate_html_report, CLUSTER_MIN,
)


def _fan_in_graph(n_users: int, user_prefix: str = "USER"):
    g = AttackGraph()
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP))
    g.add_node(ADNode("S-grp", "HELPDESK@CORP.LOCAL", NodeType.GROUP))
    g.add_edge(ADEdge("S-grp", "S-da", "GenericAll"))
    for i in range(n_users):
        uid = f"S-u{i}"
        g.add_node(ADNode(uid, f"{user_prefix}{i}@CORP.LOCAL", NodeType.USER))
        g.add_edge(ADEdge(uid, "S-grp", "MemberOf"))
    g.classify_tiers()
    report = find_all_paths(g, {"S-da"})
    return g, report, score_nodes(g, report)


def test_identical_leaf_users_collapse_into_one_cluster():
    g, report, scores = _fan_in_graph(12)
    payload, edge_index = _build_graph_json(g, report, scores)
    clusters = [n for n in payload["nodes"] if n["type"] == "Cluster"]
    assert len(clusters) == 1
    assert clusters[0]["count"] == 12
    assert payload["meta"]["hidden_in_clusters"] == 12
    # 12 users + group + DA = 14 path nodes, but only cluster + group + DA are drawn
    assert len(payload["nodes"]) == 3
    # every link index must point at a real node
    n = len(payload["nodes"])
    for s, t, ti, _p in payload["links"]:
        assert 0 <= s < n and 0 <= t < n
        assert 0 <= ti < len(payload["edgeTypes"])


def test_small_groups_are_not_clustered():
    g, report, scores = _fan_in_graph(CLUSTER_MIN - 1)
    payload, _ = _build_graph_json(g, report, scores)
    assert not [n for n in payload["nodes"] if n["type"] == "Cluster"]
    assert payload["meta"]["hidden_in_clusters"] == 0


def test_fix_endpoints_are_never_clustered():
    g, report, scores = _fan_in_graph(12)
    # Protect one user as if a fix targeted its edge: it must stay a real node.
    payload, edge_index = _build_graph_json(g, report, scores, protected={"S-u3"})
    ids = {n["id"] for n in payload["nodes"]}
    assert "S-u3" in ids
    assert ("S-u3", "S-grp", "MemberOf") in edge_index


def test_edge_index_maps_chokepoint_fix_to_a_link():
    g, report, scores = _fan_in_graph(12)
    choke = find_chokepoints(g, report, max_fixes=3)
    protected = {f.source_id for f in choke.fixes} | {f.target_id for f in choke.fixes}
    payload, edge_index = _build_graph_json(g, report, scores, protected=protected)
    for f in choke.fixes:
        li = edge_index.get((f.source_id, f.target_id, f.edge_type))
        assert li is not None and 0 <= li < len(payload["links"])


def test_node_cap_keeps_tier0_and_flags_truncation():
    g, report, scores = _fan_in_graph(40)
    payload, _ = _build_graph_json(g, report, scores, max_nodes=5)
    assert payload["meta"]["truncated"] is True
    assert any(n["tier"] == 0 for n in payload["nodes"])
    n = len(payload["nodes"])
    assert all(0 <= s < n and 0 <= t < n for s, t, _, _p in payload["links"])


def test_names_are_html_escaped_in_payload():
    g, report, scores = _fan_in_graph(3, user_prefix="<img src=x onerror=alert(1)>")
    payload, _ = _build_graph_json(g, report, scores)
    blob = json.dumps(payload)
    assert "<img" not in blob
    assert "&lt;img" in blob


def test_safe_json_cannot_close_script_tag():
    out = _safe_json({"name": "</script><script>alert(1)</script>", "x": "a&b"})
    assert "</script" not in out.lower()
    assert "<" not in out and ">" not in out
    assert json.loads(out)["name"] == "</script><script>alert(1)</script>"


def test_report_with_hostile_names_has_no_script_breakout():
    g, report, scores = _fan_in_graph(8, user_prefix="</script><script>alert(1)</script>")
    posture = score_posture(g, report)
    choke = find_chokepoints(g, report, max_fixes=3)
    html = generate_html_report(g, report, posture, scores, choke)
    assert "<script>alert(1)" not in html
    assert html.lower().count("</script>") == html.lower().count("<script")


def test_report_ships_canvas_engine_and_fix_links():
    g, report, scores = _fan_in_graph(8)
    posture = score_posture(g, report)
    choke = find_chokepoints(g, report, max_fixes=3)
    html = generate_html_report(g, report, posture, scores, choke)
    assert "function drawGraph" in html and "graph-minimap" in html
    assert "graph_link" in html
    # the template placeholder must have been substituted, not emitted literally
    assert "{graph_js}" not in html
    m = re.search(r"const fixesData = (\[.*?\]);\n", html, re.S)
    assert m and "graph_link" in m.group(1)


def test_nodes_and_links_say_whether_they_are_on_an_attack_path():
    """The viewer's "attack paths only" mode relies on these flags; context added around the paths must not be flagged."""
    g, report, scores = _fan_in_graph(3)
    from pathcutter.graph import ADEdge, ADNode, NodeType
    g.add_node(ADNode("bystander", "BYSTANDER@C.L", NodeType.USER, "C.L"))
    g.add_node(ADNode("other", "OTHER@C.L", NodeType.GROUP, "C.L"))
    g.add_edge(ADEdge("bystander", "other", "MemberOf"))
    payload, _ = _build_graph_json(g, report, scores)
    by_id = {n["id"]: n for n in payload["nodes"]}
    assert by_id["bystander"]["p"] == 0 and by_id["other"]["p"] == 0
    assert any(n["p"] for n in payload["nodes"] if n["type"] != "Cluster") or any(n["p"] for n in payload["nodes"])
    assert payload["meta"]["path_nodes"] == sum(1 for n in payload["nodes"] if n["p"])
    assert payload["meta"]["path_links"] == sum(1 for lk in payload["links"] if lk[3])
    assert all(lk[3] in (0, 1) for lk in payload["links"])
