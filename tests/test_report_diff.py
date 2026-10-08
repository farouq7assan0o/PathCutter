"""Tests for HTML report generation and snapshot diffing."""
from pathcutter.pathfinder import find_all_paths
from pathcutter.scoring import score_nodes, score_posture
from pathcutter.choke import find_chokepoints
from pathcutter.report import generate_html_report
from pathcutter.diff import compare_snapshots
from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType


def _analyze(graph):
    targets = graph.tier0_nodes
    report = find_all_paths(graph, targets)
    posture = score_posture(graph, report)
    scores = score_nodes(graph, report)
    choke = find_chokepoints(graph, report)
    return report, posture, scores, choke


def test_html_report_generated(tiny_graph):
    report, posture, scores, choke = _analyze(tiny_graph)
    html = generate_html_report(tiny_graph, report, posture, scores, choke)
    assert "<!DOCTYPE html>" in html
    assert "Pathcutter" in html
    assert "d3" in html.lower()


def test_html_contains_score(tiny_graph):
    report, posture, scores, choke = _analyze(tiny_graph)
    html = generate_html_report(tiny_graph, report, posture, scores, choke)
    assert str(posture.score) in html
    assert posture.grade in html


def test_html_contains_fixes(tiny_graph):
    report, posture, scores, choke = _analyze(tiny_graph)
    html = generate_html_report(tiny_graph, report, posture, scores, choke)
    assert "fixesData" in html
    assert "Remediation" in html


def test_html_contains_graph_data(tiny_graph):
    report, posture, scores, choke = _analyze(tiny_graph)
    html = generate_html_report(tiny_graph, report, posture, scores, choke)
    assert "graphData" in html
    assert "nodes" in html


# ---- Diff tests ----

def _build_fixed_graph(original):
    """Build a copy with GenericAll edges removed (simulating a fix)."""
    g = AttackGraph()
    for node in original.all_nodes():
        g.add_node(node)
    for u, v, data in original.all_edges():
        if data.get("edge_type") != "GenericAll":
            g.add_edge(ADEdge(u, v, data.get("edge_type", ""), data.get("inherited", False)))
    g.classify_tiers()
    return g


def test_diff_same_graph(tiny_graph):
    result = compare_snapshots(tiny_graph, tiny_graph)
    assert result.score_delta == 0
    assert result.grade_before == result.grade_after


def test_diff_after_fix(tiny_graph):
    fixed = _build_fixed_graph(tiny_graph)
    result = compare_snapshots(tiny_graph, fixed)
    assert result.paths_after <= result.paths_before
    assert len(result.eliminated_edges) > 0


def test_diff_summary(tiny_graph):
    result = compare_snapshots(tiny_graph, tiny_graph)
    summary = result.summary
    assert "Score" in summary
    assert "Paths" in summary
    assert "Grade" in summary


def test_diff_improved_flag(tiny_graph):
    fixed = _build_fixed_graph(tiny_graph)
    result = compare_snapshots(tiny_graph, fixed)
    if result.paths_after < result.paths_before:
        assert result.improved or result.score_delta <= 0
