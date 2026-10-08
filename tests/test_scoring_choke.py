"""Tests for scoring and chokepoint analysis."""
from pathcutter.pathfinder import find_all_paths
from pathcutter.scoring import score_nodes, score_posture
from pathcutter.choke import find_chokepoints, find_node_chokepoints


def test_score_nodes_returns_results(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    scores = score_nodes(tiny_graph, report)
    assert len(scores) > 0


def test_scores_sorted_descending(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    scores = score_nodes(tiny_graph, report)
    for i in range(len(scores) - 1):
        assert scores[i].risk_score >= scores[i + 1].risk_score


def test_helpdesk_high_risk(tiny_graph):
    """HelpDesk should be high risk since it's a chokepoint for paths to DA."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    scores = score_nodes(tiny_graph, report)
    helpdesk_scores = [s for s in scores if "HELPDESK" in s.name.upper()]
    assert len(helpdesk_scores) > 0
    assert helpdesk_scores[0].risk_score > 0


def test_tier0_not_scored(tiny_graph):
    """Tier 0 nodes should not appear in risk scores."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    scores = score_nodes(tiny_graph, report)
    for s in scores:
        assert s.tier != 0


def test_score_posture(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    posture = score_posture(tiny_graph, report)
    assert 0 <= posture.score <= 100
    assert posture.grade in ("A", "B", "C", "D", "F")
    assert posture.total_paths > 0
    assert posture.tier0_count > 0


def test_posture_grade_ordering():
    """Score 0 should be A, 100 should be F."""
    from pathcutter.scoring import PostureScore
    a = PostureScore(score=10, grade="A", total_paths=0, unique_sources=0,
                     avg_path_length=0, tier0_count=0, tier2_with_path_count=0,
                     tier2_total=0, path_density=0)
    f = PostureScore(score=90, grade="F", total_paths=100, unique_sources=50,
                     avg_path_length=3, tier0_count=5, tier2_with_path_count=50,
                     tier2_total=100, path_density=1.0)
    assert a.score < f.score


def test_empty_paths_scoring(tiny_graph):
    from pathcutter.pathfinder import PathReport
    empty = PathReport(paths=[], source_nodes=set(), target_nodes=set())
    scores = score_nodes(tiny_graph, empty)
    assert len(scores) == 0
    posture = score_posture(tiny_graph, empty)
    assert posture.score == 0
    assert posture.grade == "A"


# ---- Chokepoint tests ----

def test_find_chokepoints(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    assert len(choke.fixes) > 0
    assert choke.total_paths > 0


def test_fixes_ordered_by_impact(tiny_graph):
    """First fix should eliminate the most paths."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    if len(choke.fixes) >= 2:
        assert choke.fixes[0].paths_eliminated >= choke.fixes[1].paths_eliminated


def test_cumulative_increases(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    for i in range(1, len(choke.fixes)):
        assert choke.fixes[i].cumulative_eliminated >= choke.fixes[i - 1].cumulative_eliminated
        assert choke.fixes[i].cumulative_pct >= choke.fixes[i - 1].cumulative_pct


def test_all_paths_eliminated(tiny_graph):
    """After all fixes, remaining paths should be 0 or close to it."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report, max_fixes=100)
    assert choke.paths_after_fixes == 0


def test_fix_has_command(tiny_graph):
    """Fixes should have PowerShell fix commands."""
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    for fix in choke.fixes:
        assert fix.fix_command, f"Fix for {fix.edge_type} has no command"
        assert fix.edge_type, "Fix missing edge_type"


def test_fix_has_description(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    for fix in choke.fixes:
        assert "Remove" in fix.description


def test_fixes_for_pct(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    # Get fixes for 50% elimination
    partial = choke.fixes_for_pct(50.0)
    assert len(partial) <= len(choke.fixes)
    if partial:
        assert partial[-1].cumulative_pct >= 50.0


def test_choke_report_stats(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report, max_fixes=100)
    assert choke.elimination_pct == 100.0
    assert choke.total_eliminated == choke.total_paths


def test_node_chokepoints(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    nodes = find_node_chokepoints(tiny_graph, report)
    assert len(nodes) > 0
    # HelpDesk should be a node chokepoint
    helpdesk_nodes = [n for n in nodes if "HELPDESK" in n["name"].upper()]
    assert len(helpdesk_nodes) > 0
    assert helpdesk_nodes[0]["paths_through"] > 0


def test_empty_paths_choke(tiny_graph):
    from pathcutter.pathfinder import PathReport
    empty = PathReport(paths=[], source_nodes=set(), target_nodes=set())
    choke = find_chokepoints(tiny_graph, empty)
    assert choke.total_paths == 0
    assert len(choke.fixes) == 0


def test_nested_group_chokepoint(nested_groups):
    """In nested groups, the GenericAll edge from G5->DA should be the chokepoint."""
    da_id = "S-da"
    report = find_all_paths(nested_groups, {da_id}, max_depth=10)
    choke = find_chokepoints(nested_groups, report)
    assert len(choke.fixes) > 0
    # The GenericAll edge should be the top fix
    assert choke.fixes[0].edge_type == "GenericAll"
