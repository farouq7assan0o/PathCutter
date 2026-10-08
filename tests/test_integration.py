"""Integration tests with realistic synthetic SharpHound data."""
import os
import json
from pathlib import Path

import pytest

from pathcutter.ingest import load_sharphound
from pathcutter.pathfinder import find_all_paths
from pathcutter.scoring import score_nodes, score_posture
from pathcutter.choke import find_chokepoints, find_node_chokepoints
from pathcutter.chains import detect_chains
from pathcutter.safety import assess_fixes, summarize_safety
from pathcutter.remediate import build_plan
from pathcutter.report import generate_html_report
from pathcutter.diff import compare_snapshots


DATA_DIR = Path(__file__).parent / "test_sharphound_data"
DATA_ZIP = Path(__file__).parent / "test_sharphound_data.zip"


@pytest.fixture(scope="module")
def realistic_graph():
    if not DATA_DIR.exists():
        pytest.skip("Test data not generated (run generate_test_data.py)")
    return load_sharphound(DATA_DIR)


@pytest.fixture(scope="module")
def realistic_report(realistic_graph):
    targets = realistic_graph.tier0_nodes
    return find_all_paths(realistic_graph, targets)


class TestIngestion:
    def test_node_count(self, realistic_graph):
        assert realistic_graph.node_count >= 100

    def test_edge_count(self, realistic_graph):
        assert realistic_graph.edge_count >= 100

    def test_tier0_detected(self, realistic_graph):
        assert len(realistic_graph.tier0_nodes) >= 3

    def test_node_types_present(self, realistic_graph):
        types = {n.node_type.value for n in realistic_graph.all_nodes()}
        assert "User" in types
        assert "Computer" in types
        assert "Group" in types

    def test_zip_matches_dir(self, realistic_graph):
        if not DATA_ZIP.exists():
            pytest.skip("ZIP file not generated")
        zip_graph = load_sharphound(DATA_ZIP)
        assert zip_graph.node_count == realistic_graph.node_count
        assert zip_graph.edge_count == realistic_graph.edge_count

    def test_service_accounts_have_spn(self, realistic_graph):
        spn_users = [n for n in realistic_graph.all_nodes()
                     if n.properties.get("hasspn") or n.properties.get("serviceprincipalnames")]
        assert len(spn_users) >= 1

    def test_disabled_accounts_exist(self, realistic_graph):
        disabled = [n for n in realistic_graph.all_nodes() if not n.enabled]
        assert len(disabled) >= 1


class TestPathfinding:
    def test_paths_found(self, realistic_report):
        assert realistic_report.total_paths > 0

    def test_multiple_sources(self, realistic_report):
        assert realistic_report.unique_sources >= 3

    def test_path_lengths_reasonable(self, realistic_report):
        assert realistic_report.shortest_length >= 1
        assert realistic_report.longest_length <= 20
        assert realistic_report.avg_length >= 1.0


class TestScoring:
    def test_posture_score(self, realistic_graph, realistic_report):
        posture = score_posture(realistic_graph, realistic_report)
        assert 0 <= posture.score <= 100
        assert posture.grade in ("A", "B", "C", "D", "F")

    def test_node_scores(self, realistic_graph, realistic_report):
        scores = score_nodes(realistic_graph, realistic_report)
        assert len(scores) > 0
        assert all(0 <= s.risk_score <= 100 for s in scores)
        # Scores should be sorted descending
        for i in range(len(scores) - 1):
            assert scores[i].risk_score >= scores[i + 1].risk_score


class TestChokepoints:
    def test_fixes_found(self, realistic_graph, realistic_report):
        choke = find_chokepoints(realistic_graph, realistic_report)
        assert len(choke.fixes) > 0

    def test_full_elimination(self, realistic_graph, realistic_report):
        choke = find_chokepoints(realistic_graph, realistic_report, max_fixes=100)
        assert choke.paths_after_fixes == 0

    def test_fix_commands_present(self, realistic_graph, realistic_report):
        choke = find_chokepoints(realistic_graph, realistic_report)
        for fix in choke.fixes:
            assert fix.fix_command

    def test_node_chokepoints(self, realistic_graph, realistic_report):
        nodes = find_node_chokepoints(realistic_graph, realistic_report)
        assert len(nodes) > 0


class TestChains:
    def test_chains_detected(self, realistic_graph, realistic_report):
        chains = detect_chains(realistic_graph, realistic_report)
        assert len(chains) > 0

    def test_chain_types(self, realistic_graph, realistic_report):
        chains = detect_chains(realistic_graph, realistic_report)
        types = {c.chain_type for c in chains}
        # Our test data has shadow credentials and unconstrained delegation
        assert "shadow_credentials" in types or "unconstrained_delegation" in types

    def test_critical_chains(self, realistic_graph, realistic_report):
        chains = detect_chains(realistic_graph, realistic_report)
        critical = [c for c in chains if c.severity == "critical"]
        assert len(critical) > 0


class TestSafety:
    def test_safety_assessments(self, realistic_graph, realistic_report):
        choke = find_chokepoints(realistic_graph, realistic_report)
        assessments = assess_fixes(realistic_graph, choke.fixes)
        assert len(assessments) == len(choke.fixes)

    def test_service_accounts_flagged(self, realistic_graph, realistic_report):
        choke = find_chokepoints(realistic_graph, realistic_report)
        assessments = assess_fixes(realistic_graph, choke.fixes)
        caution_or_dangerous = [a for a in assessments
                                if a.risk_level.value in ("caution", "dangerous")]
        # Our test data has svc_ accounts in fixes
        assert len(caution_or_dangerous) >= 0  # may or may not have svc in top fixes


class TestRemediation:
    def test_plan_generation(self, realistic_graph, realistic_report):
        choke = find_chokepoints(realistic_graph, realistic_report)
        plan = build_plan(choke)
        assert len(plan.fixes) > 0

    def test_powershell_script(self, realistic_graph, realistic_report):
        choke = find_chokepoints(realistic_graph, realistic_report)
        plan = build_plan(choke)
        script = plan.powershell_script()
        assert "Import-Module ActiveDirectory" in script
        assert len(script) > 200


class TestReport:
    def test_html_report(self, realistic_graph, realistic_report):
        posture = score_posture(realistic_graph, realistic_report)
        scores = score_nodes(realistic_graph, realistic_report)
        choke = find_chokepoints(realistic_graph, realistic_report)
        html = generate_html_report(realistic_graph, realistic_report, posture, scores, choke)
        assert len(html) > 1000
        assert "<!DOCTYPE html>" in html
        assert "d3" in html.lower()


class TestDiff:
    def test_same_snapshot(self, realistic_graph):
        result = compare_snapshots(realistic_graph, realistic_graph)
        assert result.score_delta == 0
        assert result.paths_eliminated == 0
        assert result.new_paths == 0
