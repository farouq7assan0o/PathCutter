"""Tests for remediation plan generation and CLI."""
from pathcutter.pathfinder import find_all_paths
from pathcutter.choke import find_chokepoints
from pathcutter.remediate import build_plan
from pathcutter.cli import main


def test_build_plan(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    plan = build_plan(choke)
    assert len(plan.fixes) > 0
    assert plan.total_paths > 0
    assert plan.paths_eliminated > 0


def test_plan_categories(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    plan = build_plan(choke)
    assert len(plan.categories) > 0
    total_in_cats = sum(len(v) for v in plan.categories.values())
    assert total_in_cats == len(plan.fixes)


def test_plan_top_n(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    plan = build_plan(choke, top_n=1)
    assert len(plan.fixes) == 1


def test_powershell_script(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    plan = build_plan(choke)
    script = plan.powershell_script()
    assert "Import-Module ActiveDirectory" in script
    assert "Pathcutter Remediation Script" in script
    assert "ROLLBACK" in script


def test_powershell_no_rollback(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    plan = build_plan(choke)
    script = plan.powershell_script(include_rollback=False)
    assert "ROLLBACK" not in script


def test_markdown_summary(tiny_graph):
    da_id = "S-1-5-21-1234-512"
    report = find_all_paths(tiny_graph, {da_id})
    choke = find_chokepoints(tiny_graph, report)
    plan = build_plan(choke)
    md = plan.markdown_summary()
    assert "Remediation Plan" in md
    assert "|" in md


def test_empty_plan(tiny_graph):
    from pathcutter.pathfinder import PathReport
    from pathcutter.choke import ChokeReport
    empty_report = PathReport(paths=[], source_nodes=set(), target_nodes=set())
    empty_choke = ChokeReport(fixes=[], total_paths=0, paths_after_fixes=0)
    plan = build_plan(empty_choke)
    assert len(plan.fixes) == 0
    assert plan.elimination_pct == 0.0
    script = plan.powershell_script()
    assert "Pathcutter Remediation Script" in script


def test_cli_no_args(capsys):
    ret = main([])
    assert ret == 1


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit:
        pass
    captured = capsys.readouterr()
    assert "pathcutter" in captured.out
