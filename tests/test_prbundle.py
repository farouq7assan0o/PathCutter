"""Fix-as-code PR bundle: correct per-edge change-line direction, re-verifiable fixes, and the apply scripts."""
import pytest

from pathcutter.choke import Fix
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.prbundle import write_pr_bundle
from pathcutter.remediate import RemediationPlan


def _graph():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@C.L", NodeType.GROUP, "C.L"))
    g.add_node(ADNode("ws", "WS01@C.L", NodeType.COMPUTER, "C.L"))
    g.add_node(ADNode("svc", "SVC@C.L", NodeType.USER, "C.L"))
    g.add_node(ADNode("grp", "HELPDESK@C.L", NodeType.GROUP, "C.L"))
    g.add_edge(ADEdge("ws", "svc", "HasSession"))        # computer -> user
    g.add_edge(ADEdge("grp", "da", "GenericAll"))        # ACL: principal -> target
    g.classify_tiers()
    return g


def _fix(rank, sid, tid, edge, sname, tname):
    return Fix(source_id=sid, target_id=tid, edge_type=edge, source_name=sname, target_name=tname,
               paths_eliminated=5, cumulative_eliminated=5, cumulative_pct=100.0, fix_command="# fix", mitre="T1003",
               rank=rank)


def _plan(fixes):
    return RemediationPlan(fixes=fixes, total_paths=5, paths_eliminated=5,
                           categories={"c": fixes}, warnings=[])


def test_hassession_line_is_reversed_acl_is_not(tmp_path):
    g = _graph()
    plan = _plan([
        _fix(1, "ws", "svc", "HasSession", "WS01@C.L", "SVC@C.L"),
        _fix(2, "grp", "da", "GenericAll", "HELPDESK@C.L", "DOMAIN ADMINS@C.L"),
    ])
    write_pr_bundle(plan, tmp_path, graph=g, platform="none")
    lines = (tmp_path / "fixes.changes").read_text().splitlines()
    revokes = [ln for ln in lines if ln.startswith("revoke")]
    # HasSession: object must be the computer, so principal is the user (reversed from the edge)
    assert 'revoke "SVC@C.L" HasSession "WS01@C.L"' in revokes
    # ACL: principal -> target, as the edge runs
    assert 'revoke "HELPDESK@C.L" GenericAll "DOMAIN ADMINS@C.L"' in revokes


def test_non_revocable_edge_is_commented(tmp_path):
    g = _graph()
    g.add_node(ADNode("dom", "C.L", NodeType.DOMAIN, "C.L"))
    plan = _plan([_fix(1, "grp", "dom", "ADCSESC1", "HELPDESK@C.L", "C.L")])
    write_pr_bundle(plan, tmp_path, graph=g, platform="none")
    text = (tmp_path / "fixes.changes").read_text()
    assert "not expressible as a change line" in text
    assert not [ln for ln in text.splitlines() if ln.startswith("revoke")]   # nothing emitted as a revoke


def test_bundle_files_and_platform_opener(tmp_path):
    g = _graph()
    plan = _plan([_fix(1, "grp", "da", "GenericAll", "HELPDESK@C.L", "DOMAIN ADMINS@C.L")])
    written = write_pr_bundle(plan, tmp_path, graph=g, platform="github", base="develop")
    names = {p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] for p in written}
    assert {"remediation.ps1", "fixes.changes", "PR.md", "apply.sh", "apply.ps1"} <= names
    sh = (tmp_path / "apply.sh").read_text()
    assert "gh pr create" in sh and 'BASE="${BASE:-develop}"' in sh
    pr = (tmp_path / "PR.md").read_text()
    assert "risk reduction" in pr and "GenericAll" in pr


def test_gitlab_uses_glab_none_has_no_opener(tmp_path):
    g = _graph()
    plan = _plan([_fix(1, "grp", "da", "GenericAll", "HELPDESK@C.L", "DOMAIN ADMINS@C.L")])
    write_pr_bundle(plan, tmp_path, graph=g, platform="gitlab")
    assert "glab mr create" in (tmp_path / "apply.sh").read_text()
    import shutil
    out2 = tmp_path / "none"
    write_pr_bundle(plan, out2, graph=g, platform="none")
    sh = (out2 / "apply.sh").read_text()
    assert "gh pr create" not in sh and "glab mr create" not in sh


def test_bad_platform_rejected(tmp_path):
    g = _graph()
    plan = _plan([_fix(1, "grp", "da", "GenericAll", "HELPDESK@C.L", "DOMAIN ADMINS@C.L")])
    with pytest.raises(ValueError):
        write_pr_bundle(plan, tmp_path, graph=g, platform="bitbucket")
