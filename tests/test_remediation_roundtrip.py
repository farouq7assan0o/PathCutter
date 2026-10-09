"""Closed loop: PathCutter's own remediation script, checked by PathCutter before anyone runs it."""
import pytest

from oracle import oracle_hops
from pathcutter.changes import from_powershell, resolve_changes
from pathcutter.choke import find_chokepoints
from pathcutter.edges import EDGE_REGISTRY
from pathcutter.impact import analyze_impact
from pathcutter.ingest import load_sharphound
from pathcutter.labs import write_lab
from pathcutter.pathfinder import find_all_paths
from pathcutter.policy import Policy, evaluate
from pathcutter.remediate import build_plan


@pytest.fixture
def lab(tmp_path):
    write_lab("goad-sevenkingdoms", tmp_path)
    return load_sharphound(tmp_path)


def plan_for(lab, n=6):
    choke = find_chokepoints(lab, find_all_paths(lab, lab.tier0_nodes), max_fixes=n)
    return choke, build_plan(choke).powershell_script()


def test_generated_script_carries_a_machine_readable_twin_of_every_fix(lab):
    choke, script = plan_for(lab)
    assert script.count("# pc: revoke ") == len(choke.fixes)


def test_script_effect_equals_applying_the_fixes_directly(lab):
    choke, script = plan_for(lab)
    specs, warns = from_powershell(script, "remediation.ps1")
    resolved, errors = resolve_changes(lab, specs)
    assert not errors and len(resolved) == len(choke.fixes)
    report = analyze_impact(lab, resolved, unmodeled=warns)
    evaluate(report, Policy(), resolved)
    assert report.verdict == "pass" and report.totals["newly_exposed"] == 0

    direct = lab.clone()
    for fx in choke.fixes:
        direct.remove_edge(fx.source_id, fx.target_id, fx.edge_type)
    direct.retier()
    before = set(oracle_hops(lab))
    after = set(oracle_hops(direct))
    assert report.totals["newly_secured"] == len(before - after)
    assert report.posture["after"]["paths"] <= report.posture["before"]["paths"]


def test_gate_notices_the_template_is_broader_than_the_edge_it_describes(lab):
    _, script = plan_for(lab)
    _, warns = from_powershell(script, "remediation.ps1")
    assert any("removes ALL access entries" in w.message for w in warns)


def test_directive_free_script_is_still_understood(lab):
    choke, script = plan_for(lab)
    stripped = "\n".join(l for l in script.splitlines() if not l.startswith("# pc:"))
    specs, _ = from_powershell(stripped, "remediation.ps1")
    assert len(specs) == len(choke.fixes) and all(s.op == "remove" for s in specs)


ACL_TEMPLATE_EXPECT = {      # edge type -> the revoke the parser must derive from the template alone
    "GenericAll": "*", "GenericWrite": "GenericWrite", "WriteOwner": "WriteOwner", "WriteDacl": "WriteDacl",
    "ForceChangePassword": "ForceChangePassword", "AddMember": "AddMember", "WriteSPN": "WriteSPN",
    "WritePKIEnrollmentFlag": "WritePKIEnrollmentFlag", "WritePKINameFlag": "WritePKINameFlag",
}


@pytest.mark.parametrize("edge,expected", sorted(ACL_TEMPLATE_EXPECT.items()))
def test_every_acl_fix_template_is_parsed_to_the_right_revoke(edge, expected):
    tpl = EDGE_REGISTRY[edge].fix_template
    text = tpl.format(source_name="HELPDESK@CORP.LOCAL", target_name="SVC@CORP.LOCAL", target_dn="SVC@CORP.LOCAL",
                      source_dn="HELPDESK@CORP.LOCAL", domain="CORP.LOCAL", target_spn="", gpo_dn="SVC@CORP.LOCAL")
    specs, _ = from_powershell(text, "t.ps1")
    assert [(s.op, s.source, s.edge_type, s.target) for s in specs] == [("remove", "HELPDESK@CORP.LOCAL", expected, "SVC@CORP.LOCAL")]


def test_every_template_is_either_understood_or_reported():
    """No fix template PathCutter can emit may be silently ignored by its own gate."""
    for name, et in EDGE_REGISTRY.items():
        if et.name != name or "Get-Acl" not in et.fix_template and "$acl" not in et.fix_template:
            continue
        text = et.fix_template.format(source_name="A@C", target_name="B@C", target_dn="B@C", source_dn="A@C",
                                      domain="C", target_spn="", gpo_dn="B@C")
        specs, warns = from_powershell(text, "t.ps1")
        assert specs or warns, f"{name}: template is silently ignored"
