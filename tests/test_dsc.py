"""DSC extraction."""
from pathlib import Path

from pathcutter.extractors.dsc import extract

DSC = Path(__file__).parent / "data" / "iac" / "directory.dsc.ps1"


def test_the_sample_configuration():
    specs, warns = extract(DSC.read_text(encoding="utf-8"), "directory.dsc.ps1")
    got = [(s.op, s.source, s.edge_type, s.target, s.deny) for s in specs if s.op != "create"]
    assert ("add", "alice", "MemberOf", "Helpdesk", False) in got and ("add", "bob", "MemberOf", "Helpdesk", False) in got
    assert ("remove", "eve", "MemberOf", "Helpdesk", False) in got
    assert ("delete", "Legacy", "", "", False) in got
    assert ("add", "hank", "MemberOf", "Auditors", False) in got
    assert ("add", "helpdesk", "GenericAll", "Svc Backup", False) in got
    assert ("add", "interns", "GenericAll", "Svc Backup", True) in got, "an Allow and a Deny entry must stay distinct"
    assert ("add", "helpdesk", "AdminTo", "SRV01", False) in got and ("add", "helpdesk", "AdminTo", "SRV02", False) in got
    assert ("create", "newhire", "if-missing", "", False) in [(s.op, s.source, s.edge_type, s.target, s.deny) for s in specs]
    assert not any(s.source == "ops" for s in specs), "a Node that is a variable must not be guessed"
    msgs = " | ".join(w.message for w in warns)
    assert "exact membership" in msgs and "$Config.Printers" in msgs
    assert "cannot be resolved" in msgs and "$AllNodes.NodeName" in msgs
    assert not any("WindowsFeature" in w.message for w in warns)


def test_origin_lines_point_at_the_resource():
    specs, _ = extract(DSC.read_text(encoding="utf-8"), "d.ps1")
    s = next(x for x in specs if x.source == "alice")
    assert s.origin == "d.ps1:6"


def test_comments_and_strings_with_braces_do_not_break_blocks():
    text = "Configuration C {\n Node 'A' {\n  ADGroup 'x' { # a } comment\n   GroupName = 'G}'\n   MembersToInclude = 'u'\n  }\n  ADGroup 'y' {\n   GroupName = 'H'\n   MembersToInclude = 'v'\n  }\n }\n}\n"
    specs, _ = extract(text, "c.ps1")
    assert {(s.source, s.target) for s in specs if s.op == "add"} == {("u", "G}"), ("v", "H")}
