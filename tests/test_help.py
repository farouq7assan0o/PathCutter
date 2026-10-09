"""The help system is the front door: it must stay complete, accurate and ASCII."""
import pytest

from pathcutter.cli import main
from pathcutter.edges import EDGE_REGISTRY
from pathcutter import ps_rules

COMMANDS = ["analyze", "score", "fix", "graph", "diff", "export", "snapshot", "check", "demo", "syntax", "help"]


def out_of(capsys, *argv):
    rc = main(list(argv))
    return rc, capsys.readouterr().out


def test_top_level_help_lists_every_command(capsys):
    with pytest.raises(SystemExit):
        main(["-h"])
    text = capsys.readouterr().out
    for c in COMMANDS:
        assert c in text, c
    assert text.isascii()


@pytest.mark.parametrize("cmd", ["analyze", "score", "fix", "graph", "diff", "export", "snapshot", "check", "demo"])
def test_every_command_help_has_examples(cmd, capsys):
    with pytest.raises(SystemExit):
        main([cmd, "-h"])
    text = capsys.readouterr().out
    assert "pathcutter" in text and ("Example" in text or "EXAMPLES" in text), cmd
    assert text.isascii()


def test_check_help_teaches_how_to_build_a_command(capsys):
    with pytest.raises(SystemExit):
        main(["check", "-h"])
    text = capsys.readouterr().out
    for needle in ("BUILD A COMMAND IN THREE STEPS", "--baseline", "--changes", "--powershell", "add-member",
                   "@members(GROUP)", "EXIT CODES", "pathcutter syntax"):
        assert needle in text, needle


def test_help_command_routes_to_command_and_topics(capsys):
    rc, text = out_of(capsys, "help", "check")
    assert rc == 0 and "--baseline" in text
    rc, text = out_of(capsys, "help", "syntax", "edges")
    assert rc == 0 and "GenericAll" in text
    rc, _ = out_of(capsys, "help", "nonsense")
    assert rc == 1


def test_syntax_reference_covers_every_topic(capsys):
    rc, text = out_of(capsys, "syntax")
    assert rc == 0 and text.isascii()
    for needle in ("CHANGE LANGUAGE", "POWERSHELL EXTRACTION", "EDGE TYPES", "POLICY FILE", "EXIT CODES"):
        assert needle in text, needle
    rc, text = out_of(capsys, "syntax", "bogus")
    assert "Unknown topic" in text


def test_syntax_lists_every_modeled_cmdlet_and_every_edge(capsys):
    _, ps_text = out_of(capsys, "syntax", "powershell")
    for name in ps_rules.SUPPORTED:
        assert name in ps_text, f"{name} missing from `pathcutter syntax powershell`"
    for name in ps_rules.NOTES:
        assert name in ps_text, name
    _, edge_text = out_of(capsys, "syntax", "edges")
    for key, et in EDGE_REGISTRY.items():
        if key == et.name:
            assert et.name in edge_text, et.name


def test_documented_examples_actually_parse():
    """The examples printed in the syntax help must be valid changes."""
    from pathcutter.changes import parse_text
    text = """add-member alice "DOMAIN ADMINS"
grant SUPPORT GenericWrite SVC_SCOM
revoke bob WriteDacl "SERVER ADMINS"
revoke-all stannis kingslanding
local-admin DEVOPS SRV01
unconstrained SRV02
create user newhire
add-member newhire HELPDESK
move alice "Admins"
delete olduser
add-member "@members(HELPDESK)" "DB ADMINS"
"""
    assert len(parse_text(text, "help")) == 11


def test_demo_lab_writes_a_checkable_baseline(tmp_path, capsys):
    snap = tmp_path / "goad.pcsnap"
    rc, text = out_of(capsys, "demo", "--lab", "goad-sevenkingdoms", "-o", str(tmp_path), "--snapshot", str(snap))
    assert rc == 0 and snap.exists() and "26 nodes" in text and "Try:" in text
    assert main(["check", "--baseline", str(snap), "-q", "--change", "create user newhire",
                 "--change", "add-member newhire DragonStone"]) == 2
