"""Change-set parsing, PowerShell extraction, name resolution, apply/undo."""
import json

import pytest

from pathcutter.changes import (
    ChangeSetError, DOMAIN_SENTINEL, apply_change, canonical_edge, from_powershell, load_changes,
    parse_json, parse_line, parse_text, resolve_changes, undo_change,
)
from pathcutter.graph import ADNode, NodeType


# ------------------------------------------------------------------ DSL

def test_add_member_parses_to_memberof():
    s = parse_line("add-member alice HELPDESK", 1, "t:1")
    assert (s.op, s.edge_type, s.source, s.target) == ("add", "MemberOf", "alice", "HELPDESK")


def test_quotes_notes_and_backslashes():
    s = parse_line('add-member CORP\\alice "DOMAIN ADMINS"   # CHG-1 urgent fix', 1, "t:1")
    assert s.source == "CORP\\alice" and s.target == "DOMAIN ADMINS"
    assert s.note == "CHG-1 urgent fix"


def test_generic_grant_canonicalises_edge_name():
    s = parse_line("grant bob genericall svc_backup", 1, "t:1")
    assert s.edge_type == "GenericAll" and s.op == "add"
    assert parse_line("revoke bob WriteDacl x", 1, "t:1").op == "remove"


def test_dcsync_without_domain_uses_sentinel():
    assert parse_line("grant-dcsync mallory", 1, "t:1").target == DOMAIN_SENTINEL


def test_create_requires_known_type():
    s = parse_line("create user newhire", 1, "t:1")
    assert (s.op, s.new_type, s.source) == ("create", "user", "newhire")
    with pytest.raises(ValueError):
        parse_line("create widget x", 1, "t:1")


def test_blank_and_comment_lines_are_skipped():
    assert parse_line("", 1, "t") is None and parse_line("   # nothing", 1, "t") is None


def test_all_errors_reported_together_with_suggestions():
    text = "add-membr x y\ngrant a b\ngrant a NopeEdge c\nadd-member 'unterminated y\n"
    with pytest.raises(ChangeSetError) as ei:
        parse_text(text, "f.changes")
    msgs = "\n".join(ei.value.errors)
    assert len(ei.value.errors) == 4
    assert "did you mean add-member" in msgs and "takes 3" in msgs and "unknown edge type" in msgs
    assert "f.changes:1" in msgs


def test_indexes_are_sequential_and_skip_comments():
    specs = parse_text("# c\nadd-member a b\n\nadd-member c d\n", "f")
    assert [s.index for s in specs] == [1, 2]
    assert [s.origin for s in specs] == ["f:2", "f:4"]


def test_canonical_edge_is_case_insensitive():
    assert canonical_edge("memberof") == "MemberOf" and canonical_edge("nope") is None


# ------------------------------------------------------------------ JSON

def test_json_forms():
    as_obj = json.dumps({"changes": [{"op": "add", "source": "a", "edge": "MemberOf", "target": "G", "note": "n"},
                                     {"op": "create", "type": "user", "name": "u"}, "remove-member a G"]})
    specs = parse_json(as_obj, "j")
    assert [s.op for s in specs] == ["add", "create", "remove"]
    assert specs[0].note == "n" and specs[2].edge_type == "MemberOf"


@pytest.mark.parametrize("bad", ["{", json.dumps({"changes": "x"}), json.dumps([{"op": "zap"}]),
                                 json.dumps([{"op": "add", "source": "a", "edge": "Nope", "target": "b"}])])
def test_json_errors(bad):
    with pytest.raises(ChangeSetError):
        parse_json(bad, "j")


# ------------------------------------------------------------ PowerShell

def _ps(text):
    return from_powershell(text, "s.ps1")


def test_ps_group_membership_forms():
    specs, warns = _ps('''
Add-ADGroupMember -Identity "Domain Admins" -Members alice,"bob smith"
Add-ADGroupMember "HelpDesk" carol
Remove-ADGroupMember -Identity HelpDesk -Members dave -Confirm:$false
Add-ADPrincipalGroupMembership -Identity erin -MemberOf "CN=Backup Operators,CN=Builtin,DC=corp,DC=local"
''')
    got = [(s.op, s.source, s.target) for s in specs]
    assert got == [("add", "alice", "Domain Admins"), ("add", "bob smith", "Domain Admins"),
                   ("add", "carol", "HelpDesk"), ("remove", "dave", "HelpDesk"), ("add", "erin", "Backup Operators")]
    assert not warns
    assert specs[0].origin == "s.ps1:2"


def test_ps_rbcd_and_computer_account_dollar_is_not_a_variable():
    specs, warns = _ps("Set-ADComputer SRV01 -PrincipalsAllowedToDelegateToAccount WEB01$")
    assert [(s.source, s.edge_type, s.target) for s in specs] == [("WEB01$", "AllowedToAct", "SRV01")] and not warns


def test_ps_net_group():
    specs, _ = _ps('net group "Domain Admins" mallory /add /domain')
    assert (specs[0].op, specs[0].source, specs[0].target) == ("add", "mallory", "Domain Admins")


def test_ps_never_silently_skips_what_it_cannot_model():
    text = r'''
$g = Get-ADGroup X; Add-ADGroupMember -Identity $g -Members tharris
foreach ($u in $list) { Add-ADGroupMember -Identity "IT" -Members $u }
Get-ADUser -Filter * | Add-ADPrincipalGroupMembership -MemberOf "Backup Operators"
Set-ADAccountControl -Identity SRV02 -TrustedForDelegation $true
Set-Acl -Path "AD:\CN=x" -AclObject $acl
'''
    specs, warns = _ps(text)
    assert not specs
    assert [w.origin for w in warns] == ["s.ps1:2", "s.ps1:3", "s.ps1:4", "s.ps1:5", "s.ps1:6"]
    assert any("Unconstrained delegation" in w.message for w in warns)


def test_ps_finds_changes_after_semicolon_and_inside_blocks():
    specs, _ = _ps('if ($x) { Add-ADGroupMember "HELPDESK" "alice" }\nWrite-Host hi; Add-ADGroupMember -Identity G -Members bob')
    assert [(s.source, s.target) for s in specs] == [("alice", "HELPDESK"), ("bob", "G")]


def test_ps_comments_and_continuations():
    specs, _ = _ps("Add-ADGroupMember -Identity G `\n   -Members alice  # trailing comment with Add-ADGroupMember x y\n# Add-ADGroupMember -Identity H -Members z")
    assert [(s.source, s.target) for s in specs] == [("alice", "G")]


def test_load_changes_merges_sources_in_order(tmp_path):
    f = tmp_path / "a.changes"
    f.write_text("add-member a G\n")
    ps = tmp_path / "b.ps1"
    ps.write_text("Add-ADGroupMember -Identity H -Members b\nSet-Acl x\n")
    specs, warns = load_changes([str(f)], ["remove-member c G"], [str(ps)])
    assert [(s.index, s.source) for s in specs] == [(1, "a"), (2, "b"), (3, "c")]
    assert len(warns) == 1


def test_directories_expand_to_their_change_files_in_order(tmp_path):
    d = tmp_path / "ad-changes"
    (d / "sub").mkdir(parents=True)
    (d / "b.changes").write_text("add-member b G\n")
    (d / "a.changes").write_text("add-member a G\n")
    (d / "sub" / "c.ps1").write_text("Add-ADGroupMember -Identity G -Members c\n")
    (d / "policy.json").write_text("{}")             # not a change file; must be ignored
    (d / "notes.txt").write_text("ignore me")
    specs, _ = load_changes([str(d)])
    assert [s.source for s in specs] == ["a", "b", "c"]


def test_oversized_change_file_is_rejected(tmp_path, monkeypatch):
    import pathcutter.changes as ch
    monkeypatch.setattr(ch, "MAX_CHANGE_FILE_BYTES", 100)
    f = tmp_path / "big.changes"
    f.write_text("add-member a G\n" * 50)
    with pytest.raises(ChangeSetError) as ei:
        load_changes([str(f)])
    assert "exceeds" in ei.value.errors[0]


def test_too_many_changes_are_rejected(tmp_path, monkeypatch):
    import pathcutter.changes as ch
    monkeypatch.setattr(ch, "MAX_CHANGES", 3)
    with pytest.raises(ChangeSetError) as ei:
        load_changes(inline=["add-member a G"] * 4)
    assert "limit" in ei.value.errors[0]


def test_binary_garbage_is_a_clean_error(tmp_path):
    f = tmp_path / "x.changes"
    f.write_bytes(b"\xff\xfe\x00\x01 not text \x80\x81")
    with pytest.raises(ChangeSetError):
        load_changes([str(f)])


def test_empty_directory_is_an_error(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(ChangeSetError) as ei:
        load_changes([str(tmp_path / "empty")])
    assert "no" in ei.value.errors[0]



def test_load_changes_reports_missing_file():
    with pytest.raises(ChangeSetError) as ei:
        load_changes(["/definitely/not/here.changes"])
    assert "cannot read" in ei.value.errors[0]


# ------------------------------------------------------------ resolution

def _resolve(g, lines, **kw):
    specs, _ = load_changes(inline=lines)
    return resolve_changes(g, specs, **kw)


def test_resolves_by_display_full_sid_and_domain_prefix(corp):
    for ref in ("alice", "ALICE@CORP.LOCAL", "u-alice", "CORP\\alice", "Alice"):
        res, err = _resolve(corp, [f"add-member {ref} HELPDESK"])
        assert not err and res[0].source_id == "u-alice", ref


def test_resolves_computer_by_short_name_and_sam(corp):
    for ref in ("srv01", "SRV01$", "srv01.corp.local"):
        res, err = _resolve(corp, [f"local-admin alice {ref}"])
        assert not err and res[0].target_id == "c-srv01", ref


def test_type_context_disambiguates_user_vs_group(corp):
    corp.add_node(ADNode("u-help", "HELPDESK@corp.local", NodeType.USER, "corp.local"))
    res, err = _resolve(corp, ["add-member alice HELPDESK"])
    assert not err and res[0].target_id == "g-help"          # target of MemberOf must be a group


def test_ambiguity_is_an_error_with_options(corp):
    corp.add_node(ADNode("u-help", "HELPDESK@corp.local", NodeType.USER, "corp.local"))
    res, err = _resolve(corp, ["grant HELPDESK GenericAll svc_backup"])
    assert not res and "ambiguous" in err[0] and "HELPDESK@CORP.LOCAL" in err[0].upper()


def test_unknown_name_is_an_error_with_suggestion(corp):
    res, err = _resolve(corp, ["add-member alicia HELPDESK"])
    assert not res and "alicia" in err[0] and "alice" in err[0]


def test_suggestions_respect_expected_type(corp):
    res, err = _resolve(corp, ["local-admin alice SRV99"])
    assert "SRV01" in err[0]


def test_assume_new_creates_inert_nodes(corp):
    res, err = _resolve(corp, ["add-member newbie HELPDESK"], on_unresolved="assume-new")
    assert not err and res[0].assumed_new and res[0].new_nodes[0].node_type == NodeType.USER
    assert res[0].new_nodes[0].name.endswith("@CORP.LOCAL")


def test_create_then_use_in_later_change(corp):
    res, err = _resolve(corp, ["create user newhire", "add-member newhire HELPDESK"])
    assert not err and res[1].source_id == res[0].source_id


def test_create_existing_object_is_an_error(corp):
    _, err = _resolve(corp, ["create user alice"])
    assert "already exists" in err[0]


def test_dcsync_defaults_to_the_single_domain(corp):
    res, err = _resolve(corp, ["grant-dcsync alice"])
    assert not err and res[0].target_id == "d-corp" and res[0].spec.edge_type == "DCSync"


def test_every_error_is_reported(corp):
    _, err = _resolve(corp, ["add-member nobody1 HELPDESK", "add-member nobody2 NOGROUP"])
    assert len(err) == 3


# --------------------------------------------------------------- apply/undo

def test_apply_and_undo_add(corp):
    res, _ = _resolve(corp, ["add-member alice HELPDESK"])
    assert apply_change(corp, res[0]) and corp.has_edge_type("u-alice", "g-help", "MemberOf")
    undo_change(corp, res[0])
    assert not corp.has_edge_type("u-alice", "g-help", "MemberOf")


def test_add_existing_edge_is_a_noop(corp):
    res, _ = _resolve(corp, ['add-member bob "IT ADMINS"'])
    assert not apply_change(corp, res[0]) and res[0].noop and "already present" in res[0].noop_reason


def test_remove_restores_on_undo_and_flags_missing(corp):
    res, _ = _resolve(corp, ['remove-member svc_backup "DOMAIN ADMINS"', "remove-member alice HELPDESK"])
    assert apply_change(corp, res[0]) and not corp.has_edge_type("u-svc", "g-da", "MemberOf")
    undo_change(corp, res[0])
    assert corp.has_edge_type("u-svc", "g-da", "MemberOf")
    assert not apply_change(corp, res[1]) and res[1].noop
