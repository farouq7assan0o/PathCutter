"""Ansible extraction."""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from pathcutter.extractors.ansible import extract

PLAY = Path(__file__).parent / "data" / "iac" / "playbook.yml"


def run(text):
    specs, warns = extract(text, "p.yml")
    return [(s.op, s.source, s.edge_type, s.target, s.new_type) for s in specs], warns


def test_the_sample_playbook():
    specs, warns = extract(PLAY.read_text(encoding="utf-8"), "playbook.yml")
    got = {(s.op, s.source, s.edge_type, s.target) for s in specs}
    assert ("add", "svc_deploy", "MemberOf", "Deployers") in got
    assert {("add", "alice", "MemberOf", "Helpdesk"), ("add", "bob", "MemberOf", "Helpdesk")} <= got        # variable + list variable
    assert {("add", "carol", "MemberOf", "Server Admins"), ("add", "dave", "MemberOf", "Server Admins")} <= got   # loop expansion
    assert ("remove", "eve", "MemberOf", "Backup Operators") in got
    assert ("add", "helpdesk", "AdminTo", "srv01") in got                                                     # local group on a literal host
    assert ("add", "frank", "MemberOf", "Account Operators") in got                                           # embedded PowerShell
    assert ("add", "gina", "MemberOf", "Printers") in got                                                     # when: analyzed as if it runs
    assert ("add", "hank", "MemberOf", "Auditors") in got
    msgs = " | ".join(w.message for w in warns)
    assert "extra_member" in msgs, "an unresolved variable must be reported by name"
    assert "when: condition" in msgs and "members.set replaces" in msgs
    assert "win_user_right" in msgs, "access-changing modules without a model are reported"
    assert "inventory groups" in msgs and "windows" in msgs
    assert not any("win_copy" in w.message for w in warns), "unrelated modules are not noise"
    assert not any(s.source == "ops" for s in specs), "the fleet-wide grant must not be guessed"


def test_group_state_absent_is_a_delete_and_user_creation():
    ops, _ = run("- hosts: x\n  tasks:\n    - microsoft.ad.group: {name: Old, state: absent}\n    - microsoft.ad.user: {name: newbie}\n")
    assert ("delete", "Old", "", "", "") in ops and ("create", "newbie", "if-missing", "", "user") in ops


def test_win_domain_user_group_actions():
    ops, warns = run("- hosts: x\n  tasks:\n    - community.windows.win_domain_user: {name: u1, groups: [G1, G2], groups_action: add}\n"
                     "    - community.windows.win_domain_user: {name: u2, groups: [G3], groups_action: remove}\n"
                     "    - community.windows.win_domain_user: {name: u3, groups: [G4]}\n")
    assert ("add", "u1", "MemberOf", "G1", "") in ops and ("remove", "u2", "MemberOf", "G3", "") in ops
    assert ("add", "u3", "MemberOf", "G4", "") in ops and any("groups_action=replace" in w.message for w in warns)


def test_set_fact_and_block_and_short_module_names():
    ops, _ = run("- hosts: x\n  tasks:\n    - set_fact: {who: zed}\n    - block:\n        - win_domain_group_membership: {name: G, members: ['{{ who }}']}\n")
    assert ops == [("add", "zed", "MemberOf", "G", "")]


def test_bad_yaml_and_bare_task_lists_are_handled():
    ops, warns = run("- hosts: [unclosed\n")
    assert not ops and "could not parse" in warns[0].message
    ops, _ = run("- microsoft.ad.group: {name: T, members: {add: [a]}}\n")        # role tasks/main.yml has no play around it
    assert ("add", "a", "MemberOf", "T", "") in ops


def test_roles_are_reported_not_followed():
    _, warns = run("- hosts: x\n  roles: [ad_admins]\n")
    assert any("roles are not followed" in w.message for w in warns)


def test_unresolvable_loop_is_reported():
    ops, warns = run("- hosts: x\n  tasks:\n    - microsoft.ad.group: {name: G, members: {add: ['{{ item }}']}}\n      loop: '{{ lookup_things }}'\n")
    assert not ops and any("cannot be expanded" in w.message for w in warns)
