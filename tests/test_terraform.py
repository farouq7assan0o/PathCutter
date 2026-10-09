"""Terraform extraction: HCL configuration and plan JSON."""
import json
from pathlib import Path

import pytest

from pathcutter.extractors.hcl import Ref, Unresolved, parse
from pathcutter.extractors.terraform import extract

TF = Path(__file__).parent / "data" / "iac" / "main.tf"


def run(text):
    specs, warns = extract(text, "x.tf")
    return [(s.op, s.source, s.edge_type, s.target, s.new_type) for s in specs], warns


# ------------------------------------------------------------------------------ the HCL reader

def test_hcl_values():
    b = parse('''x "a" "b" { s = "q\\"x"  n = 3 f = 1.5 t = true z = null l = ["a", 1, ref.to.it] o = { k = "v", "q" = 2 }
                 u = "${var.x}-y" c = f(1, 2)
                 w = a ? b : c
                 nested { inner = 1 } }''')[0]
    a = b.attrs
    assert (a["s"], a["n"], a["f"], a["t"], a["z"]) == ('q"x', 3, 1.5, True, None)
    assert a["l"] == ["a", 1, Ref("ref.to.it")] and a["o"] == {"k": "v", "q": 2}
    assert isinstance(a["u"], Unresolved) and isinstance(a["c"], Unresolved) and isinstance(a["w"], Unresolved)
    assert b.blocks[0].attrs == {"inner": 1} and b.labels == ["a", "b"]


def test_hcl_comments_and_heredocs_do_not_confuse_the_parser():
    blocks = parse('# c\n// c\n/* a = "b" { */\nresource "t" "n" {\n  a = <<EOT\n x = "}"\nEOT\n  b = 1 # tail\n}\n')
    assert blocks[0].attrs["b"] == 1 and "x =" in blocks[0].attrs["a"]


def test_hcl_errors_are_reported_not_raised_by_extract():
    specs, warns = extract('resource "x" "y" { a = ', "broken.tf")
    assert not specs and "could not parse" in warns[0].message


# ------------------------------------------------------------------------------ configuration mode

def test_the_sample_configuration():
    specs, warns = extract(TF.read_text(encoding="utf-8"), "main.tf")
    got = [(s.op, s.source, s.edge_type, s.target, s.new_type) for s in specs]
    assert got == [
        ("create", "newhire", "if-missing", "", "user"), ("create", "Deployers", "if-missing", "", "group"),
        ("add", "newhire", "MemberOf", "Helpdesk", ""), ("add", "alice", "MemberOf", "Helpdesk", ""),
        ("add", "svc_break", "MemberOf", "Helpdesk", ""), ("add", "bob", "MemberOf", "Domain Admins", ""),
        ("add", "ada@corp.com", "MemberOf", "GLOBAL ADMINISTRATOR", ""), ("add", "bob@corp.com", "AZOwns", "g-cloud-admins", ""),
        ("add", "carol", "MemberOf", "Helpdesk", "")]
    msgs = " | ".join(w.message for w in warns)
    assert "for_each" in msgs, "dynamic instances must be reported"
    assert "data.external.who.result.user" in msgs, "unresolvable members must be reported by name"
    assert "Conditional Access" in msgs and "GPO" in msgs
    assert any(w.level == "note" for w in warns), "object-only resources are notes"
    assert not any("ad_group_membership.helpdesk" in w.message for w in warns)


def test_variable_and_local_resolution_and_unknown_variable():
    ops, warns = run('variable "g" { default = "Helpdesk" }\nresource "ad_group_membership" "m" { group_id = var.g\n group_members = ["a"] }')
    assert ops == [("add", "a", "MemberOf", "Helpdesk", "")]
    ops, warns = run('resource "ad_group_membership" "m" { group_id = var.nope\n group_members = ["a"] }')
    assert not ops and "cannot be resolved" in warns[0].message


# ------------------------------------------------------------------------------ plan mode

def plan(*changes):
    return json.dumps({"format_version": "1.2", "resource_changes": list(changes)})


def rc(typ, actions, before=None, after=None, unknown=None, name="x"):
    return {"address": f"{typ}.{name}", "type": typ, "name": name,
            "change": {"actions": actions, "before": before, "after": after, "after_unknown": unknown or {}}}


def test_plan_create_update_destroy():
    p = plan(
        rc("ad_group_membership", ["create"], None, {"group_id": "Helpdesk", "group_members": ["a", "b"]}, name="n"),
        rc("ad_group_membership", ["update"], {"group_id": "IT", "group_members": ["a", "b"]}, {"group_id": "IT", "group_members": ["b", "c"]}, name="u"),
        rc("azuread_group_member", ["delete"], {"group_object_id": "G1", "member_object_id": "U1"}, None, name="d"),
        rc("ad_user", ["create"], None, {"sam_account_name": "dave"}),
        rc("ad_group_membership", ["no-op"], {"group_id": "X", "group_members": ["z"]}, {"group_id": "X", "group_members": ["z"]}, name="same"))
    ops, warns = run(p)
    assert ("add", "a", "MemberOf", "Helpdesk", "") in ops and ("add", "b", "MemberOf", "Helpdesk", "") in ops
    assert ("add", "c", "MemberOf", "IT", "") in ops and ("remove", "a", "MemberOf", "IT", "") in ops
    assert ("add", "b", "MemberOf", "IT", "") not in ops and ("remove", "b", "MemberOf", "IT", "") not in ops
    assert ("remove", "U1", "MemberOf", "G1", "") in ops and ("create", "dave", "if-missing", "", "user") in ops
    assert not any("z" == o[1] for o in ops) and not warns


def test_plan_unknown_values_and_unmodeled_resources_are_reported():
    p = plan(rc("ad_group_membership", ["create"], None, {"group_id": "Helpdesk", "group_members": None}, unknown={"group_members": True}),
             rc("ad_gpo", ["update"], {}, {}, name="g"))
    ops, warns = run(p)
    assert not ops and any("only known after apply" in w.message for w in warns) and any("GPO" in w.message for w in warns)


def test_plan_moving_a_member_between_groups_is_remove_plus_add():
    ops, _ = run(plan(rc("ad_group_membership", ["update"], {"group_id": "Old", "group_members": ["a"]}, {"group_id": "New", "group_members": ["a"]})))
    assert ("remove", "a", "MemberOf", "Old", "") in ops and ("add", "a", "MemberOf", "New", "") in ops


def test_terraform_role_assignment_by_guid_and_name():
    ops, _ = run(plan(rc("azuread_directory_role_assignment", ["create"], None,
                         {"role_id": "e8611ab8-c189-46e8-94e1-60213ab1f814", "principal_object_id": "u1"})))
    assert ops == [("add", "u1", "MemberOf", "PRIVILEGED ROLE ADMINISTRATOR", "")]
