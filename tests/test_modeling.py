"""Deny ACEs, time-bound (JIT/PAM) grants and declared compensating controls through the whole gate."""
import datetime as dt
import json
import zipfile

import pytest

from pathcutter.changes import format_ttl, load_changes, parse_line, parse_ttl
from pathcutter.exposure import compute_exposure
from pathcutter.graph import Deny
from pathcutter.policy import Policy, PolicyError, parse_policy
from pathcutter.snapshot import load_snapshot, save_snapshot

TODAY = dt.date(2026, 10, 1)


# ---------------------------------------------------------------- ttl grammar

@pytest.mark.parametrize("text,minutes", [("90m", 90), ("4h", 240), ("2h30m", 150), ("1d", 1440), ("1d2h", 1560),
                                          ("01:00:00", 60), ("1.02:00:00", 1560), ("00:45:00", 45)])
def test_ttl_forms(text, minutes):
    assert parse_ttl(text) == minutes


@pytest.mark.parametrize("bad", ["", "0m", "soon", "4", "4x", "00:00:00"])
def test_bad_ttl_is_rejected(bad):
    with pytest.raises(ValueError):
        parse_ttl(bad)


def test_format_ttl_round_trips():
    assert [format_ttl(m) for m in (90, 240, 1440, 1560, 45)] == ["1h30m", "4h", "1d", "1d2h", "45m"]


def test_dsl_ttl_and_deny_parse():
    s = parse_line("add-member alice HELPDESK ttl=4h # INC-1", 1, "t")
    assert (s.ttl_minutes, s.deny, s.note) == (240, False, "INC-1")
    d = parse_line("deny alice GenericAll svc_backup", 1, "t")
    assert (d.op, d.deny, d.edge_type) == ("add", True, "GenericAll")
    assert parse_line("undeny alice GenericAll svc_backup", 1, "t").op == "remove"
    with pytest.raises(ValueError):
        parse_line("remove-member alice HELPDESK ttl=4h", 1, "t")
    assert "temporary: 4h" in s.describe()
    assert d.describe() == "deny alice GenericAll on svc_backup"


# ---------------------------------------------------------------- deny through the gate

def test_a_deny_in_the_same_change_set_cancels_the_new_exposure(corp, run_check):
    plain, _ = run_check(corp, ["add-member alice HELPDESK"])
    assert plain.verdict == "block"
    denied, _ = run_check(corp, ["add-member alice HELPDESK", "deny alice GenericAll svc_backup"])
    assert denied.verdict == "pass", denied.verdict_reason


def test_a_deny_protects_only_the_denied_identity(corp, run_check):
    rep, _ = run_check(corp, ["add-member alice HELPDESK", "add-member dave HELPDESK", "deny alice GenericAll svc_backup"])
    assert rep.verdict == "block"
    names = {p["name"].lower() for f in rep.findings if not f.superseded for p in f.principals}
    assert any("dave" in n for n in names) and not any(n.startswith("alice") for n in names)


def test_lifting_a_deny_is_reported_as_new_exposure(corp, run_check):
    corp.add_edge(__import__("pathcutter.graph", fromlist=["ADEdge"]).ADEdge("u-alice", "g-help", "MemberOf"))
    corp.denies.add(Deny("u-alice", "GenericAll", "u-svc"))
    assert "u-alice" not in compute_exposure(corp).exposed()
    rep, _ = run_check(corp, ["undeny alice GenericAll svc_backup"])
    assert rep.verdict == "block" and any(f.kind == "NEW_EXPOSURE" for f in rep.findings)


def test_undeny_of_a_deny_that_was_never_collected_says_so(corp, run_check):
    rep, rcs = run_check(corp, ["undeny alice GenericAll svc_backup"])
    assert rcs[0].noop and "collected" in rcs[0].noop_reason


def test_deny_survives_snapshot_roundtrip(corp, tmp_path):
    corp.denies.add(Deny("g-it", "GenericAll", "u-svc"))
    save_snapshot(corp, tmp_path / "b.pcsnap")
    g, _ = load_snapshot(tmp_path / "b.pcsnap")
    assert g.denies == {Deny("g-it", "GenericAll", "u-svc")}


def test_collected_deny_file_is_read(tmp_path):
    from pathcutter.ingest import load_sharphound
    users = {"meta": {"type": "users", "version": 4}, "data": [
        {"ObjectIdentifier": "S-1-5-21-1-2-3-1001", "Properties": {"name": "A@X.LOCAL", "domain": "X.LOCAL"}},
        {"ObjectIdentifier": "S-1-5-21-1-2-3-1002", "Properties": {"name": "B@X.LOCAL", "domain": "X.LOCAL"}}]}
    denies = {"meta": {"type": "denies", "version": 1}, "data": [
        {"PrincipalSID": "S-1-5-21-1-2-3-1001", "RightName": "GenericAll", "ObjectIdentifier": "S-1-5-21-1-2-3-1002"},
        {"PrincipalSID": "S-1-5-21-1-2-3-1001", "RightName": "AddKeyCredentialLink", "ObjectIdentifier": "S-1-5-21-1-2-3-1002"}]}
    z = tmp_path / "e.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("20260101_users.json", json.dumps(users))
        zf.writestr("20260101_denies.json", json.dumps(denies))
    g = load_sharphound(z)
    assert {(d.edge_type) for d in g.denies} == {"GenericAll", "WriteKeyCredentialLink"}


# ---------------------------------------------------------------- JIT / PAM

def test_time_bound_membership_is_flagged_but_not_ignored(corp, run_check):
    rep, _ = run_check(corp, ["add-member alice HELPDESK ttl=4h"], policy=Policy())
    f = next(x for x in rep.findings if x.kind == "NEW_EXPOSURE")
    assert f.temporary and f.temporary["label"] == "4h"
    assert rep.verdict == "block", "without a JIT allowance a temporary grant still blocks"


def test_jit_allowance_lowers_severity_one_step_only(corp, run_check):
    base, _ = run_check(corp, ["add-member alice HELPDESK"])
    f0 = next(x for x in base.findings if x.kind == "NEW_EXPOSURE")
    pol = parse_policy({"jit_max_minutes": 480})
    rep, _ = run_check(corp, ["add-member alice HELPDESK ttl=4h"], policy=pol)
    f1 = next(x for x in rep.findings if x.kind == "NEW_EXPOSURE")
    sevs = ["info", "low", "medium", "high", "critical"]
    assert sevs.index(f1.severity) == sevs.index(f0.severity) - 1 and f1.original_severity == f0.severity


def test_ttl_longer_than_the_jit_window_gets_no_relief(corp, run_check):
    pol = parse_policy({"jit_max_minutes": 60})
    base, _ = run_check(corp, ["add-member alice HELPDESK"])
    rep, _ = run_check(corp, ["add-member alice HELPDESK ttl=4h"], policy=pol)
    assert next(x for x in rep.findings if x.kind == "NEW_EXPOSURE").severity == \
        next(x for x in base.findings if x.kind == "NEW_EXPOSURE").severity


def test_a_tier0_promotion_never_drops_below_medium_even_with_jit(corp, run_check):
    pol = parse_policy({"jit_max_minutes": 600, "controls": [
        {"id": "PIM-1", "type": "pim", "owner": "iam", "evidence": "PIM policy", "steps": 2}]})
    rep, _ = run_check(corp, ["add-member alice 'DOMAIN ADMINS' ttl=1h"], policy=pol)
    f = next(x for x in rep.findings if x.kind == "TIER0_PROMOTION")
    assert f.severity in ("medium", "high", "critical") and f.severity != "low"


# ---------------------------------------------------------------- compensating controls

CONTROL = {"id": "CA-7", "type": "conditional-access", "owner": "iam-team", "evidence": "CA policy 'Admins need compliant device'",
           "target": "HELPDESK", "edge": "MemberOf", "expires": "2026-12-31"}


def test_declared_control_lowers_severity_and_says_it_is_unverified(corp, run_check):
    base, _ = run_check(corp, ["add-member alice HELPDESK"])
    pol = parse_policy({"controls": [CONTROL]})
    rep, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)
    f = next(x for x in rep.findings if x.kind == "NEW_EXPOSURE")
    f0 = next(x for x in base.findings if x.kind == "NEW_EXPOSURE")
    assert f.control["status"] == "applied" and f.original_severity == f0.severity and f.severity != f0.severity
    from pathcutter.impact import finding_context
    assert "cannot verify" in " ".join(finding_context(f))
    assert f.kind == "NEW_EXPOSURE", "the finding is still there"


def test_control_scope_is_respected(corp, run_check):
    pol = parse_policy({"controls": [{**CONTROL, "target": "IT ADMINS"}]})
    rep, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)
    assert all(not f.control for f in rep.findings)


def test_expired_control_stops_applying_and_is_flagged(corp, run_check):
    pol = parse_policy({"controls": [{**CONTROL, "expires": "2026-01-01"}]})
    rep, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)
    f = next(x for x in rep.findings if x.kind == "NEW_EXPOSURE")
    assert f.control["status"] == "expired" and not f.original_severity
    assert any(v["rule"] == "expired_control" for v in rep.violations)


def test_control_needs_owner_and_evidence_and_known_type():
    for bad in ({**CONTROL, "evidence": ""}, {**CONTROL, "owner": ""}, {**CONTROL, "type": "magic"},
                {**CONTROL, "steps": 3}, {**CONTROL, "colour": "red"}):
        with pytest.raises(PolicyError):
            parse_policy({"controls": [bad]})
    with pytest.raises(PolicyError):
        parse_policy({"require_waiver_expiry": True, "controls": [{k: v for k, v in CONTROL.items() if k != "expires"}]})


# ---------------------------------------------------------------- PowerShell

def ps(text):
    from pathcutter.changes import from_powershell
    return from_powershell(text, "t.ps1")


def test_powershell_member_time_to_live():
    specs, warns = ps("Add-ADGroupMember -Identity HELPDESK -Members alice -MemberTimeToLive (New-TimeSpan -Hours 4)")
    assert [(s.source, s.ttl_minutes) for s in specs] == [("alice", 240)]
    specs, _ = ps("Add-ADGroupMember -Identity HELPDESK -Members alice -MemberTimeToLive ([timespan]'01:30:00')")
    assert specs[0].ttl_minutes == 90
    specs, warns = ps("Add-ADGroupMember -Identity HELPDESK -Members alice -MemberTimeToLive $ttl")
    assert specs[0].ttl_minutes is None and any("permanent" in w.message for w in warns)


def test_powershell_deny_rule_object():
    text = r'''$acl = Get-Acl "AD:\CN=Svc,OU=Svc,DC=corp,DC=local"
$id = New-Object System.Security.Principal.NTAccount("CORP","alice")
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($id, "GenericAll", "Deny")
$acl.AddAccessRule($rule)
Set-Acl "AD:\CN=Svc,OU=Svc,DC=corp,DC=local" $acl'''
    specs, _ = ps(text)
    assert [(s.op, s.deny, s.source, s.edge_type) for s in specs] == [("add", True, "alice", "GenericAll")]


def test_hash_pc_directive_accepts_deny_and_ttl():
    specs, _ = ps("# pc: deny alice GenericAll svc_backup\n# pc: add-member bob HELPDESK ttl=2h")
    assert {(s.deny, s.ttl_minutes) for s in specs} == {(True, None), (False, 120)}
