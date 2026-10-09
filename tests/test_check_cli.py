"""`pathcutter check` and `pathcutter snapshot` end to end, including exit codes."""
import json
from pathlib import Path

import pytest

from pathcutter.cli import main
from pathcutter.snapshot import save_snapshot

SHARPHOUND = Path(__file__).parent / "test_sharphound_data"


@pytest.fixture
def baseline(corp, tmp_path):
    p = tmp_path / "base.pcsnap"
    save_snapshot(corp, p)
    return str(p)


def check(baseline, *args):
    return main(["check", "--baseline", baseline, *args])


def test_pass_exits_zero(baseline, capsys):
    assert check(baseline, "--change", "add-member alice TEAM") == 0
    assert "Verdict  : PASS" in capsys.readouterr().out


def test_block_exits_two(baseline, capsys):
    assert check(baseline, "--change", "add-member alice HELPDESK") == 2
    assert "BLOCK" in capsys.readouterr().out


def test_fail_on_never_always_exits_zero(baseline):
    assert check(baseline, "--change", "add-member alice HELPDESK", "--fail-on", "never") == 0


def test_review_exits_three_only_when_asked(baseline):
    change = ("--change", "grant TEAM GenericAll svc_backup")       # medium, groups only -> review
    assert check(baseline, *change) == 0
    assert check(baseline, *change, "--fail-on", "review") == 3


def test_unknown_object_is_an_input_error_with_help(baseline, capsys):
    assert check(baseline, "--change", "add-member alicia HELPDESK") == 1
    err = capsys.readouterr().err
    assert "alicia" in err and "alice" in err and "nothing was analyzed" in err


def test_assume_new_lets_unknown_objects_through(baseline):
    assert check(baseline, "--change", "add-member newhire TEAM", "--on-unresolved", "assume-new") == 0


def test_syntax_errors_are_reported_together(baseline, capsys):
    assert check(baseline, "--change", "add-membr a b", "--change", "grant x") == 1
    assert capsys.readouterr().err.count("[!]") >= 2


def test_no_changes_is_an_input_error(baseline, capsys):
    assert check(baseline) == 1
    assert "no changes given" in capsys.readouterr().err


def test_missing_baseline_and_bad_policy_are_input_errors(baseline, tmp_path, capsys):
    assert main(["check", "--baseline", str(tmp_path / "x.pcsnap"), "--change", "add-member a b"]) == 1
    bad = tmp_path / "p.json"
    bad.write_text('{"nope": 1}')
    assert check(baseline, "--change", "add-member alice TEAM", "--policy", str(bad)) == 1
    assert "unknown key" in capsys.readouterr().err


def test_writes_every_output_format(baseline, tmp_path, capsys):
    out = {k: tmp_path / f"out.{k}" for k in ("html", "json", "md", "sarif")}
    rc = check(baseline, "--change", "add-member alice HELPDESK", "-q", "--html", str(out["html"]),
               "--json", str(out["json"]), "--markdown", str(out["md"]), "--sarif", str(out["sarif"]))
    assert rc == 2 and capsys.readouterr().out == ""                 # -q silences the text report
    assert json.loads(out["json"].read_text())["verdict"] == "block"
    assert out["md"].read_text().startswith("## PathCutter")
    assert json.loads(out["sarif"].read_text())["version"] == "2.1.0"
    assert "<!DOCTYPE html>" in out["html"].read_text()


def test_changes_file_policy_and_waiver(baseline, tmp_path):
    changes = tmp_path / "pr.changes"
    changes.write_text("# pr 42\nadd-member alice HELPDESK   # CHG-9\n")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"waivers": [{"id": "CHG-9", "reason": "pilot", "approver": "ciso",
                                               "expires": "2099-12-31", "source": "alice", "target": "HELPDESK"}]}))
    assert check(baseline, "--changes", str(changes)) == 2
    assert check(baseline, "--changes", str(changes), "--policy", str(policy)) == 0


def test_expired_waiver_via_today_flag(baseline, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"waivers": [{"id": "CHG-9", "reason": "pilot", "expires": "2026-03-01", "source": "alice"}]}))
    base = ("--change", "add-member alice HELPDESK", "--policy", str(policy), "-q")
    assert check(baseline, *base, "--today", "2026-02-01") == 0
    assert check(baseline, *base, "--today", "2026-04-01") == 2


def test_powershell_input_and_unmodeled_review(baseline, tmp_path, capsys):
    ps = tmp_path / "deploy.ps1"
    ps.write_text('Add-ADGroupMember -Identity TEAM -Members alice\nSet-Acl -Path x -AclObject $a\n')
    assert check(baseline, "--powershell", str(ps), "--fail-on", "review") == 3
    out = capsys.readouterr().out
    assert "Not analyzed" in out and "deploy.ps1:2" in out


def test_script_with_only_unmodeled_lines_is_reviewed_not_ignored(baseline, tmp_path, capsys):
    ps = tmp_path / "only-acl.ps1"
    ps.write_text("Set-Acl -Path x -AclObject $a\n")
    assert check(baseline, "--powershell", str(ps), "--fail-on", "review") == 3
    assert "Not analyzed" in capsys.readouterr().out


def test_json_change_file(baseline, tmp_path):
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"changes": [{"op": "add", "source": "alice", "edge": "MemberOf", "target": "DOMAIN ADMINS"}]}))
    assert check(baseline, "--changes", str(f), "-q") == 2


def test_policy_extra_tier0(baseline, tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"extra_tier0": ["SRV01"]}))
    change = ("--change", 'add-member alice "IT ADMINS"', "-q")
    assert check(baseline, *change) == 0
    assert check(baseline, *change, "--policy", str(policy)) == 2
    policy.write_text(json.dumps({"extra_tier0": ["NOSUCHHOST"]}))
    assert check(baseline, *change, "--policy", str(policy)) == 1


def test_python_dash_m_propagates_exit_codes(baseline):
    import subprocess
    import sys
    proc = subprocess.run([sys.executable, "-m", "pathcutter", "check", "--baseline", baseline, "-q",
                           "--change", "add-member alice HELPDESK"], capture_output=True, text=True)
    assert proc.returncode == 2


@pytest.mark.skipif(not SHARPHOUND.exists(), reason="sharphound fixture not generated")
def test_snapshot_command_then_check(tmp_path, capsys):
    snap = tmp_path / "s.pcsnap"
    assert main(["snapshot", str(SHARPHOUND), "-o", str(snap)]) == 0
    assert snap.exists() and "Snapshot:" in capsys.readouterr().out
    assert main(["check", "--baseline", str(snap), "-q", "--change", "create user zz",
                 "--change", 'add-member zz "DOMAIN ADMINS"']) == 2


def test_snapshot_of_missing_input_fails_cleanly(tmp_path, capsys):
    assert main(["snapshot", str(tmp_path / "nope"), "-o", str(tmp_path / "s.pcsnap")]) == 1
    assert "[!]" in capsys.readouterr().err


def test_demo_snapshot_is_checkable(tmp_path):
    snap = tmp_path / "demo.pcsnap"
    assert main(["demo", "--size", "small", "-o", str(tmp_path / "demo"), "--snapshot", str(snap)]) == 0
    assert main(["check", "--baseline", str(snap), "-q", "--change", "create user zz",
                 "--change", 'add-member zz "DOMAIN ADMINS"']) == 2
