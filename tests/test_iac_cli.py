"""`pathcutter check` fed by Terraform, Ansible and DSC, on the real SEVENKINGDOMS collection."""
import json
from pathlib import Path

import pytest

from pathcutter.cli import main

BASE = next(iter(sorted((Path(__file__).parent / "data" / "real").glob("SEVENKINGDOMS*.zip"))), None)
pytestmark = pytest.mark.skipif(BASE is None, reason="real data missing")


def check(tmp_path, flag, name, content, *extra):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    out = tmp_path / "r.json"
    code = main(["check", "--baseline", str(BASE), flag, str(f), "--json", str(out), "--fail-on", "review", *extra])
    return code, json.loads(out.read_text(encoding="utf-8")) if out.exists() else None


TF = 'resource "ad_group_membership" "m" {\n  group_id = "KingsGuard"\n  group_members = ["guest"]\n}\n'
YML = "- hosts: dc\n  tasks:\n    - microsoft.ad.group:\n        name: KingsGuard\n        members:\n          add: [guest]\n"
DSC = "Configuration C {\n Node 'DC' {\n  ADGroup 'k' {\n   GroupName = 'KingsGuard'\n   MembersToInclude = 'guest'\n  }\n }\n}\n"


@pytest.mark.parametrize("flag,name,content", [("--terraform", "main.tf", TF), ("--ansible", "play.yml", YML), ("--dsc", "c.dsc.ps1", DSC)])
def test_each_source_finds_the_same_new_path_to_tier_0(tmp_path, flag, name, content):
    if flag == "--ansible":
        pytest.importorskip("yaml")
    code, rep = check(tmp_path, flag, name, content)
    kinds = {f["kind"] for f in rep["findings"]}
    assert "NEW_EXPOSURE" in kinds, kinds
    assert code == 3, "an unreviewed new path to Tier 0 must not pass (fail-on review)"
    assert any(c["describe"].startswith("grant MemberOf") or "guest" in c["describe"].lower() for c in rep["changes"])


def test_origins_point_into_the_iac_file(tmp_path):
    _, rep = check(tmp_path, "--terraform", "main.tf", TF)
    assert rep["changes"][0]["origin"].endswith("main.tf:1")


def test_terraform_plan_json_with_a_removal(tmp_path):
    plan = {"resource_changes": [{"address": "a.b", "type": "ad_group_membership", "change": {
        "actions": ["update"], "before": {"group_id": "KingsGuard", "group_members": ["guest"]},
        "after": {"group_id": "KingsGuard", "group_members": []}, "after_unknown": {}}}]}
    code, rep = check(tmp_path, "--changes", "tfplan.json", json.dumps(plan))
    assert rep is not None and code in (0, 3)             # removing a member that was never in the baseline is a reported no-op, not a crash
    assert any(f["kind"] == "NOOP" for f in rep["findings"])


def test_unmodeled_iac_blocks_when_the_policy_says_so(tmp_path):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"fail_on_unmodeled": True}), encoding="utf-8")
    code, rep = check(tmp_path, "--terraform", "main.tf", 'resource "ad_gpo" "g" { name = "x" }\n', "--policy", str(pol))
    assert code == 2 and any(f["kind"] == "UNMODELED" for f in rep["findings"])


def test_directories_are_expanded_per_extractor(tmp_path):
    (tmp_path / "tf").mkdir()
    (tmp_path / "tf" / "a.tf").write_text(TF, encoding="utf-8")
    (tmp_path / "tf" / "notes.txt").write_text("ignored", encoding="utf-8")
    out = tmp_path / "r.json"
    assert main(["check", "--baseline", str(BASE), "--terraform", str(tmp_path / "tf"), "--json", str(out), "--fail-on", "never"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["changes"]
