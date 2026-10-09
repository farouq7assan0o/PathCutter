"""Detections for residual attack paths: correctness, quoting, determinism and the CLI."""
import json
import re

import pytest

from pathcutter.cli import main
from pathcutter.detect_pack import build_pack, prerequisites, residual_points, write_pack
from pathcutter.detections import (
    MAX_OBJECTS_PER_RULE, Cond, Rule, build_rules, sam, to_elastic, to_kql, to_sigma, to_spl,
)
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.ingest import load_sharphound
from pathcutter.labs import write_lab
from pathcutter.snapshot import save_snapshot

yaml = pytest.importorskip("yaml")


@pytest.fixture
def lab(tmp_path):
    write_lab("goad-sevenkingdoms", tmp_path)
    return load_sharphound(tmp_path)


def points_for(g, **kw):
    work, pts, info = residual_points(g, **kw)
    return work, pts, info


def test_goad_residual_points_and_rule_kinds(lab):
    work, pts, info = points_for(lab, assume_fixed=0, top=25)
    assert info["paths_total"] == info["paths_residual"] > 0 and info["coverage_pct"] == 100.0
    rules = build_rules(work, pts)
    keys = {r.key for r in rules}
    assert {"T0_GROUP_MEMBERSHIP", "EXPOSED_GROUP_MEMBERSHIP", "ACL_CHANGE", "ADMIN_LOGON", "RDP_LOGON"} <= keys
    t0 = next(r for r in rules if r.key == "T0_GROUP_MEMBERSHIP")
    assert {"DOMAIN ADMINS", "DOMAIN CONTROLLERS"} <= set(t0.objects) and t0.level == "critical"
    exposed = next(r for r in rules if r.key == "EXPOSED_GROUP_MEMBERSHIP")
    assert {"SMALL COUNCIL", "KINGSGUARD", "DRAGONSTONE"} <= {o.upper() for o in exposed.objects}


def test_assuming_fixes_removes_their_edges_from_the_monitor_points(lab):
    work0, pts0, info0 = points_for(lab, assume_fixed=0, top=50)
    work3, pts3, info3 = points_for(lab, assume_fixed=3, top=50)
    assert info3["paths_residual"] < info3["paths_total"]
    assert len(info3["assumed_fixed"]) == 3
    fixed = {(f["source"], f["edge"], f["target"]) for f in info3["assumed_fixed"]}
    remaining = {(sam(work3, p["source_id"]), p["edge_type"], sam(work3, p["target_id"])) for p in pts3}
    for src, edge, tgt in fixed:
        assert (src.split("@")[0], edge, tgt.split("@")[0]) not in remaining


def test_residual_graph_is_a_copy_the_baseline_is_untouched(lab):
    before = sorted((u, v, d["edge_type"]) for u, v, d in lab.all_edges())
    residual_points(lab, assume_fixed=5)
    assert sorted((u, v, d["edge_type"]) for u, v, d in lab.all_edges()) == before


def test_every_sigma_rule_is_valid_yaml_with_the_expected_shape(lab):
    work, pts, _ = points_for(lab)
    for r in build_rules(work, pts):
        d = yaml.safe_load(to_sigma(r))
        assert d["logsource"] == {"product": "windows", "service": "security"}
        assert d["detection"]["condition"].startswith("selection")
        assert d["level"] in ("critical", "high", "medium", "low", "informational")
        assert d["id"] == r.id and d["detection"]["selection"]["EventID"] == r.event_ids
        assert all(re.match(r"attack\.[a-z_0-9.]+$", t) for t in d["tags"])


HOSTILE = 'x" OR 1=1 | delete \\ * ? () \n; newline'


def hostile_graph():
    g = AttackGraph()
    g.add_node(ADNode("t", "DOMAIN ADMINS@X", NodeType.GROUP, "x"))
    g.add_node(ADNode("u", "U@X", NodeType.USER, "x"))
    g.add_node(ADNode("h", HOSTILE + "@X", NodeType.GROUP, "x"))
    g.add_edge(ADEdge("u", "h", "MemberOf"))
    g.add_edge(ADEdge("h", "t", "GenericAll"))
    g.add_edge(ADEdge("u", "h", "AddMember"))
    g.classify_tiers()
    return g


def test_hostile_names_cannot_break_out_of_any_language():
    g = hostile_graph()
    rules = build_rules(g, [{"source_id": "u", "target_id": "h", "edge_type": "AddMember", "paths": 1},
                            {"source_id": "h", "target_id": "t", "edge_type": "GenericAll", "paths": 1}])
    assert rules
    for r in rules:
        d = yaml.safe_load(to_sigma(r))                                    # still valid YAML
        assert d["detection"]["selection"]["EventID"] == r.event_ids
        for text in (to_spl(r), to_kql(r), to_elastic(r)):
            # the raw newline and an unescaped quote must never reach the query text
            assert "\n; newline" not in text.replace("\\n", "")
            for line in text.splitlines():
                body = re.sub(r'\\.', "", line)                            # drop escaped characters
                assert body.count('"') % 2 == 0, f"unbalanced quotes: {line}"


def test_sigma_roundtrips_the_exact_hostile_value():
    r = Rule("K", "t", "d", "high", [4728], [Cond("TargetUserName", [HOSTILE])])
    d = yaml.safe_load(to_sigma(r))
    assert d["detection"]["selection"]["TargetUserName"] == [HOSTILE.replace("\n", " ")]   # control chars neutralised


def test_compilers_agree_on_operators_and_negation():
    r = Rule("K", "t", "d", "high", [4624, 4672],
             [Cond("Computer", ["SRV01", "SRV02"], op="startswith"), Cond("LogonType", ["3"]),
              Cond("TargetUserName", ["$"], negate=True, op="endswith"), Cond("ObjectDN", ["CN=X,"], op="contains")])
    spl, kql, es = to_spl(r), to_kql(r), to_elastic(r)
    assert 'EventCode IN (4624, 4672)' in spl and 'Computer IN ("SRV01*", "SRV02*")' in spl
    assert 'NOT TargetUserName="*$"' in spl and 'ObjectDN="*CN=X,*"' in spl
    assert "EventID in (4624, 4672)" in kql and 'Computer startswith "SRV01"' in kql and 'Computer startswith "SRV02"' in kql
    assert 'not((TargetUserName endswith "$"))' in kql and "ObjectDN contains" in kql and "make_bag" in kql
    assert 'event.code : ("4624" or "4672")' in es and "not winlog.event_data.TargetUserName" in es
    assert "winlog.event_data.Computer : (SRV01* or SRV02*)" in es


def test_rule_ids_are_deterministic_and_content_addressed(lab):
    work, pts, _ = points_for(lab)
    a = [r.id for r in build_rules(work, pts)]
    b = [r.id for r in build_rules(work, pts)]
    assert a == b and len(set(a)) == len(a)
    work2, pts2, _ = points_for(lab, assume_fixed=4)
    assert [r.id for r in build_rules(work2, pts2)] != a


def test_large_watch_lists_are_split_into_parts():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@X", NodeType.GROUP, "x"))
    n = MAX_OBJECTS_PER_RULE + 30
    for i in range(n):
        g.add_node(ADNode(f"g{i}", f"G{i}@X", NodeType.GROUP, "x"))
        g.add_edge(ADEdge(f"g{i}", "da", "GenericAll"))
    g.classify_tiers()
    rules = [r for r in build_rules(g, []) if r.key == "EXPOSED_GROUP_MEMBERSHIP"]
    assert [r.part for r in rules] == [1, 2] and len(rules[0].objects) == MAX_OBJECTS_PER_RULE and len({r.id for r in rules}) == 2
    assert rules[1].slug.endswith("_2")


def test_prerequisites_name_the_audit_subcategories_actually_used(lab):
    work, pts, _ = points_for(lab)
    rules = build_rules(work, pts)
    subs = {p["subcategory"] for p in prerequisites(rules)}
    assert {"Security Group Management", "Directory Service Changes", "Logon"} <= subs
    for p in prerequisites(rules):
        assert p["command"].startswith("auditpol /set /subcategory:") and p["needed_by"]


def test_write_pack_layout_and_contents(lab, tmp_path):
    work, pts, info = points_for(lab)
    pack = build_pack(work, pts, info)
    out = tmp_path / "det"
    files = write_pack(pack, out)
    n = len(pack.rules)
    assert len(list((out / "sigma").glob("*.yml"))) == n and len(list((out / "splunk").glob("*.spl"))) == n
    assert len(list((out / "sentinel").glob("*.kql"))) == n and len(list((out / "elastic").glob("*.kql"))) == n
    cov = json.loads((out / "coverage.json").read_text())
    assert len(cov["rules"]) == n and cov["prerequisites"] and cov["rules"][0]["test_command"]
    md = (out / "coverage.md").read_text()
    assert "Validate in a lab" in md and "Principals who can abuse" in md
    assert "auditpol" in (out / "prerequisites.md").read_text()
    assert all(f.read_text(encoding="utf-8").isascii() for f in files)


def test_actor_watchlists_name_the_principals_who_can_abuse_the_edge(lab):
    work, pts, _ = points_for(lab)
    rules = build_rules(work, pts)
    acl = next(r for r in rules if r.key == "ACL_CHANGE")
    actors = {a.upper() for a in acl.actors}
    assert actors & {"KINGSGUARD", "STANNIS.BARATHEON", "LORD.VARYS", "RENLY.BARATHEON"}


def test_a_graph_with_no_paths_still_gets_the_always_on_watches():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@X", NodeType.GROUP, "x"))
    g.classify_tiers()
    work, pts, info = residual_points(g)
    assert pts == [] and info["coverage_pct"] == 100.0
    assert [r.key for r in build_rules(work, pts)] == ["T0_GROUP_MEMBERSHIP"]


# ------------------------------------------------------------------------- CLI

@pytest.fixture
def snap(lab, tmp_path):
    p = tmp_path / "goad.pcsnap"
    save_snapshot(lab, p)
    return str(p)


def test_detect_command_writes_a_pack(snap, tmp_path, capsys):
    out = tmp_path / "d"
    assert main(["detect", snap, "-o", str(out), "--assume-fixed", "3", "--top", "10"]) == 0
    text = capsys.readouterr().out
    assert "assuming the top 3 fixes" in text and "prerequisites.md" in text
    assert (out / "sigma" / "pathcutter_t0_group_membership.yml").exists()


def test_detect_formats_and_errors(snap, tmp_path, capsys):
    out = tmp_path / "d"
    assert main(["detect", snap, "-o", str(out), "--formats", "sigma,elastic"]) == 0
    assert (out / "sigma").exists() and (out / "elastic").exists() and not (out / "splunk").exists()
    assert main(["detect", snap, "-o", str(out), "--formats", "bogus"]) == 1
    assert main(["detect", str(tmp_path / "missing.pcsnap"), "-o", str(out)]) == 1
    assert "[!]" in capsys.readouterr().err


def test_detect_no_watches(snap, tmp_path):
    out = tmp_path / "d"
    assert main(["detect", snap, "-o", str(out), "--no-watches", "--formats", "sigma"]) == 0
    assert not (out / "sigma" / "pathcutter_t0_group_membership.yml").exists()


def test_check_writes_compensating_detections_for_the_risk_it_found(snap, tmp_path, capsys):
    out = tmp_path / "comp"
    rc = main(["check", "--baseline", snap, "-q", "--detections", str(out),
               "--change", "create user newhire", "--change", "add-member newhire DragonStone"])
    assert rc == 2 and (out / "coverage.json").exists()
    assert "compensating detection" in capsys.readouterr().err
    cov = json.loads((out / "coverage.json").read_text())
    assert any(r["covers"] for r in cov["rules"])


def test_help_mentions_detect(capsys):
    with pytest.raises(SystemExit):
        main(["detect", "-h"])
    text = capsys.readouterr().out
    assert "--assume-fixed" in text and "prerequisites.md" in text and text.isascii()
