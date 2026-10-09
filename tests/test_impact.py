"""Change impact analysis: what a change set does to attack paths."""
from pathcutter.changes import ChangeWarning
from pathcutter.graph import ADEdge, AttackGraph, ADNode, NodeType
from pathcutter.policy import Policy


def kinds(report):
    return {f.kind for f in report.findings}


def finding(report, kind):
    return next(f for f in report.findings if f.kind == kind)


def test_adding_to_a_tier0_group_is_a_critical_promotion(corp, run_check):
    r, _ = run_check(corp, ['add-member alice "DOMAIN ADMINS"'])
    f = finding(r, "TIER0_PROMOTION")
    assert f.severity == "critical" and f.blocking and r.verdict == "block"
    assert [s["name"] for s in f.paths[0]] == ["alice", "DOMAIN ADMINS"]
    assert r.totals["promoted"] == 1 and r.changes[0].verdict == "block"


def test_new_member_of_a_dangerous_group_is_newly_exposed_with_a_fix(corp, run_check):
    r, _ = run_check(corp, ["add-member alice HELPDESK"])
    f = finding(r, "NEW_EXPOSURE")
    assert f.severity == "critical" and r.verdict == "block"
    assert [s["name"] for s in f.paths[0]] == ["alice", "HELPDESK", "svc_backup"]
    assert f.paths[0][0]["new_edge"] is True                      # the change's own edge is marked
    assert f.fix_first and f.fix_first[0]["edge_type"] == "GenericAll"
    assert f.fix_first[0]["source"].startswith("HELPDESK")
    assert "MemberOf" not in {fx["edge_type"] for fx in f.fix_first}  # never suggests undoing the change itself
    assert r.totals["newly_exposed_actors"] == 1


def test_fix_first_makes_the_change_pass(corp, run_check):
    corp.remove_edge("g-help", "u-svc", "GenericAll")              # apply the suggested fix
    r, _ = run_check(corp, ["add-member alice HELPDESK"])
    assert r.verdict == "pass" and not [f for f in r.findings if f.kind == "NEW_EXPOSURE"]


def test_change_cancelled_by_another_change_is_superseded_not_blocked(corp, run_check):
    r, _ = run_check(corp, ["add-member alice HELPDESK", 'remove-member svc_backup "DOMAIN ADMINS"'])
    f = finding(r, "NEW_EXPOSURE")
    assert f.superseded and f.severity == "info" and not f.blocking
    assert r.verdict == "pass" and r.totals["newly_exposed"] == 0


def test_combined_effect_of_individually_harmless_changes(corp, run_check):
    r, _ = run_check(corp, ["add-member alice TEAM", "grant TEAM GenericAll svc_backup"])
    f = finding(r, "COMBINED_EFFECT")
    assert "alice" in [p["name"] for p in f.principals]
    assert sorted(f.changes) == [1, 2] and r.verdict == "block"
    # alone, adding alice to TEAM changes nothing
    assert r.changes[0].newly_exposed == 0 and r.changes[1].newly_exposed >= 1


def test_shorter_path_is_reported(corp, run_check):
    corp.add_edge(ADEdge("u-dave", "g-team", "MemberOf"))
    corp.add_edge(ADEdge("g-team", "g-help", "MemberOf"))          # dave: 3 hops to Tier 0
    r, _ = run_check(corp, ["grant TEAM GenericAll svc_backup"])  # now 2
    f = finding(r, "PATH_SHORTENED")
    dave = next(p for p in f.principals if p["name"] == "dave")
    assert (dave["hops_before"], dave["hops_after"]) == (3, 2)
    assert r.totals["shortened"] >= 1 and not [x for x in r.findings if x.kind == "NEW_EXPOSURE"]


def test_removing_privilege_is_a_risk_reduction(corp, run_check):
    r, _ = run_check(corp, ['remove-member svc_backup "DOMAIN ADMINS"'])
    f = finding(r, "RISK_REDUCTION")
    assert f.severity == "info" and r.verdict == "pass"
    assert r.totals["newly_secured"] == 1 and r.totals["demoted"] == 1
    assert r.changes[0].effect == "reduces_exposure"
    assert r.posture["after"]["score"] <= r.posture["before"]["score"]


def test_noop_change_is_flagged_but_harmless(corp, run_check):
    r, _ = run_check(corp, ['add-member bob "IT ADMINS"'])
    assert kinds(r) == {"NOOP"} and r.changes[0].effect == "noop" and r.verdict == "pass"


def test_unmodeled_script_lines_force_review(corp, run_check):
    w = ChangeWarning("deploy.ps1:7", "Set-Acl not modeled", "Set-Acl x")
    r, _ = run_check(corp, ["add-member alice TEAM"], unmodeled=[w])
    f = finding(r, "UNMODELED")
    assert f.origin == "deploy.ps1:7" and r.verdict == "review"


def test_unmodeled_can_block_when_policy_says_so(corp, run_check):
    w = ChangeWarning("deploy.ps1:7", "Set-Acl not modeled", "Set-Acl x")
    r, _ = run_check(corp, ["add-member alice TEAM"], policy=Policy(fail_on_unmodeled=True), unmodeled=[w])
    assert r.verdict == "block"


def test_policy_extra_tier0_makes_crown_jewels_count(corp, run_check):
    r0, _ = run_check(corp, ['add-member alice "IT ADMINS"'])
    assert r0.verdict == "pass"                                    # SRV01 is not Tier 0 by default
    r1, _ = run_check(corp, ['add-member alice "IT ADMINS"'], extra_tier0={"c-srv01"})
    assert r1.verdict == "block" and finding(r1, "NEW_EXPOSURE")


def test_disabled_account_is_downgraded_one_level(corp, run_check):
    r, _ = run_check(corp, ["add-member carol HELPDESK"])
    assert finding(r, "NEW_EXPOSURE").severity == "high"           # alice would be critical


def test_group_only_exposure_is_latent_medium(corp, run_check):
    r, _ = run_check(corp, ["grant TEAM GenericAll svc_backup"])
    f = finding(r, "NEW_EXPOSURE")
    assert f.severity == "medium" and f.actors_total == 0 and "groups only" in f.title
    assert r.verdict == "review"


def test_new_object_via_create_is_analyzed(corp, run_check):
    r, _ = run_check(corp, ["create user newhire", "add-member newhire HELPDESK"])
    f = finding(r, "NEW_EXPOSURE")
    assert f.principals[0]["name"].lower() == "newhire" and f.principals[0]["new"] is True


def test_per_change_attribution_is_independent(corp, run_check):
    r, _ = run_check(corp, ["add-member alice HELPDESK", "add-member dave TEAM", 'add-member bob "IT ADMINS"'])
    by = {c.index: c for c in r.changes}
    assert by[1].newly_exposed == 1 and by[2].newly_exposed == 0 and by[3].effect == "noop"
    assert by[1].effect == "increases_exposure" and by[2].effect == "neutral"


def test_attribution_limit_falls_back_to_totals(corp, run_check):
    r, _ = run_check(corp, ["add-member alice HELPDESK"], max_marginal=0)
    assert any("per-change attribution" in w for w in r.warnings)
    assert finding(r, "NEW_EXPOSURE").changes == [1] and r.totals["newly_exposed"] == 1


def test_path_cap_marks_counts_approximate(corp, run_check):
    r, _ = run_check(corp, ["add-member alice HELPDESK"], max_paths=1)
    assert r.totals["paths_truncated"] and r.totals["paths_added"] is None and not r.posture_reliable
    assert any("cap" in w for w in r.warnings)
    assert r.totals["newly_exposed"] == 1                          # exposure stays exact under the cap


def test_baseline_without_tier0_warns():
    g = AttackGraph()
    g.add_node(ADNode("a", "a@x", NodeType.USER, "x"))
    g.add_node(ADNode("g", "G@X", NodeType.GROUP, "x"))
    from pathcutter.changes import load_changes, resolve_changes
    from pathcutter.impact import analyze_impact
    specs, _ = load_changes(inline=["add-member a G"])
    resolved, _ = resolve_changes(g, specs)
    r = analyze_impact(g, resolved)
    assert any("no Tier 0" in w for w in r.warnings)


def test_analysis_does_not_mutate_the_baseline(corp, run_check):
    before = sorted((u, v, d["edge_type"]) for u, v, d in corp.all_edges())
    tiers = {n.object_id: n.tier for n in corp.all_nodes()}
    count = corp.node_count
    run_check(corp, ['add-member alice "DOMAIN ADMINS"', 'remove-member svc_backup "DOMAIN ADMINS"'])
    assert sorted((u, v, d["edge_type"]) for u, v, d in corp.all_edges()) == before
    assert {n.object_id: n.tier for n in corp.all_nodes()} == tiers
    assert corp.node_count == count


def test_report_dict_is_json_serialisable(corp, run_check):
    import json
    r, _ = run_check(corp, ["add-member alice HELPDESK"])
    d = json.loads(json.dumps(r.to_dict()))
    assert d["schema"] == "pathcutter.check/1" and d["verdict"] == "block"
    assert "ids" not in d["findings"][0]
