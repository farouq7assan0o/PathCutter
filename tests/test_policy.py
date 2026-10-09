"""Policy parsing, waivers and verdicts."""
import datetime as dt
import json

import pytest

from pathcutter.policy import Policy, PolicyError, load_policy, parse_policy, resolve_extra_tier0

TODAY = dt.date(2026, 6, 15)


def waiver(**kw):
    base = {"id": "CHG-1", "reason": "approved by CISO", "approver": "ciso", "expires": "2026-12-31",
            "source": "alice", "target": "HELPDESK"}
    base.update(kw)
    return base


# ------------------------------------------------------------------ parsing

def test_default_policy_blocks_high_exposure():
    p = Policy()
    assert p.block_severity == "high" and "NEW_EXPOSURE" in p.block_kinds


def test_unknown_keys_are_rejected_to_catch_typos():
    with pytest.raises(PolicyError) as ei:
        parse_policy({"block_severty": "high", "waivers": [{"id": "x", "reason": "y", "sorce": "z"}]})
    msg = "\n".join(ei.value.errors)
    assert "block_severty" in msg and "sorce" in msg


@pytest.mark.parametrize("bad", [
    {"block_severity": "extreme"}, {"max_new_exposed_actors": -1}, {"max_new_exposed_actors": "ten"},
    {"block_kinds": ["NOT_A_KIND"]}, {"waivers": [{"id": "x"}]}, {"waivers": [{"id": "x", "reason": "r", "expires": "tomorrow"}]},
    {"waivers": ["nope"]}, {"schema": "pathcutter.policy/99"}, [],
])
def test_invalid_policies_fail_loudly(bad):
    with pytest.raises(PolicyError):
        parse_policy(bad)


def test_waiver_expiry_can_be_made_mandatory():
    with pytest.raises(PolicyError) as ei:
        parse_policy({"require_waiver_expiry": True, "waivers": [{"id": "x", "reason": "r"}]})
    assert "expires" in ei.value.errors[0]


def test_load_policy_reads_file_and_reports_problems(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"block_severity": "critical"}))
    assert load_policy(f).block_severity == "critical" and load_policy(None).source == "built-in default"
    f.write_text("{not json")
    with pytest.raises(PolicyError):
        load_policy(f)
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.json")


def test_extra_tier0_names_resolve_to_ids(corp):
    ids, errors = resolve_extra_tier0(corp, ("SRV01", "nothing-here"))
    assert ids == {"c-srv01"} and "nothing-here" in errors[0]


# ----------------------------------------------------------------- verdicts

def test_block_severity_threshold(corp, run_check):
    lenient = Policy(block_severity="critical")
    r, _ = run_check(corp, ["grant TEAM GenericAll svc_backup"], policy=lenient)       # medium, groups only
    assert r.verdict == "review"
    r2, _ = run_check(corp, ["add-member alice HELPDESK"], policy=lenient)             # critical
    assert r2.verdict == "block"


def test_valid_waiver_accepts_the_risk(corp, run_check):
    pol = parse_policy({"waivers": [waiver()]})
    r, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)
    f = next(f for f in r.findings if f.kind == "NEW_EXPOSURE")
    assert r.verdict == "pass" and f.waiver["status"] == "applied" and not f.blocking
    assert r.changes[0].verdict == "waived"
    assert r.policy["waivers_applied"][0]["id"] == "CHG-1"


def test_waiver_matches_by_glob_and_kind(corp, run_check):
    pol = parse_policy({"waivers": [waiver(source="ali*", target="HELP*", kinds=["NEW_EXPOSURE"])]})
    assert run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)[0].verdict == "pass"
    pol = parse_policy({"waivers": [waiver(kinds=["TIER0_PROMOTION"])]})                # wrong kind
    assert run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)[0].verdict == "block"


def test_waiver_for_someone_else_does_not_apply(corp, run_check):
    pol = parse_policy({"waivers": [waiver(source="dave")]})
    assert run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)[0].verdict == "block"


def test_expired_waiver_blocks_and_is_called_out(corp, run_check):
    pol = parse_policy({"waivers": [waiver(expires="2026-01-01")]})
    r, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)
    f = next(f for f in r.findings if f.kind == "NEW_EXPOSURE")
    assert r.verdict == "block" and f.waiver["status"] == "expired" and f.blocking
    assert any(v["rule"] == "expired_waiver" for v in r.violations)


def test_waiver_is_valid_on_its_expiry_day(corp, run_check):
    pol = parse_policy({"waivers": [waiver(expires="2026-06-15")]})
    assert run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)[0].verdict == "pass"


def test_combined_finding_needs_every_involved_change_waived(corp, run_check):
    changes = ["add-member alice TEAM", "grant TEAM GenericAll svc_backup"]
    one = parse_policy({"waivers": [waiver(source="alice", target="TEAM", kinds=["*"])]})
    assert run_check(corp, changes, policy=one, today=TODAY)[0].verdict == "block"
    both = parse_policy({"waivers": [waiver(source="alice", target="TEAM"),
                                     waiver(id="CHG-2", source="TEAM", target="svc_backup")]})
    assert run_check(corp, changes, policy=both, today=TODAY)[0].verdict == "pass"


def test_exposure_limit_applies_after_waivers(corp, run_check):
    pol = parse_policy({"max_new_exposed_actors": 0, "block_kinds": ["TIER0_PROMOTION"], "waivers": []})
    r, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)
    assert r.verdict == "block" and r.violations[0]["rule"] == "max_new_exposed_actors"
    pol = parse_policy({"max_new_exposed_actors": 0, "block_kinds": ["TIER0_PROMOTION"], "waivers": [waiver()]})
    assert run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)[0].verdict == "pass"


def test_score_increase_limit(corp, run_check):
    pol = parse_policy({"max_score_increase": 0, "block_kinds": ["TIER0_PROMOTION"]})
    r, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY)
    assert r.verdict == "block" and r.violations[0]["rule"] == "max_score_increase"


def test_score_limit_is_advisory_when_paths_are_capped(corp, run_check):
    pol = parse_policy({"max_score_increase": 0, "block_kinds": ["TIER0_PROMOTION"]})
    r, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol, today=TODAY, max_paths=1)
    v = next(v for v in r.violations if v["rule"] == "max_score_increase") if r.violations else None
    assert v is None or v["blocking"] is False


def test_stale_baseline_is_a_non_blocking_note(corp, run_check):
    from pathcutter.changes import load_changes, resolve_changes
    from pathcutter.impact import analyze_impact
    from pathcutter.policy import evaluate
    specs, _ = load_changes(inline=["add-member alice TEAM"])
    resolved, _ = resolve_changes(corp, specs)
    r = analyze_impact(corp, resolved)
    r.baseline = {"age_days": 120}
    evaluate(r, Policy(max_baseline_age_days=30), resolved, TODAY)
    assert r.verdict == "review" and "120 days old" in r.verdict_reason


def test_clean_change_passes_with_clear_reason(corp, run_check):
    r, _ = run_check(corp, ["add-member alice TEAM"])
    assert r.verdict == "pass" and "No change introduces" in r.verdict_reason
