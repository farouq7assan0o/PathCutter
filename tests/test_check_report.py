"""Renderers: text, Markdown, JSON, SARIF and the HTML review page."""
import json
import re

from pathcutter.check_html import path_svg, render_html
from pathcutter.check_report import chain_text, render_json, render_markdown, render_sarif, render_text
from pathcutter.policy import parse_policy

TODAY = None


def blocked(corp, run_check, extra=()):
    r, res = run_check(corp, ["add-member alice HELPDESK", *extra])
    r.baseline = {"path": "base.pcsnap", "kind": "snapshot", "nodes": 13, "edges": 4, "age_days": 3}
    return r


def test_text_report_has_verdict_path_and_fix(corp, run_check):
    t = render_text(blocked(corp, run_check))
    assert "Verdict  : BLOCK" in t and "alice -[+MemberOf]-> HELPDESK -[GenericAll]-> svc_backup" in t
    assert "fix first: Remove GenericAll" in t and "3 days old" in t


def test_text_report_is_pure_ascii(corp, run_check):
    t = render_text(blocked(corp, run_check))
    assert t.isascii()


def test_chain_text_marks_new_edges_and_objects():
    path = [{"name": "alice", "edge": "MemberOf", "new_edge": True, "new": True},
            {"name": "G", "edge": None, "new_edge": False}]
    assert chain_text(path) == "alice (new) -[+MemberOf]-> G"


def test_markdown_is_a_compact_pr_comment(corp, run_check):
    md = render_markdown(blocked(corp, run_check))
    assert md.startswith("## PathCutter AD change check: **BLOCKED**")
    assert "| 1 | `add alice to group HELPDESK`" in md and "<details open>" in md and "Fix these first" in md


def _outside_code(md: str) -> str:
    md = re.sub(r"```.*?```", "", md, flags=re.S)
    return re.sub(r"`[^`\n]*`", "", md)


def test_markdown_neutralises_hostile_names(corp, run_check):
    nasty = "<img src=x onerror=alert(1)>[click](https://evil.example)@some-org/team|`x`"
    r, _ = run_check(corp, [f'create user "{nasty}"', f'add-member "{nasty}" HELPDESK  # note {nasty}'])
    visible = _outside_code(render_markdown(r))
    assert "<img" not in visible and "](" not in visible
    assert "@some-org" not in visible                  # mention broken by a zero-width space
    assert "https://evil.example" not in visible.replace("\\(", "(") or "](" not in visible


def test_json_matches_schema(corp, run_check):
    d = json.loads(render_json(blocked(corp, run_check)))
    assert d["schema"] == "pathcutter.check/1"
    assert {"verdict", "posture", "totals", "changes", "findings", "policy", "warnings", "methodology"} <= set(d)
    assert d["findings"][0]["paths"][0][0]["name"] == "alice"


def test_sarif_is_valid_and_points_at_the_change_line(corp, run_check):
    from pathcutter.changes import load_changes, resolve_changes
    from pathcutter.impact import analyze_impact
    from pathcutter.policy import Policy, evaluate
    specs, _ = load_changes(inline=["add-member alice HELPDESK"])
    import dataclasses
    specs = [dataclasses.replace(specs[0], origin="infra/changes/pr-42.changes:7")]
    resolved, _ = resolve_changes(corp, specs)
    r = analyze_impact(corp, resolved)
    evaluate(r, Policy(), resolved)
    doc = json.loads(render_sarif(r))
    assert doc["version"] == "2.1.0" and doc["runs"][0]["tool"]["driver"]["name"] == "PathCutter"
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "NEW_EXPOSURE" and res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "infra/changes/pr-42.changes" and loc["region"]["startLine"] == 7
    assert {r_["id"] for r_ in doc["runs"][0]["tool"]["driver"]["rules"]} >= {"NEW_EXPOSURE"}


def test_sarif_marks_waived_findings_suppressed_and_omits_risk_reduction(corp, run_check):
    pol = parse_policy({"waivers": [{"id": "CHG-9", "reason": "pilot", "source": "alice", "target": "HELPDESK"}]})
    r, _ = run_check(corp, ["add-member alice HELPDESK", 'remove-member svc_backup "DOMAIN ADMINS"'.replace("svc_backup", "bob")],
                     policy=pol)
    doc = json.loads(render_sarif(r))
    results = doc["runs"][0]["results"]
    assert all(x["ruleId"] != "RISK_REDUCTION" for x in results)
    waived = [x for x in results if x.get("suppressions")]
    assert waived and "CHG-9" in waived[0]["suppressions"][0]["justification"]


def test_sarif_has_no_location_for_inline_changes(corp, run_check):
    doc = json.loads(render_sarif(blocked(corp, run_check)))
    assert "locations" not in doc["runs"][0]["results"][0]


# ----------------------------------------------------------------------- HTML

def test_html_review_page_structure(corp, run_check):
    h = render_html(blocked(corp, run_check))
    assert "<title>PathCutter change check - BLOCK</title>" in h
    for needle in ("Do not apply this change set as written", "THIS CHANGE", "Fix these first", "Proposed changes",
                   "Policy and waivers", "How to read this", 'id="report-json"', 'class="pathsvg"'):
        assert needle in h, needle
    assert "http" not in re.sub(r"https://attack\.mitre\.org/techniques/[A-Z0-9/]+", "", h).replace(
        "http://www.w3.org/2000/svg", "")  # no external network resources


def test_html_pass_state(corp, run_check):
    r, _ = run_check(corp, ['remove-member svc_backup "DOMAIN ADMINS"'])
    h = render_html(r)
    assert "reduces attack paths" in h and ">PASS<" in h


def test_html_hostile_names_cannot_inject_markup_or_scripts(corp, run_check):
    nasty = "</script><script>alert(1)</script><img src=x onerror=alert(2)>"
    r, _ = run_check(corp, [f'create user "{nasty}"', f'add-member "{nasty}" HELPDESK', f'grant HELPDESK GenericAll "{nasty}"'])
    h = render_html(r)
    assert "<script>alert" not in h and "<img src=x" not in h
    assert h.lower().count("<script") == h.lower().count("</script>")
    embedded = re.search(r'<script type="application/json" id="report-json">(.*?)</script>', h, re.S).group(1)
    assert "</script" not in embedded.lower() and json.loads(embedded)["schema"] == "pathcutter.check/1"


def test_path_svg_escapes_and_labels_the_change():
    svg = path_svg([{"name": "<b>x</b>", "type": "User", "tier": 2, "edge": "MemberOf", "new_edge": True},
                    {"name": "DA", "type": "Group", "tier": 0, "edge": None}])
    assert "<b>x</b>" not in svg and "&lt;b&gt;" in svg
    assert "THIS CHANGE" in svg and "TIER 0" in svg and svg.startswith("<svg")


def test_html_lists_waivers_and_violations(corp, run_check):
    pol = parse_policy({"waivers": [{"id": "CHG-7", "reason": "board approved", "approver": "cio",
                                     "expires": "2099-01-01", "source": "alice"}]})
    r, _ = run_check(corp, ["add-member alice HELPDESK"], policy=pol)
    h = render_html(r)
    assert "CHG-7" in h and "board approved" in h and "approved by cio" in h
