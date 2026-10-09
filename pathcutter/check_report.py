"""Plain-text, Markdown, JSON and SARIF renderers for a change-check ImpactReport.

All output is ASCII (project rule: no smart quotes or dashes) so it is safe in any
terminal, CI log or PR comment.
"""
from __future__ import annotations

import json

from . import __version__
from .impact import SEVERITIES, Finding, ImpactReport, finding_context, severity_rank

VERDICT_LABEL = {"block": "BLOCK", "review": "REVIEW", "pass": "PASS"}
KIND_LABEL = {
    "TIER0_PROMOTION": "Tier 0 promotion",
    "NEW_EXPOSURE": "New path to Tier 0",
    "COMBINED_EFFECT": "Combined effect",
    "PATH_SHORTENED": "Shorter path",
    "RISK_REDUCTION": "Risk reduction",
    "NOOP": "No effect",
    "NOTE": "Note",
    "UNMODELED": "Not modeled",
}
CHANGE_VERDICT_LABEL = {"ok": "OK", "review": "REVIEW", "block": "BLOCK", "waived": "WAIVED"}


def chain_text(path: list[dict]) -> str:
    parts = []
    for step in path:
        name = step["name"] + (" (new)" if step.get("new") else "")
        parts.append(name)
        if step.get("edge"):
            mark = "+" if step.get("new_edge") else ""
            parts.append(f"-[{mark}{step['edge']}]->")
    return " ".join(parts)


def _delta(report: ImpactReport) -> str:
    d = report.posture.get("score_delta", 0)
    return f"{d:+d}" if d else "no change"


def _sorted_findings(report: ImpactReport) -> list[Finding]:
    return sorted(report.findings, key=lambda f: (not f.blocking, -severity_rank(f.severity), f.id))


# ----------------------------------------------------------------------- text

def render_text(report: ImpactReport, width: int = 100) -> str:
    b, a = report.posture["before"], report.posture["after"]
    t = report.totals
    out = ["PathCutter change check", "=" * 23]
    base = report.baseline
    if base:
        age = f", {base['age_days']} days old" if base.get("age_days") is not None else ""
        out.append(f"Baseline : {base.get('path', '?')} ({base.get('kind', '?')}, {base.get('nodes', 0):,} nodes, "
                   f"{base.get('edges', 0):,} edges{age})")
    out.append(f"Changes  : {t['changes']}")
    out.append(f"Verdict  : {VERDICT_LABEL[report.verdict]} - {report.verdict_reason}")
    out.append("")
    out.append(f"Risk score      {b['score']} ({b['grade']}) -> {a['score']} ({a['grade']})   [{_delta(report)}]")
    out.append(f"Tier 0 promotions {t['promoted']}   newly exposed {t['newly_exposed']} "
               f"({t['newly_exposed_actors']} accounts)   shorter paths {t['shortened']}   secured {t['newly_secured']}")
    if t.get("paths_truncated"):
        out.append(f"Attack paths    capped at {a['paths']}; path counts and score are approximate")
    else:
        out.append(f"Attack paths    {b['paths']} -> {a['paths']}  (+{t['paths_added']} / -{t['paths_removed']})")
    out.append("")

    findings = _sorted_findings(report)
    for cr in report.changes:
        out.append(f"#{cr.index}  {cr.describe}   [{CHANGE_VERDICT_LABEL.get(cr.verdict, cr.verdict).upper()}]")
        meta = " | ".join(x for x in (cr.origin, cr.note) if x)
        if meta:
            out.append(f"    {meta}")
        for f in (x for x in findings if x.id in cr.finding_ids and (len(x.changes) == 1 or x.kind == "COMBINED_EFFECT")):
            out.extend(_finding_text(f, width))
        out.append("")
    shown = {fid for cr in report.changes for fid in cr.finding_ids}
    loose = [f for f in findings if f.id not in shown]
    if loose:
        out.append("Other findings")
        for f in loose:
            out.extend(_finding_text(f, width))
        out.append("")
    for v in report.violations:
        out.append(f"{'POLICY' if v['blocking'] else 'NOTE'}: {v['message']}")
    for w in report.warnings:
        out.append(f"WARNING: {w}")
    return "\n".join(out).rstrip() + "\n"


def _finding_text(f: Finding, width: int) -> list[str]:
    flag = " [WAIVED]" if f.waiver and f.waiver.get("status") == "applied" else ""
    flag = " [SUPERSEDED]" if f.superseded else flag
    lines = [f"    [{f.severity}] {KIND_LABEL.get(f.kind, f.kind)}{flag}: {f.title}"]
    if f.paths:
        lines.append(f"      path : {chain_text(f.paths[0])}")
    if f.principals and f.kind in ("NEW_EXPOSURE", "COMBINED_EFFECT", "PATH_SHORTENED"):
        names = ", ".join(p["name"] for p in f.principals[:6])
        more = f" and {f.principal_total - 6} more" if f.principal_total > 6 else ""
        lines.append(f"      who  : {names}{more}")
    if f.mitre:
        lines.append(f"      mitre: {', '.join(f.mitre)}")
    if f.kind == "UNMODELED" and f.origin:
        lines.append(f"      at   : {f.origin}")
    for fx in f.fix_first[:3]:
        lines.append(f"      fix first: {fx['description']} (cuts {fx['paths_eliminated']} path"
                     f"{'s' if fx['paths_eliminated'] != 1 else ''}, {fx['safety']})")
    if f.fix_note and not f.fix_first:
        lines.append(f"      note : {f.fix_note}")
    for ctx_line in finding_context(f):
        lines.append(f"      note : {ctx_line}")
    if f.waiver:
        w = f.waiver
        lines.append(f"      waiver {w['id']} ({w['status']}): {w['reason']}"
                     + (f" - approved by {w['approver']}" if w.get("approver") else "")
                     + (f", expires {w['expires']}" if w.get("expires") else ""))
    return lines


# ------------------------------------------------------------------- markdown

def _h(text: str) -> str:
    """Inert text for raw-HTML context inside Markdown (e.g. a <summary> line)."""
    import html as _html
    flat = str(text).replace("\r", " ").replace("\n", " ")
    return _html.escape(flat, quote=True).replace("@", "@&#8203;")


def _code(text: str) -> str:
    """Inert text for an inline code span or fenced block (backslash escapes do not apply there)."""
    return str(text).replace("`", "'").replace("\r", " ").replace("\n", " ")


_MD_SPECIAL = "\\`*_{}[]()#+!~|"


def _md(text: str) -> str:
    """Make attacker-controlled text inert in GitHub-flavoured Markdown.

    Object names and change notes come from a pull request author, so they must not be able to
    create links, images, HTML or @mentions in the comment we post.
    """
    out = []
    for ch in str(text).replace("\r", " ").replace("\n", " "):
        if ch == "<":
            out.append("&lt;")
        elif ch == ">":
            out.append("&gt;")
        elif ch == "@":
            out.append("@&#8203;")          # zero-width space: the text is no longer a mention
        elif ch in _MD_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def render_markdown(report: ImpactReport, max_findings: int = 12) -> str:
    b, a = report.posture["before"], report.posture["after"]
    t = report.totals
    badge = {"block": "BLOCKED", "review": "NEEDS REVIEW", "pass": "PASSED"}[report.verdict]
    out = [f"## PathCutter AD change check: **{badge}**", "", f"> {_md(report.verdict_reason)}", ""]
    out.append("| Metric | Before | After |")
    out.append("|---|---|---|")
    out.append(f"| Risk score | {b['score']} ({b['grade']}) | {a['score']} ({a['grade']}) |")
    out.append(f"| Exposed accounts | {b['exposed_actors']} | {a['exposed_actors']} |")
    out.append(f"| Attack paths | {b['paths']}{' (capped)' if t.get('paths_truncated') else ''} | {a['paths']}{' (capped)' if t.get('paths_truncated') else ''} |")
    out.append(f"| Tier 0 objects | {b['tier0']} | {a['tier0']} |")
    out.append("")
    out.append("| # | Change | Result |")
    out.append("|---|---|---|")
    for cr in report.changes:
        out.append(f"| {cr.index} | `{_code(cr.describe).replace('|', chr(92) + '|')}`{' - ' + _md(cr.note) if cr.note else ''} | "
                   f"**{CHANGE_VERDICT_LABEL.get(cr.verdict, cr.verdict)}** |")
    out.append("")
    findings = [f for f in _sorted_findings(report) if f.kind not in ("NOOP",) or f.blocking]
    for f in findings[:max_findings]:
        status = " (waived)" if f.waiver and f.waiver.get("status") == "applied" else (" (superseded)" if f.superseded else "")
        out.append(f"<details{' open' if f.blocking else ''}><summary><b>[{f.severity}]</b> "
                   f"{KIND_LABEL.get(f.kind, f.kind)}: {_h(f.title)}{status}</summary>")
        out.append("")
        out.append(_md(f.detail))
        out.append("")
        if f.paths:
            out.append("```text")
            out.append(_code(chain_text(f.paths[0])))
            out.append("```")
        if f.principals and f.kind in ("NEW_EXPOSURE", "COMBINED_EFFECT", "PATH_SHORTENED"):
            names = ", ".join(f"`{_code(p['name'])}`" for p in f.principals[:8])
            out.append(f"Exposed: {names}{' and ' + str(f.principal_total - 8) + ' more' if f.principal_total > 8 else ''}")
            out.append("")
        if f.fix_first:
            out.append("**Fix these first:**")
            for fx in f.fix_first:
                out.append(f"- {_md(fx['description'])} (cuts {fx['paths_eliminated']} paths, safety: {fx['safety']})")
            out.append("")
        elif f.fix_note:
            out.append(f"_{_md(f.fix_note)}_")
            out.append("")
        for ctx_line in finding_context(f):
            out.append(f"> {_md(ctx_line)}")
            out.append("")
        if f.waiver:
            w = f.waiver
            out.append(f"Waiver `{_code(w['id'])}` ({w['status']}): {_md(w['reason'])}"
                       + (f", approved by {_md(w['approver'])}" if w.get("approver") else "")
                       + (f", expires {w['expires']}" if w.get("expires") else ""))
            out.append("")
        out.append("</details>")
        out.append("")
    if len(findings) > max_findings:
        out.append(f"_{len(findings) - max_findings} more finding(s) in the full report._")
        out.append("")
    for v in report.violations:
        out.append(f"- **{'Policy' if v['blocking'] else 'Note'}:** {_md(v['message'])}")
    for w in report.warnings:
        out.append(f"- Warning: {_md(w)}")
    out.append("")
    out.append(f"<sub>PathCutter {__version__} - {report.schema} - baseline {_h(report.baseline.get('path', ''))}</sub>")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------ json

def render_json(report: ImpactReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str) + "\n"


# ------------------------------------------------------------------------ sarif

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _location(origin: str) -> dict | None:
    if ":" not in origin:
        return None
    path, _, line = origin.rpartition(":")
    if not line.isdigit() or not path or path.startswith("--change"):
        return None
    return {"physicalLocation": {"artifactLocation": {"uri": path.replace("\\", "/")},
                                 "region": {"startLine": int(line)}}}


def render_sarif(report: ImpactReport) -> str:
    rules = []
    seen = set()
    for f in report.findings:
        if f.kind in seen:
            continue
        seen.add(f.kind)
        rules.append({
            "id": f.kind, "name": KIND_LABEL.get(f.kind, f.kind),
            "shortDescription": {"text": KIND_LABEL.get(f.kind, f.kind)},
            "fullDescription": {"text": {
                "TIER0_PROMOTION": "A change makes a principal a member of a Tier 0 group.",
                "NEW_EXPOSURE": "A change gives objects a new attack path to Tier 0.",
                "COMBINED_EFFECT": "Changes that are harmless alone open a path to Tier 0 together.",
                "PATH_SHORTENED": "A change shortens existing attack paths to Tier 0.",
                "RISK_REDUCTION": "A change removes attack paths to Tier 0.",
                "NOOP": "A change has no effect on the baseline.",
                "NOTE": "A recognised action with no modeled effect on attack paths, or worth reading.",
                "UNMODELED": "Part of the change could not be analyzed.",
            }.get(f.kind, f.kind)},
            "helpUri": "https://github.com/farouq7assan0o/PathCutter",
        })
    changes = {c.index: c for c in report.changes}
    results = []
    for f in report.findings:
        if f.kind == "RISK_REDUCTION":
            continue
        locs = []
        if f.origin:
            loc = _location(f.origin)
            locs = [loc] if loc else []
        else:
            for idx in f.changes:
                loc = _location(changes[idx].origin) if idx in changes else None
                if loc:
                    locs.append(loc)
        text = f"{f.title}. {f.detail}"
        if f.paths:
            text += f" Path: {chain_text(f.paths[0])}"
        result = {"ruleId": f.kind, "level": _SARIF_LEVEL[f.severity] if not f.superseded else "note",
                  "message": {"text": text}, "properties": {
                      "severity": f.severity, "blocking": f.blocking, "principals": f.principal_total,
                      "mitre": f.mitre, "findingId": f.id}}
        if locs:
            result["locations"] = locs
        if f.waiver and f.waiver.get("status") == "applied":
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": f"{f.waiver['id']}: {f.waiver['reason']}"}]
        results.append(result)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "PathCutter", "version": __version__,
                                      "informationUri": "https://github.com/farouq7assan0o/PathCutter",
                                      "rules": rules}},
                  "results": results,
                  "properties": {"verdict": report.verdict, "scoreBefore": report.posture["before"]["score"],
                                 "scoreAfter": report.posture["after"]["score"]}}],
    }
    return json.dumps(doc, indent=2) + "\n"
