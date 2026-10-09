"""Self-contained HTML review page for a change-check ImpactReport.

Server-rendered (no framework, no network): the attack-path diagrams are inline SVG
built here, so the file works offline, prints cleanly and can be attached to a
change ticket. Every dynamic string is HTML-escaped because AD object names are
attacker-controlled.
"""
from __future__ import annotations

import html
from itertools import count

from . import __version__
from .check_report import CHANGE_VERDICT_LABEL, KIND_LABEL, VERDICT_LABEL
from .impact import Finding, ImpactReport, finding_context, severity_rank
from .report import _safe_json

e = html.escape

NODE_COLORS = {"User": "#3b82f6", "Computer": "#10b981", "Group": "#f59e0b", "Domain": "#ef4444",
               "GPO": "#8b5cf6", "OU": "#6366f1", "CertTemplate": "#ec4899", "EnterpriseCA": "#ec4899"}
_EDGE_RED = {"GenericAll", "DCSync", "AllowedToDelegate", "WriteKeyCredentialLink"}
_EDGE_ORANGE = {"GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AllowedToAct", "AddAllowedToAct", "GPOControlsObject"}
_EDGE_YELLOW = {"ForceChangePassword", "AddMember", "WriteSPN", "ReadLAPSPassword", "ReadGMSAPassword"}
_EDGE_PURPLE = {"AdminTo", "HasSession", "CanRDP", "CanPSRemote", "ExecuteDCOM", "SQLAdmin"}
GRADE_COLOR = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}


def edge_color(et: str) -> str:
    if et in _EDGE_RED:
        return "#ef4444"
    if et in _EDGE_ORANGE:
        return "#f97316"
    if et in _EDGE_YELLOW:
        return "#eab308"
    if et in _EDGE_PURPLE:
        return "#a855f7"
    return "#64748b"


# ---------------------------------------------------------------- SVG diagrams

_uid = count(1)


def path_svg(path: list[dict]) -> str:
    """One attack path as a left-to-right chain of nodes joined by labelled arrows."""
    uid = next(_uid)
    pad, h, cy = 14, 74, 40
    x = pad
    parts: list[str] = []
    colors_used: set[str] = set()
    for i, step in enumerate(path):
        label = step["name"] + (" (new)" if step.get("new") else "")
        shown = label if len(label) <= 24 else label[:22] + ".."
        w = max(88, int(len(shown) * 6.9) + 30)
        color = NODE_COLORS.get(step["type"], "#64748b")
        is_t0 = step.get("tier") == 0
        stroke = "#ef4444" if is_t0 else color
        dash = ' stroke-dasharray="5 3"' if step.get("new") else ""
        parts.append(
            f'<g><title>{e(label)} [{e(step["type"])}, tier {step.get("tier", 2)}]</title>'
            f'<rect x="{x}" y="{cy - 17}" width="{w}" height="34" rx="9" fill="{color}" fill-opacity="0.16" '
            f'stroke="{stroke}" stroke-width="{2.4 if is_t0 else 1.6}"{dash}/>'
            f'<circle cx="{x + 13}" cy="{cy}" r="4.5" fill="{color}"/>'
            f'<text x="{x + 24}" y="{cy + 4}" font-size="12" font-weight="600" fill="currentColor">{e(shown)}</text>'
            + (f'<text x="{x + w - 6}" y="{cy - 21}" font-size="9" font-weight="700" fill="#ef4444" text-anchor="end">TIER 0</text>' if is_t0 else "")
            + "</g>")
        x += w
        et = step.get("edge")
        if et and i + 1 < len(path):
            gap = max(84, int(len(et) * 6.6) + 34)
            ec = "#22c55e" if step.get("new_edge") else edge_color(et)
            colors_used.add(ec)
            sw = 3.2 if step.get("new_edge") else 1.8
            x1, x2 = x + 3, x + gap - 5
            parts.append(f'<line x1="{x1}" y1="{cy}" x2="{x2}" y2="{cy}" stroke="{ec}" stroke-width="{sw}" '
                         f'marker-end="url(#m{uid}{ec[1:]})"/>')
            lw = len(et) * 6.4 + 12
            lx = x + gap / 2
            if step.get("new_edge"):
                parts.append(f'<rect x="{lx - lw / 2}" y="{cy - 29}" width="{lw}" height="16" rx="8" fill="#22c55e"/>'
                             f'<text x="{lx}" y="{cy - 17}" font-size="10" font-weight="700" fill="#052e16" text-anchor="middle">+ {e(et)}</text>'
                             f'<text x="{lx}" y="{cy + 20}" font-size="9" font-weight="700" fill="#22c55e" text-anchor="middle">THIS CHANGE</text>')
            else:
                parts.append(f'<text x="{lx}" y="{cy - 9}" font-size="10.5" fill="{ec}" text-anchor="middle" font-weight="600">{e(et)}</text>')
            x += gap
    width = x + pad
    defs = "".join(f'<marker id="m{uid}{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                   f'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="{c}"/></marker>' for c in sorted(colors_used))
    return (f'<svg class="pathsvg" role="img" aria-label="Attack path" width="{width}" height="{h}" '
            f'viewBox="0 0 {width} {h}"><defs>{defs}</defs>{"".join(parts)}</svg>')


def gauge_svg(score: int, grade: str, label: str) -> str:
    c = GRADE_COLOR.get(grade, "#94a3b8")
    circ = 2 * 3.14159 * 34
    off = circ * (1 - max(0, min(score, 100)) / 100)
    return (f'<figure class="gauge"><svg viewBox="0 0 84 84" width="96" height="96" role="img" aria-label="{e(label)} risk score {score}">'
            f'<circle cx="42" cy="42" r="34" fill="none" stroke="var(--line)" stroke-width="7"/>'
            f'<circle cx="42" cy="42" r="34" fill="none" stroke="{c}" stroke-width="7" stroke-linecap="round" '
            f'stroke-dasharray="{circ:.1f}" stroke-dashoffset="{off:.1f}" transform="rotate(-90 42 42)"/>'
            f'<text x="42" y="46" text-anchor="middle" font-size="22" font-weight="800" fill="currentColor">{score}</text>'
            f'<text x="42" y="60" text-anchor="middle" font-size="9" fill="var(--dim)">Grade {e(grade)}</text></svg>'
            f'<figcaption>{e(label)}</figcaption></figure>')


# --------------------------------------------------------------------- sections

def _chip(text: str, cls: str) -> str:
    return f'<span class="chip {cls}">{e(text)}</span>'


def _hops(p: dict) -> str:
    b, a = p.get("hops_before"), p.get("hops_after")
    if a == 0:
        return "becomes Tier 0"
    left = "none" if b is None else f"{b} hops"
    right = "secured" if a is None else f"{a} hop{'s' if a != 1 else ''}"
    return f"{left} &rarr; {right}"


def _finding_html(f: Finding, changes_by_index: dict, expanded: bool = False) -> str:
    waived = f.waiver and f.waiver.get("status") == "applied"
    classes = f"finding sev-{f.severity}" + (" waived" if waived else "") + (" superseded" if f.superseded else "") + (" blocking" if f.blocking else "")
    head = [_chip(f.severity.upper(), f"sev sev-{f.severity}"), _chip(KIND_LABEL.get(f.kind, f.kind), "kind")]
    if f.blocking:
        head.append(_chip("BLOCKS MERGE", "block"))
    if waived:
        head.append(_chip("WAIVED", "waived"))
    if f.superseded:
        head.append(_chip("CANCELLED BY OTHER CHANGES", "ok"))
    refs = " ".join(f'<a class="chg" href="#c{i}">change #{i}</a>' for i in f.changes[:6]) if f.changes else ""
    out = [f'<article class="{classes}" id="{f.id}" data-sev="{f.severity}" data-kind="{f.kind}">',
           f'<header>{"".join(head)}<h3>{e(f.title)}</h3>{refs}</header>', f'<p class="detail">{e(f.detail)}</p>']
    if f.fix_first:
        out.append(f'<p class="nextfix"><strong>Fix first:</strong> {e(f.fix_first[0]["description"])}</p>')
    out.append(f'<details class="body"{" open" if expanded else ""}><summary>Paths, who is affected, fixes</summary>')
    if f.paths:
        out.append('<div class="diagram" aria-label="Attack paths">' + "".join(path_svg(p) for p in f.paths[:3]) + "</div>")
        if len(f.paths) > 3:
            out.append(f'<p class="dim small">Showing 3 of {len(f.paths)} example paths.</p>')
    cols = []
    if f.why or f.mitre:
        li = "".join(f"<li>{e(w)}</li>" for w in f.why)
        mitre = "".join(f'<a class="mitre" href="https://attack.mitre.org/techniques/{e(m.replace(".", "/"))}/" rel="noopener noreferrer">{e(m)}</a>' for m in f.mitre)
        cols.append(f'<div><h4>Why this works</h4><ul>{li}</ul><div class="mitres">{mitre}</div></div>')
    if f.principals and f.kind != "NOOP":
        rows = "".join(
            f'<tr><td>{e(p["name"])}{" <em>(new)</em>" if p.get("new") else ""}</td><td>{e(p["type"])}</td>'
            f'<td><span class="tier t{p["tier"]}">T{p["tier"]}</span></td><td>{_hops(p)}</td></tr>'
            for p in f.principals[:12])
        extra = ""
        if len(f.principals) > 12:
            more = "".join(f'<tr><td>{e(p["name"])}</td><td>{e(p["type"])}</td><td><span class="tier t{p["tier"]}">T{p["tier"]}</span></td><td>{_hops(p)}</td></tr>' for p in f.principals[12:])
            extra = f'<details><summary>Show {len(f.principals) - 12} more listed</summary><table class="tbl"><tbody>{more}</tbody></table></details>'
        acct = f"{f.actors_total} user/computer account{'s' if f.actors_total != 1 else ''}"
        total_note = f' <span class="dim small">({f.principal_total} total, {acct})</span>' if f.principal_total > len(f.principals) or f.actors_total else ""
        cols.append(f'<div><h4>Who is affected{total_note}</h4><table class="tbl"><thead><tr><th>Object</th><th>Type</th><th>Tier</th><th>Path to Tier 0</th></tr></thead><tbody>{rows}</tbody></table>{extra}</div>')
    if cols:
        out.append(f'<div class="cols">{"".join(cols)}</div>')
    if f.fix_first or f.fix_note:
        fixes = []
        for fx in f.fix_first:
            warn = "".join(f"<li>{e(w)}</li>" for w in fx.get("warnings", []))
            fixes.append(
                f'<div class="fixrow"><div class="fixhead"><strong>{e(fx["description"])}</strong> '
                f'<span class="dim small">cuts {fx["paths_eliminated"]} path{"s" if fx["paths_eliminated"] != 1 else ""} '
                f'({fx["cumulative_pct"]:.0f}% cumulative)</span> {_chip(fx["safety"], "safety-" + fx["safety"])}</div>'
                + (f'<ul class="warn">{warn}</ul>' if warn else "")
                + (f'<div class="cmdwrap"><button class="copy" type="button" aria-label="Copy command">Copy</button><pre class="cmd">{e(fx["command"])}</pre></div>' if fx.get("command") else "")
                + "</div>")
        out.append(f'<div class="fix"><h4>Fix these first, then re-run the check</h4><p class="small">{e(f.fix_note)}</p>{"".join(fixes)}</div>')
    for ctx_line in finding_context(f):
        out.append(f'<div class="waiver"><strong>Context:</strong> {e(ctx_line)}</div>')
    if f.waiver:
        w = f.waiver
        exp = f' &middot; expires {e(str(w["expires"]))}' if w.get("expires") else ""
        who = f' &middot; approved by {e(w["approver"])}' if w.get("approver") else ""
        label = "Accepted risk (waiver applied)" if w["status"] == "applied" else "Waiver expired - no longer applies"
        out.append(f'<div class="waiver {e(w["status"])}"><strong>{label}:</strong> {e(w["id"])}{who}{exp}<br>{e(w["reason"])}</div>')
    out.append("</details></article>")
    return "".join(out)


def _change_html(cr, findings_by_id: dict) -> str:
    chips = {"ok": "ok", "review": "review", "block": "block", "waived": "waived"}[cr.verdict]
    bits = []
    if cr.promoted:
        bits.append(f"{cr.promoted} promoted to Tier 0")
    if cr.newly_exposed:
        bits.append(f"{cr.newly_exposed} newly exposed")
    if cr.shortened:
        bits.append(f"{cr.shortened} shorter paths")
    if cr.newly_secured:
        bits.append(f"{cr.newly_secured} secured")
    if cr.effect == "noop":
        bits.append("no effect: " + e(cr.noop_reason))
    if not bits:
        bits.append("no change in exposure")
    links = " ".join(f'<a href="#{fid}">{fid}</a>' for fid in cr.finding_ids if fid in findings_by_id)
    note = f'<span class="note">{e(cr.note)}</span>' if cr.note else ""
    origin = f'<span class="origin">{e(cr.origin)}</span>' if cr.origin else ""
    assumed = f'<div class="small dim">Assumed new object(s): {e(", ".join(cr.assumed_new))}</div>' if cr.assumed_new else ""
    return (f'<li class="change v-{chips}" id="c{cr.index}"><span class="idx">{cr.index}</span>'
            f'<div class="cbody"><div class="cline"><code>{e(cr.describe)}</code>{note}{origin}</div>'
            f'<div class="small dim">{" &middot; ".join(bits)} {links}</div>{assumed}</div>'
            f'{_chip(CHANGE_VERDICT_LABEL.get(cr.verdict, cr.verdict), "v " + chips)}</li>')


def _tile(label: str, value: str, sub: str = "", cls: str = "") -> str:
    return f'<div class="tile {cls}"><div class="tl">{e(label)}</div><div class="tv">{value}</div><div class="ts">{sub}</div></div>'


_HEADLINE = {
    "block": "Do not apply this change set as written",
    "review": "This change set needs a human decision",
    "pass": "No new route to Tier 0",
}


def render_html(report: ImpactReport) -> str:
    b, a, t = report.posture["before"], report.posture["after"], report.totals
    delta = report.posture.get("score_delta", 0)
    headline = _HEADLINE[report.verdict]
    if report.verdict == "pass" and t["newly_secured"]:
        headline = "This change set reduces attack paths to Tier 0"
    dcls = "up" if delta > 0 else "down" if delta < 0 else "flat"
    findings = sorted(report.findings, key=lambda f: (not f.blocking, -severity_rank(f.severity), f.id))
    by_id = {f.id: f for f in findings}
    visible = [f for f in findings if f.kind != "NOOP" or f.blocking]
    changes_by_index = {c.index: c for c in report.changes}
    base = report.baseline

    tiles = "".join([
        _tile("Risk score", f'{b["score"]} &rarr; {a["score"]}', f'<span class="delta {dcls}">{delta:+d} points</span>' if delta else '<span class="delta flat">no change</span>'),
        _tile("Tier 0 promotions", str(t["promoted"]), "principals gain domain-wide control", "bad" if t["promoted"] else ""),
        _tile("Newly exposed", str(t["newly_exposed"]), f'{t["newly_exposed_actors"]} user/computer accounts', "bad" if t["newly_exposed"] else ""),
        _tile("Shorter paths", str(t["shortened"]), "objects that got an easier route", "warn" if t["shortened"] else ""),
        _tile("Secured", str(t["newly_secured"]), f'{t["newly_secured_actors"]} accounts lose their route', "good" if t["newly_secured"] else ""),
        _tile("Attack paths", f'{b["paths"]} &rarr; {a["paths"]}', "enumeration capped; counts are approximate" if t.get("paths_truncated") else f'+{t["paths_added"]} / -{t["paths_removed"]}'),
    ])

    age = f' &middot; {base["age_days"]} days old' if base.get("age_days") is not None else ""
    base_name = str(base.get("path", "?")).replace("\\", "/").rsplit("/", 1)[-1] if base else ""
    base_line = (f'<span class="chip kind" title="{e(str(base.get("path", "")))}">Baseline: {e(base_name)} ({e(str(base.get("kind", "?")))}, '
                 f'{base.get("nodes", 0):,} nodes, {base.get("edges", 0):,} edges{age})</span>') if base else ""

    sev_counts = {}
    for f in visible:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    filters = "".join(f'<button class="fchip sev-{s}" type="button" data-f="{s}" aria-pressed="true">{s} ({sev_counts[s]})</button>'
                      for s in ("critical", "high", "medium", "low", "info") if s in sev_counts)

    pol = report.policy or {}
    policy_rows = [
        ("Block when severity is at least", pol.get("block_severity", "high")),
        ("Blocking kinds", ", ".join(pol.get("block_kinds", []))),
        ("Needs review at severity", pol.get("review_severity", "medium")),
        ("Max newly exposed accounts", pol.get("max_new_exposed_actors") if pol.get("max_new_exposed_actors") is not None else "not set"),
        ("Max score increase", pol.get("max_score_increase") if pol.get("max_score_increase") is not None else "not set"),
        ("Extra Tier 0 assets", ", ".join(pol.get("extra_tier0", [])) or "none"),
        ("Policy source", pol.get("source", "built-in default")),
    ]
    waiver_html = ""
    for w in pol.get("waivers_applied", []):
        waiver_html += f'<li><strong>{e(w["id"])}</strong> applied: {e(w["reason"])}{" - " + e(w["approver"]) if w.get("approver") else ""}{", expires " + e(str(w["expires"])) if w.get("expires") else ""}</li>'
    for w in pol.get("waivers_expired", []):
        waiver_html += f'<li class="expired"><strong>{e(w["id"])}</strong> EXPIRED {e(str(w["expires"]))} - no longer applies</li>'
    for c in pol.get("controls_applied", []):
        waiver_html += (f'<li><strong>{e(c["id"])}</strong> declared control ({e(c["type"])}, owner {e(c["owner"])}) lowered severity: '
                        f'{e(c["evidence"])}. Declared, not verified.</li>')
    for c in pol.get("controls_expired", []):
        waiver_html += f'<li class="expired"><strong>{e(c["id"])}</strong> declared control EXPIRED {e(str(c["expires"]))} - no longer applies</li>'
    if pol.get("jit_max_minutes"):
        policy_rows.append(("Time-bound grants relieved up to", f'{pol["jit_max_minutes"]} minutes (one severity step)'))
    if pol.get("controls"):
        policy_rows.append(("Declared controls", ", ".join(c["id"] for c in pol["controls"])))
    prow = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in policy_rows)
    viol = "".join(f'<li class="{"bad" if v["blocking"] else "warn"}">{e(v["message"])}</li>' for v in report.violations)
    warns = "".join(f"<li>{e(w)}</li>" for w in report.warnings)
    method = "".join(f"<li>{e(m)}</li>" for m in report.methodology)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PathCutter change check - {VERDICT_LABEL[report.verdict]}</title>
<style>{_CSS}</style></head>
<body>
<a class="skip" href="#findings">Skip to findings</a>
<header class="top"><div class="brand"><span class="logo" aria-hidden="true">PC</span><span>PathCutter</span><span class="sub">AD change check</span></div>
<div class="tools"><button id="theme" type="button">Theme</button><button id="dl" type="button">Download JSON</button><button id="print" type="button">Print</button></div></header>
<main>
<section class="hero v-{report.verdict}" aria-labelledby="h-verdict">
  <div class="vbadge" role="status">{VERDICT_LABEL[report.verdict]}</div>
  <div class="vtext"><h1 id="h-verdict">{e(headline)}</h1><p>{e(report.verdict_reason)}</p>
  <div class="chips">{base_line}<span class="chip kind">{t["changes"]} change{"s" if t["changes"] != 1 else ""}</span><span class="chip kind">generated {e(report.generated)}</span></div></div>
  <div class="gauges">{gauge_svg(b["score"], b["grade"], "Before")}<span class="arrow" aria-hidden="true">&rarr;</span>{gauge_svg(a["score"], a["grade"], "After")}</div>
</section>
<section class="tiles" aria-label="Summary">{tiles}</section>
<section aria-labelledby="h-changes"><h2 id="h-changes">Proposed changes</h2><ol class="changes">{"".join(_change_html(c, by_id) for c in report.changes)}</ol></section>
<section id="findings" aria-labelledby="h-findings"><div class="fhead"><h2 id="h-findings">Findings</h2><div class="filters" role="group" aria-label="Filter by severity">{filters}<button type="button" id="expall">Expand all</button></div></div>
{"".join(_finding_html(f, changes_by_index, expanded=(i < 3 and (f.blocking or f.severity in ("critical", "high")))) for i, f in enumerate(visible)) or '<p class="empty">No findings. This change set does not alter any route to Tier 0.</p>'}</section>
<section aria-labelledby="h-policy"><h2 id="h-policy">Policy and waivers</h2><div class="cols"><div><table class="tbl kv"><tbody>{prow}</tbody></table></div>
<div>{('<h4>Violations</h4><ul class="vl">' + viol + '</ul>') if viol else ''}{('<h4>Waivers</h4><ul class="vl">' + waiver_html + '</ul>') if waiver_html else '<p class="dim small">No waivers applied.</p>'}</div></div></section>
{('<section aria-labelledby="h-warn"><h2 id="h-warn">Warnings</h2><ul class="vl warn">' + warns + '</ul></section>') if warns else ''}
<section aria-labelledby="h-method"><h2 id="h-method">How to read this</h2><ul class="method">{method}</ul></section>
</main>
<footer>PathCutter {e(__version__)} &middot; {e(report.schema)} &middot; analysis took {t.get("analysis_seconds", 0)}s</footer>
<script type="application/json" id="report-json">{_safe_json(report.to_dict())}</script>
<script>{_JS}</script></body></html>"""


_CSS = """
:root{--bg:#0b1220;--panel:#111a2e;--panel2:#16213a;--line:#25324d;--text:#e6ecf7;--dim:#94a3b8;--accent:#60a5fa;
--ok:#22c55e;--warn:#eab308;--bad:#ef4444;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#60a5fa;--info:#94a3b8;color-scheme:dark}
:root[data-theme=light]{--bg:#f5f7fb;--panel:#fff;--panel2:#eef2f9;--line:#d5dcec;--text:#0f172a;--dim:#51607a;--accent:#2563eb;color-scheme:light}
@media(prefers-color-scheme:light){:root:not([data-theme=dark]){--bg:#f5f7fb;--panel:#fff;--panel2:#eef2f9;--line:#d5dcec;--text:#0f172a;--dim:#51607a;--accent:#2563eb;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:0 16px 40px}h1,h2,h3,h4{margin:0}h2{font-size:1.15rem;margin:30px 0 12px}h3{font-size:1rem}h4{font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);margin:0 0 6px}
a{color:var(--accent)}code,pre{font-family:ui-monospace,Cascadia Code,Consolas,monospace}.dim{color:var(--dim)}.small{font-size:.8rem}
.skip{position:absolute;left:-999px}.skip:focus{left:8px;top:8px;background:var(--panel);padding:6px 10px;z-index:9}
.top{max-width:1180px;margin:0 auto;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:700}.logo{display:grid;place-items:center;width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;font-size:.78rem}
.sub{color:var(--dim);font-weight:500}.tools{display:flex;gap:8px}button{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer}
button:hover{border-color:var(--accent)}button:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.hero{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:22px;align-items:center;background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--line);border-radius:14px;padding:22px}
.hero.v-block{border-left-color:var(--bad)}.hero.v-review{border-left-color:var(--warn)}.hero.v-pass{border-left-color:var(--ok)}
.vbadge{font-weight:800;font-size:1.5rem;letter-spacing:.08em;padding:12px 20px;border-radius:10px;color:#fff;background:var(--line)}
.v-block .vbadge{background:var(--bad)}.v-review .vbadge{background:#b45309}.v-pass .vbadge{background:#15803d}
.vtext h1{font-size:1.45rem;margin-bottom:4px}.vtext p{margin:0 0 10px;color:var(--dim)}.chips{display:flex;gap:6px;flex-wrap:wrap;min-width:0}.chips .chip{max-width:100%;overflow:hidden;text-overflow:ellipsis}
.gauges{display:flex;align-items:center;gap:6px}.gauge{margin:0;text-align:center}.gauge figcaption{font-size:.72rem;color:var(--dim)}.arrow{font-size:1.4rem;color:var(--dim)}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.72rem;font-weight:700;background:var(--panel2);border:1px solid var(--line);color:var(--dim);white-space:nowrap}
.chip.sev-critical{background:var(--crit);border-color:var(--crit);color:#fff}.chip.sev-high{background:var(--high);border-color:var(--high);color:#1a0b00}
.chip.sev-medium{background:var(--med);border-color:var(--med);color:#241a00}.chip.sev-low{background:var(--low);border-color:var(--low);color:#00152e}.chip.sev-info{background:var(--info);border-color:var(--info);color:#0f172a}
.chip.block,.chip.v.block{background:var(--bad);border-color:var(--bad);color:#fff}.chip.v.review{background:#b45309;border-color:#b45309;color:#fff}.chip.v.ok,.chip.ok{background:#166534;border-color:#166534;color:#dcfce7}
.chip.waived,.chip.v.waived{background:#475569;border-color:#475569;color:#fff}.chip.safety-safe{color:var(--ok)}.chip.safety-caution{color:var(--warn)}.chip.safety-dangerous{color:var(--bad)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:14px}.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
.tl{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--dim)}.tv{font-size:1.5rem;font-weight:800;margin:2px 0}.ts{font-size:.78rem;color:var(--dim)}
.tile.bad .tv{color:var(--bad)}.tile.warn .tv{color:var(--warn)}.tile.good .tv{color:var(--ok)}.delta.up{color:var(--bad)}.delta.down{color:var(--ok)}.delta.flat{color:var(--dim)}
.changes{list-style:none;margin:0;padding:0;display:grid;gap:8px}.change{display:flex;align-items:center;gap:12px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.change.v-block{border-left:4px solid var(--bad)}.change.v-review{border-left:4px solid var(--warn)}.change.v-ok{border-left:4px solid var(--ok)}.change.v-waived{border-left:4px solid #64748b}
.idx{display:grid;place-items:center;min-width:28px;height:28px;border-radius:50%;background:var(--panel2);border:1px solid var(--line);font-weight:700;font-size:.8rem}.cbody{flex:1;min-width:0}
.cline{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline}.cline code{font-size:.88rem;word-break:break-word}.origin{color:var(--dim);font-size:.75rem}.note{color:var(--accent);font-size:.8rem}
.fhead{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin:30px 0 12px}.fhead h2{margin:0}.filters{display:flex;gap:6px;flex-wrap:wrap}
.fchip{border-radius:999px;font-size:.74rem;padding:3px 11px;text-transform:capitalize}.fchip[aria-pressed=false]{opacity:.4}
.finding{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:12px;padding:16px 18px;margin-bottom:14px}
.finding.sev-critical{border-left-color:var(--crit)}.finding.sev-high{border-left-color:var(--high)}.finding.sev-medium{border-left-color:var(--med)}.finding.sev-low{border-left-color:var(--low)}
.finding.superseded,.finding.waived{opacity:.82}.finding header{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:6px}.finding h3{flex:1 1 280px}.chg{font-size:.78rem}
.detail{margin:4px 0 10px}.nextfix{margin:0 0 6px;font-size:.85rem;color:var(--ok)}.body>summary{margin:2px 0 8px;font-weight:600}.finding{content-visibility:auto;contain-intrinsic-size:auto 180px}.diagram{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:8px;overflow-x:auto;display:grid;gap:2px}.pathsvg{display:block;color:var(--text)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px;margin-top:12px}ul{margin:4px 0;padding-left:18px}.mitres{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.mitre{font-size:.72rem;border:1px solid var(--line);border-radius:6px;padding:1px 7px;text-decoration:none;background:var(--panel2)}
.tbl{width:100%;border-collapse:collapse;font-size:.82rem}.tbl th,.tbl td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}.tbl thead th{font-size:.7rem;text-transform:uppercase;color:var(--dim)}.kv th{width:46%;color:var(--dim);font-weight:500}
.tier{font-size:.7rem;font-weight:700;padding:1px 6px;border-radius:4px;background:var(--panel2)}.tier.t0{background:rgba(239,68,68,.2);color:#fca5a5}.tier.t1{background:rgba(234,179,8,.2);color:#fde047}
.fix{margin-top:14px;background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.35);border-radius:10px;padding:12px 14px}.fixrow{margin-top:8px}.fixhead{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.warn li{color:var(--warn)}.cmdwrap{position:relative;margin-top:6px}.cmd{margin:0;background:#070c16;color:#d6e2ff;border:1px solid var(--line);border-radius:8px;padding:10px 70px 10px 12px;white-space:pre-wrap;word-break:break-word;font-size:.76rem;max-height:170px;overflow:auto}
.copy{position:absolute;top:6px;right:6px;padding:2px 10px;font-size:.72rem}
.waiver{margin-top:12px;border-radius:8px;padding:10px 12px;font-size:.85rem;border:1px dashed var(--line);background:var(--panel2)}.waiver.expired{border-color:var(--bad);color:var(--bad)}
.vl li.bad{color:var(--bad)}.vl li.warn,.vl.warn li{color:var(--warn)}.vl li.expired{color:var(--bad)}.method li{margin:5px 0;color:var(--dim)}.empty{padding:22px;text-align:center;color:var(--dim);background:var(--panel);border:1px dashed var(--line);border-radius:12px}
details>summary{cursor:pointer;color:var(--accent);font-size:.8rem;margin-top:6px}footer{text-align:center;color:var(--dim);font-size:.75rem;padding:20px}
@media(max-width:980px){.hero{grid-template-columns:1fr}.gauges{justify-content:center}.vbadge{justify-self:start}}@media(max-width:760px){.change{flex-wrap:wrap}.tools{width:100%}}
@media print{:root{--bg:#fff;--panel:#fff;--panel2:#f3f4f6;--line:#cbd5e1;--text:#000;--dim:#475569}.tools,.filters,.skip{display:none}.finding{break-inside:avoid}.diagram{overflow:visible}}
"""

_JS = """
(function(){
var root=document.documentElement;
document.getElementById('theme').addEventListener('click',function(){root.setAttribute('data-theme',root.getAttribute('data-theme')==='light'?'dark':'light');});
document.getElementById('print').addEventListener('click',function(){window.print();});
document.getElementById('dl').addEventListener('click',function(){
  var data=document.getElementById('report-json').textContent;
  var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([data],{type:'application/json'}));
  a.download='pathcutter-check.json';a.click();setTimeout(function(){URL.revokeObjectURL(a.href);},1500);});
document.querySelectorAll('.copy').forEach(function(b){b.addEventListener('click',function(){
  var t=b.parentElement.querySelector('.cmd').textContent;
  (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1400);},function(){b.textContent='Select + Ctrl+C';});});});
var ea=document.getElementById('expall');if(ea){ea.addEventListener('click',function(){var open=ea.textContent==='Expand all';
  document.querySelectorAll('.finding .body').forEach(function(d){d.open=open;});ea.textContent=open?'Collapse all':'Expand all';});}
document.querySelectorAll('.fchip').forEach(function(c){c.addEventListener('click',function(){
  var on=c.getAttribute('aria-pressed')!=='true';c.setAttribute('aria-pressed',on);
  document.querySelectorAll('.finding[data-sev="'+c.dataset.f+'"]').forEach(function(f){f.style.display=on?'':'none';});});});
})();
"""
