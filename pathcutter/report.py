"""HTML report generation - interactive dashboard with D3 attack graph and path explorer."""
from __future__ import annotations

import html
import json
import time

from .graph import AttackGraph
from .pathfinder import PathReport
from .scoring import PostureScore, NodeRisk
from .choke import ChokeReport


def generate_html_report(graph: AttackGraph, path_report: PathReport,
                         posture: PostureScore, node_scores: list[NodeRisk],
                         choke: ChokeReport,
                         chains=None, safety=None) -> str:
    """Generate a self-contained HTML dashboard with interactive path explorer."""
    graph_data = _build_graph_json(graph, path_report, node_scores)
    fixes_data = _build_fixes_json(choke, safety)
    risks_data = _build_risks_json(node_scores[:30])
    chains_data = _build_chains_json(chains) if chains else []
    paths_data = _build_paths_json(path_report, graph)

    summary = graph.summary()
    defend_data = _build_defend_json(graph)

    return _HTML_TEMPLATE.format(
        generated=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        score=posture.score,
        grade=posture.grade,
        total_paths=posture.total_paths,
        unique_sources=posture.unique_sources,
        avg_path_length=posture.avg_path_length,
        exposure_pct=round(posture.exposure_pct, 1),
        path_density=posture.path_density,
        tier0_count=posture.tier0_count,
        tier2_with_path=posture.tier2_with_path_count,
        tier2_total=posture.tier2_total,
        node_count=graph.node_count,
        edge_count=graph.edge_count,
        fix_count=len(choke.fixes),
        elimination_pct=round(choke.elimination_pct, 1),
        chain_count=len(chains) if chains else 0,
        graph_json=json.dumps(graph_data),
        fixes_json=json.dumps(fixes_data),
        risks_json=json.dumps(risks_data),
        chains_json=json.dumps(chains_data),
        paths_json=json.dumps(paths_data),
        summary_json=json.dumps(summary),
        defend_json=json.dumps(defend_data),
        grade_color=_grade_color(posture.grade),
    )


def _build_graph_json(graph: AttackGraph, path_report: PathReport,
                      node_scores: list[NodeRisk]) -> dict:
    """Build D3-compatible graph data from attack paths."""
    nodes_in_paths = set()
    edges_in_paths = []
    score_map = {ns.node_id: ns.risk_score for ns in node_scores}

    for path in path_report.paths[:500]:
        for nid in path.nodes:
            nodes_in_paths.add(nid)
        for i, edge in enumerate(path.edges):
            edges_in_paths.append({
                "source": path.nodes[i],
                "target": path.nodes[i + 1],
                "type": edge.get("edge_type", ""),
            })

    seen_edges = set()
    unique_edges = []
    for e in edges_in_paths:
        key = (e["source"], e["target"], e["type"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    nodes = []
    for nid in nodes_in_paths:
        node = graph.get_node(nid)
        if node:
            nodes.append({
                "id": nid,
                "name": node.display_name,
                "type": node.node_type.value,
                "tier": node.tier,
                "score": score_map.get(nid, 0),
                "enabled": node.enabled,
            })

    return {"nodes": nodes, "links": unique_edges}


def _build_fixes_json(choke: ChokeReport, safety=None) -> list[dict]:
    safety_list = safety or []
    fixes = []
    for i, f in enumerate(choke.fixes):
        fix_data = {
            "rank": f.rank,
            "source": f.source_name,
            "source_id": f.source_id,
            "target": f.target_name,
            "target_id": f.target_id,
            "edge_type": f.edge_type,
            "paths_eliminated": f.paths_eliminated,
            "cumulative_pct": f.cumulative_pct,
            "mitre": f.mitre,
            "fix_command": f.fix_command,
            "description": f.description,
        }
        if i < len(safety_list):
            sa = safety_list[i]
            fix_data["safety"] = sa.risk_level.value
            fix_data["safety_warnings"] = sa.warnings
            fix_data["safety_recs"] = sa.recommendations
        fixes.append(fix_data)
    return fixes


def _build_risks_json(node_scores: list[NodeRisk]) -> list[dict]:
    return [
        {
            "id": ns.node_id,
            "name": ns.display_name,
            "type": ns.node_type,
            "tier": ns.tier,
            "score": ns.risk_score,
            "path_count": ns.path_count,
            "blast_radius": ns.blast_radius,
            "tier0_reach": ns.tier0_reach,
        }
        for ns in node_scores
    ]


def _build_chains_json(chains) -> list[dict]:
    if not chains:
        return []
    return [
        {
            "type": c.chain_type,
            "description": c.description,
            "severity": c.severity,
            "mitre": c.mitre,
            "involved_nodes": c.involved_nodes[:8],
            "remediation": c.remediation,
            "path_count": c.path_count,
        }
        for c in chains
    ]


def _build_paths_json(path_report: PathReport, graph: AttackGraph) -> list[dict]:
    """Build a compact path list for the path explorer (top 200 paths)."""
    result = []
    for p in path_report.paths[:200]:
        steps = []
        for i, edge in enumerate(p.edges):
            src = graph.get_node(p.nodes[i])
            steps.append({
                "from": src.display_name if src else p.nodes[i],
                "from_id": p.nodes[i],
                "edge": edge.get("edge_type", "?"),
            })
        tgt = graph.get_node(p.target)
        result.append({
            "source": graph.get_node(p.source).display_name if graph.get_node(p.source) else p.source,
            "source_id": p.source,
            "target": tgt.display_name if tgt else p.target,
            "target_id": p.target,
            "length": p.length,
            "steps": steps,
            "node_ids": p.nodes,
        })
    return result


def _build_defend_json(graph: AttackGraph) -> list[dict]:
    """Build detection guidance data from edge types present in the graph."""
    from .edges import get_edge_type
    edge_counts: dict[str, int] = {}
    for _, _, data in graph.all_edges():
        et = data.get("edge_type", "")
        edge_counts[et] = edge_counts.get(et, 0) + 1

    result = []
    seen = set()
    for et_name, count in sorted(edge_counts.items(), key=lambda x: -x[1]):
        if et_name in seen or not et_name:
            continue
        seen.add(et_name)
        et = get_edge_type(et_name)
        if not et or et.exploitability == 0:
            continue
        log_sources = _detection_log_sources(et_name)
        result.append({
            "edge_type": et.name,
            "count": count,
            "category": et.category.value,
            "mitre": et.mitre,
            "exploitability": et.exploitability,
            "detection_difficulty": et.detection_difficulty,
            "abuse": et.abuse,
            "log_sources": log_sources,
            "detection_hints": _detection_hints(et.name),
        })
    return result


def _detection_log_sources(edge_type: str) -> list[str]:
    sources = {
        "GenericAll": ["Security 4662", "Security 5136"],
        "GenericWrite": ["Security 4662", "Security 5136"],
        "WriteOwner": ["Security 4662", "Security 5136"],
        "WriteDacl": ["Security 4662", "Security 5136"],
        "ForceChangePassword": ["Security 4724", "Security 4723"],
        "AddMember": ["Security 4728", "Security 4732", "Security 4756"],
        "Owns": ["Security 4662"],
        "WriteSPN": ["Security 5136", "Security 4662"],
        "AddAllowedToAct": ["Security 5136"],
        "WriteKeyCredentialLink": ["Security 5136", "Security 4768"],
        "AllowedToDelegate": ["Security 4768", "Security 4769"],
        "AllowedToAct": ["Security 4768", "Security 4769"],
        "AdminTo": ["Security 4624 (Type 3/10)", "Sysmon 1"],
        "HasSession": ["Security 4624", "Security 4648"],
        "CanRDP": ["Security 4624 (Type 10)", "Security 4778"],
        "CanPSRemote": ["Security 4624 (Type 3)", "WinRM 91/168"],
        "ExecuteDCOM": ["Security 4624 (Type 3)", "Sysmon 1"],
        "SQLAdmin": ["SQL Audit Logs", "Security 4624"],
        "DCSync": ["Security 4662 (DS-Replication)", "Sysmon 1 (mimikatz)"],
        "GPOControlsObject": ["Security 5136", "Security 5137"],
        "ReadLAPSPassword": ["Security 4662"],
        "ReadGMSAPassword": ["Security 4662"],
        "Enroll": ["Security 4886", "Security 4887"],
        "ManageCA": ["Security 4886", "CA Audit Logs"],
        "ManageCertificates": ["Security 4886", "CA Audit Logs"],
    }
    return sources.get(edge_type, ["Security 4662"])


def _detection_hints(edge_type: str) -> str:
    hints = {
        "GenericAll": "Monitor Event 4662 for WriteProperty/WriteDACL on sensitive objects. Alert on ACL changes to Tier 0 objects.",
        "GenericWrite": "Monitor Event 5136 for attribute changes on user/computer objects. Watch for SPN modifications.",
        "WriteOwner": "Monitor Event 4662 for WRITE_OWNER access on sensitive objects. Ownership changes are rare.",
        "WriteDacl": "Monitor Event 4662 for WRITE_DAC access. Any DACL modification to privileged objects is suspicious.",
        "ForceChangePassword": "Monitor Event 4724 (password reset by admin). Correlate with help desk tickets.",
        "AddMember": "Monitor Events 4728/4732/4756 for group membership changes. Alert on Tier 0 group modifications.",
        "DCSync": "Monitor Event 4662 with DS-Replication-Get-Changes GUID from non-DC sources. Critical alert.",
        "AdminTo": "Implement tiered admin model. Monitor Type 3/10 logons to servers from non-admin workstations.",
        "HasSession": "Restrict privileged account logons via GPO. Monitor for Tier 0 sessions on non-DC systems.",
        "AllowedToDelegate": "Audit all unconstrained delegation. Monitor Event 4768 for TGT requests with delegation flag.",
        "AllowedToAct": "Monitor Event 5136 for msDS-AllowedToActOnBehalfOfOtherIdentity changes.",
        "WriteSPN": "Monitor Event 5136 for servicePrincipalName changes. Kerberoasting precursor.",
        "WriteKeyCredentialLink": "Monitor Event 5136 for msDS-KeyCredentialLink changes. Shadow Credentials attack.",
        "ReadLAPSPassword": "Audit ms-Mcs-AdmPwd reads via Event 4662. Restrict LAPS password readers.",
        "ReadGMSAPassword": "Audit msDS-GroupMSAMembership. Monitor Event 4662 for gMSA password reads.",
        "Enroll": "Review certificate template permissions. Monitor 4886/4887 for enrollment events.",
        "ManageCA": "Restrict CA management to dedicated admin accounts. Monitor CA audit logs.",
    }
    return hints.get(edge_type, "Monitor Event 4662 for object access. Implement least privilege.")


def _grade_color(grade: str) -> str:
    return {
        "A": "#22c55e",
        "B": "#84cc16",
        "C": "#eab308",
        "D": "#f97316",
        "F": "#ef4444",
    }.get(grade, "#6b7280")


def generate_diff_html(diff_result, graph_before: AttackGraph, graph_after: AttackGraph) -> str:
    """Generate an HTML diff report comparing two snapshots."""
    from .diff import DiffResult
    r = diff_result
    summary_before = graph_before.summary()
    summary_after = graph_after.summary()

    return _DIFF_HTML_TEMPLATE.format(
        generated=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        score_before=r.before.score,
        score_after=r.after.score,
        grade_before=r.grade_before,
        grade_after=r.grade_after,
        color_before=_grade_color(r.grade_before),
        color_after=_grade_color(r.grade_after),
        paths_before=r.paths_before,
        paths_after=r.paths_after,
        paths_eliminated=r.paths_eliminated,
        new_paths=r.new_paths,
        score_delta=r.score_delta,
        direction="improved" if r.improved else "worsened",
        direction_color="var(--success)" if r.improved else "var(--danger)",
        delta_sign="-" if r.score_delta < 0 else "+",
        nodes_before=graph_before.node_count,
        nodes_after=graph_after.node_count,
        edges_before=graph_before.edge_count,
        edges_after=graph_after.edge_count,
        eliminated_json=json.dumps(r.eliminated_edges[:100]),
        new_json=json.dumps(r.new_edges[:100]),
        summary_before_json=json.dumps(summary_before),
        summary_after_json=json.dumps(summary_after),
    )


_DIFF_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pathcutter Diff Report</title>
<style>
:root {{
  --bg: #0f172a; --surface: #1e293b; --surface-2: #253349; --border: #334155;
  --text: #e2e8f0; --text-dim: #94a3b8; --accent: #3b82f6;
  --danger: #ef4444; --success: #22c55e; --warning: #eab308; --orange: #f97316;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 16px; }}
h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: 4px; }}
.subtitle {{ color: var(--text-dim); font-size: 0.85rem; margin-bottom: 20px; }}
.grid {{ display: grid; gap: 16px; }}
.grid-2 {{ grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
.grid-3 {{ grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.card h3 {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }}
.card .value {{ font-size: 2rem; font-weight: 700; }}
.card .detail {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 4px; }}
.comparison {{ display: grid; grid-template-columns: 1fr auto 1fr; gap: 20px; align-items: center; text-align: center; }}
.comparison .arrow {{ font-size: 2rem; color: var(--text-dim); }}
.score-box {{ padding: 20px; border-radius: 12px; }}
.score-box .num {{ font-size: 3rem; font-weight: 800; }}
.score-box .label {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
th {{ text-align: left; padding: 8px 12px; color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; border-bottom: 1px solid var(--border); background: var(--surface); }}
td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}
tr:hover {{ background: rgba(59,130,246,0.05); }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
.badge-success {{ background: rgba(34,197,94,0.2); color: #86efac; }}
.badge-danger {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
.delta {{ display: flex; align-items: center; gap: 8px; }}
.delta-down {{ color: var(--success); }}
.delta-up {{ color: var(--danger); }}
</style>
</head>
<body>
<div class="container">
  <h1>Pathcutter - Diff Report</h1>
  <p class="subtitle">Generated {generated} | Posture {direction}</p>

  <div class="card" style="margin-bottom:16px">
    <div class="comparison">
      <div class="score-box" style="border:2px solid {color_before}">
        <div class="label">BEFORE</div>
        <div class="num" style="color:{color_before}">{score_before}</div>
        <div class="label">Grade {grade_before}</div>
      </div>
      <div>
        <div class="arrow">&#8594;</div>
        <div style="font-size:1.5rem;font-weight:700;color:{direction_color}">{delta_sign}{score_delta}</div>
      </div>
      <div class="score-box" style="border:2px solid {color_after}">
        <div class="label">AFTER</div>
        <div class="num" style="color:{color_after}">{score_after}</div>
        <div class="label">Grade {grade_after}</div>
      </div>
    </div>
  </div>

  <div class="grid grid-3" style="margin-bottom:16px">
    <div class="card">
      <h3>Attack Paths</h3>
      <div class="delta">
        <div class="value">{paths_before} &#8594; {paths_after}</div>
      </div>
      <div class="detail">-{paths_eliminated} eliminated, +{new_paths} new</div>
    </div>
    <div class="card">
      <h3>Nodes</h3>
      <div class="value">{nodes_before} &#8594; {nodes_after}</div>
    </div>
    <div class="card">
      <h3>Edges</h3>
      <div class="value">{edges_before} &#8594; {edges_after}</div>
    </div>
  </div>

  <div class="grid grid-2">
    <div class="card">
      <h3>Eliminated Edges <span class="badge badge-success">{paths_eliminated} paths cut</span></h3>
      <table>
        <thead><tr><th>Source</th><th>Target</th><th>Type</th></tr></thead>
        <tbody id="eliminated-table"></tbody>
      </table>
    </div>
    <div class="card">
      <h3>New Edges (Regressions) <span class="badge badge-danger">{new_paths} new paths</span></h3>
      <table>
        <thead><tr><th>Source</th><th>Target</th><th>Type</th></tr></thead>
        <tbody id="new-table"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const eliminated = {eliminated_json};
const newEdges = {new_json};

function render(data, tableId, color) {{
  const table = document.getElementById(tableId);
  if (!data.length) {{
    table.innerHTML = '<tr><td colspan="3" style="color:var(--text-dim)">None</td></tr>';
    return;
  }}
  data.forEach(e => {{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${{e.source}}</td><td>${{e.target}}</td><td style="color:${{color}}">${{e.type}}</td>`;
    table.appendChild(tr);
  }});
}}
render(eliminated, 'eliminated-table', 'var(--success)');
render(newEdges, 'new-table', 'var(--danger)');
</script>
</body>
</html>'''


_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pathcutter Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
:root {{
  --bg: #0f172a;
  --surface: #1e293b;
  --surface-2: #253349;
  --border: #334155;
  --text: #e2e8f0;
  --text-dim: #94a3b8;
  --text-dimmer: #64748b;
  --accent: #3b82f6;
  --accent-dim: #1d4ed8;
  --danger: #ef4444;
  --success: #22c55e;
  --warning: #eab308;
  --orange: #f97316;
  --purple: #a855f7;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; }}
.container {{ max-width: 1600px; margin: 0 auto; padding: 16px; }}
h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: 4px; }}
.subtitle {{ color: var(--text-dim); font-size: 0.85rem; margin-bottom: 20px; }}

.tabs {{ display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin-bottom: 16px; flex-wrap: wrap; }}
.tab {{ padding: 10px 18px; cursor: pointer; color: var(--text-dim); border-bottom: 2px solid transparent; transition: all 0.2s; font-size: 0.85rem; white-space: nowrap; }}
.tab:hover {{ color: var(--text); }}
.tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
.tab .badge {{ background: var(--accent-dim); color: white; font-size: 0.7rem; padding: 1px 6px; border-radius: 8px; margin-left: 6px; }}
.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}

.grid {{ display: grid; gap: 16px; }}
.grid-2 {{ grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
.grid-3 {{ grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }}
.grid-4 {{ grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); }}

.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.card h3 {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }}
.card .value {{ font-size: 2rem; font-weight: 700; }}
.card .detail {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 4px; }}

.score-ring {{ position: relative; width: 140px; height: 140px; margin: 0 auto 8px; }}
.score-ring svg {{ width: 100%; height: 100%; }}
.score-label {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }}
.score-label .num {{ font-size: 2.5rem; font-weight: 800; }}
.score-label .grade {{ font-size: 1rem; color: var(--text-dim); }}

table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
th {{ text-align: left; padding: 8px 12px; color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--surface); z-index: 1; }}
td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}
tr:hover {{ background: rgba(59,130,246,0.05); }}
tr.highlighted {{ background: rgba(59,130,246,0.15) !important; }}
tr {{ cursor: pointer; }}

.tier-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
.tier-0 {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
.tier-1 {{ background: rgba(234,179,8,0.2); color: #fde047; }}
.tier-2 {{ background: rgba(59,130,246,0.2); color: #93c5fd; }}

.severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
.severity-critical {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
.severity-high {{ background: rgba(249,115,22,0.2); color: #fdba74; }}
.severity-medium {{ background: rgba(234,179,8,0.2); color: #fde047; }}

.safety-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
.safety-safe {{ background: rgba(34,197,94,0.2); color: #86efac; }}
.safety-caution {{ background: rgba(234,179,8,0.2); color: #fde047; }}
.safety-dangerous {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}

.bar {{ height: 6px; border-radius: 3px; background: var(--border); overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 3px; transition: width 0.5s ease; }}

.btn {{ background: var(--accent); color: white; border: none; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; transition: background 0.15s; }}
.btn:hover {{ background: #2563eb; }}
.btn-sm {{ padding: 3px 8px; font-size: 0.72rem; }}
.btn-outline {{ background: transparent; border: 1px solid var(--border); color: var(--text-dim); }}
.btn-outline:hover {{ background: var(--surface-2); color: var(--text); }}

.search-box {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; color: var(--text); font-size: 0.85rem; width: 100%; outline: none; }}
.search-box:focus {{ border-color: var(--accent); }}
.search-box::placeholder {{ color: var(--text-dimmer); }}

#graph-container {{ width: 100%; height: 700px; background: #0a0f1e; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; position: relative; }}
#graph-controls {{ position: absolute; top: 10px; right: 10px; display: flex; gap: 6px; z-index: 5; }}
#graph-search {{ position: absolute; top: 10px; left: 10px; z-index: 15; width: 260px; }}
#graph-search input {{ width: 100%; background: rgba(15,23,42,0.95); border: 1px solid var(--border); border-radius: 6px; padding: 7px 10px 7px 30px; color: var(--text); font-size: 0.8rem; outline: none; }}
#graph-search input:focus {{ border-color: var(--accent); }}
#graph-search .icon {{ position: absolute; left: 8px; top: 8px; color: var(--text-dimmer); font-size: 0.85rem; pointer-events: none; }}
#graph-search-results {{ position: absolute; top: 100%; left: 0; width: 100%; background: rgba(15,23,42,0.98); border: 1px solid var(--border); border-radius: 0 0 6px 6px; max-height: 220px; overflow-y: auto; display: none; }}
#graph-search-results .sr {{ padding: 6px 10px; cursor: pointer; font-size: 0.8rem; display: flex; justify-content: space-between; align-items: center; }}
#graph-search-results .sr:hover, #graph-search-results .sr.active {{ background: rgba(59,130,246,0.15); }}
#graph-search-results .sr .sr-type {{ font-size: 0.7rem; color: var(--text-dimmer); }}
#edge-filter {{ position: absolute; top: 44px; right: 10px; background: rgba(10,15,30,0.98); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-size: 0.75rem; z-index: 6; display: none; max-height: 380px; overflow-y: auto; width: 200px; }}
#edge-filter .ef-title {{ font-weight: 600; color: var(--text-dim); margin-bottom: 6px; }}
#edge-filter label {{ display: flex; align-items: center; gap: 6px; padding: 3px 0; cursor: pointer; color: var(--text); }}
#edge-filter label:hover {{ color: var(--accent); }}
#edge-filter input[type="checkbox"] {{ accent-color: var(--accent); }}
#edge-filter .ef-sep {{ height: 1px; background: var(--border); margin: 6px 0; }}
.ctx-menu {{ position: absolute; background: rgba(15,23,42,0.98); border: 1px solid var(--border); border-radius: 8px; padding: 4px 0; z-index: 30; min-width: 180px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}
.ctx-menu .ctx-item {{ padding: 7px 14px; cursor: pointer; font-size: 0.8rem; display: flex; align-items: center; gap: 8px; }}
.ctx-menu .ctx-item:hover {{ background: rgba(59,130,246,0.15); }}
.ctx-menu .ctx-sep {{ height: 1px; background: var(--border); margin: 2px 0; }}
.chart-container {{ width: 100%; height: 180px; }}
#graph-legend {{ position: absolute; bottom: 10px; left: 10px; background: rgba(10,15,30,0.95); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-size: 0.75rem; z-index: 5; }}
#graph-legend .item {{ display: flex; align-items: center; gap: 8px; margin: 4px 0; }}
#graph-legend .icon {{ width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; }}
#graph-edge-legend {{ position: absolute; bottom: 10px; right: 10px; background: rgba(10,15,30,0.95); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-size: 0.72rem; z-index: 5; max-width: 180px; }}
#graph-edge-legend .item {{ display: flex; align-items: center; gap: 6px; margin: 3px 0; }}
#graph-edge-legend .line {{ width: 20px; height: 2px; border-radius: 1px; }}
#graph-tooltip {{ position: absolute; background: rgba(10,15,30,0.95); border: 1px solid var(--accent); border-radius: 6px; padding: 8px 12px; font-size: 0.8rem; z-index: 20; pointer-events: none; display: none; max-width: 280px; }}
#graph-tooltip .tt-name {{ font-weight: 700; margin-bottom: 4px; }}
#graph-tooltip .tt-type {{ color: var(--text-dim); font-size: 0.72rem; }}

.node-detail {{ position: absolute; top: 8px; left: 8px; width: 280px; max-height: calc(100% - 16px); overflow-y: auto; background: rgba(15,23,42,0.95); border: 1px solid var(--border); border-radius: 8px; padding: 12px; z-index: 10; font-size: 0.8rem; }}
.node-detail h4 {{ font-size: 0.9rem; margin-bottom: 8px; }}
.node-detail .close {{ position: absolute; top: 8px; right: 8px; cursor: pointer; color: var(--text-dim); font-size: 1.1rem; }}
.node-detail .close:hover {{ color: var(--text); }}
.node-detail .stat {{ display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid var(--border); }}
.node-detail .path-list {{ margin-top: 8px; }}
.node-detail .path-item {{ background: var(--surface-2); border-radius: 4px; padding: 6px 8px; margin: 4px 0; font-size: 0.75rem; cursor: pointer; }}
.node-detail .path-item:hover {{ background: var(--accent-dim); }}

.path-explorer {{ display: grid; grid-template-columns: 320px 1fr; gap: 16px; min-height: 500px; }}
.path-list-panel {{ overflow-y: auto; max-height: 600px; }}
.path-detail-panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.path-step {{ display: flex; align-items: center; gap: 8px; padding: 6px 0; }}
.path-step .node-name {{ font-weight: 600; }}
.path-step .edge-label {{ background: var(--surface-2); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; color: var(--warning); }}
.path-step .arrow {{ color: var(--text-dimmer); }}

.path-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; margin-bottom: 6px; cursor: pointer; transition: all 0.15s; }}
.path-card:hover {{ border-color: var(--accent); }}
.path-card.selected {{ border-color: var(--accent); background: rgba(59,130,246,0.08); }}
.path-card .path-meta {{ color: var(--text-dim); font-size: 0.75rem; margin-top: 4px; }}

.chain-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
.chain-card .chain-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
.chain-card .chain-desc {{ color: var(--text-dim); font-size: 0.85rem; margin-bottom: 8px; }}
.chain-card .chain-fix {{ background: var(--surface-2); border-radius: 6px; padding: 10px; font-size: 0.8rem; }}

.fix-cmd {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 8px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.75rem; white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow-y: auto; margin-top: 4px; }}

.toast {{ position: fixed; bottom: 20px; right: 20px; background: var(--success); color: white; padding: 10px 20px; border-radius: 8px; font-size: 0.85rem; z-index: 1000; opacity: 0; transition: opacity 0.3s; pointer-events: none; }}
.toast.show {{ opacity: 1; }}

@media (max-width: 768px) {{
  .path-explorer {{ grid-template-columns: 1fr; }}
  .node-detail {{ width: calc(100% - 16px); }}
  .tab {{ padding: 8px 12px; font-size: 0.8rem; }}
}}
</style>
</head>
<body>
<div class="container">
  <h1>Pathcutter - AD Attack Path Report</h1>
  <p class="subtitle">Generated {generated} | {node_count} nodes, {edge_count} edges</p>

  <div class="tabs">
    <div class="tab active" data-tab="overview">Overview</div>
    <div class="tab" data-tab="risks">Riskiest Nodes</div>
    <div class="tab" data-tab="fixes">Remediation<span class="badge">{fix_count}</span></div>
    <div class="tab" data-tab="chains">Attack Chains<span class="badge">{chain_count}</span></div>
    <div class="tab" data-tab="defend">Defend</div>
    <div class="tab" data-tab="paths">Path Explorer<span class="badge">{total_paths}</span></div>
    <div class="tab" data-tab="graph">Attack Graph</div>
  </div>

  <!-- OVERVIEW -->
  <div id="overview" class="tab-content active">
    <div class="grid grid-2" style="margin-bottom:16px">
      <div class="card" style="text-align:center">
        <h3>Risk Score</h3>
        <div class="score-ring">
          <svg viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
            <circle cx="60" cy="60" r="52" fill="none" stroke="{grade_color}" stroke-width="8"
              stroke-dasharray="326.7" stroke-dashoffset="" stroke-linecap="round"
              transform="rotate(-90 60 60)" id="score-arc"/>
          </svg>
          <div class="score-label">
            <div class="num" style="color:{grade_color}">{score}</div>
            <div class="grade">Grade {grade}</div>
          </div>
        </div>
      </div>
      <div class="card">
        <h3>Key Metrics</h3>
        <div style="display:grid;gap:12px;margin-top:8px">
          <div><span style="color:var(--text-dim)">Attack paths:</span> <strong>{total_paths}</strong></div>
          <div><span style="color:var(--text-dim)">Unique sources:</span> <strong>{unique_sources}</strong></div>
          <div><span style="color:var(--text-dim)">Avg path length:</span> <strong>{avg_path_length}</strong></div>
          <div><span style="color:var(--text-dim)">Path density:</span> <strong>{path_density}</strong> paths/node</div>
          <div><span style="color:var(--text-dim)">Tier 0 nodes:</span> <strong>{tier0_count}</strong></div>
        </div>
      </div>
    </div>
    <div class="grid grid-3">
      <div class="card">
        <h3>Exposure</h3>
        <div class="value" style="color:var(--danger)">{exposure_pct}%</div>
        <div class="detail">{tier2_with_path} of {tier2_total} Tier 2 nodes can reach Tier 0</div>
        <div class="bar" style="margin-top:8px"><div class="bar-fill" style="width:{exposure_pct}%;background:var(--danger)"></div></div>
      </div>
      <div class="card">
        <h3>Fix Coverage</h3>
        <div class="value" style="color:var(--success)">{elimination_pct}%</div>
        <div class="detail">{fix_count} fixes eliminate {elimination_pct}% of attack paths</div>
        <div class="bar" style="margin-top:8px"><div class="bar-fill" style="width:{elimination_pct}%;background:var(--success)"></div></div>
      </div>
      <div class="card">
        <h3>Attack Chains</h3>
        <div class="value" style="color:var(--orange)">{chain_count}</div>
        <div class="detail">Composite attack patterns detected</div>
      </div>
    </div>
    <div class="grid grid-2" style="margin-top:16px">
      <div class="card">
        <h3>Node Distribution</h3>
        <div class="chart-container" id="chart-nodes"></div>
      </div>
      <div class="card">
        <h3>Top Edge Types (Attack Surface)</h3>
        <div class="chart-container" id="chart-edges"></div>
      </div>
    </div>
  </div>

  <!-- RISKS -->
  <div id="risks" class="tab-content">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0">Top Riskiest Nodes</h3>
        <input class="search-box" style="width:240px" placeholder="Filter nodes..." id="risk-search">
      </div>
      <table>
        <thead>
          <tr><th>Name</th><th>Type</th><th>Tier</th><th>Risk Score</th><th>Paths</th><th>Blast Radius</th><th>T0 Reach</th><th></th></tr>
        </thead>
        <tbody id="risks-table"></tbody>
      </table>
    </div>
  </div>

  <!-- FIXES -->
  <div id="fixes" class="tab-content">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0">Remediation Priority - {elimination_pct}% path elimination with {fix_count} fixes</h3>
        <button class="btn btn-sm" onclick="copyAllFixes()">Copy All Commands</button>
      </div>
      <table>
        <thead>
          <tr><th>#</th><th>Fix</th><th>Type</th><th>Safety</th><th>Paths Cut</th><th>Cumulative</th><th>MITRE</th><th>Command</th></tr>
        </thead>
        <tbody id="fixes-table"></tbody>
      </table>
    </div>
  </div>

  <!-- CHAINS -->
  <div id="chains" class="tab-content">
    <div id="chains-list"></div>
  </div>

  <!-- DEFEND -->
  <div id="defend" class="tab-content">
    <div class="grid grid-3" style="margin-bottom:16px">
      <div class="card" id="defend-coverage">
        <h3>MITRE Coverage</h3>
        <div class="chart-container" id="chart-mitre"></div>
      </div>
      <div class="card">
        <h3>Detection Difficulty</h3>
        <div class="chart-container" id="chart-difficulty"></div>
      </div>
      <div class="card">
        <h3>Required Log Sources</h3>
        <div id="log-sources-list" style="max-height:160px;overflow-y:auto;font-size:0.8rem"></div>
      </div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0">Detection Guidance by Edge Type</h3>
        <input class="search-box" style="width:240px" placeholder="Filter edge types..." id="defend-search">
      </div>
      <table>
        <thead>
          <tr><th>Edge Type</th><th>Count</th><th>MITRE</th><th>Exploitability</th><th>Detection</th><th>Log Sources</th><th>Guidance</th></tr>
        </thead>
        <tbody id="defend-table"></tbody>
      </table>
    </div>
  </div>

  <!-- PATH EXPLORER -->
  <div id="paths" class="tab-content">
    <div class="path-explorer">
      <div>
        <input class="search-box" placeholder="Search paths by node name..." id="path-search" style="margin-bottom:10px">
        <div class="path-list-panel" id="path-list"></div>
      </div>
      <div class="path-detail-panel" id="path-detail">
        <div style="color:var(--text-dim);text-align:center;margin-top:80px">
          <p style="font-size:1.2rem">Click a path to explore it</p>
          <p style="margin-top:8px">Each step shows the attack relationship used</p>
        </div>
      </div>
    </div>
  </div>

  <!-- GRAPH -->
  <div id="graph" class="tab-content">
    <div class="card" style="padding:0;position:relative">
      <div id="graph-container">
        <div id="graph-search">
          <span class="icon">&#128269;</span>
          <input type="text" placeholder="Search nodes..." id="graph-search-input" autocomplete="off">
          <div id="graph-search-results"></div>
        </div>
        <div id="graph-controls">
          <button class="btn btn-sm btn-outline" onclick="resetGraph()">Reset</button>
          <button class="btn btn-sm btn-outline" onclick="toggleLabels()">Labels</button>
          <button class="btn btn-sm btn-outline" onclick="toggleEdgeLabels()">Edge Labels</button>
          <button class="btn btn-sm btn-outline" onclick="toggleEdgeFilter()">Filter</button>
          <button class="btn btn-sm btn-outline" onclick="toggleLayout()">Layout</button>
        </div>
        <div id="edge-filter"></div>
        <div id="graph-legend">
          <div style="font-weight:600;margin-bottom:4px;color:var(--text-dim)">NODES</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="10" cy="7" r="4" fill="#3b82f6"/><path d="M3 18 Q3 12 10 12 Q17 12 17 18" fill="#3b82f6" opacity="0.5"/></svg></div> User</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><rect x="2" y="4" width="16" height="10" rx="1" fill="#10b981"/><rect x="7" y="14" width="6" height="2" fill="#10b981" opacity="0.6"/><rect x="5" y="16" width="10" height="1" rx="0.5" fill="#10b981" opacity="0.4"/></svg></div> Computer</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="7" cy="7" r="3" fill="#f59e0b"/><circle cx="13" cy="7" r="3" fill="#f59e0b"/><circle cx="10" cy="13" r="3" fill="#f59e0b"/></svg></div> Group</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="10" cy="10" r="8" fill="none" stroke="#ef4444" stroke-width="1.5"/><path d="M2 10 H18 M10 2 Q14 10 10 18 M10 2 Q6 10 10 18" fill="none" stroke="#ef4444" stroke-width="1" opacity="0.6"/></svg></div> Domain</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><rect x="3" y="2" width="14" height="16" rx="1.5" fill="none" stroke="#8b5cf6" stroke-width="1.5"/><line x1="6" y1="6" x2="14" y2="6" stroke="#8b5cf6" stroke-width="1" opacity="0.5"/><line x1="6" y1="9" x2="14" y2="9" stroke="#8b5cf6" stroke-width="1" opacity="0.5"/><line x1="6" y1="12" x2="14" y2="12" stroke="#8b5cf6" stroke-width="1" opacity="0.5"/></svg></div> GPO</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M10 2 L18 10 L10 18 L2 10 Z" fill="none" stroke="#ef4444" stroke-width="2"/></svg></div> Tier 0</div>
        </div>
        <div id="graph-edge-legend">
          <div style="font-weight:600;margin-bottom:4px;color:var(--text-dim)">EDGES</div>
          <div class="item"><div class="line" style="background:#ef4444"></div> Critical ACL</div>
          <div class="item"><div class="line" style="background:#f97316"></div> Dangerous ACL</div>
          <div class="item"><div class="line" style="background:#eab308"></div> Moderate Risk</div>
          <div class="item"><div class="line" style="background:#a855f7"></div> Session/Admin</div>
          <div class="item"><div class="line" style="background:#334155"></div> Structural</div>
        </div>
        <div id="graph-tooltip"></div>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast">Copied!</div>

<script>
const graphData = {graph_json};
const fixesData = {fixes_json};
const risksData = {risks_json};
const chainsData = {chains_json};
const pathsData = {paths_json};
const summaryData = {summary_json};
const defendData = {defend_json};

// Toast
function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}}

// Tabs
document.querySelectorAll('.tab').forEach(tab => {{
  tab.addEventListener('click', () => {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
    if (tab.dataset.tab === 'graph' && !window._graphDrawn) drawGraph();
  }});
}});

// Score arc
const scoreArc = document.getElementById('score-arc');
const circumference = 2 * Math.PI * 52;
scoreArc.setAttribute('stroke-dashoffset', circumference * (1 - {score} / 100));

// ---- RISKS TABLE ----
function renderRisks(filter) {{
  const table = document.getElementById('risks-table');
  table.innerHTML = '';
  const q = (filter || '').toLowerCase();
  risksData.filter(r => !q || r.name.toLowerCase().includes(q) || r.type.toLowerCase().includes(q))
    .forEach(r => {{
      const tr = document.createElement('tr');
      const tierClass = 'tier-' + r.tier;
      const barW = Math.min(r.score, 100);
      tr.innerHTML = `<td><strong>${{r.name}}</strong></td><td>${{r.type}}</td><td><span class="tier-badge ${{tierClass}}">T${{r.tier}}</span></td><td><div style="display:flex;align-items:center;gap:8px"><div class="bar" style="width:60px"><div class="bar-fill" style="width:${{barW}}%;background:${{barW > 70 ? 'var(--danger)' : barW > 40 ? 'var(--warning)' : 'var(--accent)'}}"></div></div><strong>${{r.score}}</strong></div></td><td>${{r.path_count}}</td><td>${{r.blast_radius}}</td><td>${{r.tier0_reach}}</td><td><button class="btn btn-sm btn-outline" onclick="showNodePaths('${{r.id}}','${{r.name}}')">Paths</button></td>`;
      table.appendChild(tr);
    }});
}}
renderRisks();
document.getElementById('risk-search').addEventListener('input', e => renderRisks(e.target.value));

function showNodePaths(nodeId, nodeName) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="paths"]').classList.add('active');
  document.getElementById('paths').classList.add('active');
  document.getElementById('path-search').value = nodeName;
  renderPathList(nodeName);
}}

// ---- FIXES TABLE ----
const fixesTable = document.getElementById('fixes-table');
fixesData.forEach(f => {{
  const tr = document.createElement('tr');
  const cmdEsc = f.fix_command.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const safety = f.safety || 'safe';
  const safetyLabel = {{safe:'OK', caution:'WARN', dangerous:'RISK'}}[safety] || safety;
  let warnings = '';
  if (f.safety_warnings && f.safety_warnings.length) {{
    warnings = '<div style="font-size:0.72rem;color:var(--warning);margin-top:4px">' + f.safety_warnings.map(w => '- ' + w).join('<br>') + '</div>';
  }}
  tr.innerHTML = `<td>${{f.rank}}</td><td><div>${{f.description}}</div>${{warnings}}</td><td>${{f.edge_type}}</td><td><span class="safety-badge safety-${{safety}}">${{safetyLabel}}</span></td><td>${{f.paths_eliminated}}</td><td><div style="display:flex;align-items:center;gap:6px"><div class="bar" style="width:50px"><div class="bar-fill" style="width:${{f.cumulative_pct}}%;background:var(--success)"></div></div>${{f.cumulative_pct}}%</div></td><td style="font-size:0.75rem">${{f.mitre || 'N/A'}}</td><td><button class="btn btn-sm" onclick="copyCmd(this)">Copy</button><div class="fix-cmd">${{cmdEsc}}</div></td>`;
  tr.addEventListener('click', () => highlightFixPaths(f));
  fixesTable.appendChild(tr);
}});

function copyCmd(btn) {{
  const cmd = btn.closest('td').querySelector('.fix-cmd').textContent;
  navigator.clipboard.writeText(cmd);
  showToast('Command copied!');
}}

function copyAllFixes() {{
  const all = fixesData.map(f => '# Fix #' + f.rank + ': ' + f.description + '\\n' + f.fix_command).join('\\n\\n');
  navigator.clipboard.writeText(all);
  showToast('All ' + fixesData.length + ' fix commands copied!');
}}

function highlightFixPaths(fix) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="paths"]').classList.add('active');
  document.getElementById('paths').classList.add('active');
  document.getElementById('path-search').value = fix.source.split('@')[0];
  renderPathList(fix.source.split('@')[0]);
}}

// ---- CHAINS ----
const chainsList = document.getElementById('chains-list');
if (chainsData.length === 0) {{
  chainsList.innerHTML = '<div class="card"><p style="color:var(--text-dim)">No composite attack chains detected.</p></div>';
}} else {{
  chainsData.forEach(c => {{
    const div = document.createElement('div');
    div.className = 'chain-card';
    const sevClass = 'severity-' + c.severity;
    div.innerHTML = `
      <div class="chain-header">
        <span class="severity-badge ${{sevClass}}">${{c.severity.toUpperCase()}}</span>
        <strong style="font-size:0.95rem">${{c.type.replace(/_/g,' ').replace(/\\b\\w/g, l => l.toUpperCase())}}</strong>
        <span style="color:var(--text-dim);font-size:0.8rem">${{c.path_count}} paths</span>
        ${{c.mitre.length ? '<span style="font-size:0.75rem;color:var(--purple)">' + c.mitre.join(', ') + '</span>' : ''}}
      </div>
      <div class="chain-desc">${{c.description}}</div>
      ${{c.involved_nodes.length ? '<div style="font-size:0.8rem;margin-bottom:8px"><strong>Involved:</strong> ' + c.involved_nodes.join(', ') + '</div>' : ''}}
      <div class="chain-fix"><strong>Remediation:</strong> ${{c.remediation}}</div>
    `;
    chainsList.appendChild(div);
  }});
}}

// ---- PATH EXPLORER ----
function renderPathList(filter) {{
  const panel = document.getElementById('path-list');
  panel.innerHTML = '';
  const q = (filter || '').toLowerCase();
  const filtered = pathsData.filter(p => {{
    if (!q) return true;
    if (p.source.toLowerCase().includes(q) || p.target.toLowerCase().includes(q)) return true;
    return p.steps.some(s => s.from.toLowerCase().includes(q));
  }});

  if (filtered.length === 0) {{
    panel.innerHTML = '<div style="color:var(--text-dim);padding:16px">No matching paths</div>';
    return;
  }}

  filtered.forEach((p, idx) => {{
    const card = document.createElement('div');
    card.className = 'path-card';
    card.innerHTML = `<div><strong>${{p.source}}</strong> <span style="color:var(--text-dimmer)">&#8594;</span> <strong style="color:var(--danger)">${{p.target}}</strong></div><div class="path-meta">${{p.length}} hops | ${{p.steps.map(s => s.edge).join(' > ')}}</div>`;
    card.addEventListener('click', () => {{
      document.querySelectorAll('.path-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      renderPathDetail(p);
    }});
    panel.appendChild(card);
  }});
}}
renderPathList();
document.getElementById('path-search').addEventListener('input', e => renderPathList(e.target.value));

function renderPathDetail(p) {{
  const panel = document.getElementById('path-detail');
  let html = '<h3 style="margin-bottom:12px;font-size:0.9rem">Attack Path: ' + p.length + ' hops</h3>';
  html += '<div style="display:flex;flex-direction:column;gap:2px">';

  for (let i = 0; i < p.steps.length; i++) {{
    const s = p.steps[i];
    const edgeColor = getEdgeColor(s.edge);
    html += `<div class="path-step"><span class="node-name">${{s.from}}</span></div>`;
    html += `<div class="path-step" style="padding-left:16px"><span class="arrow">|</span><span class="edge-label" style="color:${{edgeColor}}">${{s.edge}}</span><span class="arrow">&#8595;</span></div>`;
  }}
  html += `<div class="path-step"><span class="node-name" style="color:var(--danger)">${{p.target}}</span> <span class="tier-badge tier-0">T0</span></div>`;
  html += '</div>';

  html += '<div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">';
  html += '<button class="btn btn-sm" onclick="highlightPathInGraph(' + JSON.stringify(p.node_ids).replace(/"/g, '&quot;') + ')">Show in Graph</button>';
  html += '</div>';

  panel.innerHTML = html;
}}

function getEdgeColor(edgeType) {{
  const colors = {{
    GenericAll: '#ef4444', GenericWrite: '#f97316', WriteDacl: '#f97316', WriteOwner: '#f97316',
    DCSync: '#ef4444', ForceChangePassword: '#eab308', AddMember: '#eab308',
    AdminTo: '#a855f7', HasSession: '#8b5cf6', WriteSPN: '#f59e0b',
    AllowedToDelegate: '#ef4444', AllowedToAct: '#f97316', AddAllowedToAct: '#f97316',
    WriteKeyCredentialLink: '#ef4444', ReadLAPSPassword: '#eab308', ReadGMSAPassword: '#eab308',
    MemberOf: '#64748b', Contains: '#64748b',
  }};
  return colors[edgeType] || 'var(--warning)';
}}

// ---- D3 GRAPH (BloodHound-style) ----
let simulation, svg, gRoot, nodeGroups, linkElements, linkLabels, labelElements;
let labelsVisible = true, edgeLabelsVisible = false, hierarchicalLayout = false;

const NODE_COLORS = {{ User: '#3b82f6', Computer: '#10b981', Group: '#f59e0b', Domain: '#ef4444', GPO: '#8b5cf6', OU: '#6366f1', Container: '#64748b', CertTemplate: '#ec4899', EnterpriseCA: '#ec4899', RootCA: '#ec4899', AIACA: '#ec4899', NTAuthStore: '#ec4899', Unknown: '#64748b' }};
const NODE_SIZES = {{ 0: 18, 1: 12, 2: 8 }};
const EDGE_COLORS = {{
  GenericAll: '#ef4444', GenericWrite: '#f97316', WriteDacl: '#f97316', WriteOwner: '#f97316', Owns: '#f97316',
  DCSync: '#ff2222', ForceChangePassword: '#eab308', AddMember: '#eab308', WriteSPN: '#eab308',
  AllowedToDelegate: '#ef4444', AllowedToAct: '#f97316', AddAllowedToAct: '#f97316',
  WriteKeyCredentialLink: '#ef4444', ReadLAPSPassword: '#eab308', ReadGMSAPassword: '#eab308',
  AdminTo: '#a855f7', HasSession: '#8b5cf6', CanRDP: '#8b5cf6', CanPSRemote: '#8b5cf6', ExecuteDCOM: '#8b5cf6', SQLAdmin: '#a855f7',
  GPOControlsObject: '#f97316', Enroll: '#ec4899', ManageCA: '#ec4899',
  MemberOf: '#334155', Contains: '#334155', TrustedBy: '#64748b',
}};

function nodeShape(g, d) {{
  const r = NODE_SIZES[d.tier] || 8;
  const c = NODE_COLORS[d.type] || '#64748b';
  if (d.type === 'User') {{
    g.append('circle').attr('r', r * 0.55).attr('cy', -r * 0.2).attr('fill', c);
    g.append('path').attr('d', `M${{-r*0.8}} ${{r}} Q${{-r*0.8}} ${{r*0.15}} 0 ${{r*0.15}} Q${{r*0.8}} ${{r*0.15}} ${{r*0.8}} ${{r}}`).attr('fill', c).attr('opacity', 0.55);
  }} else if (d.type === 'Computer') {{
    g.append('rect').attr('x', -r).attr('y', -r*0.7).attr('width', r*2).attr('height', r*1.2).attr('rx', 2).attr('fill', c);
    g.append('rect').attr('x', -r*0.3).attr('y', r*0.5).attr('width', r*0.6).attr('height', r*0.35).attr('fill', c).attr('opacity', 0.5);
    g.append('rect').attr('x', -r*0.55).attr('y', r*0.85).attr('width', r*1.1).attr('height', r*0.15).attr('rx', 1).attr('fill', c).attr('opacity', 0.35);
  }} else if (d.type === 'Group') {{
    g.append('circle').attr('r', r*0.42).attr('cx', -r*0.35).attr('cy', -r*0.15).attr('fill', c);
    g.append('circle').attr('r', r*0.42).attr('cx', r*0.35).attr('cy', -r*0.15).attr('fill', c);
    g.append('circle').attr('r', r*0.42).attr('cx', 0).attr('cy', r*0.35).attr('fill', c);
  }} else if (d.type === 'Domain') {{
    g.append('circle').attr('r', r).attr('fill', 'none').attr('stroke', c).attr('stroke-width', 1.8);
    g.append('path').attr('d', `M${{-r}} 0 H${{r}} M0 ${{-r}} Q${{r*0.4}} 0 0 ${{r}} M0 ${{-r}} Q${{-r*0.4}} 0 0 ${{r}}`).attr('fill', 'none').attr('stroke', c).attr('stroke-width', 0.8).attr('opacity', 0.5);
  }} else if (d.type === 'GPO') {{
    g.append('rect').attr('x', -r*0.65).attr('y', -r).attr('width', r*1.3).attr('height', r*2).attr('rx', 2).attr('fill', 'none').attr('stroke', c).attr('stroke-width', 1.5);
    [-.4, 0, .4].forEach(y => g.append('line').attr('x1', -r*0.35).attr('x2', r*0.35).attr('y1', r*y).attr('y2', r*y).attr('stroke', c).attr('stroke-width', 0.8).attr('opacity', 0.4));
  }} else {{
    g.append('circle').attr('r', r * 0.7).attr('fill', c);
  }}
  // Tier 0 diamond outline
  if (d.tier === 0) {{
    const s = r * 1.4;
    g.append('path').attr('d', `M0 ${{-s}} L${{s}} 0 L0 ${{s}} L${{-s}} 0 Z`).attr('fill', 'none').attr('stroke', '#ef4444').attr('stroke-width', 2.2).attr('stroke-dasharray', d.type === 'Domain' ? 'none' : 'none');
  }}
  // Risk glow for high-risk nodes
  if (d.score > 50) {{
    const glowR = r * 1.6;
    g.insert('circle', ':first-child').attr('r', glowR).attr('fill', 'none').attr('stroke', '#ef4444').attr('stroke-width', 1).attr('opacity', 0.3 + (d.score / 200));
  }}
}}

function edgeStroke(d) {{ return EDGE_COLORS[d.type] || '#475569'; }}
function isStructural(d) {{ return d.type === 'MemberOf' || d.type === 'Contains'; }}

function drawGraph() {{
  window._graphDrawn = true;
  const container = document.getElementById('graph-container');
  const width = container.clientWidth;
  const height = container.clientHeight || 700;

  svg = d3.select('#graph-container').append('svg')
    .attr('width', width).attr('height', height);

  // Arrow markers for each edge color
  const defs = svg.append('defs');
  const usedColors = new Set(graphData.links.map(l => edgeStroke(l)));
  usedColors.forEach(c => {{
    const id = 'arrow-' + c.replace('#','');
    defs.append('marker').attr('id', id).attr('viewBox', '0 -4 8 8').attr('refX', 22).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
      .append('path').attr('d', 'M0,-3.5L7,0L0,3.5').attr('fill', c);
  }});
  // Glow filter
  const glow = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
  glow.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
  glow.append('feMerge').html('<feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/>');

  gRoot = svg.append('g');
  const zoom = d3.zoom().scaleExtent([0.08, 8]).on('zoom', (e) => gRoot.attr('transform', e.transform));
  svg.call(zoom);
  window._zoom = zoom;

  // Detect parallel edges and assign curve offset
  const edgePairCount = {{}};
  graphData.links.forEach(l => {{
    const k = [l.source, l.target].sort().join('|');
    edgePairCount[k] = (edgePairCount[k] || 0) + 1;
    l._pairIndex = edgePairCount[k];
  }});
  graphData.links.forEach(l => {{
    const k = [typeof l.source === 'object' ? l.source.id : l.source, typeof l.target === 'object' ? l.target.id : l.target].sort().join('|');
    const total = edgePairCount[k] || 1;
    l._curveOffset = total > 1 ? (l._pairIndex - (total + 1) / 2) * 18 : 0;
  }});

  // Links as curved paths
  linkElements = gRoot.append('g').attr('class', 'links').selectAll('path')
    .data(graphData.links).enter().append('path')
    .attr('fill', 'none')
    .attr('stroke', d => edgeStroke(d))
    .attr('stroke-width', d => isStructural(d) ? 0.6 : 1.8)
    .attr('stroke-opacity', d => isStructural(d) ? 0.15 : 0.55)
    .attr('marker-end', d => isStructural(d) ? '' : `url(#arrow-${{edgeStroke(d).replace('#','')}})`)
    .style('transition', 'stroke-opacity 0.3s, stroke-width 0.3s');

  // Edge labels (hidden by default)
  linkLabels = gRoot.append('g').attr('class', 'link-labels').selectAll('text')
    .data(graphData.links.filter(d => !isStructural(d))).enter().append('text')
    .text(d => d.type)
    .attr('font-size', '7px').attr('fill', d => edgeStroke(d)).attr('text-anchor', 'middle')
    .attr('dy', -4).attr('opacity', 0.7)
    .style('pointer-events', 'none').style('display', 'none');

  // Node groups with shaped icons
  nodeGroups = gRoot.append('g').attr('class', 'nodes').selectAll('g')
    .data(graphData.nodes).enter().append('g')
    .style('cursor', 'pointer')
    .on('click', (e, d) => {{ e.stopPropagation(); showNodeDetail(d); }})
    .on('contextmenu', (e, d) => showContextMenu(e, d))
    .on('mouseenter', (e, d) => showTooltip(e, d))
    .on('mouseleave', () => hideTooltip())
    .call(d3.drag()
      .on('start', (e, d) => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
      .on('drag', (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
      .on('end', (e, d) => {{ if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }})
    );
  nodeGroups.each(function(d) {{ nodeShape(d3.select(this), d); }});

  // Labels
  labelElements = gRoot.append('g').attr('class', 'labels').selectAll('text')
    .data(graphData.nodes.filter(n => n.tier === 0 || n.score > 25)).enter().append('text')
    .text(d => d.name.length > 20 ? d.name.substring(0, 18) + '..' : d.name)
    .attr('font-size', d => d.tier === 0 ? '10px' : '8px')
    .attr('font-weight', d => d.tier === 0 ? '600' : '400')
    .attr('fill', d => d.tier === 0 ? '#fca5a5' : '#94a3b8')
    .attr('text-anchor', 'middle')
    .attr('dy', d => -(NODE_SIZES[d.tier] || 8) - 6)
    .style('pointer-events', 'none')
    .style('text-shadow', '0 0 4px rgba(0,0,0,0.8), 0 0 8px rgba(0,0,0,0.6)');

  // Force simulation
  simulation = d3.forceSimulation(graphData.nodes)
    .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(d => isStructural(d) ? 40 : 90).strength(d => isStructural(d) ? 0.8 : 0.4))
    .force('charge', d3.forceManyBody().strength(d => d.tier === 0 ? -300 : -80))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(d => (NODE_SIZES[d.tier] || 8) + 6))
    .force('y', d3.forceY().y(d => {{ const h = height; return d.tier === 0 ? h * 0.85 : d.tier === 1 ? h * 0.5 : h * 0.2; }}).strength(0.05));

  function linkPath(d) {{
    const dx = d.target.x - d.source.x, dy = d.target.y - d.source.y;
    if (Math.abs(d._curveOffset) < 1) return `M${{d.source.x}},${{d.source.y}}L${{d.target.x}},${{d.target.y}}`;
    const mx = (d.source.x + d.target.x) / 2, my = (d.source.y + d.target.y) / 2;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    const nx = -dy / len, ny = dx / len;
    const cx = mx + nx * d._curveOffset, cy = my + ny * d._curveOffset;
    return `M${{d.source.x}},${{d.source.y}}Q${{cx}},${{cy}} ${{d.target.x}},${{d.target.y}}`;
  }}

  simulation.on('tick', () => {{
    linkElements.attr('d', linkPath);
    nodeGroups.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
    labelElements.attr('x', d => d.x).attr('y', d => d.y);
    linkLabels.attr('x', d => (d.source.x + d.target.x) / 2).attr('y', d => (d.source.y + d.target.y) / 2);
  }});

  // Click background to deselect
  svg.on('click', () => {{
    const detail = document.querySelector('.node-detail');
    if (detail) detail.remove();
    resetHighlights();
  }});
}}

function showTooltip(e, d) {{
  const tt = document.getElementById('graph-tooltip');
  const c = NODE_COLORS[d.type] || '#64748b';
  tt.innerHTML = `<div class="tt-name" style="color:${{c}}">${{d.name}}</div><div class="tt-type">${{d.type}} - Tier ${{d.tier}}${{d.score > 0 ? ' - Risk: ' + d.score : ''}}</div>`;
  tt.style.display = 'block';
  const rect = document.getElementById('graph-container').getBoundingClientRect();
  tt.style.left = (e.clientX - rect.left + 12) + 'px';
  tt.style.top = (e.clientY - rect.top - 10) + 'px';
}}
function hideTooltip() {{ document.getElementById('graph-tooltip').style.display = 'none'; }}

function resetHighlights() {{
  if (!nodeGroups) return;
  nodeGroups.attr('opacity', 1);
  linkElements
    .attr('stroke-opacity', d => isStructural(d) ? 0.15 : 0.55)
    .attr('stroke-width', d => isStructural(d) ? 0.6 : 1.8);
}}

function resetGraph() {{
  if (svg && window._zoom) svg.transition().duration(500).call(window._zoom.transform, d3.zoomIdentity);
  resetHighlights();
  const detail = document.querySelector('.node-detail');
  if (detail) detail.remove();
}}

function toggleLabels() {{
  labelsVisible = !labelsVisible;
  if (labelElements) labelElements.style('display', labelsVisible ? 'block' : 'none');
}}

function toggleEdgeLabels() {{
  edgeLabelsVisible = !edgeLabelsVisible;
  if (linkLabels) linkLabels.style('display', edgeLabelsVisible ? 'block' : 'none');
}}

function toggleLayout() {{
  hierarchicalLayout = !hierarchicalLayout;
  if (!simulation) return;
  const height = document.getElementById('graph-container').clientHeight || 700;
  simulation.force('y', d3.forceY().y(d => {{
    if (!hierarchicalLayout) return height / 2;
    return d.tier === 0 ? height * 0.85 : d.tier === 1 ? height * 0.5 : height * 0.15;
  }}).strength(hierarchicalLayout ? 0.15 : 0.02));
  simulation.alpha(0.5).restart();
}}

function showNodeDetail(d) {{
  const existing = document.querySelector('.node-detail');
  if (existing) existing.remove();

  const paths = pathsData.filter(p => p.node_ids.includes(d.id));
  const div = document.createElement('div');
  div.className = 'node-detail';
  div.onclick = e => e.stopPropagation();
  const c = NODE_COLORS[d.type] || '#64748b';
  let html = `<span class="close" onclick="this.parentElement.remove();resetHighlights()">&times;</span>`;
  html += `<h4 style="color:${{c}}">${{d.name}}</h4>`;
  html += `<div class="stat"><span>Type</span><span>${{d.type}}</span></div>`;
  html += `<div class="stat"><span>Tier</span><span class="tier-badge tier-${{d.tier}}">T${{d.tier}}</span></div>`;
  html += `<div class="stat"><span>Risk Score</span><span style="color:${{d.score > 60 ? '#ef4444' : d.score > 30 ? '#eab308' : '#94a3b8'}}">${{d.score}}</span></div>`;
  html += `<div class="stat"><span>In Paths</span><span>${{paths.length}}</span></div>`;

  if (paths.length > 0) {{
    html += '<div class="path-list"><strong style="font-size:0.75rem;color:var(--text-dim)">ATTACK PATHS:</strong>';
    paths.slice(0, 10).forEach(p => {{
      html += `<div class="path-item" onclick="goToPath('${{p.source}}')">${{p.source}} &#8594; ${{p.target}} <span style="color:var(--text-dimmer)">(${{p.length}} hops)</span></div>`;
    }});
    if (paths.length > 10) html += `<div style="font-size:0.72rem;color:var(--text-dimmer);margin-top:4px">+ ${{paths.length - 10}} more</div>`;
    html += '</div>';
  }}

  div.innerHTML = html;
  document.getElementById('graph-container').appendChild(div);

  // Highlight connected paths with animation
  const nodeIds = new Set();
  paths.forEach(p => p.node_ids.forEach(n => nodeIds.add(n)));
  nodeIds.add(d.id);

  if (nodeGroups) {{
    nodeGroups.transition().duration(300)
      .attr('opacity', n => nodeIds.has(n.id) ? 1 : 0.08);
    linkElements.transition().duration(300)
      .attr('stroke-opacity', l => nodeIds.has(l.source.id) && nodeIds.has(l.target.id) ? 0.85 : 0.02)
      .attr('stroke-width', l => nodeIds.has(l.source.id) && nodeIds.has(l.target.id) ? 3 : 0.3);
  }}
}}

function goToPath(sourceName) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="paths"]').classList.add('active');
  document.getElementById('paths').classList.add('active');
  document.getElementById('path-search').value = sourceName;
  renderPathList(sourceName);
}}

function highlightPathInGraph(nodeIds) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="graph"]').classList.add('active');
  document.getElementById('graph').classList.add('active');
  if (!window._graphDrawn) drawGraph();

  const idSet = new Set(nodeIds);
  setTimeout(() => {{
    if (nodeGroups) {{
      nodeGroups.transition().duration(400)
        .attr('opacity', n => idSet.has(n.id) ? 1 : 0.05);
      linkElements.transition().duration(400)
        .attr('stroke-opacity', l => idSet.has(l.source.id) && idSet.has(l.target.id) ? 0.95 : 0.01)
        .attr('stroke-width', l => idSet.has(l.source.id) && idSet.has(l.target.id) ? 3.5 : 0.2);
    }}
  }}, 150);
}}

// ---- GRAPH SEARCH ----
(function() {{
  const input = document.getElementById('graph-search-input');
  const results = document.getElementById('graph-search-results');
  let activeIdx = -1;

  input.addEventListener('input', () => {{
    const q = input.value.toLowerCase().trim();
    results.innerHTML = '';
    activeIdx = -1;
    if (q.length < 2) {{ results.style.display = 'none'; return; }}
    const matches = graphData.nodes.filter(n => n.name.toLowerCase().includes(q)).slice(0, 12);
    if (!matches.length) {{ results.style.display = 'none'; return; }}
    matches.forEach((m, i) => {{
      const div = document.createElement('div');
      div.className = 'sr';
      div.innerHTML = `<span>${{m.name}}</span><span class="sr-type">${{m.type}} T${{m.tier}}</span>`;
      div.addEventListener('click', () => zoomToNode(m));
      div.addEventListener('mouseenter', () => {{
        results.querySelectorAll('.sr').forEach(s => s.classList.remove('active'));
        div.classList.add('active');
        activeIdx = i;
      }});
      results.appendChild(div);
    }});
    results.style.display = 'block';
  }});

  input.addEventListener('keydown', (e) => {{
    const items = results.querySelectorAll('.sr');
    if (!items.length) return;
    if (e.key === 'ArrowDown') {{ e.preventDefault(); activeIdx = Math.min(activeIdx + 1, items.length - 1); }}
    else if (e.key === 'ArrowUp') {{ e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); }}
    else if (e.key === 'Enter' && activeIdx >= 0) {{ e.preventDefault(); items[activeIdx].click(); return; }}
    else if (e.key === 'Escape') {{ results.style.display = 'none'; return; }}
    else return;
    items.forEach(s => s.classList.remove('active'));
    if (activeIdx >= 0) items[activeIdx].classList.add('active');
  }});

  document.addEventListener('click', (e) => {{
    if (!e.target.closest('#graph-search')) results.style.display = 'none';
  }});
}})();

function zoomToNode(node) {{
  if (!window._graphDrawn) drawGraph();
  document.getElementById('graph-search-results').style.display = 'none';
  document.getElementById('graph-search-input').value = node.name;
  const d = graphData.nodes.find(n => n.id === node.id);
  if (!d || d.x == null) return;
  const container = document.getElementById('graph-container');
  const w = container.clientWidth, h = container.clientHeight;
  const scale = 2.5;
  const tx = w / 2 - d.x * scale, ty = h / 2 - d.y * scale;
  svg.transition().duration(600)
    .call(window._zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  // Pulse the node
  const nodeIds = new Set([d.id]);
  const paths = pathsData.filter(p => p.node_ids.includes(d.id));
  paths.forEach(p => p.node_ids.forEach(n => nodeIds.add(n)));
  nodeGroups.transition().duration(400).attr('opacity', n => nodeIds.has(n.id) ? 1 : 0.12);
  linkElements.transition().duration(400)
    .attr('stroke-opacity', l => nodeIds.has(l.source.id) && nodeIds.has(l.target.id) ? 0.85 : 0.03)
    .attr('stroke-width', l => nodeIds.has(l.source.id) && nodeIds.has(l.target.id) ? 3 : 0.3);
}}

// ---- EDGE TYPE FILTER ----
let edgeFilterVisible = false;
const hiddenEdgeTypes = new Set();

function toggleEdgeFilter() {{
  edgeFilterVisible = !edgeFilterVisible;
  const panel = document.getElementById('edge-filter');
  if (edgeFilterVisible) {{
    buildEdgeFilter();
    panel.style.display = 'block';
  }} else {{
    panel.style.display = 'none';
  }}
}}

function buildEdgeFilter() {{
  const panel = document.getElementById('edge-filter');
  if (panel.querySelector('.ef-title')) return;
  const types = {{}};
  graphData.links.forEach(l => {{ types[l.type] = (types[l.type] || 0) + 1; }});
  const sorted = Object.entries(types).sort((a, b) => b[1] - a[1]);
  const categories = {{
    'Critical ACL': ['GenericAll', 'DCSync', 'WriteDacl', 'WriteOwner', 'Owns'],
    'Dangerous ACL': ['GenericWrite', 'ForceChangePassword', 'AddMember', 'WriteSPN', 'WriteKeyCredentialLink', 'AddAllowedToAct'],
    'Session/Admin': ['AdminTo', 'HasSession', 'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'SQLAdmin'],
    'Delegation': ['AllowedToDelegate', 'AllowedToAct'],
    'ADCS': ['Enroll', 'AutoEnroll', 'ManageCA', 'ManageCertificates', 'WritePKIEnrollmentFlag', 'WritePKINameFlag'],
    'Structural': ['MemberOf', 'Contains', 'TrustedBy', 'GPOControlsObject'],
  }};

  let html = '<div class="ef-title">EDGE FILTERS</div>';
  html += '<label style="margin-bottom:4px"><input type="checkbox" checked onchange="toggleAllEdges(this.checked)"> <strong>All</strong></label>';
  html += '<div class="ef-sep"></div>';
  for (const [cat, edgeTypes] of Object.entries(categories)) {{
    const present = edgeTypes.filter(t => types[t]);
    if (!present.length) continue;
    html += `<div style="color:var(--text-dim);font-size:0.7rem;margin-top:4px;margin-bottom:2px">${{cat}}</div>`;
    present.forEach(t => {{
      const color = EDGE_COLORS[t] || '#475569';
      html += `<label><input type="checkbox" checked data-edge="${{t}}" onchange="filterEdge('${{t}}',this.checked)"><span style="color:${{color}}">${{t}}</span> <span style="color:var(--text-dimmer)">(${{types[t]}})</span></label>`;
    }});
  }}
  const categorized = new Set(Object.values(categories).flat());
  const other = sorted.filter(([t]) => !categorized.has(t));
  if (other.length) {{
    html += '<div class="ef-sep"></div><div style="color:var(--text-dim);font-size:0.7rem;margin-bottom:2px">Other</div>';
    other.forEach(([t, count]) => {{
      html += `<label><input type="checkbox" checked data-edge="${{t}}" onchange="filterEdge('${{t}}',this.checked)">${{t}} <span style="color:var(--text-dimmer)">(${{count}})</span></label>`;
    }});
  }}
  panel.innerHTML = html;
}}

function filterEdge(edgeType, visible) {{
  if (visible) hiddenEdgeTypes.delete(edgeType);
  else hiddenEdgeTypes.add(edgeType);
  applyEdgeFilter();
}}

function toggleAllEdges(visible) {{
  const panel = document.getElementById('edge-filter');
  panel.querySelectorAll('input[data-edge]').forEach(cb => {{ cb.checked = visible; }});
  if (visible) hiddenEdgeTypes.clear();
  else graphData.links.forEach(l => hiddenEdgeTypes.add(l.type));
  applyEdgeFilter();
}}

function applyEdgeFilter() {{
  if (!linkElements) return;
  linkElements.attr('display', d => hiddenEdgeTypes.has(d.type) ? 'none' : 'block');
  if (linkLabels) linkLabels.attr('display', d => hiddenEdgeTypes.has(d.type) ? 'none' : (edgeLabelsVisible ? 'block' : 'none'));
}}

// ---- CONTEXT MENU ----
(function() {{
  document.addEventListener('click', () => {{
    const m = document.querySelector('.ctx-menu');
    if (m) m.remove();
  }});
}})();

function showContextMenu(e, d) {{
  e.preventDefault();
  e.stopPropagation();
  const old = document.querySelector('.ctx-menu');
  if (old) old.remove();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  const rect = document.getElementById('graph-container').getBoundingClientRect();
  menu.style.left = (e.clientX - rect.left) + 'px';
  menu.style.top = (e.clientY - rect.top) + 'px';
  const c = NODE_COLORS[d.type] || '#64748b';
  menu.innerHTML = `
    <div style="padding:6px 14px;font-weight:600;color:${{c}};font-size:0.85rem;border-bottom:1px solid var(--border)">${{d.name}}</div>
    <div class="ctx-item" onclick="showNodeDetail(graphData.nodes.find(n=>n.id==='${{d.id}}'))">Show details</div>
    <div class="ctx-item" onclick="goToPath('${{d.name.split('@')[0]}}')">Find attack paths</div>
    <div class="ctx-item" onclick="isolateNode('${{d.id}}')">Isolate neighborhood</div>
    <div class="ctx-sep"></div>
    <div class="ctx-item" onclick="copyText('${{d.name}}')">Copy name</div>
    <div class="ctx-item" onclick="copyText('${{d.id}}')">Copy SID</div>
  `;
  document.getElementById('graph-container').appendChild(menu);
}}

function isolateNode(nodeId) {{
  const neighbors = new Set([nodeId]);
  graphData.links.forEach(l => {{
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    if (sid === nodeId) neighbors.add(tid);
    if (tid === nodeId) neighbors.add(sid);
  }});
  nodeGroups.transition().duration(400).attr('opacity', n => neighbors.has(n.id) ? 1 : 0.04);
  linkElements.transition().duration(400)
    .attr('stroke-opacity', l => {{
      const sid = typeof l.source === 'object' ? l.source.id : l.source;
      const tid = typeof l.target === 'object' ? l.target.id : l.target;
      return (sid === nodeId || tid === nodeId) ? 0.9 : 0.01;
    }})
    .attr('stroke-width', l => {{
      const sid = typeof l.source === 'object' ? l.source.id : l.source;
      const tid = typeof l.target === 'object' ? l.target.id : l.target;
      return (sid === nodeId || tid === nodeId) ? 3 : 0.2;
    }});
}}

function copyText(text) {{
  navigator.clipboard.writeText(text);
  showToast('Copied: ' + text.substring(0, 40));
}}

// ---- OVERVIEW CHARTS ----
function drawOverviewCharts() {{
  const nodeTypes = summaryData.node_types || {{}};
  const edgeTypes = summaryData.edge_types || {{}};

  // Node distribution bar chart
  const nd = Object.entries(nodeTypes).sort((a, b) => b[1] - a[1]);
  if (nd.length) {{
    const ct = document.getElementById('chart-nodes');
    const w = ct.clientWidth, h = ct.clientHeight;
    const svgN = d3.select('#chart-nodes').append('svg').attr('width', w).attr('height', h);
    const margin = {{top: 8, right: 12, bottom: 24, left: 50}};
    const iw = w - margin.left - margin.right, ih = h - margin.top - margin.bottom;
    const g = svgN.append('g').attr('transform', `translate(${{margin.left}},${{margin.top}})`);
    const x = d3.scaleLinear().domain([0, d3.max(nd, d => d[1])]).range([0, iw]);
    const y = d3.scaleBand().domain(nd.map(d => d[0])).range([0, ih]).padding(0.3);
    g.selectAll('rect').data(nd).enter().append('rect')
      .attr('x', 0).attr('y', d => y(d[0])).attr('width', d => x(d[1])).attr('height', y.bandwidth())
      .attr('fill', d => NODE_COLORS[d[0]] || '#64748b').attr('rx', 3).attr('opacity', 0.85);
    g.selectAll('.label').data(nd).enter().append('text')
      .attr('x', d => x(d[1]) + 4).attr('y', d => y(d[0]) + y.bandwidth() / 2)
      .attr('dy', '0.35em').attr('fill', '#94a3b8').attr('font-size', '10px').text(d => d[1]);
    g.selectAll('.name').data(nd).enter().append('text')
      .attr('x', -4).attr('y', d => y(d[0]) + y.bandwidth() / 2)
      .attr('dy', '0.35em').attr('text-anchor', 'end').attr('fill', '#e2e8f0').attr('font-size', '10px')
      .text(d => d[0].length > 8 ? d[0].substring(0, 7) + '..' : d[0]);
  }}

  // Edge type distribution (top 10)
  const ed = Object.entries(edgeTypes).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (ed.length) {{
    const ct = document.getElementById('chart-edges');
    const w = ct.clientWidth, h = ct.clientHeight;
    const svgE = d3.select('#chart-edges').append('svg').attr('width', w).attr('height', h);
    const margin = {{top: 8, right: 12, bottom: 24, left: 80}};
    const iw = w - margin.left - margin.right, ih = h - margin.top - margin.bottom;
    const g = svgE.append('g').attr('transform', `translate(${{margin.left}},${{margin.top}})`);
    const x = d3.scaleLinear().domain([0, d3.max(ed, d => d[1])]).range([0, iw]);
    const y = d3.scaleBand().domain(ed.map(d => d[0])).range([0, ih]).padding(0.25);
    g.selectAll('rect').data(ed).enter().append('rect')
      .attr('x', 0).attr('y', d => y(d[0])).attr('width', d => x(d[1])).attr('height', y.bandwidth())
      .attr('fill', d => EDGE_COLORS[d[0]] || '#475569').attr('rx', 3).attr('opacity', 0.85);
    g.selectAll('.label').data(ed).enter().append('text')
      .attr('x', d => x(d[1]) + 4).attr('y', d => y(d[0]) + y.bandwidth() / 2)
      .attr('dy', '0.35em').attr('fill', '#94a3b8').attr('font-size', '10px').text(d => d[1]);
    g.selectAll('.name').data(ed).enter().append('text')
      .attr('x', -4).attr('y', d => y(d[0]) + y.bandwidth() / 2)
      .attr('dy', '0.35em').attr('text-anchor', 'end').attr('fill', '#e2e8f0').attr('font-size', '10px')
      .text(d => d[0]);
  }}
}}
drawOverviewCharts();

// ---- DEFEND TAB ----
function renderDefend(filter) {{
  const table = document.getElementById('defend-table');
  table.innerHTML = '';
  const q = (filter || '').toLowerCase();
  defendData.filter(d => !q || d.edge_type.toLowerCase().includes(q) || d.mitre.toLowerCase().includes(q) || d.category.toLowerCase().includes(q))
    .forEach(d => {{
      const tr = document.createElement('tr');
      const diffColor = {{low: 'var(--success)', medium: 'var(--warning)', high: 'var(--danger)'}}[d.detection_difficulty] || 'var(--text-dim)';
      const expBar = Math.min(d.exploitability * 10, 100);
      tr.innerHTML = `<td><strong style="color:${{EDGE_COLORS[d.edge_type] || 'var(--text)'}}">${{d.edge_type}}</strong><div style="font-size:0.72rem;color:var(--text-dimmer)">${{d.category}}</div></td><td>${{d.count}}</td><td style="font-size:0.78rem">${{d.mitre || '-'}}</td><td><div style="display:flex;align-items:center;gap:6px"><div class="bar" style="width:50px"><div class="bar-fill" style="width:${{expBar}}%;background:${{expBar > 70 ? 'var(--danger)' : expBar > 40 ? 'var(--warning)' : 'var(--accent)'}}"></div></div>${{d.exploitability}}/10</div></td><td><span style="color:${{diffColor}}">${{d.detection_difficulty}}</span></td><td style="font-size:0.72rem">${{d.log_sources.join(', ')}}</td><td style="font-size:0.75rem;max-width:300px">${{d.detection_hints}}</td>`;
      table.appendChild(tr);
    }});
}}
renderDefend();
document.getElementById('defend-search').addEventListener('input', e => renderDefend(e.target.value));

// Defend charts
function drawDefendCharts() {{
  if (!defendData.length) return;

  // MITRE coverage donut
  const mitreCounts = {{}};
  defendData.forEach(d => {{ if (d.mitre) mitreCounts[d.mitre] = (mitreCounts[d.mitre] || 0) + d.count; }});
  const mitreEntries = Object.entries(mitreCounts).sort((a, b) => b[1] - a[1]);
  if (mitreEntries.length) {{
    const ct = document.getElementById('chart-mitre');
    const w = ct.clientWidth, h = ct.clientHeight;
    const svgM = d3.select('#chart-mitre').append('svg').attr('width', w).attr('height', h);
    const radius = Math.min(w, h) / 2 - 10;
    const g = svgM.append('g').attr('transform', `translate(${{w/2}},${{h/2}})`);
    const color = d3.scaleOrdinal(d3.schemeSet2);
    const pie = d3.pie().value(d => d[1]).sort(null);
    const arc = d3.arc().innerRadius(radius * 0.5).outerRadius(radius);
    g.selectAll('path').data(pie(mitreEntries)).enter().append('path')
      .attr('d', arc).attr('fill', (d, i) => color(i)).attr('stroke', '#0f172a').attr('stroke-width', 2)
      .append('title').text(d => `${{d.data[0]}}: ${{d.data[1]}} edges`);
    g.selectAll('text').data(pie(mitreEntries)).enter().append('text')
      .attr('transform', d => `translate(${{arc.centroid(d)}})`)
      .attr('text-anchor', 'middle').attr('font-size', '8px').attr('fill', '#e2e8f0')
      .text(d => d.data[1] > mitreEntries[0][1] * 0.08 ? d.data[0] : '');
    g.append('text').attr('text-anchor', 'middle').attr('dy', '-0.2em').attr('fill', '#e2e8f0')
      .attr('font-size', '18px').attr('font-weight', '700').text(mitreEntries.length);
    g.append('text').attr('text-anchor', 'middle').attr('dy', '1.2em').attr('fill', '#94a3b8')
      .attr('font-size', '10px').text('techniques');
  }}

  // Detection difficulty breakdown
  const diffCounts = {{low: 0, medium: 0, high: 0}};
  defendData.forEach(d => {{ diffCounts[d.detection_difficulty] = (diffCounts[d.detection_difficulty] || 0) + d.count; }});
  const diffEntries = Object.entries(diffCounts).filter(d => d[1] > 0);
  if (diffEntries.length) {{
    const ct = document.getElementById('chart-difficulty');
    const w = ct.clientWidth, h = ct.clientHeight;
    const svgD = d3.select('#chart-difficulty').append('svg').attr('width', w).attr('height', h);
    const margin = {{top: 20, right: 20, bottom: 30, left: 20}};
    const iw = w - margin.left - margin.right, ih = h - margin.top - margin.bottom;
    const g = svgD.append('g').attr('transform', `translate(${{margin.left}},${{margin.top}})`);
    const colors = {{low: '#22c55e', medium: '#eab308', high: '#ef4444'}};
    const x = d3.scaleBand().domain(diffEntries.map(d => d[0])).range([0, iw]).padding(0.35);
    const y = d3.scaleLinear().domain([0, d3.max(diffEntries, d => d[1])]).range([ih, 0]);
    g.selectAll('rect').data(diffEntries).enter().append('rect')
      .attr('x', d => x(d[0])).attr('y', d => y(d[1])).attr('width', x.bandwidth())
      .attr('height', d => ih - y(d[1])).attr('fill', d => colors[d[0]]).attr('rx', 4);
    g.selectAll('.label').data(diffEntries).enter().append('text')
      .attr('x', d => x(d[0]) + x.bandwidth() / 2).attr('y', d => y(d[1]) - 4)
      .attr('text-anchor', 'middle').attr('fill', '#e2e8f0').attr('font-size', '12px').attr('font-weight', '600')
      .text(d => d[1]);
    g.selectAll('.name').data(diffEntries).enter().append('text')
      .attr('x', d => x(d[0]) + x.bandwidth() / 2).attr('y', ih + 16)
      .attr('text-anchor', 'middle').attr('fill', '#94a3b8').attr('font-size', '11px')
      .text(d => d[0].charAt(0).toUpperCase() + d[0].slice(1));
  }}

  // Log sources list
  const logSources = {{}};
  defendData.forEach(d => d.log_sources.forEach(ls => {{ logSources[ls] = (logSources[ls] || 0) + d.count; }}));
  const logEntries = Object.entries(logSources).sort((a, b) => b[1] - a[1]);
  const logList = document.getElementById('log-sources-list');
  logEntries.forEach(([source, count]) => {{
    const div = document.createElement('div');
    div.style.cssText = 'display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border)';
    div.innerHTML = `<span>${{source}}</span><span style="color:var(--text-dim)">${{count}} edges</span>`;
    logList.appendChild(div);
  }});
}}

// Draw defend charts when tab is first shown
const defendTabBtn = document.querySelector('[data-tab="defend"]');
let defendChartsDrawn = false;
defendTabBtn.addEventListener('click', () => {{
  if (!defendChartsDrawn) {{ drawDefendCharts(); defendChartsDrawn = true; }}
}});
</script>
</body>
</html>'''
