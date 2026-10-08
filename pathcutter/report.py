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


def _grade_color(grade: str) -> str:
    return {
        "A": "#22c55e",
        "B": "#84cc16",
        "C": "#eab308",
        "D": "#f97316",
        "F": "#ef4444",
    }.get(grade, "#6b7280")


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

#graph-container {{ width: 100%; height: 600px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; position: relative; }}
#graph-controls {{ position: absolute; top: 8px; right: 8px; display: flex; gap: 4px; z-index: 5; }}
#graph-legend {{ position: absolute; bottom: 8px; left: 8px; background: rgba(15,23,42,0.9); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size: 0.72rem; z-index: 5; }}
#graph-legend .item {{ display: flex; align-items: center; gap: 6px; margin: 2px 0; }}
#graph-legend .dot {{ width: 10px; height: 10px; border-radius: 50%; }}

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
        <div id="graph-controls">
          <button class="btn btn-sm btn-outline" onclick="resetGraph()">Reset Zoom</button>
          <button class="btn btn-sm btn-outline" onclick="toggleLabels()">Labels</button>
        </div>
        <div id="graph-legend">
          <div class="item"><div class="dot" style="background:#3b82f6"></div> User</div>
          <div class="item"><div class="dot" style="background:#10b981"></div> Computer</div>
          <div class="item"><div class="dot" style="background:#f59e0b"></div> Group</div>
          <div class="item"><div class="dot" style="background:#ef4444"></div> Domain</div>
          <div class="item"><div class="dot" style="background:#8b5cf6"></div> GPO</div>
          <div class="item"><div class="dot" style="background:transparent;border:2px solid #ef4444"></div> Tier 0</div>
        </div>
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

// ---- D3 GRAPH ----
let simulation, svg, g, nodeElements, linkElements, labelElements;
let labelsVisible = true;

function drawGraph() {{
  window._graphDrawn = true;
  const container = document.getElementById('graph-container');
  const width = container.clientWidth;
  const height = container.clientHeight || 600;

  svg = d3.select('#graph-container').append('svg')
    .attr('width', width).attr('height', height);

  g = svg.append('g');
  const zoom = d3.zoom().scaleExtent([0.1, 6]).on('zoom', (e) => g.attr('transform', e.transform));
  svg.call(zoom);
  window._zoom = zoom;

  const colorMap = {{ User: '#3b82f6', Computer: '#10b981', Group: '#f59e0b', Domain: '#ef4444', GPO: '#8b5cf6', OU: '#6366f1', Container: '#64748b' }};
  const tierRadius = {{ 0: 14, 1: 8, 2: 5 }};

  // Edge type -> color for links
  const edgeColors = {{
    GenericAll: '#ef4444', GenericWrite: '#f97316', WriteDacl: '#f97316', WriteOwner: '#f97316',
    DCSync: '#ef4444', AddMember: '#eab308', AdminTo: '#a855f7', HasSession: '#8b5cf6',
    MemberOf: '#334155', Contains: '#334155',
  }};

  simulation = d3.forceSimulation(graphData.nodes)
    .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(70))
    .force('charge', d3.forceManyBody().strength(-120))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(d => (tierRadius[d.tier] || 5) + 3));

  linkElements = g.append('g').selectAll('line')
    .data(graphData.links).enter().append('line')
    .attr('stroke', d => edgeColors[d.type] || '#475569')
    .attr('stroke-width', d => d.type === 'MemberOf' || d.type === 'Contains' ? 0.5 : 1.5)
    .attr('stroke-opacity', d => d.type === 'MemberOf' || d.type === 'Contains' ? 0.2 : 0.5);

  nodeElements = g.append('g').selectAll('circle')
    .data(graphData.nodes).enter().append('circle')
    .attr('r', d => tierRadius[d.tier] || 5)
    .attr('fill', d => colorMap[d.type] || '#64748b')
    .attr('stroke', d => d.tier === 0 ? '#ef4444' : 'none')
    .attr('stroke-width', d => d.tier === 0 ? 3 : 0)
    .style('cursor', 'pointer')
    .on('click', (e, d) => showNodeDetail(d))
    .call(d3.drag()
      .on('start', (e, d) => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
      .on('drag', (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
      .on('end', (e, d) => {{ if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }})
    );

  labelElements = g.append('g').selectAll('text')
    .data(graphData.nodes.filter(n => n.tier === 0 || n.score > 30)).enter().append('text')
    .text(d => d.name).attr('font-size', '9px').attr('fill', '#94a3b8')
    .attr('dx', 12).attr('dy', 3).style('pointer-events', 'none');

  simulation.on('tick', () => {{
    linkElements.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    nodeElements.attr('cx', d => d.x).attr('cy', d => d.y);
    labelElements.attr('x', d => d.x).attr('y', d => d.y);
  }});
}}

function resetGraph() {{
  if (svg && window._zoom) {{
    svg.transition().duration(500).call(window._zoom.transform, d3.zoomIdentity);
  }}
  // Reset highlights
  if (nodeElements) {{
    nodeElements.attr('opacity', 1);
    linkElements.attr('opacity', d => d.type === 'MemberOf' || d.type === 'Contains' ? 0.2 : 0.5)
      .attr('stroke-width', d => d.type === 'MemberOf' || d.type === 'Contains' ? 0.5 : 1.5);
  }}
}}

function toggleLabels() {{
  labelsVisible = !labelsVisible;
  if (labelElements) labelElements.style('display', labelsVisible ? 'block' : 'none');
}}

function showNodeDetail(d) {{
  const existing = document.querySelector('.node-detail');
  if (existing) existing.remove();

  const paths = pathsData.filter(p => p.node_ids.includes(d.id));
  const div = document.createElement('div');
  div.className = 'node-detail';
  let html = `<span class="close" onclick="this.parentElement.remove()">&times;</span>`;
  html += `<h4>${{d.name}}</h4>`;
  html += `<div class="stat"><span>Type</span><span>${{d.type}}</span></div>`;
  html += `<div class="stat"><span>Tier</span><span class="tier-badge tier-${{d.tier}}">T${{d.tier}}</span></div>`;
  html += `<div class="stat"><span>Risk Score</span><span>${{d.score}}</span></div>`;
  html += `<div class="stat"><span>In Paths</span><span>${{paths.length}}</span></div>`;

  if (paths.length > 0) {{
    html += '<div class="path-list"><strong style="font-size:0.75rem;color:var(--text-dim)">PATHS THROUGH THIS NODE:</strong>';
    paths.slice(0, 8).forEach(p => {{
      html += `<div class="path-item" onclick="goToPath('${{p.source}}')">${{p.source}} -> ${{p.target}} (${{p.length}} hops)</div>`;
    }});
    if (paths.length > 8) html += `<div style="font-size:0.72rem;color:var(--text-dimmer);margin-top:4px">+ ${{paths.length - 8}} more paths</div>`;
    html += '</div>';
  }}

  div.innerHTML = html;
  document.getElementById('graph-container').appendChild(div);

  // Highlight this node's paths in the graph
  const nodeIds = new Set();
  paths.forEach(p => p.node_ids.forEach(n => nodeIds.add(n)));

  if (nodeElements) {{
    nodeElements.attr('opacity', n => nodeIds.has(n.id) ? 1 : 0.15);
    linkElements.attr('opacity', l => nodeIds.has(l.source.id) && nodeIds.has(l.target.id) ? 0.8 : 0.05)
      .attr('stroke-width', l => nodeIds.has(l.source.id) && nodeIds.has(l.target.id) ? 2.5 : 0.5);
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
  // Switch to graph tab
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="graph"]').classList.add('active');
  document.getElementById('graph').classList.add('active');
  if (!window._graphDrawn) drawGraph();

  const idSet = new Set(nodeIds);
  setTimeout(() => {{
    if (nodeElements) {{
      nodeElements.attr('opacity', n => idSet.has(n.id) ? 1 : 0.1);
      linkElements.attr('opacity', l => idSet.has(l.source.id) && idSet.has(l.target.id) ? 0.9 : 0.03)
        .attr('stroke-width', l => idSet.has(l.source.id) && idSet.has(l.target.id) ? 3 : 0.3);
    }}
  }}, 100);
}}
</script>
</body>
</html>'''
