"""HTML report generation - interactive dashboard with D3 attack graph visualization."""
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
                         choke: ChokeReport) -> str:
    """Generate a self-contained HTML dashboard."""
    graph_data = _build_graph_json(graph, path_report, node_scores)
    fixes_data = _build_fixes_json(choke)
    risks_data = _build_risks_json(node_scores[:20])

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
        graph_json=json.dumps(graph_data),
        fixes_json=json.dumps(fixes_data),
        risks_json=json.dumps(risks_data),
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
            })

    return {"nodes": nodes, "links": unique_edges}


def _build_fixes_json(choke: ChokeReport) -> list[dict]:
    return [
        {
            "rank": f.rank,
            "source": f.source_name,
            "target": f.target_name,
            "edge_type": f.edge_type,
            "paths_eliminated": f.paths_eliminated,
            "cumulative_pct": f.cumulative_pct,
            "mitre": f.mitre,
            "fix_command": f.fix_command,
            "description": f.description,
        }
        for f in choke.fixes
    ]


def _build_risks_json(node_scores: list[NodeRisk]) -> list[dict]:
    return [
        {
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
  --border: #334155;
  --text: #e2e8f0;
  --text-dim: #94a3b8;
  --accent: #3b82f6;
  --danger: #ef4444;
  --success: #22c55e;
  --warning: #eab308;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 16px; }}
h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: 4px; }}
.subtitle {{ color: var(--text-dim); font-size: 0.85rem; margin-bottom: 20px; }}

.tabs {{ display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
.tab {{ padding: 10px 20px; cursor: pointer; color: var(--text-dim); border-bottom: 2px solid transparent; transition: all 0.2s; }}
.tab:hover {{ color: var(--text); }}
.tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}

.grid {{ display: grid; gap: 16px; }}
.grid-2 {{ grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
.grid-3 {{ grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }}

.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.card h3 {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }}
.card .value {{ font-size: 2rem; font-weight: 700; }}
.card .detail {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 4px; }}

.gauge {{ width: 120px; height: 120px; margin: 0 auto; }}

.score-ring {{ position: relative; width: 140px; height: 140px; margin: 0 auto 8px; }}
.score-ring svg {{ width: 100%; height: 100%; }}
.score-label {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }}
.score-label .num {{ font-size: 2.5rem; font-weight: 800; }}
.score-label .grade {{ font-size: 1rem; color: var(--text-dim); }}

table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
th {{ text-align: left; padding: 8px 12px; color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }}
td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}
tr:hover {{ background: rgba(59,130,246,0.05); }}

.tier-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
.tier-0 {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
.tier-1 {{ background: rgba(234,179,8,0.2); color: #fde047; }}
.tier-2 {{ background: rgba(59,130,246,0.2); color: #93c5fd; }}

.bar {{ height: 6px; border-radius: 3px; background: var(--border); overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 3px; transition: width 0.5s ease; }}

.copy-btn {{ background: var(--accent); color: white; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 0.75rem; }}
.copy-btn:hover {{ background: #2563eb; }}

#graph-container {{ width: 100%; height: 500px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}

.node-tooltip {{ position: absolute; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size: 0.8rem; pointer-events: none; z-index: 10; }}

.fix-cmd {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 8px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.75rem; white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow-y: auto; margin-top: 4px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Pathcutter - AD Attack Path Report</h1>
  <p class="subtitle">Generated {generated} | {node_count} nodes, {edge_count} edges</p>

  <div class="tabs">
    <div class="tab active" data-tab="overview">Overview</div>
    <div class="tab" data-tab="risks">Riskiest Nodes</div>
    <div class="tab" data-tab="fixes">Remediation</div>
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
        <div class="value">{exposure_pct}%</div>
        <div class="detail">{tier2_with_path} of {tier2_total} Tier 2 nodes can reach Tier 0</div>
        <div class="bar" style="margin-top:8px"><div class="bar-fill" style="width:{exposure_pct}%;background:var(--danger)"></div></div>
      </div>
      <div class="card">
        <h3>Fix Coverage</h3>
        <div class="value">{elimination_pct}%</div>
        <div class="detail">{fix_count} fixes eliminate {elimination_pct}% of attack paths</div>
        <div class="bar" style="margin-top:8px"><div class="bar-fill" style="width:{elimination_pct}%;background:var(--success)"></div></div>
      </div>
      <div class="card">
        <h3>Tier 0 Assets</h3>
        <div class="value">{tier0_count}</div>
        <div class="detail">High-value targets (DA, EA, DCs, KRBTGT)</div>
      </div>
    </div>
  </div>

  <!-- RISKS -->
  <div id="risks" class="tab-content">
    <div class="card">
      <h3>Top Riskiest Nodes</h3>
      <table>
        <thead>
          <tr><th>Name</th><th>Type</th><th>Tier</th><th>Risk Score</th><th>Paths</th><th>Blast Radius</th><th>T0 Reach</th></tr>
        </thead>
        <tbody id="risks-table"></tbody>
      </table>
    </div>
  </div>

  <!-- FIXES -->
  <div id="fixes" class="tab-content">
    <div class="card">
      <h3>Remediation Priority</h3>
      <table>
        <thead>
          <tr><th>#</th><th>Fix</th><th>Type</th><th>Paths Cut</th><th>Cumulative</th><th>MITRE</th><th>Command</th></tr>
        </thead>
        <tbody id="fixes-table"></tbody>
      </table>
    </div>
  </div>

  <!-- GRAPH -->
  <div id="graph" class="tab-content">
    <div class="card">
      <h3>Attack Path Graph (top 500 paths)</h3>
      <div id="graph-container"></div>
    </div>
  </div>
</div>

<script>
const graphData = {graph_json};
const fixesData = {fixes_json};
const risksData = {risks_json};

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

// Risks table
const risksTable = document.getElementById('risks-table');
risksData.forEach(r => {{
  const tr = document.createElement('tr');
  const tierClass = 'tier-' + r.tier;
  tr.innerHTML = `<td>${{r.name}}</td><td>${{r.type}}</td><td><span class="tier-badge ${{tierClass}}">T${{r.tier}}</span></td><td><strong>${{r.score}}</strong></td><td>${{r.path_count}}</td><td>${{r.blast_radius}}</td><td>${{r.tier0_reach}}</td>`;
  risksTable.appendChild(tr);
}});

// Fixes table
const fixesTable = document.getElementById('fixes-table');
fixesData.forEach(f => {{
  const tr = document.createElement('tr');
  const cmdEsc = f.fix_command.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  tr.innerHTML = `<td>${{f.rank}}</td><td>${{f.description}}</td><td>${{f.edge_type}}</td><td>${{f.paths_eliminated}}</td><td>${{f.cumulative_pct}}%</td><td>${{f.mitre || 'N/A'}}</td><td><button class="copy-btn" onclick="navigator.clipboard.writeText(this.closest('tr').querySelector('.fix-cmd').textContent)">Copy</button><div class="fix-cmd">${{cmdEsc}}</div></td>`;
  fixesTable.appendChild(tr);
}});

// D3 Force Graph
function drawGraph() {{
  window._graphDrawn = true;
  const container = document.getElementById('graph-container');
  const width = container.clientWidth;
  const height = container.clientHeight || 500;

  const svg = d3.select('#graph-container').append('svg')
    .attr('width', width).attr('height', height);

  const g = svg.append('g');
  svg.call(d3.zoom().scaleExtent([0.1, 4]).on('zoom', (e) => g.attr('transform', e.transform)));

  const colorMap = {{ User: '#3b82f6', Computer: '#10b981', Group: '#f59e0b', Domain: '#ef4444', GPO: '#8b5cf6', OU: '#6366f1', Container: '#64748b' }};
  const tierRadius = {{ 0: 12, 1: 8, 2: 5 }};

  const simulation = d3.forceSimulation(graphData.nodes)
    .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(60))
    .force('charge', d3.forceManyBody().strength(-100))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(d => (tierRadius[d.tier] || 5) + 2));

  const link = g.append('g').selectAll('line')
    .data(graphData.links).enter().append('line')
    .attr('stroke', '#475569').attr('stroke-width', 1).attr('stroke-opacity', 0.4);

  const node = g.append('g').selectAll('circle')
    .data(graphData.nodes).enter().append('circle')
    .attr('r', d => tierRadius[d.tier] || 5)
    .attr('fill', d => colorMap[d.type] || '#64748b')
    .attr('stroke', d => d.tier === 0 ? '#ef4444' : 'none')
    .attr('stroke-width', d => d.tier === 0 ? 2 : 0)
    .call(d3.drag()
      .on('start', (e, d) => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
      .on('drag', (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
      .on('end', (e, d) => {{ if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }})
    );

  const label = g.append('g').selectAll('text')
    .data(graphData.nodes.filter(n => n.tier === 0 || n.score > 30)).enter().append('text')
    .text(d => d.name).attr('font-size', '9px').attr('fill', '#94a3b8')
    .attr('dx', 10).attr('dy', 3);

  node.append('title').text(d => `${{d.name}} (${{d.type}}, T${{d.tier}})\\nRisk: ${{d.score}}`);

  simulation.on('tick', () => {{
    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    node.attr('cx', d => d.x).attr('cy', d => d.y);
    label.attr('x', d => d.x).attr('y', d => d.y);
  }});
}}
</script>
</body>
</html>'''
