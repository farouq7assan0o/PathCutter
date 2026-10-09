"""HTML report generation - interactive dashboard with D3 attack graph and path explorer."""
from __future__ import annotations

import html
import json
import time
from pathlib import Path

from .graph import AttackGraph
from .pathfinder import PathReport
from .scoring import PostureScore, NodeRisk
from .choke import ChokeReport


GRAPH_MAX_NODES = 6000
CLUSTER_MIN = 6
_GRAPH_JS_PATH = Path(__file__).with_name("graph_view.js")


def _e(value) -> str:
    """HTML-escape attacker-controllable AD strings (names) before embedding."""
    return html.escape(str(value), quote=True)


def _safe_json(obj) -> str:
    """JSON for embedding in a <script> block: neutralise </script> and HTML comments."""
    return (json.dumps(obj)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def generate_html_report(graph: AttackGraph, path_report: PathReport,
                         posture: PostureScore, node_scores: list[NodeRisk],
                         choke: ChokeReport,
                         chains=None, safety=None,
                         max_graph_nodes: int = GRAPH_MAX_NODES) -> str:
    """Generate a self-contained HTML dashboard with interactive path explorer."""
    protected = set()
    for f in choke.fixes:
        protected.add(f.source_id)
        protected.add(f.target_id)
    graph_data, edge_index = _build_graph_json(graph, path_report, node_scores,
                                               max_nodes=max_graph_nodes, protected=protected)
    fixes_data = _build_fixes_json(choke, safety)
    for fd in fixes_data:
        fd["graph_link"] = edge_index.get((fd["source_id"], fd["target_id"], fd["edge_type"]), -1)
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
        graph_json=_safe_json(graph_data),
        fixes_json=_safe_json(fixes_data),
        risks_json=_safe_json(risks_data),
        chains_json=_safe_json(chains_data),
        paths_json=_safe_json(paths_data),
        summary_json=_safe_json(summary),
        defend_json=_safe_json(defend_data),
        grade_color=_grade_color(posture.grade),
        graph_js=_GRAPH_JS_PATH.read_text(encoding="utf-8"),
    )


def _build_graph_json(graph: AttackGraph, path_report: PathReport,
                      node_scores: list[NodeRisk],
                      max_nodes: int = GRAPH_MAX_NODES,
                      protected: set[str] | None = None):
    """Build the graph payload from ALL enumerated attack paths.

    Large environments stay renderable by (1) capping to the most path-relevant
    nodes and (2) collapsing leaf nodes that share one identical edge into a
    single cluster node. Returns (payload, edge_index) where edge_index maps
    (src_id, tgt_id, edge_type) to a link index.
    """
    protected = protected or set()
    score_map = {ns.node_id: ns.risk_score for ns in node_scores}
    participation: dict[str, int] = {}
    link_set: dict[tuple, None] = {}

    for path in path_report.paths:
        for nid in path.nodes:
            participation[nid] = participation.get(nid, 0) + 1
        for i, edge in enumerate(path.edges):
            link_set[(path.nodes[i], path.nodes[i + 1], edge.get("edge_type", ""))] = None

    total_in_paths = len(participation)
    truncated = False
    if total_in_paths > max_nodes:
        truncated = True
        keep = set()
        for nid in participation:
            n = graph.get_node(nid)
            if (n is not None and n.tier == 0) or nid in protected:
                keep.add(nid)
        rest = sorted((n for n in participation if n not in keep),
                      key=lambda n: participation[n], reverse=True)
        keep.update(rest[:max(0, max_nodes - len(keep))])
        links = [k for k in link_set if k[0] in keep and k[1] in keep]
        used = {k[0] for k in links} | {k[1] for k in links}
        kept_ids = [n for n in participation if n in used]
    else:
        links = list(link_set)
        kept_ids = list(participation)

    # Cluster identical leaf sources: no inbound edges, one distinct outbound edge.
    out_edges: dict[str, list[tuple]] = {}
    in_count: dict[str, int] = {}
    for k in links:
        out_edges.setdefault(k[0], []).append(k)
        in_count[k[1]] = in_count.get(k[1], 0) + 1
    groups: dict[tuple, list[str]] = {}
    for nid in kept_ids:
        node = graph.get_node(nid)
        if node is None or node.tier == 0 or nid in protected:
            continue
        if node.node_type.value not in ("User", "Computer"):
            continue
        if in_count.get(nid, 0) or score_map.get(nid, 0) > 25:
            continue
        oe = out_edges.get(nid, [])
        if len(oe) == 1:
            groups.setdefault((oe[0][1], oe[0][2]), []).append(nid)
    clustered: dict[str, tuple] = {}
    for key, members in groups.items():
        if len(members) >= CLUSTER_MIN:
            for m in members:
                clustered[m] = key

    nodes: list[dict] = []
    index: dict[str, int] = {}
    for nid in kept_ids:
        if nid in clustered:
            continue
        node = graph.get_node(nid)
        if node is None:
            continue
        index[nid] = len(nodes)
        nodes.append({
            "id": nid, "name": _e(node.display_name), "type": node.node_type.value,
            "tier": node.tier, "score": score_map.get(nid, 0), "enabled": node.enabled,
        })

    cluster_idx: dict[tuple, int] = {}
    hidden_in_clusters = 0
    for key, members in groups.items():
        if len(members) < CLUSTER_MIN:
            continue
        member_nodes = [graph.get_node(m) for m in members]
        kinds = {mn.node_type.value for mn in member_nodes if mn}
        kind = next(iter(kinds)) if len(kinds) == 1 else "object"
        tgt = graph.get_node(key[0])
        cluster_idx[key] = len(nodes)
        hidden_in_clusters += len(members)
        nodes.append({
            "id": f"cluster:{key[0]}:{key[1]}",
            "name": f"{len(members)} {kind.lower()}s",
            "type": "Cluster", "tier": 2,
            "score": max((score_map.get(m, 0) for m in members), default=0),
            "enabled": True, "count": len(members), "kind": kind,
            "target": _e(tgt.display_name if tgt else key[0]), "via": key[1],
            "members": [_e(mn.display_name) for mn in member_nodes[:150] if mn],
        })

    edge_types: list[str] = []
    et_idx: dict[str, int] = {}
    out_links: list[list[int]] = []
    edge_index: dict[tuple, int] = {}
    seen_cluster_links: set[tuple] = set()
    for (s, t, ty) in links:
        if t not in index:
            continue
        if s in clustered:
            key = clustered[s]
            if key in seen_cluster_links:
                continue
            seen_cluster_links.add(key)
            si = cluster_idx[key]
        else:
            if s not in index:
                continue
            si = index[s]
        if ty not in et_idx:
            et_idx[ty] = len(edge_types)
            edge_types.append(ty)
        edge_index[(s, t, ty)] = len(out_links)
        out_links.append([si, index[t], et_idx[ty]])

    meta = {
        "graph_total": graph.node_count,
        "in_paths": total_in_paths,
        "shown": len(nodes),
        "hidden_in_clusters": hidden_in_clusters,
        "truncated": truncated,
        "links": len(out_links),
        "max_nodes": max_nodes,
    }
    return {"nodes": nodes, "links": out_links, "edgeTypes": edge_types, "meta": meta}, edge_index


def _build_fixes_json(choke: ChokeReport, safety=None) -> list[dict]:
    safety_list = safety or []
    fixes = []
    for i, f in enumerate(choke.fixes):
        fix_data = {
            "rank": f.rank,
            "source": _e(f.source_name),
            "source_id": f.source_id,
            "target": _e(f.target_name),
            "target_id": f.target_id,
            "edge_type": f.edge_type,
            "paths_eliminated": f.paths_eliminated,
            "cumulative_pct": f.cumulative_pct,
            "mitre": f.mitre,
            "fix_command": f.fix_command,
            "description": _e(f.description),
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
            "name": _e(ns.display_name),
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
            "description": _e(c.description),
            "severity": c.severity,
            "mitre": c.mitre,
            "involved_nodes": [_e(n) for n in c.involved_nodes[:8]],
            "remediation": _e(c.remediation),
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
                "from": _e(src.display_name if src else p.nodes[i]),
                "from_id": p.nodes[i],
                "edge": edge.get("edge_type", "?"),
            })
        tgt = graph.get_node(p.target)
        result.append({
            "source": _e(graph.get_node(p.source).display_name if graph.get_node(p.source) else p.source),
            "source_id": p.source,
            "target": _e(tgt.display_name if tgt else p.target),
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

#graph-container {{ width: 100%; height: 78vh; min-height: 600px; max-height: 980px; background: #0a0f1e; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; position: relative; }}
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

#graph-container canvas#graph-canvas {{ position: absolute; inset: 0; width: 100%; height: 100%; display: block; }}
#graph-minimap {{ position: absolute; bottom: 10px; right: 10px; width: 180px; height: 120px; background: rgba(10,15,30,0.92); border: 1px solid var(--border); border-radius: 8px; z-index: 5; cursor: crosshair; }}
#graph-hud {{ position: absolute; top: 52px; left: 10px; font-size: 0.7rem; color: var(--text-dimmer); z-index: 4; line-height: 1.5; pointer-events: none; text-shadow: 0 0 4px #000; }}
#graph-loading {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); width: 260px; text-align: center; z-index: 8; font-size: 0.8rem; color: var(--text-dim); pointer-events: none; }}
#graph-loading .gl-bar {{ height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; margin-bottom: 8px; }}
#graph-loading .gl-fill {{ height: 100%; width: 0; background: var(--accent); transition: width 0.15s; }}
#graph-sim {{ position: absolute; bottom: 10px; left: 160px; right: 205px; max-width: 560px; margin: 0 auto; background: rgba(10,15,30,0.95); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; z-index: 6; font-size: 0.75rem; }}
#graph-sim .gs-row {{ display: flex; align-items: center; gap: 8px; margin: 3px 0; }}
#graph-sim .gs-title {{ font-weight: 600; color: var(--text-dim); white-space: nowrap; font-size: 0.68rem; letter-spacing: 0.04em; }}
#graph-sim input[type=range] {{ flex: 1; accent-color: var(--success); }}
#graph-sim select {{ flex: 1; background: var(--surface-2); color: var(--text); border: 1px solid var(--border); border-radius: 4px; padding: 3px 6px; font-size: 0.72rem; }}
#gs-result {{ color: var(--text-dim); margin: 2px 0 4px; }}
#gs-result b {{ color: var(--success); }}
#graph-pathbar {{ position: absolute; top: 48px; left: 50%; transform: translateX(-50%); width: max-content; max-width: 44%; min-width: 240px; background: rgba(10,15,30,0.96); border: 1px solid var(--accent); border-radius: 8px; padding: 8px 12px; z-index: 12; font-size: 0.75rem; display: none; max-height: 240px; overflow-y: auto; }}
#graph-pathbar .pb-head {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 4px; font-weight: 600; }}
#graph-pathbar .pb-step {{ padding: 1px 0; color: var(--text); }}
#graph-pathbar .pb-edge {{ font-size: 0.68rem; padding: 0 5px; border-radius: 3px; background: var(--surface-2); margin: 0 4px; }}
.node-detail .btn-row {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; }}
.node-detail .member-list {{ max-height: 130px; overflow-y: auto; font-size: 0.72rem; color: var(--text-dim); margin-top: 6px; }}
#whatif-gauge {{ width: 160px; height: 160px; margin: 0 auto 8px; position: relative; }}
#whatif-gauge svg {{ width: 100%; height: 100%; }}
#whatif-gauge .label {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }}
#whatif-gauge .num {{ font-size: 2.8rem; font-weight: 800; transition: all 0.4s ease; }}
#whatif-gauge .grade {{ font-size: 1rem; color: var(--text-dim); }}

.whatif-layout {{ display: grid; grid-template-columns: 1fr 340px; gap: 16px; }}
.whatif-fixes {{ max-height: 600px; overflow-y: auto; }}
.whatif-fix {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; display: flex; align-items: center; gap: 14px; transition: all 0.2s; }}
.whatif-fix.applied {{ border-color: var(--success); background: rgba(34,197,94,0.06); }}
.whatif-fix .fix-info {{ flex: 1; }}
.whatif-fix .fix-label {{ font-weight: 600; font-size: 0.85rem; }}
.whatif-fix .fix-meta {{ color: var(--text-dim); font-size: 0.75rem; margin-top: 2px; }}
.whatif-fix .fix-impact {{ text-align: right; font-size: 0.8rem; }}
.whatif-fix .fix-impact .cut {{ font-size: 1.1rem; font-weight: 700; color: var(--success); }}

.toggle {{ position: relative; width: 42px; height: 22px; flex-shrink: 0; }}
.toggle input {{ opacity: 0; width: 0; height: 0; }}
.toggle .slider {{ position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: var(--border); border-radius: 11px; transition: 0.3s; }}
.toggle .slider:before {{ content: ''; position: absolute; height: 16px; width: 16px; left: 3px; bottom: 3px; background: var(--text-dim); border-radius: 50%; transition: 0.3s; }}
.toggle input:checked + .slider {{ background: var(--success); }}
.toggle input:checked + .slider:before {{ transform: translateX(20px); background: white; }}

.whatif-summary {{ position: sticky; top: 0; }}
.whatif-delta {{ display: flex; align-items: center; gap: 8px; margin: 12px 0; padding: 10px; background: var(--surface-2); border-radius: 8px; }}
.whatif-delta .arrow-down {{ color: var(--success); font-size: 1.3rem; font-weight: 700; }}
.whatif-delta .arrow-up {{ color: var(--danger); font-size: 1.3rem; font-weight: 700; }}
.whatif-delta .delta-text {{ font-size: 0.85rem; }}
.whatif-delta .delta-text strong {{ font-size: 1.1rem; }}

.whatif-bar {{ height: 20px; background: var(--border); border-radius: 10px; overflow: hidden; margin: 8px 0; position: relative; }}
.whatif-bar-fill {{ height: 100%; border-radius: 10px; transition: width 0.5s ease; }}
.whatif-bar-label {{ position: absolute; top: 50%; transform: translateY(-50%); font-size: 0.7rem; font-weight: 600; padding: 0 8px; }}

.whatif-btns {{ display: flex; gap: 6px; margin-bottom: 12px; }}

@media (max-width: 768px) {{
  .path-explorer {{ grid-template-columns: 1fr; }}
  .node-detail {{ width: calc(100% - 16px); }}
  .tab {{ padding: 8px 12px; font-size: 0.8rem; }}
  .whatif-layout {{ grid-template-columns: 1fr; }}
  #graph-sim {{ left: 10px; right: 10px; bottom: 140px; }}
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
    <div class="tab" data-tab="whatif">What If</div>
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

  <!-- WHAT IF -->
  <div id="whatif" class="tab-content">
    <div class="whatif-layout">
      <div>
        <div class="whatif-btns">
          <button class="btn btn-sm" onclick="whatifApplyAll()">Apply All</button>
          <button class="btn btn-sm btn-outline" onclick="whatifClearAll()">Clear All</button>
          <button class="btn btn-sm btn-outline" onclick="whatifApplyTopN(5)">Top 5</button>
          <button class="btn btn-sm btn-outline" onclick="whatifApplyTopN(10)">Top 10</button>
        </div>
        <div class="whatif-fixes" id="whatif-fixes"></div>
      </div>
      <div class="whatif-summary">
        <div class="card" style="text-align:center">
          <h3>Projected Risk Score</h3>
          <div id="whatif-gauge">
            <svg viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
              <circle cx="60" cy="60" r="52" fill="none" stroke="var(--text-dim)" stroke-width="8"
                stroke-dasharray="326.7" stroke-dashoffset="326.7" stroke-linecap="round"
                transform="rotate(-90 60 60)" id="whatif-arc"/>
            </svg>
            <div class="label">
              <div class="num" id="whatif-score">{score}</div>
              <div class="grade" id="whatif-grade">Grade {grade}</div>
            </div>
          </div>
          <div id="whatif-delta"></div>
        </div>
        <div class="card" style="margin-top:12px">
          <h3>Path Elimination</h3>
          <div class="whatif-bar">
            <div class="whatif-bar-fill" id="whatif-elim-bar" style="width:0%;background:var(--success)"></div>
          </div>
          <div style="display:flex;justify-content:space-between;font-size:0.8rem;color:var(--text-dim)">
            <span id="whatif-paths-cut">0 paths cut</span>
            <span id="whatif-paths-remain">{total_paths} remain</span>
          </div>
        </div>
        <div class="card" style="margin-top:12px">
          <h3>Exposure After Fixes</h3>
          <div class="whatif-bar">
            <div class="whatif-bar-fill" id="whatif-exposure-bar" style="width:{exposure_pct}%;background:var(--warning)"></div>
          </div>
          <div style="display:flex;justify-content:space-between;font-size:0.8rem;color:var(--text-dim)">
            <span id="whatif-exposure-pct">{exposure_pct}%</span>
            <span>of Tier 2 exposed</span>
          </div>
        </div>
        <div class="card" style="margin-top:12px">
          <h3>Fixes Applied</h3>
          <div style="display:flex;align-items:baseline;gap:6px">
            <span class="value" id="whatif-fix-count" style="font-size:2rem">0</span>
            <span style="color:var(--text-dim)">of {fix_count}</span>
          </div>
        </div>
      </div>
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
          <button class="btn btn-sm btn-outline" onclick="resetGraph()" title="Clear selection and fit to view">Fit</button>
          <button class="btn btn-sm btn-outline" onclick="toggleLabels()">Labels</button>
          <button class="btn btn-sm btn-outline" onclick="toggleEdgeLabels()">Edge Labels</button>
          <button class="btn btn-sm btn-outline" onclick="toggleStructural()" title="Hide MemberOf / Contains edges">Structural</button>
          <button class="btn btn-sm btn-outline" onclick="toggleEdgeFilter()">Filter</button>
          <button class="btn btn-sm btn-outline" onclick="toggleLayout()">Layout</button>
          <button class="btn btn-sm btn-outline" onclick="exportGraphPNG()">PNG</button>
        </div>
        <div id="edge-filter"></div>
        <div id="graph-legend">
          <div style="font-weight:600;margin-bottom:4px;color:var(--text-dim)">NODES</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="10" cy="7" r="4" fill="#3b82f6"/><path d="M3 18 Q3 12 10 12 Q17 12 17 18" fill="#3b82f6" opacity="0.5"/></svg></div> User</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><rect x="2" y="4" width="16" height="10" rx="1" fill="#10b981"/><rect x="7" y="14" width="6" height="2" fill="#10b981" opacity="0.6"/><rect x="5" y="16" width="10" height="1" rx="0.5" fill="#10b981" opacity="0.4"/></svg></div> Computer</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="7" cy="7" r="3" fill="#f59e0b"/><circle cx="13" cy="7" r="3" fill="#f59e0b"/><circle cx="10" cy="13" r="3" fill="#f59e0b"/></svg></div> Group</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="10" cy="10" r="8" fill="none" stroke="#ef4444" stroke-width="1.5"/><path d="M2 10 H18 M10 2 Q14 10 10 18 M10 2 Q6 10 10 18" fill="none" stroke="#ef4444" stroke-width="1" opacity="0.6"/></svg></div> Domain</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><rect x="3" y="2" width="14" height="16" rx="1.5" fill="none" stroke="#8b5cf6" stroke-width="1.5"/><line x1="6" y1="6" x2="14" y2="6" stroke="#8b5cf6" stroke-width="1" opacity="0.5"/><line x1="6" y1="9" x2="14" y2="9" stroke="#8b5cf6" stroke-width="1" opacity="0.5"/><line x1="6" y1="12" x2="14" y2="12" stroke="#8b5cf6" stroke-width="1" opacity="0.5"/></svg></div> GPO</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M10 2 L17 5 L17 11 Q17 16 10 18 Q3 16 3 11 L3 5 Z" fill="#ec4899"/></svg></div> CA / PKI / Entra role</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M10 2 L17 6 L17 14 L10 18 L3 14 L3 6 Z" fill="#a78bfa"/></svg></div> App / service principal / cloud resource</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M10 2 L18 10 L10 18 L2 10 Z" fill="none" stroke="#ef4444" stroke-width="2"/></svg></div> Tier 0</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="10" cy="10" r="7" fill="#64748b" fill-opacity="0.35" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="3 2"/></svg></div> Cluster (collapsed)</div>
          <div class="item"><div class="icon"><svg viewBox="0 0 20 20" width="16" height="16"><circle cx="10" cy="10" r="6" fill="none" stroke="#22c55e" stroke-width="2"/></svg></div> Secured by fixes</div>
        </div>
        <canvas id="graph-minimap" width="180" height="120"></canvas>
        <div id="graph-hud"></div>
        <div id="graph-loading"><div class="gl-bar"><div class="gl-fill" id="gl-fill"></div></div><div id="gl-text">Laying out graph...</div></div>
        <div id="graph-sim">
          <div class="gs-row"><span class="gs-title">SIMULATE FIXES</span>
            <input type="range" id="gs-slider" min="0" max="{fix_count}" value="0" step="1">
            <span id="gs-count">0 / {fix_count}</span></div>
          <div id="gs-result">Drag to apply top fixes and watch attack paths disappear.</div>
          <div class="gs-row"><select id="gs-locate"><option value="">Locate a fix on the graph...</option></select></div>
        </div>
        <div id="graph-pathbar"></div>
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
      tr.innerHTML = `<td><strong>${{r.name}}</strong></td><td>${{r.type}}</td><td><span class="tier-badge ${{tierClass}}">T${{r.tier}}</span></td><td><div style="display:flex;align-items:center;gap:8px"><div class="bar" style="width:60px"><div class="bar-fill" style="width:${{barW}}%;background:${{barW > 70 ? 'var(--danger)' : barW > 40 ? 'var(--warning)' : 'var(--accent)'}}"></div></div><strong>${{r.score}}</strong></div></td><td>${{r.path_count}}</td><td>${{r.blast_radius}}</td><td>${{r.tier0_reach}}</td><td><button class="btn btn-sm btn-outline">Paths</button></td>`;
      tr.querySelector('button').addEventListener('click', () => showNodePaths(r.id, r.name));
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

  // SVG path diagram
  const nodeW = 140, nodeH = 28, gapY = 48, padX = 40, padY = 20;
  const svgW = nodeW + padX * 2;
  const svgH = (p.steps.length + 1) * (nodeH + gapY) - gapY + padY * 2;
  html += `<svg width="100%" viewBox="0 0 ${{svgW}} ${{svgH}}" style="max-width:320px;display:block;margin:0 auto 16px">`;
  html += '<defs><marker id="path-arrow" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="#94a3b8"/></marker></defs>';

  const allNodes = [...p.steps.map(s => ({{name: s.from, edge: s.edge}})), {{name: p.target, edge: null}}];
  allNodes.forEach((n, i) => {{
    const cx = svgW / 2;
    const cy = padY + i * (nodeH + gapY) + nodeH / 2;
    const isTarget = i === allNodes.length - 1;
    const fill = isTarget ? 'rgba(239,68,68,0.15)' : 'rgba(59,130,246,0.1)';
    const stroke = isTarget ? '#ef4444' : '#3b82f6';
    const textColor = isTarget ? '#fca5a5' : '#e2e8f0';

    html += `<rect x="${{cx - nodeW/2}}" y="${{cy - nodeH/2}}" width="${{nodeW}}" height="${{nodeH}}" rx="6" fill="${{fill}}" stroke="${{stroke}}" stroke-width="1.5"/>`;
    const label = n.name.length > 18 ? n.name.substring(0, 16) + '..' : n.name;
    html += `<text x="${{cx}}" y="${{cy}}" text-anchor="middle" dominant-baseline="central" fill="${{textColor}}" font-size="11" font-weight="600">${{label}}</text>`;

    if (i < allNodes.length - 1) {{
      const y1 = cy + nodeH / 2;
      const y2 = cy + nodeH / 2 + gapY;
      const edgeColor = getEdgeColor(n.edge);
      html += `<line x1="${{cx}}" y1="${{y1 + 2}}" x2="${{cx}}" y2="${{y2 - nodeH/2 - 4}}" stroke="${{edgeColor}}" stroke-width="2" marker-end="url(#path-arrow)"/>`;
      html += `<text x="${{cx + 8}}" y="${{(y1 + y2 - nodeH/2) / 2}}" fill="${{edgeColor}}" font-size="9" font-weight="600" dominant-baseline="central">${{n.edge}}</text>`;
    }}
  }});
  html += '</svg>';

  // Text step list
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

{graph_js}

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

// ---- WHAT IF SIMULATOR ----
const WHATIF_ORIGINAL_SCORE = {score};
const WHATIF_TOTAL_PATHS = {total_paths};
const WHATIF_EXPOSURE_PCT = {exposure_pct};
const WHATIF_CIRCUMFERENCE = 2 * Math.PI * 52;

function whatifGradeFromScore(s) {{
  if (s <= 20) return 'A';
  if (s <= 40) return 'B';
  if (s <= 60) return 'C';
  if (s <= 80) return 'D';
  return 'F';
}}

function whatifGradeColor(g) {{
  return {{'A':'#22c55e','B':'#86efac','C':'#eab308','D':'#f97316','F':'#ef4444'}}[g] || '#94a3b8';
}}

function renderWhatIf() {{
  const container = document.getElementById('whatif-fixes');
  container.innerHTML = '';
  fixesData.forEach((f, i) => {{
    const div = document.createElement('div');
    div.className = 'whatif-fix';
    div.id = 'whatif-fix-' + i;
    const safety = f.safety || 'safe';
    const safetyLabel = {{safe:'OK',caution:'WARN',dangerous:'RISK'}}[safety] || safety;
    div.innerHTML = `<label class="toggle"><input type="checkbox" data-fix-idx="${{i}}" onchange="whatifUpdate()"><span class="slider"></span></label><div class="fix-info"><div class="fix-label">#${{f.rank}} ${{f.description}}</div><div class="fix-meta">${{f.edge_type}} <span class="safety-badge safety-${{safety}}" style="margin-left:4px">${{safetyLabel}}</span></div></div><div class="fix-impact"><div class="cut">-${{f.paths_eliminated}}</div><div style="color:var(--text-dim);font-size:0.72rem">paths</div></div>`;
    container.appendChild(div);
  }});
}}

function whatifUpdate() {{
  const checks = document.querySelectorAll('#whatif-fixes input[type="checkbox"]');
  let appliedCount = 0;
  let totalEliminated = 0;

  checks.forEach((cb, i) => {{
    const card = document.getElementById('whatif-fix-' + i);
    if (cb.checked) {{
      appliedCount++;
      card.classList.add('applied');
    }} else {{
      card.classList.remove('applied');
    }}
  }});

  // Use greedy ordering: when fixes 1..N are all checked, use cumulative_pct from fix N
  // For sparse selections, sum individual paths_eliminated (capped at total)
  let lastConsecutive = -1;
  for (let i = 0; i < checks.length; i++) {{
    if (checks[i].checked) lastConsecutive = i;
    else break;
  }}

  if (lastConsecutive >= 0 && appliedCount === lastConsecutive + 1) {{
    // All checked fixes are the top-N consecutive ones - use exact cumulative
    totalEliminated = Math.round(fixesData[lastConsecutive].cumulative_pct / 100 * WHATIF_TOTAL_PATHS);
  }} else {{
    // Sparse selection - sum individual (may overcount due to overlap, but reasonable estimate)
    checks.forEach((cb, i) => {{
      if (cb.checked) totalEliminated += fixesData[i].paths_eliminated;
    }});
    totalEliminated = Math.min(totalEliminated, WHATIF_TOTAL_PATHS);
  }}

  const pathsRemain = WHATIF_TOTAL_PATHS - totalEliminated;
  const elimPct = WHATIF_TOTAL_PATHS > 0 ? (totalEliminated / WHATIF_TOTAL_PATHS * 100) : 0;

  // Project score: scale linearly by path reduction
  const reductionFactor = WHATIF_TOTAL_PATHS > 0 ? pathsRemain / WHATIF_TOTAL_PATHS : 1;
  const projScore = Math.max(0, Math.round(WHATIF_ORIGINAL_SCORE * reductionFactor));
  const projGrade = whatifGradeFromScore(projScore);
  const projColor = whatifGradeColor(projGrade);

  // Update gauge
  const arc = document.getElementById('whatif-arc');
  arc.setAttribute('stroke-dashoffset', WHATIF_CIRCUMFERENCE * (1 - projScore / 100));
  arc.setAttribute('stroke', projColor);

  const scoreEl = document.getElementById('whatif-score');
  scoreEl.textContent = projScore;
  scoreEl.style.color = projColor;
  document.getElementById('whatif-grade').textContent = 'Grade ' + projGrade;

  // Delta
  const delta = WHATIF_ORIGINAL_SCORE - projScore;
  const deltaEl = document.getElementById('whatif-delta');
  if (delta > 0) {{
    deltaEl.innerHTML = `<div class="whatif-delta"><span class="arrow-down">&#9660;</span><div class="delta-text"><strong>-${{delta}} points</strong> from baseline ${{WHATIF_ORIGINAL_SCORE}}</div></div>`;
  }} else if (delta === 0) {{
    deltaEl.innerHTML = `<div class="whatif-delta" style="opacity:0.5"><div class="delta-text">No change from baseline</div></div>`;
  }} else {{
    deltaEl.innerHTML = `<div class="whatif-delta"><span class="arrow-up">&#9650;</span><div class="delta-text"><strong>+${{Math.abs(delta)}} points</strong> above baseline</div></div>`;
  }}

  // Path elimination bar
  document.getElementById('whatif-elim-bar').style.width = elimPct + '%';
  document.getElementById('whatif-paths-cut').textContent = totalEliminated + ' paths cut';
  document.getElementById('whatif-paths-remain').textContent = pathsRemain + ' remain';

  // Exposure projection
  const projExposure = Math.max(0, WHATIF_EXPOSURE_PCT * reductionFactor);
  document.getElementById('whatif-exposure-bar').style.width = projExposure.toFixed(1) + '%';
  document.getElementById('whatif-exposure-pct').textContent = projExposure.toFixed(1) + '%';

  // Fix count
  document.getElementById('whatif-fix-count').textContent = appliedCount;
  const appliedSet = new Set();
  checks.forEach((cb, i) => {{ if (cb.checked) appliedSet.add(i); }});
  if (window.graphSetApplied) graphSetApplied(appliedSet);
}}

function whatifApplyAll() {{
  document.querySelectorAll('#whatif-fixes input[type="checkbox"]').forEach(cb => cb.checked = true);
  whatifUpdate();
}}

function whatifClearAll() {{
  document.querySelectorAll('#whatif-fixes input[type="checkbox"]').forEach(cb => cb.checked = false);
  whatifUpdate();
}}

function whatifApplyTopN(n) {{
  const checks = document.querySelectorAll('#whatif-fixes input[type="checkbox"]');
  checks.forEach((cb, i) => cb.checked = i < n);
  whatifUpdate();
}}

// Init What If when tab is first shown
renderWhatIf();

// ---- KEYBOARD SHORTCUTS ----
const TAB_ORDER = ['overview','risks','fixes','chains','defend','whatif','paths','graph'];
document.addEventListener('keydown', (e) => {{
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
  const tabs = document.querySelectorAll('.tab');
  const activeTab = document.querySelector('.tab.active');
  const activeId = activeTab ? activeTab.dataset.tab : 'overview';
  const idx = TAB_ORDER.indexOf(activeId);

  if (e.key === 'ArrowRight' || e.key === 'l') {{
    const next = TAB_ORDER[(idx + 1) % TAB_ORDER.length];
    document.querySelector(`[data-tab="${{next}}"]`).click();
    e.preventDefault();
  }} else if (e.key === 'ArrowLeft' || e.key === 'h') {{
    const prev = TAB_ORDER[(idx - 1 + TAB_ORDER.length) % TAB_ORDER.length];
    document.querySelector(`[data-tab="${{prev}}"]`).click();
    e.preventDefault();
  }} else if (e.key === '/' || (e.key === 'f' && !e.ctrlKey && !e.metaKey)) {{
    const searchBoxes = {{'risks': 'risk-search', 'paths': 'path-search', 'defend': 'defend-search', 'graph': 'graph-search-input'}};
    const box = searchBoxes[activeId];
    if (box) {{ document.getElementById(box).focus(); e.preventDefault(); }}
  }} else if (e.key === 'Escape') {{
    document.activeElement.blur();
  }} else if (e.key >= '1' && e.key <= '8') {{
    const tabIdx = parseInt(e.key) - 1;
    if (tabIdx < TAB_ORDER.length) {{
      document.querySelector(`[data-tab="${{TAB_ORDER[tabIdx]}}"]`).click();
      e.preventDefault();
    }}
  }} else if (e.key === '?') {{
    showToast('Keys: 1-8 tabs | Left/Right navigate | / search | Esc blur');
  }}
}});
</script>
</body>
</html>'''
