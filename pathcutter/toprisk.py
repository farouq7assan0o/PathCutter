"""Two derived views that turn the existing graph into the sharpest questions a defender can ask.

protect_leaderboard - work the attacker's economics in reverse: which ordinary principals, if phished or compromised,
put the most Tier 0 within reach. It ranks the non-Tier-0 actors by how many Tier 0 objects they can reach, so a team
has a short, proactive "protect these first" list instead of a flat finding dump.

blind_spots - the single truest top risk is a path you can NEITHER cut with your prioritised fixes NOR see with your
telemetry. We already compute the minimum fix set (choke) and per-path detection coverage separately; the intersection -
paths that survive the recommended fixes and are blind - is the set nobody is addressing and nobody would notice being
used. (coverage.py's own docstring calls this out; this module surfaces it.)
"""
from __future__ import annotations

_ACTOR_TYPES = {"User", "Computer", "AZUser", "AZServicePrincipal"}


def protect_leaderboard(node_scores, top: int = 10) -> list[dict]:
    """From scored nodes, the non-Tier-0 actors whose compromise reaches the most Tier 0, highest first.

    Reuses scoring.score_nodes (no extra traversal): tier0_reach is how many Tier 0 objects the node can reach."""
    cand = [ns for ns in node_scores if ns.tier != 0 and ns.node_type in _ACTOR_TYPES and ns.tier0_reach > 0]
    cand.sort(key=lambda ns: (-ns.tier0_reach, -ns.path_count, -ns.risk_score, ns.display_name.lower()))
    return [{"name": ns.display_name, "type": ns.node_type, "tier": ns.tier, "tier0_reach": ns.tier0_reach,
             "paths": ns.path_count, "risk": ns.risk_score} for ns in cand[:top]]


def blind_spots(graph, path_report, choke_fixes, coverage_status) -> dict:
    """Paths that survive the prioritised fixes AND are blind (no detection). coverage_status is the per-path status list
    aligned to path_report.paths (as `_coverage_summary` builds it); it may be shorter than the full path list (capped)."""
    fix_edges = {(f.source_id, f.target_id, f.edge_type) for f in (choke_fixes or [])}

    def nm(nid):
        node = graph.get_node(nid)
        return node.display_name if node is not None else nid

    groups: dict[tuple, int] = {}
    n = 0
    considered = min(len(path_report.paths), len(coverage_status or []))
    for i in range(considered):
        if coverage_status[i] != "blind":
            continue
        p = path_report.paths[i]
        cut = any((p.nodes[j], p.nodes[j + 1], e.get("edge_type")) in fix_edges for j, e in enumerate(p.edges))
        if cut:
            continue
        n += 1
        key = (nm(p.source), nm(p.target), " > ".join(p.edge_types))
        groups[key] = groups.get(key, 0) + 1
    return {
        "count": n,
        "assessed": considered,
        "capped": len(path_report.paths) > len(coverage_status or []),
        "groups": [{"source": s, "target": t, "edges": e, "times": k} for (s, t, e), k in
                   sorted(groups.items(), key=lambda kv: -kv[1])[:10]],
    }
