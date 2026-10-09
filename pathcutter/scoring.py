"""Risk scoring - quantifies risk per node and overall AD posture."""
from __future__ import annotations

from dataclasses import dataclass
from math import log2

from .graph import AttackGraph, NodeType
from .pathfinder import PathReport, reachable_from, reachable_tier0


@dataclass
class NodeRisk:
    """Risk assessment for a single AD node."""
    node_id: str
    name: str
    node_type: str
    tier: int
    path_count: int  # how many paths to Tier 0 start from or traverse this node
    centrality: float  # fraction of all paths that traverse this node
    blast_radius: int  # how many nodes are reachable from this node
    tier0_reach: int  # how many Tier 0 nodes are reachable
    risk_score: float  # composite 0-100

    @property
    def display_name(self) -> str:
        if "@" in self.name:
            return self.name.split("@")[0]
        return self.name


@dataclass
class PostureScore:
    """Overall AD security posture."""
    score: int  # 0-100, higher = more risk
    grade: str  # A-F
    total_paths: int
    unique_sources: int
    avg_path_length: float
    tier0_count: int
    tier2_with_path_count: int
    tier2_total: int
    path_density: float  # paths per non-T0 node

    @property
    def exposure_pct(self) -> float:
        """Percentage of Tier 2 nodes that can reach Tier 0."""
        if self.tier2_total == 0:
            return 0.0
        return self.tier2_with_path_count / self.tier2_total * 100


def score_nodes(graph: AttackGraph, path_report: PathReport) -> list[NodeRisk]:
    """Score every node by its role in attack paths."""
    total_paths = path_report.total_paths
    if total_paths == 0:
        return []

    # Count paths through each node
    node_path_counts: dict[str, int] = {}
    for path in path_report.paths:
        for node_id in path.nodes:
            node_path_counts[node_id] = node_path_counts.get(node_id, 0) + 1

    # Pre-compute blast radius and T0 reach only for top-N candidates by path count,
    # since BFS per node is expensive on large graphs.
    sorted_by_count = sorted(
        ((nid, cnt) for nid, cnt in node_path_counts.items()
         if graph.get_node(nid) is not None and graph.get_node(nid).tier != 0),
        key=lambda x: x[1],
        reverse=True,
    )

    # Only compute expensive BFS for top 100 nodes; rest get estimated values
    FULL_ANALYSIS_CAP = 100
    blast_cache: dict[str, int] = {}
    t0_cache: dict[str, int] = {}

    for i, (node_id, _) in enumerate(sorted_by_count[:FULL_ANALYSIS_CAP]):
        reach = reachable_from(graph, node_id, max_depth=6)         # once: the Tier 0 reach is a subset of it
        blast_cache[node_id] = len(reach)
        t0_cache[node_id] = len(reach & graph.tier0_nodes)

    results = []
    for node_id, count in sorted_by_count:
        node = graph.get_node(node_id)
        centrality = count / total_paths

        blast = blast_cache.get(node_id, min(count, 50))
        t0_reach = t0_cache.get(node_id, 1 if count > 0 else 0)

        path_factor = min(log2(count + 1) / 10.0, 1.0) * 40
        centrality_factor = centrality * 30
        blast_factor = min(blast / 50.0, 1.0) * 15
        t0_factor = min(t0_reach / 3.0, 1.0) * 15

        risk_score = path_factor + centrality_factor + blast_factor + t0_factor
        risk_score = min(risk_score, 100.0)

        results.append(NodeRisk(
            node_id=node_id,
            name=node.name,
            node_type=node.node_type.value,
            tier=node.tier,
            path_count=count,
            centrality=centrality,
            blast_radius=blast,
            tier0_reach=t0_reach,
            risk_score=round(risk_score, 1),
        ))

    return sorted(results, key=lambda r: r.risk_score, reverse=True)


def score_posture(graph: AttackGraph, path_report: PathReport) -> PostureScore:
    """Compute overall AD security posture score (0-100, higher = worse)."""
    tier0_count = len(graph.tier0_nodes)
    tier2_nodes = [n for n in graph.all_nodes() if n.tier == 2]
    tier2_total = len(tier2_nodes)

    # Count how many T2 nodes appear as sources in paths
    tier2_with_path = sum(1 for n in tier2_nodes if n.object_id in path_report.source_nodes)

    total_paths = path_report.total_paths
    non_t0 = graph.node_count - tier0_count
    path_density = total_paths / non_t0 if non_t0 > 0 else 0.0

    # Score components (all 0-1, weighted):
    # 1. Exposure: what % of T2 can reach T0? (40%)
    exposure = tier2_with_path / tier2_total if tier2_total > 0 else 0.0
    # 2. Path density: how many paths per node? (25%)
    density = min(path_density / 10.0, 1.0)
    # 3. Path shortness: shorter avg path = easier attacks (20%)
    avg_len = path_report.avg_length
    shortness = max(0, 1.0 - (avg_len - 1) / 10.0) if avg_len > 0 else 0.0
    # 4. Scale: raw path count (log-scaled) (15%)
    scale = min(log2(total_paths + 1) / 15.0, 1.0) if total_paths > 0 else 0.0

    raw_score = (exposure * 40 + density * 25 + shortness * 20 + scale * 15)
    score = min(int(round(raw_score)), 100)

    if score <= 20:
        grade = "A"
    elif score <= 40:
        grade = "B"
    elif score <= 60:
        grade = "C"
    elif score <= 80:
        grade = "D"
    else:
        grade = "F"

    return PostureScore(
        score=score,
        grade=grade,
        total_paths=total_paths,
        unique_sources=path_report.unique_sources,
        avg_path_length=round(path_report.avg_length, 1),
        tier0_count=tier0_count,
        tier2_with_path_count=tier2_with_path,
        tier2_total=tier2_total,
        path_density=round(path_density, 2),
    )
