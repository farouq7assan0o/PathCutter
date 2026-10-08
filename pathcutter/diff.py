"""Posture drift analysis - compare two SharpHound snapshots to verify remediation."""
from __future__ import annotations

from dataclasses import dataclass, field

from .graph import AttackGraph
from .pathfinder import PathReport, find_all_paths
from .scoring import score_posture, PostureScore


@dataclass
class DiffResult:
    """Comparison between two AD snapshots."""
    before: PostureScore
    after: PostureScore
    paths_before: int
    paths_after: int
    paths_eliminated: int
    new_paths: int
    score_delta: int
    grade_before: str
    grade_after: str
    eliminated_edges: list[dict] = field(default_factory=list)
    new_edges: list[dict] = field(default_factory=list)

    @property
    def improved(self) -> bool:
        return self.score_delta < 0

    @property
    def summary(self) -> str:
        direction = "improved" if self.improved else "worsened"
        return (
            f"Score {direction}: {self.before.score} -> {self.after.score} "
            f"(Grade {self.grade_before} -> {self.grade_after}) | "
            f"Paths: {self.paths_before} -> {self.paths_after} "
            f"(-{self.paths_eliminated}, +{self.new_paths})"
        )


def compare_snapshots(graph_before: AttackGraph, graph_after: AttackGraph,
                      max_depth: int = 20, max_paths: int = 10000) -> DiffResult:
    """Compare two SharpHound snapshots and report posture drift."""
    targets_before = graph_before.tier0_nodes
    targets_after = graph_after.tier0_nodes

    report_before = find_all_paths(graph_before, targets_before, max_depth, max_paths)
    report_after = find_all_paths(graph_after, targets_after, max_depth, max_paths)

    posture_before = score_posture(graph_before, report_before)
    posture_after = score_posture(graph_after, report_after)

    edges_before = _path_edge_set(report_before)
    edges_after = _path_edge_set(report_after)

    eliminated = edges_before - edges_after
    new = edges_after - edges_before

    return DiffResult(
        before=posture_before,
        after=posture_after,
        paths_before=report_before.total_paths,
        paths_after=report_after.total_paths,
        paths_eliminated=max(0, report_before.total_paths - report_after.total_paths),
        new_paths=max(0, report_after.total_paths - report_before.total_paths),
        score_delta=posture_after.score - posture_before.score,
        grade_before=posture_before.grade,
        grade_after=posture_after.grade,
        eliminated_edges=[{"source": e[0], "target": e[1], "type": e[2]} for e in eliminated],
        new_edges=[{"source": e[0], "target": e[1], "type": e[2]} for e in new],
    )


def _path_edge_set(report: PathReport) -> set[tuple[str, str, str]]:
    """Extract unique (source, target, edge_type) tuples from all paths."""
    edges = set()
    for path in report.paths:
        for i, edge in enumerate(path.edges):
            edges.add((path.nodes[i], path.nodes[i + 1], edge.get("edge_type", "")))
    return edges
