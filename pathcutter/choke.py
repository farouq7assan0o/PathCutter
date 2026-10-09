"""Chokepoint analysis - find the minimum set of fixes that eliminate the most attack paths.

This is the core value proposition: given 300 attack paths, which 5 fixes kill 80% of them?
Uses a greedy set cover approach: iteratively pick the fix that eliminates the most remaining paths.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .graph import AttackGraph
from .pathfinder import PathReport, AttackPath
from .edges import get_edge_type


@dataclass
class Fix:
    """A single remediation action."""
    source_id: str
    target_id: str
    edge_type: str
    source_name: str
    target_name: str
    paths_eliminated: int
    cumulative_eliminated: int
    cumulative_pct: float  # percentage of total paths eliminated so far
    fix_command: str
    mitre: str
    rank: int  # 1 = highest priority

    @property
    def description(self) -> str:
        et = self.edge_type
        if et.startswith("ADCSESC"):                         # derived from template / CA settings: nothing to "remove"
            return f"Close AD CS {et[4:]} for {self.source_name} (fix the template or CA setting, or restrict who can enroll)"
        if et == "GoldenCert":
            return f"Treat {self.source_name} (it holds a CA key) as Tier 0: remove non-admin local administrators"
        if et == "SyncedTo":
            return f"Stop synchronizing {self.target_name} from on-premises (keep privileged cloud accounts cloud-only)"
        if et in ("AZMGGrantRole", "AZMGAddSecret", "AZMGAddMember", "AZMGResetPassword"):
            return f"Remove the dangerous Microsoft Graph permission from {self.source_name}"
        return f"Remove {et} from {self.source_name} to {self.target_name}"


@dataclass
class ChokeReport:
    """Result of chokepoint analysis."""
    fixes: list[Fix]
    total_paths: int
    paths_after_fixes: int

    @property
    def total_eliminated(self) -> int:
        return self.total_paths - self.paths_after_fixes

    @property
    def elimination_pct(self) -> float:
        if self.total_paths == 0:
            return 0.0
        return self.total_eliminated / self.total_paths * 100

    def top(self, n: int) -> list[Fix]:
        return self.fixes[:n]

    def fixes_for_pct(self, target_pct: float) -> list[Fix]:
        """Return the minimum fixes needed to eliminate target_pct% of paths."""
        result = []
        for fix in self.fixes:
            result.append(fix)
            if fix.cumulative_pct >= target_pct:
                break
        return result


def _edge_key(source_id: str, target_id: str, edge_type: str) -> tuple[str, str, str]:
    return (source_id, target_id, edge_type)


def find_chokepoints(graph: AttackGraph, path_report: PathReport,
                     max_fixes: int = 50, prefer_safe: bool = True,
                     exclude_edges: set[tuple[str, str, str]] | None = None) -> ChokeReport:
    """Greedy set cover: iteratively find the edge whose removal eliminates the most remaining paths.

    For each remaining path, identify which edges are "cuttable" (attack edges, not MemberOf/Contains).
    Pick the edge that appears in the most paths. Remove those paths. Repeat.

    When prefer_safe is True and two edges eliminate the same number of paths,
    prefer the one targeting a non-service-account source (safer to fix).
    exclude_edges are (source, target, edge_type) keys that must not be proposed as fixes.
    """
    if not path_report.paths:
        return ChokeReport(fixes=[], total_paths=0, paths_after_fixes=0)

    # Non-cuttable edges (structural, not attack)
    STRUCTURAL = frozenset({"MemberOf", "Contains"})

    # Service account prefixes for safety tie-breaking
    SVC_PREFIXES = ("SVC_", "SA_", "MSOL_", "EXCHANGE", "SCCM", "KRBTGT")

    # Build edge -> set of path indices
    edge_to_paths: dict[tuple, set[int]] = {}
    for i, path in enumerate(path_report.paths):
        for j, edge_data in enumerate(path.edges):
            et = edge_data.get("edge_type", "")
            if et in STRUCTURAL:
                continue
            key = _edge_key(path.nodes[j], path.nodes[j + 1], et)
            if exclude_edges and key in exclude_edges:
                continue
            edge_to_paths.setdefault(key, set()).add(i)

    remaining_paths = set(range(len(path_report.paths)))
    total_paths = len(path_report.paths)
    fixes = []
    cumulative = 0

    def _safety_score(edge_key: tuple) -> int:
        """Lower = safer to fix. Used for tie-breaking when two edges eliminate equal paths."""
        src_id = edge_key[0]
        src = graph.get_node(src_id)
        if not src:
            return 0
        score = 0
        name_upper = src.name.upper().split("@")[0]
        if any(name_upper.startswith(p) for p in SVC_PREFIXES):
            score += 2
        if not src.enabled:
            score -= 1
        if src.admin_count:
            score += 1
        return score

    for rank in range(1, max_fixes + 1):
        if not remaining_paths:
            break

        # Find edge that eliminates the most remaining paths
        best_edge = None
        best_count = 0
        best_safety = 999
        best_eliminated = set()

        for key, path_indices in edge_to_paths.items():
            active = path_indices & remaining_paths
            count = len(active)
            if count > best_count:
                best_edge = key
                best_count = count
                best_eliminated = active
                best_safety = _safety_score(key) if prefer_safe else 0
            elif count == best_count and count > 0 and prefer_safe:
                s = _safety_score(key)
                if s < best_safety:
                    best_edge = key
                    best_eliminated = active
                    best_safety = s

        if best_edge is None or not best_eliminated:
            break

        source_id, target_id, edge_type = best_edge
        remaining_paths -= best_eliminated
        cumulative += len(best_eliminated)

        # Generate fix command
        et_info = get_edge_type(edge_type)
        fix_cmd = ""
        mitre = ""
        if et_info:
            fix_cmd = et_info.fix_template.format(
                source_name=graph.get_node_name(source_id),
                target_name=graph.get_node_name(target_id),
                target_dn=graph.get_node_name(target_id),
                source_dn=graph.get_node_name(source_id),
                domain=_extract_domain(graph.get_node_name(target_id)),
                target_spn="",
                gpo_dn=graph.get_node_name(target_id),
            )
            mitre = et_info.mitre

        fixes.append(Fix(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            source_name=graph.get_node_name(source_id),
            target_name=graph.get_node_name(target_id),
            paths_eliminated=len(best_eliminated),
            cumulative_eliminated=cumulative,
            cumulative_pct=round(cumulative / total_paths * 100, 1),
            fix_command=fix_cmd,
            mitre=mitre,
            rank=rank,
        ))

    return ChokeReport(
        fixes=fixes,
        total_paths=total_paths,
        paths_after_fixes=len(remaining_paths),
    )


def _extract_domain(name: str) -> str:
    if "@" in name:
        return name.split("@")[-1]
    return ""


def find_node_chokepoints(graph: AttackGraph, path_report: PathReport,
                          max_nodes: int = 20) -> list[dict]:
    """Find nodes whose compromise enables the most paths (not edge removal, but node removal).

    Useful for identifying which accounts to monitor or restrict, rather than ACL fixes.
    """
    if not path_report.paths:
        return []

    STRUCTURAL = frozenset({"MemberOf", "Contains"})
    node_to_paths: dict[str, set[int]] = {}

    for i, path in enumerate(path_report.paths):
        # Skip source and target, count intermediate nodes
        for node_id in path.nodes[1:-1]:
            node_to_paths.setdefault(node_id, set()).add(i)

    results = []
    for node_id, path_indices in sorted(node_to_paths.items(),
                                         key=lambda x: len(x[1]), reverse=True)[:max_nodes]:
        node = graph.get_node(node_id)
        results.append({
            "node_id": node_id,
            "name": node.name if node else node_id,
            "type": node.node_type.value if node else "Unknown",
            "tier": node.tier if node else 2,
            "paths_through": len(path_indices),
            "pct_of_total": round(len(path_indices) / len(path_report.paths) * 100, 1),
        })

    return results
