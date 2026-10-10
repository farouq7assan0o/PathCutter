"""Path finding algorithms - BFS, shortest paths, all paths, reachability, blast radius.

Performance notes for large graphs (50k+ nodes):
- Reverse BFS from targets avoids exploring the full graph from every source
- Adjacency pre-computation (predecessors dict) avoids repeated NetworkX lookups
- Visited sets use frozenset for immutable sharing between queue entries
- Path cap prevents combinatorial explosion
- Scoring uses lazy blast radius with configurable depth cap
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .edges import NON_TRAVERSABLE
from .graph import AttackGraph


@dataclass
class AttackPath:
    """A single attack path from source to target."""
    nodes: list[str]
    edges: list[dict]  # edge data for each hop
    total_weight: float = 0.0

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def source(self) -> str:
        return self.nodes[0]

    @property
    def target(self) -> str:
        return self.nodes[-1]

    @property
    def edge_types(self) -> list[str]:
        return [e.get("edge_type", "?") for e in self.edges]

    def involves_node(self, node_id: str) -> bool:
        return node_id in self.nodes

    def involves_edge(self, source_id: str, target_id: str, edge_type: str) -> bool:
        for i, e in enumerate(self.edges):
            if (self.nodes[i] == source_id and self.nodes[i + 1] == target_id
                    and e.get("edge_type") == edge_type):
                return True
        return False


@dataclass
class PathReport:
    """Collection of attack paths with summary statistics."""
    paths: list[AttackPath]
    source_nodes: set[str] = field(default_factory=set)
    target_nodes: set[str] = field(default_factory=set)

    @property
    def total_paths(self) -> int:
        return len(self.paths)

    @property
    def unique_sources(self) -> int:
        return len(self.source_nodes)

    @property
    def shortest_length(self) -> int:
        if not self.paths:
            return 0
        return min(p.length for p in self.paths)

    @property
    def longest_length(self) -> int:
        if not self.paths:
            return 0
        return max(p.length for p in self.paths)

    @property
    def avg_length(self) -> float:
        if not self.paths:
            return 0.0
        return sum(p.length for p in self.paths) / len(self.paths)

    def paths_through_node(self, node_id: str) -> list[AttackPath]:
        return [p for p in self.paths if p.involves_node(node_id)]

    def paths_through_edge(self, source_id: str, target_id: str, edge_type: str) -> list[AttackPath]:
        return [p for p in self.paths if p.involves_edge(source_id, target_id, edge_type)]


# Non-exploitable edges that are traversed for inheritance but don't count as "attack steps"
_STRUCTURAL_EDGES = frozenset({"MemberOf", "Contains"})

# Edges that represent actual attack capabilities
_ATTACK_EDGES = frozenset({
    "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", "ForceChangePassword",
    "AddMember", "Owns", "WriteSPN", "AddAllowedToAct", "WriteKeyCredentialLink",
    "AllowedToDelegate", "AllowedToAct", "AdminTo", "HasSession", "CanRDP",
    "CanPSRemote", "ExecuteDCOM", "SQLAdmin", "DCSync", "GPOControlsObject",
    "ReadLAPSPassword", "ReadGMSAPassword", "TrustedBy", "HasSIDHistory", "WriteGPLink", "ADCSAbuse", "ADCSESC1", "ADCSESC4", "ADCSESC6", "ADCSESC7", "ADCSESC3", "ADCSESC5", "GoldenCert", "ADCSESC9", "ADCSESC15", "ADCSESC13", "ADCSESC10", "ADCSESC8", "CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP", "GPOUserRight", "ADCSESC16", "ADCSESC11", "AZMGAddMember", "AZMGResetPassword",
    "AZOwner", "AZContributor", "AZUserAccessAdmin", "AZVMAdminLogin", "AZManagedIdentity",
    "AZMGGrantRole", "AZMGAddSecret",
    "AZOwns", "AZRunsAs", "AZEligibleRole", "AZResetPassword", "AZAddSecret", "SyncedTo",
})


def find_all_paths(graph: AttackGraph, targets: set[str],
                   max_depth: int = 20, max_paths: int = 10000) -> PathReport:
    """Find all attack paths from any non-Tier-0 node to any target.

    Uses reverse BFS from targets to avoid exploring the entire graph from every source.
    Caps at max_paths to prevent combinatorial explosion.

    Performance: pre-computes predecessor adjacency and edge data lookups to avoid
    repeated NetworkX dict access in the inner loop.
    """
    # Pre-compute predecessor adjacency for all nodes in the graph.
    # This turns O(dict_lookup) per predecessor() call into a single dict read,
    # which matters when the queue processes millions of entries.
    pred_cache: dict[str, list[tuple[str, list[dict]]]] = {}

    def _get_preds(node_id: str) -> list[tuple[str, list[dict]]]:
        if node_id not in pred_cache:
            preds = []
            for src in graph.predecessors(node_id):
                edges = [e for e in (graph.get_edge_data(src, node_id) or []) if e.get("edge_type") not in NON_TRAVERSABLE]
                if edges:
                    preds.append((src, edges))
            pred_cache[node_id] = preds
        return pred_cache[node_id]

    paths: list[AttackPath] = []
    sources: set[str] = set()

    for target_id in targets:
        found = _bfs_paths_to(graph, target_id, max_depth, max_paths - len(paths), _get_preds, targets)
        for p in found:
            paths.append(p)
            sources.add(p.source)
            if len(paths) >= max_paths:
                break
        if len(paths) >= max_paths:
            break

    return PathReport(paths=paths, source_nodes=sources, target_nodes=targets)


def _bfs_paths_to(graph: AttackGraph, target_id: str, max_depth: int,
                  max_paths: int,
                  get_preds, targets: frozenset | set = frozenset()) -> list[AttackPath]:
    """BFS from target backwards to find all paths reaching it.

    Optimizations vs naive BFS:
    - Pre-computed predecessor lookup (get_preds) avoids repeated NetworkX access
    - has_attack_edge tracked incrementally (bool flag) instead of scanning all edges
    - Weight accumulated incrementally instead of summing at path creation
    """
    paths: list[AttackPath] = []
    # (current_node, path_nodes, path_edges, visited, has_attack_edge, cumulative_weight)
    queue: deque[tuple[str, list[str], list[dict], frozenset[str], bool, float]] = deque()
    queue.append((target_id, [target_id], [], frozenset({target_id}), False, 0.0))

    while queue and len(paths) < max_paths:
        current, path_nodes, path_edges, visited, has_attack, cum_weight = queue.popleft()

        if len(path_nodes) - 1 >= max_depth:
            continue

        for source_id, edge_data_list in get_preds(current):
            if source_id in visited:
                continue

            for edge_data in edge_data_list:
                edge_type = edge_data.get("edge_type", "")
                edge_weight = edge_data.get("weight", 1.0)

                new_nodes = [source_id] + path_nodes
                new_edges = [edge_data] + path_edges
                new_visited = visited | {source_id}
                new_has_attack = has_attack or edge_type in _ATTACK_EDGES
                new_weight = cum_weight + edge_weight

                source_node = graph.get_node(source_id)
                is_non_t0 = source_node is not None and source_node.tier != 0

                if new_has_attack and is_non_t0:
                    paths.append(AttackPath(nodes=new_nodes, edges=new_edges, total_weight=new_weight))
                    if len(paths) >= max_paths:
                        return paths

                # a route that already passed through another target has arrived: nothing before that matters
                if len(new_nodes) - 1 < max_depth and source_id not in targets:
                    queue.append((source_id, new_nodes, new_edges, new_visited, new_has_attack, new_weight))

    return paths


def shortest_path(graph: AttackGraph, source_id: str, target_id: str) -> AttackPath | None:
    """Find the shortest (lowest weight) attack path from source to target."""
    import networkx as nx
    try:
        node_path = nx.shortest_path(graph.graph, source_id, target_id, weight="weight")
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None

    edges = []
    total_weight = 0.0
    for i in range(len(node_path) - 1):
        edge_data_list = graph.get_edge_data(node_path[i], node_path[i + 1])
        if not edge_data_list:
            return None
        # Pick the edge with lowest weight (most exploitable)
        best = min(edge_data_list, key=lambda e: e.get("weight", 100.0))
        edges.append(best)
        total_weight += best.get("weight", 1.0)

    return AttackPath(nodes=node_path, edges=edges, total_weight=total_weight)


def shortest_paths_to_targets(graph: AttackGraph, source_id: str,
                               targets: set[str]) -> list[AttackPath]:
    """Find shortest paths from a single source to all reachable targets."""
    results = []
    for target_id in targets:
        path = shortest_path(graph, source_id, target_id)
        if path:
            results.append(path)
    return sorted(results, key=lambda p: p.total_weight)


def reachable_from(graph: AttackGraph, node_id: str, max_depth: int = 20) -> set[str]:
    """Blast radius: all nodes reachable from this node (BFS, follows all edge types)."""
    adj = graph.graph._succ                      # the adjacency dict itself: no per-node list copies on a 190k-edge graph
    if node_id not in adj:
        return set()
    visited = {node_id}
    frontier = [node_id]
    for _ in range(max_depth):
        nxt = []
        for cur in frontier:
            for succ in adj[cur]:
                if succ not in visited:
                    visited.add(succ)
                    nxt.append(succ)
        if not nxt:
            break
        frontier = nxt
    visited.discard(node_id)
    return visited


def reachable_tier0(graph: AttackGraph, node_id: str, max_depth: int = 20) -> set[str]:
    """Which Tier 0 nodes are reachable from this node?"""
    return reachable_from(graph, node_id, max_depth) & graph.tier0_nodes


def nodes_reaching_targets(graph: AttackGraph, targets: set[str],
                            max_depth: int = 20) -> set[str]:
    """Reverse reachability: which nodes can reach any target (backwards BFS)?"""
    visited = set()
    queue = deque([(t, 0) for t in targets])

    while queue:
        current, depth = queue.popleft()
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        for pred in graph.predecessors(current):
            if pred not in visited:
                queue.append((pred, depth + 1))

    visited -= targets
    return visited
