"""Path finding algorithms - BFS, shortest paths, all paths, reachability, blast radius."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

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
    "ReadLAPSPassword", "ReadGMSAPassword", "TrustedBy",
})


def find_all_paths(graph: AttackGraph, targets: set[str],
                   max_depth: int = 20, max_paths: int = 10000) -> PathReport:
    """Find all attack paths from any non-Tier-0 node to any target.

    Uses reverse BFS from targets to avoid exploring the entire graph from every source.
    Caps at max_paths to prevent combinatorial explosion.
    """
    paths = []
    sources = set()

    for target_id in targets:
        found = _bfs_paths_to(graph, target_id, max_depth, max_paths - len(paths))
        for p in found:
            paths.append(p)
            sources.add(p.source)
            if len(paths) >= max_paths:
                break
        if len(paths) >= max_paths:
            break

    return PathReport(paths=paths, source_nodes=sources, target_nodes=targets)


def _bfs_paths_to(graph: AttackGraph, target_id: str, max_depth: int,
                  max_paths: int) -> list[AttackPath]:
    """BFS from target backwards to find all paths reaching it."""
    paths = []
    # (current_node, path_nodes_reversed, path_edges_reversed, visited)
    queue: deque[tuple[str, list[str], list[dict], frozenset[str]]] = deque()
    queue.append((target_id, [target_id], [], frozenset({target_id})))

    while queue and len(paths) < max_paths:
        current, path_nodes, path_edges, visited = queue.popleft()

        if len(path_nodes) - 1 >= max_depth:
            continue

        # Check predecessors
        for source_id in graph.predecessors(current):
            if source_id in visited:
                continue

            edge_data_list = graph.get_edge_data(source_id, current)
            for edge_data in edge_data_list:
                edge_type = edge_data.get("edge_type", "")

                new_nodes = [source_id] + path_nodes
                new_edges = [edge_data] + path_edges
                new_visited = visited | {source_id}

                source_node = graph.get_node(source_id)

                # If source is not Tier 0 and has at least one attack edge in path, it's a valid path start
                has_attack_edge = any(e.get("edge_type") in _ATTACK_EDGES for e in new_edges)
                is_non_t0 = source_node is not None and source_node.tier != 0

                if has_attack_edge and is_non_t0:
                    weight = sum(e.get("weight", 1.0) for e in new_edges)
                    paths.append(AttackPath(nodes=new_nodes, edges=new_edges, total_weight=weight))
                    if len(paths) >= max_paths:
                        return paths

                # Keep searching deeper if within depth limit
                if len(new_nodes) - 1 < max_depth:
                    queue.append((source_id, new_nodes, new_edges, new_visited))

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
    visited = set()
    queue = deque([(node_id, 0)])

    while queue:
        current, depth = queue.popleft()
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        for succ in graph.successors(current):
            if succ not in visited:
                queue.append((succ, depth + 1))

    visited.discard(node_id)
    return visited


def reachable_tier0(graph: AttackGraph, node_id: str, max_depth: int = 20) -> set[str]:
    """Which Tier 0 nodes are reachable from this node?"""
    reachable = reachable_from(graph, node_id, max_depth)
    return reachable & graph.tier0_nodes


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
