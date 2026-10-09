"""Exact attack-path reachability to Tier 0.

Path *enumeration* (pathfinder.py) is capped for speed, so its path counts are
estimates on big graphs. A change gate cannot afford estimates for the question
"can this principal now reach Tier 0?", so this module answers that exactly with a
reverse breadth-first search that never enumerates paths.

State is (node, has_attack_edge). A principal is *exposed* when the state
(node, True) is reachable: some route to Tier 0 contains at least one genuine
attack edge (not just MemberOf/Contains plumbing), which matches how
pathfinder.find_all_paths defines an attack path. BFS order also gives the
minimum hop count for free, and the parent pointers rebuild a concrete shortest
attack path for any exposed principal.

The search runs over walks, which is exact whenever the shortest route is a simple
path (always true on acyclic graphs). When the shortest route revisits a node
(a cycle that only "helps" by looping back on itself) the node is re-checked with
an exact bounded search for a real simple path: if none exists the node is dropped,
if the search budget runs out it is kept and listed in `unverified` (a gate should
prefer a flagged maybe over a silent miss).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .graph import AttackGraph
from .pathfinder import _ATTACK_EDGES

State = tuple[str, bool]
VERIFY_MAX_DEPTH = 14
VERIFY_BUDGET = 60000          # node expansions per suspicious node


@dataclass
class PathStep:
    node_id: str
    edge_type: str | None = None   # edge from this node to the next; None on the last node


@dataclass
class Exposure:
    """Result of one reverse search over a graph."""
    dist: dict[State, int] = field(default_factory=dict)
    nxt: dict[State, tuple[State, str]] = field(default_factory=dict)
    tier0: frozenset[str] = frozenset()
    removed: set[str] = field(default_factory=set)             # walk-only: no real simple path exists
    override: dict[str, list[PathStep]] = field(default_factory=dict)   # verified simple paths
    unverified: set[str] = field(default_factory=set)          # kept, but the exact check hit its budget

    def exposed(self) -> set[str]:
        return {n for (n, flag) in self.dist if flag and n not in self.tier0 and n not in self.removed}

    def hops(self, node_id: str) -> int | None:
        if node_id in self.removed:
            return None
        if node_id in self.override:
            return len(self.override[node_id]) - 1
        return self.dist.get((node_id, True))

    def path(self, node_id: str) -> list[PathStep]:
        """Shortest attack path from node_id to Tier 0 (empty if not exposed)."""
        if node_id in self.removed:
            return []
        if node_id in self.override:
            return list(self.override[node_id])
        return self._walk_path(node_id)

    def _walk_path(self, node_id: str) -> list[PathStep]:
        state: State = (node_id, True)
        if state not in self.dist:
            return []
        steps: list[PathStep] = []
        guard = 0
        while state in self.nxt and guard < 400:
            nxt_state, edge_type = self.nxt[state]
            steps.append(PathStep(state[0], edge_type))
            state = nxt_state
            guard += 1
        steps.append(PathStep(state[0], None))
        return steps


def compute_exposure(graph: AttackGraph, verify: bool = True) -> Exposure:
    tier0 = frozenset(graph.tier0_nodes)
    result = Exposure(tier0=tier0)
    dist, nxt = result.dist, result.nxt
    queue: deque[State] = deque()
    for t in tier0:
        if t in graph.graph:
            dist[(t, False)] = 0
            queue.append((t, False))

    g = graph.graph
    while queue:
        state = queue.popleft()
        v, flag = state
        d = dist[state]
        for u, _, data in g.in_edges(v, data=True):
            if u in tier0:
                continue          # already Tier 0; no need to route through it
            et = data.get("edge_type", "")
            nflag = flag or et in _ATTACK_EDGES
            ns = (u, nflag)
            if ns in dist:
                continue
            dist[ns] = d + 1
            nxt[ns] = (state, et)
            queue.append(ns)
    if verify:
        _verify_cyclic(graph, result)
    return result


def _verify_cyclic(graph: AttackGraph, result: Exposure) -> None:
    for n in sorted(result.exposed()):
        steps = result._walk_path(n)
        if len({s.node_id for s in steps}) == len(steps):
            continue                                   # the shortest route is already a simple path
        found, exhausted = _simple_attack_path(graph, n, result.tier0, len(steps) - 1)
        if found:
            result.override[n] = found
        elif exhausted:
            result.unverified.add(n)
        else:
            result.removed.add(n)


def _simple_attack_path(graph: AttackGraph, start: str, tier0: frozenset[str], min_len: int
                        ) -> tuple[list[PathStep] | None, bool]:
    """Shortest SIMPLE path from start to Tier 0 containing an attack edge, by iterative deepening.

    Returns (steps | None, budget_exhausted).
    """
    g = graph.graph
    budget = [VERIFY_BUDGET]
    out_cache: dict[str, list[tuple[str, str]]] = {}

    def out(node: str) -> list[tuple[str, str]]:
        if node not in out_cache:
            seen, lst = set(), []
            for _, v, data in g.out_edges(node, data=True):
                et = data.get("edge_type", "")
                if (v, et) not in seen:
                    seen.add((v, et))
                    lst.append((v, et))
            out_cache[node] = lst
        return out_cache[node]

    def dfs(node: str, limit: int, trail: list[PathStep], seen: set[str], attack: bool) -> list[PathStep] | None:
        if budget[0] <= 0:
            return None
        for v, et in out(node):
            if v in seen:
                continue
            budget[0] -= 1
            is_attack = attack or et in _ATTACK_EDGES
            step = PathStep(node, et)
            if v in tier0:
                if is_attack and len(trail) + 1 == limit:
                    return trail + [step, PathStep(v, None)]
                continue
            if len(trail) + 1 >= limit:
                continue
            seen.add(v)
            found = dfs(v, limit, trail + [step], seen, is_attack)
            seen.discard(v)
            if found:
                return found
            if budget[0] <= 0:
                return None
        return None

    for limit in range(max(1, min_len), VERIFY_MAX_DEPTH + 1):
        found = dfs(start, limit, [], {start}, False)
        if found:
            return found, False
        if budget[0] <= 0:
            return None, True
    return None, False
