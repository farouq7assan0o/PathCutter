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

Reachability uses walks rather than simple paths; the two only differ in rare
cyclic cases where the single attack edge sits inside a cycle.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .graph import AttackGraph
from .pathfinder import _ATTACK_EDGES

State = tuple[str, bool]


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

    def exposed(self) -> set[str]:
        return {n for (n, flag) in self.dist if flag and n not in self.tier0}

    def hops(self, node_id: str) -> int | None:
        return self.dist.get((node_id, True))

    def path(self, node_id: str) -> list[PathStep]:
        """Shortest attack path from node_id to Tier 0 (empty if not exposed)."""
        state: State = (node_id, True)
        if state not in self.dist:
            return []
        steps: list[PathStep] = []
        guard = 0
        while state in self.nxt and guard < 200:
            nxt_state, edge_type = self.nxt[state]
            steps.append(PathStep(state[0], edge_type))
            state = nxt_state
            guard += 1
        steps.append(PathStep(state[0], None))
        return steps


def compute_exposure(graph: AttackGraph) -> Exposure:
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
    return result
