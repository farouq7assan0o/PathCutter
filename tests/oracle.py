"""Independent brute-force reference implementation used to check the production engine.

Deliberately shares no code with pathcutter.exposure: it enumerates SIMPLE paths with a plain DFS.
For each non-Tier-0 node it returns the minimum hop count of a simple path to a Tier 0 node that
contains at least one attack edge, or omits the node when none exists.
"""
from __future__ import annotations

from pathcutter.pathfinder import _ATTACK_EDGES


def oracle_hops(graph, max_depth: int = 14) -> dict[str, int]:
    t0 = set(graph.tier0_nodes)
    g = graph.graph
    best: dict[str, int] = {}

    def dfs(start: str, node: str, seen: set, depth: int, attack: bool) -> None:
        if depth >= max_depth:
            return
        for _, nxt, data in g.out_edges(node, data=True):
            if nxt in seen:
                continue
            is_attack = attack or data.get("edge_type") in _ATTACK_EDGES
            if nxt in t0:
                if is_attack and depth + 1 < best.get(start, 10 ** 9):
                    best[start] = depth + 1
                continue                      # a path ends where it first reaches Tier 0
            seen.add(nxt)
            dfs(start, nxt, seen, depth + 1, is_attack)
            seen.discard(nxt)

    for n in list(g.nodes):
        if n in t0:
            continue
        dfs(n, n, {n}, 0, False)
    return best
