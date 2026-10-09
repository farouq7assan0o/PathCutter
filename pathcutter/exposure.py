"""Exact attack-path reachability to Tier 0, on an integer-indexed graph.

This is the production engine. `exposure_ref.py` keeps the original dictionary-based implementation as an executable
specification: the two are fuzzed against each other (tests/test_engine_equivalence.py), so the fast version can keep
changing without anyone having to re-derive what "correct" means.

Semantics (unchanged): a principal is *exposed* when some route to Tier 0 contains at least one genuine attack edge.
The search is a reverse breadth-first search over (node, has_attack_edge) states, so hop counts are minimal and no
paths are enumerated. It runs over walks, which is exact whenever the shortest route is a simple path; a node whose
shortest route revisits a node is re-checked with an exact bounded search (a gate prefers a flagged maybe to a silent
miss). Only nodes whose route touches a node that is reachable in BOTH states can possibly repeat, so only those are
re-checked: that keeps the exact check off the hot path.

Deny ACEs are identity-sensitive and use the product search in exposure_ref.py.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from .exposure_ref import PathStep, VERIFY_BUDGET, VERIFY_MAX_DEPTH, _simple_attack_path  # noqa: F401
from .graph import AttackGraph
from .pathfinder import _ATTACK_EDGES

__all__ = ["Exposure", "PathStep", "compute_exposure"]


@dataclass
class Exposure:
    """Result of one reverse search over a graph."""
    fx: object = None                                   # FastIndex the arrays refer to
    dist: list = field(default_factory=list)            # state (2*node + flag) -> hops, -1 = unreachable
    nxt: list = field(default_factory=list)             # state -> successor state toward Tier 0
    nxt_et: list = field(default_factory=list)          # state -> edge type of that hop
    tier0: frozenset = frozenset()
    removed: set = field(default_factory=set)           # walk-only: no real simple path exists
    override: dict = field(default_factory=dict)        # verified simple paths (node id -> steps)
    unverified: set = field(default_factory=set)        # kept, but the exact check hit its budget
    _exposed: set | None = None
    _kids: tuple | None = None                          # (first_child, next_sibling): the reverse of `nxt`, built on demand
    # --- a fork is a base result plus a sparse overlay of the states that an added edge improved
    base: "Exposure | None" = None
    over: dict = field(default_factory=dict)            # state -> (dist, successor state, edge type)

    def _d(self, s: int) -> int:
        o = self.over.get(s)
        if o is not None:
            return o[0]
        b = self.base if self.base is not None else self
        return b.dist[s] if s < len(b.dist) else -1

    def _walk_exposed(self) -> set[str]:
        """Nodes with a route containing an attack edge by WALK (before the simple-path verdicts are applied)."""
        if self._exposed is None:
            ids, dist, t0 = self.fx.ids, self.dist, self.tier0
            self._exposed = {ids[i] for i in range(len(dist) // 2) if dist[2 * i + 1] >= 0 and ids[i] not in t0}
        return self._exposed

    def exposed(self) -> set[str]:
        if self.base is not None:
            ids, t0 = self.fx.ids, self.tier0
            out = set(self.base._walk_exposed())
            for s, (d, _, _) in self.over.items():
                if s & 1 and ids[s >> 1] not in t0:
                    (out.add if d >= 0 else out.discard)(ids[s >> 1])
            return out - self.removed
        return self._walk_exposed() - self.removed

    def hops(self, node_id: str) -> int | None:
        if node_id in self.removed:
            return None
        if node_id in self.override:
            return len(self.override[node_id]) - 1
        i = self.fx.pos.get(node_id)
        if i is None:
            return None
        d = self._d(2 * i + 1)
        return d if d >= 0 else None

    def path(self, node_id: str) -> list[PathStep]:
        """Shortest attack path from node_id to Tier 0 (empty if not exposed)."""
        if node_id in self.removed:
            return []
        if node_id in self.override:
            return list(self.override[node_id])
        return self._walk_path(node_id)

    def _walk_path(self, node_id: str) -> list[PathStep]:
        i = self.fx.pos.get(node_id)
        if i is None or self._d(2 * i + 1) < 0:
            return []
        ids = self.fx.ids
        b = self.base if self.base is not None else self
        s = 2 * i + 1
        steps: list[PathStep] = []
        guard = 0
        while guard < 400:
            o = self.over.get(s)
            if o is not None:
                nx_s, et = o[1], o[2]
            elif s < len(b.nxt):
                nx_s, et = b.nxt[s], b.nxt_et[s]
            else:
                break
            if nx_s < 0:
                break
            steps.append(PathStep(ids[s >> 1], et))
            s = nx_s
            guard += 1
        steps.append(PathStep(ids[s >> 1], None))
        return steps


def compute_exposure(graph: AttackGraph, verify: bool = True):
    if graph.denies:
        from . import exposure_ref
        return exposure_ref.compute_exposure(graph, verify)
    fx = graph.fast()
    n = len(fx.ids)
    tier0 = frozenset(graph.tier0_nodes)
    result = Exposure(fx=fx, tier0=tier0)
    pos, rev = fx.pos, fx.rev
    dist = [-1] * (2 * n)
    nxt = [-1] * (2 * n)
    nxt_et: list = [None] * (2 * n)
    is_t0 = bytearray(n)
    queue: list[int] = []
    for t in tier0:
        i = pos.get(t)
        if i is not None:
            is_t0[i] = 1
            dist[2 * i] = 0
            queue.append(2 * i)
    attack = _ATTACK_EDGES
    head = 0
    while head < len(queue):
        s = queue[head]
        head += 1
        d = dist[s] + 1
        flag = s & 1
        for u, et in rev[s >> 1]:
            if is_t0[u]:
                continue
            ns = 2 * u + (1 if (flag or et in attack) else 0)
            if dist[ns] < 0:
                dist[ns] = d
                nxt[ns] = s
                nxt_et[ns] = et
                queue.append(ns)
    result.dist, result.nxt, result.nxt_et = dist, nxt, nxt_et
    if verify:
        _verify_cyclic(graph, result, queue)
    return result


def fork_with_added_edges(base: Exposure, graph: AttackGraph, edges: list[tuple[str, str, str]]) -> Exposure:
    """Exposure after ADDING edges, derived from `base` without recomputing it.

    `graph` must already contain the edges (and have the same Tier 0 set as `base`). Adding an edge can only shorten
    or create routes, so a decrease-only relaxation seeded at the new edges finds every changed state; the result is
    a sparse overlay on `base`. Equivalent to compute_exposure(graph) (fuzzed in tests/test_engine_equivalence.py).
    """
    fx = graph.fast()
    pos, rev = fx.pos, fx.rev
    fork = Exposure(fx=fx, tier0=base.tier0, base=base.base or base)
    is_t0 = lambda i: fx.ids[i] in base.tier0           # noqa: E731
    attack = _ATTACK_EDGES
    over = fork.over
    heap: list[tuple[int, int]] = []

    def improve(s: int, d: int, succ: int, et: str) -> None:
        cur = fork._d(s)
        if cur < 0 or d < cur:
            over[s] = (d, succ, et)
            heapq.heappush(heap, (d, s))

    for u, v, et in edges:
        iu, iv = pos.get(u), pos.get(v)
        if iu is None or iv is None or fx.ids[iu] in base.tier0:
            continue
        for f in (0, 1):
            sv = 2 * iv + f
            dv = fork._d(sv)
            if dv >= 0:
                improve(2 * iu + (1 if (f or et in attack) else 0), dv + 1, sv, et)
    while heap:
        d, s = heapq.heappop(heap)
        if fork._d(s) != d:
            continue
        flag = s & 1
        for u, et in rev[s >> 1]:
            if fx.ids[u] in base.tier0:
                continue
            improve(2 * u + (1 if (flag or et in attack) else 0), d + 1, s, et)
    # Cycle check. A node needs a fresh verdict if its route changed, OR if it already needed the exact check in the
    # base (removed / override / unverified): adding an edge can turn a walk-only route into a real one without
    # changing the walk at all. Everything else keeps its verified base answer.
    changed = {s >> 1 for s in over if s & 1}
    special = set(base.removed) | set(base.override) | set(base.unverified)
    recheck = changed | {fx.pos[n] for n in special if n in fx.pos}
    fork.removed = {n for n in base.removed if fx.pos.get(n) not in recheck}
    fork.override = {n: p for n, p in base.override.items() if fx.pos.get(n) not in recheck}
    fork.unverified = {n for n in base.unverified if fx.pos.get(n) not in recheck}
    for i in recheck:
        node = fx.ids[i]
        if node in base.tier0 or fork._d(2 * i + 1) < 0:
            continue
        steps = fork._walk_path(node)
        if len({st.node_id for st in steps}) == len(steps):
            continue
        found, exhausted = _simple_attack_path(graph, node, base.tier0, len(steps) - 1)
        if found:
            fork.override[node] = found
        elif exhausted:
            fork.unverified.add(node)
        else:
            fork.removed.add(node)
    return fork


def _children(base: Exposure) -> tuple[list[int], list[int]]:
    """first_child / next_sibling arrays of the shortest-route forest (state -> states whose route goes through it)."""
    if base._kids is None:
        n = len(base.nxt)
        first, sib = [-1] * n, [-1] * n
        for s in range(n):
            p = base.nxt[s]
            if p >= 0:
                sib[s] = first[p]
                first[p] = s
        base._kids = (first, sib)
    return base._kids


def fork_with_removed_edges(base: Exposure, graph: AttackGraph, edges: list[tuple[str, str, str]]) -> Exposure:
    """Exposure after REMOVING edges, derived from `base` (decremental single-source-style update).

    Only states whose shortest route used a removed edge, and the states routed through them, can change. They are marked
    unreachable, then re-attached from their surviving out-edges by a Dijkstra restricted to that affected set. `graph`
    must already have the edges removed and the same Tier 0 set as `base`. Equivalent to compute_exposure(graph).
    """
    fx = graph.fast()
    root = base.base or base
    pos = fx.pos
    fork = Exposure(fx=fx, tier0=base.tier0, base=root)
    ids, t0 = fx.ids, base.tier0
    attack = _ATTACK_EDGES
    first, sib = _children(root)
    n_base = len(root.nxt)
    gone = {(pos[u], pos[v], et) for u, v, et in edges if u in pos and v in pos}
    seeds = []
    for iu, iv, et in gone:
        for f in (0, 1):
            s = 2 * iu + f
            if s < n_base:
                p = root.nxt[s]
                if p >= 0 and (p >> 1) == iv and root.nxt_et[s] == et:
                    seeds.append(s)
    affected: set[int] = set()
    stack = list(seeds)
    while stack:
        s = stack.pop()
        if s in affected:
            continue
        affected.add(s)
        c = first[s]
        while c >= 0:
            stack.append(c)
            c = sib[c]
    over = fork.over
    for s in affected:
        over[s] = (-1, -1, None)
    heap: list = []
    g = graph.graph
    for s in affected:
        u, flag = s >> 1, s & 1
        best = None
        for _, vid, et in g.out_edges(ids[u], data="edge_type"):
            iv = pos.get(vid)
            if iv is None:
                continue
            for gflag in (0, 1):
                if (1 if (gflag or et in attack) else 0) != flag:
                    continue
                t = 2 * iv + gflag
                if t in affected or t >= n_base:
                    continue
                dt = root.dist[t]
                if dt >= 0 and (best is None or dt + 1 < best[0]):
                    best = (dt + 1, t, et)
        if best:
            heapq.heappush(heap, (best[0], s, best[1], best[2]))
    while heap:
        d, s, t, et = heapq.heappop(heap)
        if over[s][0] >= 0:
            continue
        over[s] = (d, t, et)
        flag = s & 1
        for u, et2 in fx.rev[s >> 1]:
            if ids[u] in t0:
                continue
            ns = 2 * u + (1 if (flag or et2 in attack) else 0)
            if ns in affected and over[ns][0] < 0:
                heapq.heappush(heap, (d + 1, ns, s, et2))
    # states that stayed unreachable are simply marked -1 in the overlay; now the simple-path verdicts
    changed = {s >> 1 for s in over if s & 1}
    special = set(root.removed) | set(root.override) | set(root.unverified)
    recheck = changed | {pos[x] for x in special if x in pos}
    fork.removed = {x for x in root.removed if pos.get(x) not in recheck}
    fork.override = {x: p for x, p in root.override.items() if pos.get(x) not in recheck}
    fork.unverified = {x for x in root.unverified if pos.get(x) not in recheck}
    for i in recheck:
        node = ids[i]
        if node in t0 or fork._d(2 * i + 1) < 0:
            continue
        steps = fork._walk_path(node)
        if len({st.node_id for st in steps}) == len(steps):
            continue
        found, exhausted = _simple_attack_path(graph, node, t0, len(steps) - 1)
        if found:
            fork.override[node] = found
        elif exhausted:
            fork.unverified.add(node)
        else:
            fork.removed.add(node)
    return fork


def shortened_nodes(base: Exposure, new: Exposure, exposed_base: set, exposed_new: set) -> set:
    """Nodes exposed in both whose route got shorter. For a fork only the changed states can differ."""
    nb = getattr(new, "base", None)
    if nb is not None and (nb is base or nb is getattr(base, "base", None)):
        ids = new.fx.ids
        cand = {ids[s >> 1] for s in new.over if s & 1} & exposed_base & exposed_new
    else:
        cand = exposed_new & exposed_base
    out = set()
    for n in cand:
        a, b = new.hops(n), base.hops(n)
        if a is not None and b is not None and a < b:
            out.add(n)
    return out


def _verify_cyclic(graph: AttackGraph, result: Exposure, order: list[int]) -> None:
    """Re-check nodes whose shortest walk might revisit a node.

    A walk can only repeat a node if that node is reachable in both states (it appears once before and once after the
    last attack edge). `touch[s]` marks states whose route passes through such a node; every other route is
    provably simple and is never walked.
    """
    dist, nxt = result.dist, result.nxt
    n = len(result.fx.ids)
    both = bytearray(n)
    any_both = False
    for i in range(n):
        if dist[2 * i] >= 0 and dist[2 * i + 1] >= 0:
            both[i] = 1
            any_both = True
    if not any_both:
        return
    touch = bytearray(2 * n)
    for s in order:                                   # BFS order: a state's successor is always earlier
        p = nxt[s]
        touch[s] = 1 if (both[s >> 1] or (p >= 0 and touch[p])) else 0
    ids = result.fx.ids
    t0 = result.tier0
    for i in range(n):
        s = 2 * i + 1
        if dist[s] < 0 or ids[i] in t0 or not touch[s]:
            continue
        steps = result._walk_path(ids[i])
        if len({st.node_id for st in steps}) == len(steps):
            continue                                   # the shortest route is already a simple path
        found, exhausted = _simple_attack_path(graph, ids[i], result.tier0, len(steps) - 1)
        if found:
            result.override[ids[i]] = found
        elif exhausted:
            result.unverified.add(ids[i])
        else:
            result.removed.add(ids[i])
