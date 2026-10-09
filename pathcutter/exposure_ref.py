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

Deny ACEs are identity-sensitive: a deny on (principal P, right R, object O) stops every identity in P's token from
using R on O, whichever allow would have granted it, while everyone else keeps the right. When the graph carries
effective denies the search runs over (node, has_attack_edge, deny-signature) where the signature is the set of
denies binding the identity that most recently *landed* (the start, or the target of any non-MemberOf hop).
Group membership keeps the identity; every other hop re-computes it. Without denies nothing changes.
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
    denial: "DenyContext | None" = None                        # set when Deny ACEs shaped this result
    pnxt: dict = field(default_factory=dict)                   # product-search parent pointers (with denies)

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
        if self.denial is not None:
            pstate = (node_id, True, self.denial.sig(node_id))
            if pstate not in self.pnxt:
                return []
            steps_p: list[PathStep] = []
            guard = 0
            while pstate in self.pnxt and guard < 400:
                nxt_p, edge_type = self.pnxt[pstate]
                steps_p.append(PathStep(pstate[0], edge_type))
                pstate = nxt_p
                guard += 1
            steps_p.append(PathStep(pstate[0], None))
            return steps_p
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


class DenyContext:
    """Per-graph lookup tables for identity-sensitive denies."""

    def __init__(self, graph: AttackGraph):
        entries = graph.deny_actor_sets()
        self.entries = entries
        self.guard: dict[tuple[str, str], frozenset[int]] = {}      # (target, edge type) -> deny indices guarding it
        sig: dict[str, set[int]] = {}
        for i, (d, actors) in enumerate(entries):
            self.guard[(d.target_id, d.edge_type)] = self.guard.get((d.target_id, d.edge_type), frozenset()) | {i}
            for a in actors:
                sig.setdefault(a, set()).add(i)
        self.sig_of: dict[str, frozenset[int]] = {n: frozenset(s) for n, s in sig.items()}
        self.universe: set[frozenset[int]] = {frozenset()} | set(self.sig_of.values())

    def blocked(self, sig: frozenset, target: str, edge_type: str) -> bool:
        g = self.guard.get((target, edge_type))
        return bool(g and (sig & g))

    def sig(self, node: str) -> frozenset:
        return self.sig_of.get(node, frozenset())


def compute_exposure(graph: AttackGraph, verify: bool = True) -> Exposure:
    tier0 = frozenset(graph.tier0_nodes)
    result = Exposure(tier0=tier0)
    if graph.denies:
        ctx = DenyContext(graph)
        if ctx.entries:
            return _compute_with_denies(graph, result, ctx, verify)
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


def _compute_with_denies(graph: AttackGraph, result: Exposure, ctx: DenyContext, verify: bool) -> Exposure:
    result.denial = ctx
    g = graph.graph
    tier0 = result.tier0
    pdist: dict[tuple, int] = {}
    queue: deque = deque()
    for t in tier0:
        if t in g:
            for s in ctx.universe:
                pdist[(t, False, s)] = 0
                queue.append((t, False, s))
    pnxt = result.pnxt
    while queue:
        state = queue.popleft()
        v, flag, s_v = state
        d = pdist[state]
        for u, _, data in g.in_edges(v, data=True):
            if u in tier0:
                continue
            et = data.get("edge_type", "")
            if et == "MemberOf":                       # same identity, one group up
                cands = [((u, flag, s_v), et)]
            else:                                      # a landing: the identity becomes v, so s_v must be v's own signature
                if s_v != ctx.sig(v):
                    continue
                nflag = flag or et in _ATTACK_EDGES
                cands = [((u, nflag, s), et) for s in ctx.universe if not ctx.blocked(s, v, et)]
            for ns, e in cands:
                if ns in pdist:
                    continue
                pdist[ns] = d + 1
                pnxt[ns] = (state, e)
                queue.append(ns)
    for (n, flag, s), dist_v in pdist.items():
        if s == ctx.sig(n) and n not in tier0:
            result.dist[(n, flag)] = dist_v
    for t in tier0:
        if t in g:
            result.dist[(t, False)] = 0
    if verify:
        _verify_cyclic(graph, result)
    return result


def _verify_cyclic(graph: AttackGraph, result: Exposure) -> None:
    for n in sorted(result.exposed()):
        steps = result._walk_path(n)
        if len({s.node_id for s in steps}) == len(steps):
            continue                                   # the shortest route is already a simple path
        found, exhausted = _simple_attack_path(graph, n, result.tier0, len(steps) - 1, result.denial)
        if found:
            result.override[n] = found
        elif exhausted:
            result.unverified.add(n)
        else:
            result.removed.add(n)


def _simple_attack_path(graph: AttackGraph, start: str, tier0: frozenset[str], min_len: int,
                        denial: DenyContext | None = None) -> tuple[list[PathStep] | None, bool]:
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

    def dfs(node: str, limit: int, trail: list[PathStep], seen: set[str], attack: bool,
            sig: frozenset = frozenset()) -> list[PathStep] | None:
        if budget[0] <= 0:
            return None
        for v, et in out(node):
            if v in seen:
                continue
            if denial is not None:
                if et != "MemberOf" and denial.blocked(sig, v, et):
                    continue
                nsig = sig if et == "MemberOf" else denial.sig(v)
            else:
                nsig = sig
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
            found = dfs(v, limit, trail + [step], seen, is_attack, nsig)
            seen.discard(v)
            if found:
                return found
            if budget[0] <= 0:
                return None
        return None

    for limit in range(max(1, min_len), VERIFY_MAX_DEPTH + 1):
        found = dfs(start, limit, [], {start}, False, denial.sig(start) if denial else frozenset())
        if found:
            return found, False
        if budget[0] <= 0:
            return None, True
    return None, False
