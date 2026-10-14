"""Assume breach: if this host or this credential leaks, what can the attacker reach, and by the cheapest and quietest route?

Every other PathCutter view starts from Tier 0 and works outward. This one starts from a single object the defender names -
a laptop, a service account, a contractor - and asks the question an incident responder asks first: *given that this is
owned, how far does it go?* It reports the blast radius (everything reachable), which Tier 0 objects fall, and for each one
the route an attacker would actually prefer: the cheapest (least work) and the stealthiest (least likely to be seen), scored
by cost.py. Cross-plane hops (on-premises into the cloud, or the reverse) are flagged because they usually cross a team
boundary too.

It walks forward from the chosen start over attack edges (structural MemberOf / Contains hops are free and do not count as
steps), stopping each route at the first Tier 0 object it reaches. The search is bounded by depth and a path cap; when the cap
is hit the result is a lower bound and says so.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from . import cost as costmod
from .edges import NON_TRAVERSABLE
from .graph import AttackGraph, NodeType
from .pathfinder import reachable_from

ACTOR_TYPES = {NodeType.USER.value, NodeType.COMPUTER.value, NodeType.AZ_USER.value, NodeType.AZ_SP.value}
_STRUCTURAL = frozenset({"MemberOf", "Contains", "AZContains"})
_ATTACK = None  # imported lazily to avoid a cycle with pathfinder


def _attack_edges() -> frozenset:
    global _ATTACK
    if _ATTACK is None:
        from .pathfinder import _ATTACK_EDGES
        _ATTACK = _ATTACK_EDGES
    return _ATTACK


def resolve_principals(graph: AttackGraph, query: str) -> tuple[list[str], list[dict]]:
    """Resolve a user-supplied id or name to object ids. Returns (ids, candidates) where candidates
    describe every match for an ambiguous query so the caller can report them."""
    q = query.strip()
    if graph.get_node(q) is not None:
        return [q], []
    ql = q.lower()
    exact, sub = [], []
    for n in graph.all_nodes():
        name = n.name.lower()
        disp = n.display_name.lower()
        if ql in (name, disp) or n.object_id.lower() == ql:
            exact.append(n)
        elif ql in name:
            sub.append(n)
    hits = exact or sub
    cands = [{"id": n.object_id, "name": n.display_name, "type": n.node_type.value, "tier": n.tier} for n in hits]
    return [n.object_id for n in hits], cands


def _node_ref(graph: AttackGraph, nid: str) -> dict:
    n = graph.get_node(nid)
    if n is None:
        return {"id": nid, "name": nid, "type": "Unknown", "tier": 2}
    return {"id": nid, "name": n.display_name, "type": n.node_type.value, "tier": n.tier}


def _paths_to_targets(graph: AttackGraph, start: str, targets: set[str],
                      max_depth: int, max_paths: int) -> dict[str, list[list[dict]]]:
    """Forward BFS from `start`; collect, per target reached, the routes that contain at least one attack edge.

    Each route is a list of step dicts {id, name, type, tier, edge} where `edge` is the edge type leaving that node
    (None on the final target). A route ends at the first target it reaches."""
    attack = _attack_edges()
    out: dict[str, list[list[dict]]] = {}
    found = 0
    # queue item: (current, node_path, edge_path, visited, has_attack)
    start_node = graph.get_node(start)
    if start_node is None:
        return out
    queue: deque = deque([(start, [start], [], frozenset({start}), False)])
    while queue and found < max_paths:
        current, npath, epath, visited, has_attack = queue.popleft()
        if len(npath) - 1 >= max_depth:
            continue
        for _, tgt, data in graph.out_edges(current):
            if tgt in visited:
                continue
            et = data.get("edge_type", "")
            if et in NON_TRAVERSABLE:
                continue
            new_has = has_attack or et in attack
            new_np = npath + [tgt]
            new_ep = epath + [et]
            if tgt in targets:
                if new_has:
                    out.setdefault(tgt, []).append(_route(graph, new_np, new_ep))
                    found += 1
                    if found >= max_paths:
                        break
                continue                                   # a route stops at the first Tier 0 it reaches
            if len(new_np) - 1 < max_depth:
                queue.append((tgt, new_np, new_ep, visited | {tgt}, new_has))
    return out


def _route(graph: AttackGraph, npath: list[str], epath: list[str]) -> list[dict]:
    steps = []
    for i, nid in enumerate(npath):
        d = _node_ref(graph, nid)
        d["edge"] = epath[i] if i < len(epath) else None
        steps.append(d)
    return steps


@dataclass
class BreachReport:
    start: list[dict]
    start_query: str = ""
    already_tier0: list[dict] = field(default_factory=list)
    tier0_total: int = 0
    reachable_tier0: list[dict] = field(default_factory=list)   # {id,name,type,cheapest:{route,cost},stealthiest:{...}}
    downstream_tier0: list[dict] = field(default_factory=list)   # reachable only after taking over one of the above first
    blast_nodes: int = 0
    blast_actors: int = 0
    cross_plane: bool = False
    truncated: bool = False
    candidates: list[dict] = field(default_factory=list)        # set only when the query was ambiguous/unmatched

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def analyse_breach(graph: AttackGraph, query: str, *, profile: str = "balanced",
                   max_depth: int = 12, max_paths: int = 4000) -> BreachReport:
    ids, cands = resolve_principals(graph, query)
    if not ids:
        return BreachReport(start=[], start_query=query, candidates=cands)
    if len(set(ids)) > 1:
        # ambiguous: let the caller disambiguate rather than guess
        return BreachReport(start=[], start_query=query, candidates=cands)

    start = ids[0]
    rep = BreachReport(start=[_node_ref(graph, start)], start_query=query, tier0_total=len(graph.tier0_nodes))

    t0 = graph.tier0_nodes
    if start in t0:
        rep.already_tier0 = [_node_ref(graph, start)]

    reach = reachable_from(graph, start, max_depth=max_depth)
    rep.blast_nodes = len(reach)
    rep.blast_actors = sum(1 for n in reach
                           if (g := graph.get_node(n)) is not None and g.node_type.value in ACTOR_TYPES)
    reachable_t0 = (reach & t0) - {start}

    routes_by_t0 = _paths_to_targets(graph, start, reachable_t0, max_depth, max_paths) if reachable_t0 else {}
    rep.truncated = sum(len(v) for v in routes_by_t0.values()) >= max_paths

    planes: set[str] = set()
    items = []
    # a route stops at the first Tier 0 it reaches, so a Tier 0 with no direct route is reachable only PAST another one
    # (unless enumeration was capped, in which case truncated says so)
    downstream = sorted(reachable_t0 - set(routes_by_t0.keys()),
                        key=lambda n: (graph.get_node(n).display_name.lower() if graph.get_node(n) else n))
    rep.downstream_tier0 = [_node_ref(graph, n) for n in downstream]
    for tid in routes_by_t0:
        routes = routes_by_t0[tid]
        ref = _node_ref(graph, tid)
        cheap_p, cheap_c = costmod.cheapest(routes)
        stealth_p, stealth_c = costmod.stealthiest(routes)
        pref_p, pref_c = costmod.rank(routes, profile)[0]
        planes.update(cheap_c["planes"])
        ref["routes_found"] = len(routes)
        ref["cheapest"] = {"route": cheap_p, "cost": cheap_c}
        ref["stealthiest"] = {"route": stealth_p, "cost": stealth_c}
        ref["preferred"] = {"route": pref_p, "cost": pref_c, "profile": profile}
        items.append(ref)
    # most attractive to this attacker profile first (then nearest)
    items.sort(key=lambda it: (costmod.attractiveness(it["preferred"]["cost"], profile),
                               it["preferred"]["cost"]["steps"], it["name"].lower()))
    rep.reachable_tier0 = items
    rep.cross_plane = any(it.get("cheapest") and it["cheapest"]["cost"]["cross_plane"] for it in items)
    return rep


def _fmt_route(route: list[dict]) -> str:
    parts = []
    for s in route:
        parts.append(s["name"])
        if s.get("edge"):
            parts.append(f"-[{s['edge']}]->")
    return " ".join(parts)


def render(rep: BreachReport, top: int = 10) -> str:
    if not rep.start:
        if rep.candidates:
            out = [f'"{rep.start_query}" matches more than one object; pick one by its exact name or id:']
            for c in rep.candidates[:12]:
                out.append(f"  {c['name']:<32} {c['type']:<16} {c['id']}")
            if len(rep.candidates) > 12:
                out.append(f"  ... and {len(rep.candidates) - 12} more")
            return "\n".join(out) + "\n"
        return f'No object matches "{rep.start_query}".\n'

    s = rep.start[0]
    out = ["pathcutter breach", "=" * 60,
           f"Compromised      : {s['name']}  ({s['type']})",
           f"Blast radius     : {rep.blast_nodes} object(s) reachable"
           + (f", {rep.blast_actors} of them user/computer account(s)" if rep.blast_actors else ""),
           f"Tier 0 reachable : {len(rep.reachable_tier0) + len(rep.downstream_tier0)} of {rep.tier0_total}"
           + ("  (capped: lower bound)" if rep.truncated else "")]
    if rep.already_tier0:
        out.append("  NOTE: this object is itself Tier 0 - its compromise is already domain takeover.")
    if rep.cross_plane:
        out.append("  Some cheapest routes cross between on-premises and the cloud.")
    out.append("")
    if not rep.reachable_tier0:
        if rep.downstream_tier0:
            out.append(f"{len(rep.downstream_tier0)} Tier 0 object(s) are reachable, but every route runs through another "
                       "Tier 0 object first.")
        else:
            out.append("No Tier 0 object is reachable from here within the search budget.")
        return "\n".join(out) + "\n"

    out.append("Tier 0 within reach (cheapest route first):")
    for it in rep.reachable_tier0[:top]:
        ch = it.get("cheapest")
        if not ch:
            out.append(f"  {it['name']}  (reachable; no scored attack route within budget)")
            continue
        c = ch["cost"]
        out.append(f"  {it['name']}  ({it['type']})   {costmod.label(c)}")
        out.append(f"      cheapest   : {_fmt_route(ch['route'])}")
        st = it.get("stealthiest")
        if st and st["route"] != ch["route"]:
            out.append(f"      stealthiest: {_fmt_route(st['route'])}   (noise {st['cost']['noise']})")
    if len(rep.reachable_tier0) > top:
        out.append(f"  ... and {len(rep.reachable_tier0) - top} more Tier 0 object(s)")
    if rep.downstream_tier0:
        names = ", ".join(d["name"] for d in rep.downstream_tier0[:5])
        more = f" and {len(rep.downstream_tier0) - 5} more" if len(rep.downstream_tier0) > 5 else ""
        out.append(f"  (+{len(rep.downstream_tier0)} further Tier 0 object(s) reachable only after owning one of the above: {names}{more})")
    out.append("")
    out.append("Effort = attacker work (higher = harder); noise = how loud (higher = easier to catch). "
               "Routes are reachability, not a guarantee of exploitation.")
    return "\n".join(out) + "\n"
