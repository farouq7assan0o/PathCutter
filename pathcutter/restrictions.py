"""Restrictions: facts that make an edge unusable, applied once after the graph is built.

Each restriction is a function registered with @restriction. It may remove edges and must record what it removed in
graph.meta["restrictions"] so the report, `audit` and `check` can say so (a restriction that hides an edge silently
would be a quiet pass).

Protected Users / "Account is sensitive and cannot be delegated": Kerberos delegation cannot impersonate such an
account. A delegation edge (constrained or resource-based) into a computer is only useful if some account that is an
administrator of that computer can be impersonated, so the edge is unusable when EVERY administrator of the target
is protected. An unconstrained-delegation host is not affected: it captures the domain controller's own machine
ticket, and computer accounts are never members of Protected Users.
"""
from __future__ import annotations

from typing import Callable

from .graph import AttackGraph, NodeType

RESTRICTIONS: list[Callable[[AttackGraph], None]] = []
_MAX_ADMINS = 5000          # beyond this a target has too many administrators to all be protected; keep the edge


def restriction(fn):
    RESTRICTIONS.append(fn)
    return fn


def apply_restrictions(graph: AttackGraph) -> None:
    for fn in RESTRICTIONS:
        fn(graph)


def protected_accounts(graph: AttackGraph) -> set[str]:
    """Users that cannot be impersonated through delegation."""
    out = {n.object_id for n in graph.nodes_by_type(NodeType.USER) if n.properties.get("sensitive")}
    for g in graph.nodes_by_type(NodeType.GROUP):
        if g.display_name.upper() == "PROTECTED USERS":
            out |= graph._recursive_members(g.object_id)
    return out


def _administrators(graph: AttackGraph, computer: str) -> set[str] | None:
    """Every user that administers a computer (directly or through groups), or None when it is unbounded."""
    users: set[str] = set()
    for src, _, d in graph.in_edges(computer):
        if d.get("edge_type") != "AdminTo":
            continue
        n = graph.get_node(src)
        if n is None:
            continue
        if n.node_type == NodeType.USER:
            users.add(src)
        elif n.node_type == NodeType.GROUP:
            members = graph._recursive_members(src)
            if len(members) > _MAX_ADMINS:
                return None
            users |= {m for m in members if (graph.get_node(m) is not None and graph.get_node(m).node_type == NodeType.USER)}
        else:
            users.add(src)                       # a computer account administrator is never protected
        if len(users) > _MAX_ADMINS:
            return None
    return users


@restriction
def protected_users_block_delegation(graph: AttackGraph) -> None:
    prot = protected_accounts(graph)
    if not prot:
        return
    cache: dict[str, bool] = {}
    removed: list[dict] = []
    for u, v, d in list(graph.all_edges()):
        et = d.get("edge_type")
        if et not in ("AllowedToDelegate", "AllowedToAct"):
            continue
        src = graph.get_node(u)
        if src is None or src.properties.get("unconstraineddelegation"):
            continue
        tgt = graph.get_node(v)
        if tgt is None or tgt.node_type != NodeType.COMPUTER:
            continue
        if v not in cache:
            admins = _administrators(graph, v)
            cache[v] = bool(admins) and admins <= prot
        if cache[v]:
            removed.append({"source": u, "target": v, "edge_type": et})
    for r in removed:
        graph.remove_edge(r["source"], r["target"], r["edge_type"])
    if removed:
        graph.meta.setdefault("restrictions", []).append({
            "kind": "protected-users", "count": len(removed), "edges": removed[:50],
            "note": "Delegation edges removed because every administrator of the target is in Protected Users or marked sensitive. "
                    "Adding an unprotected administrator to a target re-opens the edge; `check` does not re-evaluate this.",
        })
