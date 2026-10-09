"""Edges that exist only as a combination of collected rights.

DCSync needs BOTH replication rights (DS-Replication-Get-Changes and Get-Changes-All). A principal holds them either
directly or through nested groups, and the two rights are frequently granted to different groups, so the combination
cannot be read off a single ACE: it is derived here, as BloodHound derives it. A principal holding only one right gets
no DCSync edge (it cannot read secrets); `AllExtendedRights` on the domain object already includes both and is turned
into DCSync at ingest.
"""
from __future__ import annotations

from .adcs import _both, _holders
from .graph import ADEdge, AttackGraph, NodeType


def derive_dcsync(graph: AttackGraph) -> int:
    added = 0
    for dom in graph.nodes_by_type(NodeType.DOMAIN):
        a = _holders(graph, dom.object_id, {"GetChanges"})
        b = _holders(graph, dom.object_id, {"GetChangesAll"})
        if not a or not b:
            continue
        for src in _both(graph, a, b):
            if src in graph.tier0_nodes or graph.has_edge_type(src, dom.object_id, "DCSync"):
                continue
            graph.add_edge(ADEdge(src, dom.object_id, "DCSync"))
            added += 1
    return added
