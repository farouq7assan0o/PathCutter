"""GPO user-rights assignments: privileges a policy hands to principals on every computer it applies to.

SharpHound resolves only the local-group part of a GPO (Restricted Groups / Group Policy Preferences). The other half of
a security template, [Privilege Rights] in GptTmpl.inf, is read from SYSVOL by tools/Export-AdGpoRights.ps1 into
`*_gporights.json`. A principal that holds SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege,
SeDebugPrivilege, SeLoadDriverPrivilege, SeTcbPrivilege or SeCreateTokenPrivilege on a computer can become SYSTEM there, so
each becomes a `GPOUserRight` edge principal -> computer, which the exposure search follows like local administration
(on a domain controller it ends at Tier 0).

Where a GPO applies is read from the graph: the objects it is linked to (`GPOControlsObject`) and everything they contain.
Security filtering, WMI filters, link enforcement and blocked inheritance are not evaluated, so this can only over-report.
A GPO that reaches more than _MAX_TARGETS computers is reduced to its domain controllers and Tier 0 computers and the
truncation is recorded in graph.meta["gpo_rights_truncated"].
"""
from __future__ import annotations

from .graph import ADEdge, AttackGraph, NodeType

DANGEROUS = {"SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege",
             "SeTcbPrivilege", "SeCreateTokenPrivilege", "SeSyncAgentPrivilege"}
_MAX_TARGETS = 50_000


def capture(data: dict, graph: AttackGraph) -> None:
    """Keep the raw records; they are turned into edges once every file is loaded (`derive_gpo_privileges`)."""
    recs = graph.meta.setdefault("gpo_rights", [])
    for rec in data.get("data", []):
        rights = {k: [str(s).upper() for s in v] for k, v in (rec.get("Rights") or {}).items() if k in DANGEROUS and isinstance(v, list) and v}
        if rec.get("GPO") and rights:
            recs.append({"gpo": str(rec["GPO"]).upper().strip("{}"), "rights": rights})


def _resolve(graph: AttackGraph, sid: str, domain: str) -> str | None:
    if graph.get_node(sid) is not None:
        return sid
    cand = f"{domain}-{sid}" if domain else ""
    return cand if cand and graph.get_node(cand) is not None else None


def _scope(graph: AttackGraph, gpo: str) -> set[str]:
    """Computers the GPO applies to: everything below the objects it is linked to."""
    out: set[str] = set()
    stack = [t for _, t, d in graph.out_edges(gpo) if d.get("edge_type") == "GPOControlsObject"]
    seen: set[str] = set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        n = graph.get_node(cur)
        if n is None:
            continue
        if n.node_type == NodeType.COMPUTER:
            out.add(cur)
            continue
        stack.extend(t for _, t, d in graph.out_edges(cur) if d.get("edge_type") == "Contains")
    return out


def derive_gpo_privileges(graph: AttackGraph) -> int:
    recs = graph.meta.get("gpo_rights") or []
    if not recs:
        return 0
    from .ingest import find_dc_sids
    dcs = set(find_dc_sids(graph))
    added = 0
    graph.meta["gpo_rights_truncated"] = []
    for rec in recs:
        gpo = next((n for n in graph.nodes_by_type(NodeType.GPO) if n.object_id.upper().strip("{}") == rec["gpo"]), None)
        if gpo is None:
            continue
        targets = _scope(graph, gpo.object_id)
        if len(targets) > _MAX_TARGETS:
            graph.meta["gpo_rights_truncated"].append(gpo.display_name)
            targets = {c for c in targets if c in dcs or c in graph.tier0_nodes}
        domain = str(gpo.domain or "").upper()
        for right, sids in rec["rights"].items():
            for sid in sids:
                who = _resolve(graph, sid, domain)
                if who is None:
                    continue
                for comp in targets:
                    if comp != who and not graph.has_edge_type(who, comp, "GPOUserRight"):
                        graph.add_edge(ADEdge(source_id=who, target_id=comp, edge_type="GPOUserRight", properties={"right": right, "gpo": gpo.display_name}))
                        added += 1
    return added
