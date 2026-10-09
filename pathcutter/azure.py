"""Microsoft Entra ID (Azure AD) and hybrid identity, from AzureHound output.

AzureHound writes `{"meta": {"type": "azure", ...}, "data": [{"kind": "AZUser", "data": {...}}, ...]}`. This module turns
that into graph nodes and edges next to the on-premises ones, so one exposure search follows a path that starts in
Active Directory, crosses the sync boundary and ends in a privileged Entra role (or the other way round).

Modeled:
  users, groups, applications, service principals, directory roles, the tenant
  group membership and ownership, application / service principal ownership
  active role assignments (principal -> role) and PIM-eligible assignments (an attack edge: the holder can activate)
  Tier 0 roles: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator,
  Partner Tier2 Support
  hybrid: an on-premises user synced to an Entra user (onPremisesSecurityIdentifier) -> SyncedTo
  password reset by Helpdesk / User / Password / Authentication Administrator, and add-secret by Application /
  Cloud Application Administrator, limited to targets that lead somewhere (so the graph does not grow by one edge per user)

Not modeled (said so by `pathcutter syntax model`): Azure resource RBAC (subscriptions, resource groups, VMs, key
vaults), Conditional Access policy evaluation, administrative units, app API permissions (Graph application roles).
The schema is taken from the AzureHound source models; it has been exercised on synthetic data shaped from them, not on
a real tenant export.
"""
from __future__ import annotations

from .graph import ADEdge, ADNode, AttackGraph, NodeType

TIER0_ROLES = {
    "62E90394-69F5-4237-9190-012177145E10": "GLOBAL ADMINISTRATOR",
    "E8611AB8-C189-46E8-94E1-60213AB1F814": "PRIVILEGED ROLE ADMINISTRATOR",
    "7BE44C8A-ADAF-4E2A-84D6-AB2649E08A13": "PRIVILEGED AUTHENTICATION ADMINISTRATOR",
    "E00E864A-17C5-4A4B-9C06-F5B95A8D5BD8": "PARTNER TIER2 SUPPORT",
}
RESET_ROLES = {   # can reset passwords of non-privileged users
    "729827E3-9C14-49F7-BB1B-9608F156BBB8": "HELPDESK ADMINISTRATOR",
    "FE930BE7-5E62-47DB-91AF-98C3A49A38B1": "USER ADMINISTRATOR",
    "966707D0-3269-4727-9BE2-8C3A10F19B9D": "PASSWORD ADMINISTRATOR",
    "C4E39BD9-1100-46D3-8C65-FB160DA0071F": "AUTHENTICATION ADMINISTRATOR",
}
SECRET_ROLES = {  # can add credentials to any application / service principal
    "9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3": "APPLICATION ADMINISTRATOR",
    "158C047A-C907-4556-B7EF-446551A6B5F7": "CLOUD APPLICATION ADMINISTRATOR",
}
KNOWN_ROLES = {**TIER0_ROLES, **RESET_ROLES, **SECRET_ROLES}

_KIND_TYPE = {"AZUser": NodeType.AZ_USER, "AZGroup": NodeType.AZ_GROUP, "AZApp": NodeType.AZ_APP,
              "AZServicePrincipal": NodeType.AZ_SP, "AZTenant": NodeType.AZ_TENANT, "AZRole": NodeType.AZ_ROLE}
_ATTACK_KINDS = {"AZOwns", "AZRunsAs", "AZEligibleRole", "AZResetPassword", "AZAddSecret", "SyncedTo"}


def _id(x) -> str:
    return str(x).upper() if x else ""


def _member_id(m) -> str:
    if isinstance(m, dict):
        inner = m.get("member") or m.get("owner") or m
        if isinstance(inner, dict):
            return _id(inner.get("id") or inner.get("objectId"))
    return ""


def is_azure_file(data: dict) -> bool:
    return str((data.get("meta") or {}).get("type", "")).lower() == "azure"


def parse_azure_file(data: dict, graph: AttackGraph) -> int:
    """Add the objects of one AzureHound file. Relationship kinds are processed in a second pass so file order is free."""
    items = [x for x in data.get("data", []) if isinstance(x, dict) and isinstance(x.get("data"), (dict, list))]
    count = 0
    for it in items:
        kind, d = it.get("kind", ""), it["data"]
        nt = _KIND_TYPE.get(kind)
        if nt is None or not isinstance(d, dict):
            continue
        oid = _id(d.get("id") or d.get("tenantId") or d.get("objectId"))
        if not oid:
            continue
        name = (d.get("userPrincipalName") if nt == NodeType.AZ_USER else None) or d.get("displayName") or d.get("defaultDomain") or oid
        props = {k: v for k, v in d.items() if isinstance(v, (str, int, float, bool)) or v is None}
        node = ADNode(oid, str(name).upper(), nt, _id(d.get("tenantId")),
                      enabled=d.get("accountEnabled", True) is not False, properties=props)
        graph.add_node(node)
        count += 1
    for it in items:
        _relationships(it.get("kind", ""), it["data"], graph)
    return count


def _edge(graph: AttackGraph, src: str, dst: str, kind: str) -> None:
    if src and dst and src != dst and not graph.has_edge_type(src, dst, kind):
        graph.add_edge(ADEdge(src, dst, kind))


def _ensure(graph: AttackGraph, oid: str, node_type: NodeType, name: str = "") -> None:
    if graph.get_node(oid) is None:
        graph.add_node(ADNode(oid, (name or oid).upper(), node_type, ""))


def _relationships(kind: str, d, graph: AttackGraph) -> None:
    if kind == "AZGroupMember" and isinstance(d, dict):
        gid = _id(d.get("groupId"))
        for m in d.get("members") or []:
            _edge(graph, _member_id(m), gid, "MemberOf")
    elif kind in ("AZGroupOwner", "AZAppOwner", "AZServicePrincipalOwner") and isinstance(d, dict):
        target = _id(d.get("groupId") or d.get("appId") or d.get("servicePrincipalId") or d.get("objectId"))
        for o in d.get("owners") or []:
            _edge(graph, _member_id(o), target, "AZOwns")
    elif kind == "AZRoleAssignment" and isinstance(d, dict):
        rid = _id(d.get("roleDefinitionId"))
        _ensure(graph, rid, NodeType.AZ_ROLE, KNOWN_ROLES.get(rid, ""))
        for ra in d.get("roleAssignments") or []:
            _edge(graph, _id(ra.get("principalId")), rid, "MemberOf")
    elif kind in ("AZRoleEligibilityScheduleInstance", "AZRoleEligibility") and isinstance(d, dict):
        rid = _id(d.get("roleDefinitionId"))
        _ensure(graph, rid, NodeType.AZ_ROLE, KNOWN_ROLES.get(rid, ""))
        _edge(graph, _id(d.get("principalId")), rid, "AZEligibleRole")
    elif kind == "AZApp" and isinstance(d, dict):
        pass    # the app -> service principal link comes from the service principal's appId (finalize)


def finalize_azure(graph: AttackGraph) -> None:
    """Cross-object links that need every file loaded: names of known roles, app->SP, hybrid sync, fan-out edges."""
    roles = graph.nodes_by_type(NodeType.AZ_ROLE)
    if not roles and not graph.nodes_by_type(NodeType.AZ_USER):
        return
    for r in roles:
        if r.object_id in KNOWN_ROLES and not r.name.strip():
            r.name = KNOWN_ROLES[r.object_id]
    # service principal runs as its application
    apps = {str(n.properties.get("appId") or "").upper(): n.object_id for n in graph.nodes_by_type(NodeType.AZ_APP)}
    for sp in graph.nodes_by_type(NodeType.AZ_SP):
        app = apps.get(str(sp.properties.get("appId") or "").upper())
        if app:
            _edge(graph, app, sp.object_id, "AZRunsAs")
    # hybrid: the on-premises account behind a synced cloud user
    for u in graph.nodes_by_type(NodeType.AZ_USER):
        sid = u.properties.get("onPremisesSecurityIdentifier")
        if sid and graph.get_node(str(sid)) is not None and u.properties.get("onPremisesSyncEnabled") is not False:
            _edge(graph, str(sid), u.object_id, "SyncedTo")
    _fan_out(graph)


def _has_onward(graph: AttackGraph, node_id: str) -> bool:
    return any(d.get("edge_type") in _ATTACK_KINDS or d.get("edge_type") == "MemberOf" for _, _, d in graph.out_edges(node_id))


def _fan_out(graph: AttackGraph) -> None:
    """role -> victim edges, but only to objects that lead somewhere (they have an outgoing attack or membership edge)."""
    privileged = set()
    for rid in TIER0_ROLES:
        if graph.get_node(rid) is not None:
            privileged |= {u for u, _, d in graph.in_edges(rid) if d.get("edge_type") == "MemberOf"}
    users = [u for u in graph.nodes_by_type(NodeType.AZ_USER) if u.object_id not in privileged and _has_onward(graph, u.object_id)]
    objects = [n for n in graph.nodes_by_type(NodeType.AZ_APP) + graph.nodes_by_type(NodeType.AZ_SP) if _has_onward(graph, n.object_id)]
    for rid in RESET_ROLES:
        if graph.get_node(rid) is not None:
            for u in users:
                _edge(graph, rid, u.object_id, "AZResetPassword")
    for rid in SECRET_ROLES:
        if graph.get_node(rid) is not None:
            for n in objects:
                _edge(graph, rid, n.object_id, "AZAddSecret")
