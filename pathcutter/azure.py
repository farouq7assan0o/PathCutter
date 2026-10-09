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

Azure resource RBAC: subscriptions, resource groups, VMs and key vaults with Owner / Contributor / User Access
Administrator / VM administrator login assignments, the scope hierarchy, and VM managed identities (a VM controller can
act as the identity). Subscriptions are not Tier 0 by default; name them in the policy's `extra_tier0` to make them targets.

Dangerous Microsoft Graph application permissions held by service principals: RoleManagement.ReadWrite.Directory and
AppRoleAssignment.ReadWrite.All (the holder can make itself Global Administrator) and Application.ReadWrite.All (the holder can
add a secret to any application).

Roles scoped to an administrative unit or to one object only reach that scope (edges to the unit's collected members; an assignment
whose unit was not collected adds nothing and is reported by `audit`).

Not modeled (said so by `pathcutter syntax model`): other Graph application permissions, the contents of custom roles,
deny assignments, key vault data-plane access policies.
The schema was taken from the AzureHound source models and then checked against one real collection (SpecterOps' PhantomCorp demo
tenant, tests/data/real/entra_sampledata.zip). Role capabilities (reset passwords, add secrets, create role assignments) are read from
each role's allowedResourceActions, so custom roles and unlisted built-in roles count.
"""
from __future__ import annotations

import re

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

_KIND_TYPE = {"AZSubscription": NodeType.AZ_SUBSCRIPTION, "AZResourceGroup": NodeType.AZ_RG, "AZVM": NodeType.AZ_VM,
              "AZKeyVault": NodeType.AZ_KEYVAULT, "AZManagementGroup": NodeType.AZ_MGMTGROUP,
              "AZUser": NodeType.AZ_USER, "AZGroup": NodeType.AZ_GROUP, "AZApp": NodeType.AZ_APP,
              **{k: NodeType.AZ_RESOURCE for k in ("AZFunctionApp", "AZWebApp", "AZAutomationAccount", "AZLogicApp", "AZVMScaleSet",
                                                   "AZManagedCluster", "AZContainerRegistry")},
              "AZServicePrincipal": NodeType.AZ_SP, "AZTenant": NodeType.AZ_TENANT, "AZRole": NodeType.AZ_ROLE}
GRANT_ROLE_PERMS = {"9E3F62CF-CA93-4989-B6CE-BF83C28F9FE8": "RoleManagement.ReadWrite.Directory",
                    "06B708A9-E830-4DB3-A914-8E69DA51D44F": "AppRoleAssignment.ReadWrite.All"}
ADD_SECRET_PERMS = {"1BFEFB4E-E0B5-418B-A88F-73C46D2CC8E9": "Application.ReadWrite.All"}
ADD_MEMBER_PERMS = {"62A82D76-70EA-41E2-9197-370581804D09": "Group.ReadWrite.All", "DBAAE8CF-10B5-4B86-A4A1-F871C94C6695": "GroupMember.ReadWrite.All",
                    "19DBC75E-C2E2-444C-A770-EC69D8559FC7": "Directory.ReadWrite.All"}
RESET_PW_PERMS = {"741F803B-C850-494E-B5DF-CDE7C675A1CA": "User.ReadWrite.All", "50483E42-D915-4231-9639-7FDB7FD190E5": "UserAuthenticationMethod.ReadWrite.All"}
_ATTACK_KINDS = {"AZMGGrantRole", "AZMGAddSecret", "AZMGAddMember", "AZMGResetPassword", "AZOwns", "AZRunsAs", "AZEligibleRole", "AZResetPassword", "AZAddSecret", "SyncedTo"}


_DEFAULT_ROLES = {"USER", "GUEST USER", "RESTRICTED GUEST USER"}       # default permissions, not assignable roles
_RESET_ACTIONS = {"microsoft.directory/users/password/update"}
_SECRET_ACTIONS = {"microsoft.directory/applications/credentials/update", "microsoft.directory/serviceprincipals/credentials/update"}


def _capabilities(d: dict) -> list[str]:
    """What an Entra role definition lets its holder do, read from its allowedResourceActions (so custom roles count)."""
    acts = {str(a).lower() for p in d.get("rolePermissions") or [] if isinstance(p, dict) for a in p.get("allowedResourceActions") or []}
    caps = []
    if acts & _RESET_ACTIONS:
        caps.append("reset")
    if acts & _SECRET_ACTIONS:
        caps.append("secret")
    if any(a.startswith("microsoft.directory/roleassignments/") and (a.endswith("/alltasks") or a.endswith("/create")) for a in acts):
        caps.append("grant")
    return caps


def _can(graph: AttackGraph, rid: str, cap: str) -> bool:
    n = graph.get_node(rid)
    if n is None or n.display_name.upper() in _DEFAULT_ROLES or rid in TIER0_ROLES:
        return False
    return cap in (n.properties.get("_caps") or ())


def _id(x) -> str:
    return str(x).upper() if x else ""


def _sub(x) -> str:
    """Subscriptions appear as a bare GUID in some places and as /subscriptions/GUID in others: one canonical form."""
    v = _id(x)
    if not v:
        return ""
    if v.startswith("/SUBSCRIPTIONS/"):
        return "/SUBSCRIPTIONS/" + v.split("/")[2]
    return "/SUBSCRIPTIONS/" + v.strip("/")


def _member_id(m) -> str:
    if isinstance(m, dict):
        inner = m.get("member") or m.get("owner") or m
        if isinstance(inner, dict):
            return _id(inner.get("id") or inner.get("objectId"))
    return ""


def is_azure_file(data: dict) -> bool:
    """AzureHound writes {"meta": {"type": "azure"}, "data": [...]} or just {"data": [...]}: recognise it by its AZ* kinds."""
    if str((data.get("meta") or {}).get("type", "")).lower() == "azure":
        return True
    items = data.get("data")
    return isinstance(items, list) and bool(items) and all(
        isinstance(x, dict) and str(x.get("kind", "")).startswith("AZ") and isinstance(x.get("data"), (dict, list)) for x in items[:50])


def parse_azure_file(data: dict, graph: AttackGraph) -> int:
    """Add the objects of one AzureHound file. Relationship kinds are processed in a second pass so file order is free."""
    items = [x for x in data.get("data", []) if isinstance(x, dict) and isinstance(x.get("data"), (dict, list))]
    count = 0
    for it in items:
        kind, d = it.get("kind", ""), it["data"]
        nt = _KIND_TYPE.get(kind)
        if nt is None or not isinstance(d, dict):
            continue
        oid = _sub(d.get("id") or d.get("subscriptionId")) if kind == "AZSubscription" else             _id(d.get("id") or d.get("tenantId") or d.get("objectId"))
        if not oid:
            continue
        name = (d.get("userPrincipalName") if nt == NodeType.AZ_USER else None) or d.get("displayName") or d.get("defaultDomain") or (d.get("name") if nt == NodeType.AZ_RESOURCE else None) or oid
        props = {k: v for k, v in d.items() if isinstance(v, (str, int, float, bool)) or v is None}
        if kind == "AZRole":
            props["_caps"] = _capabilities(d)
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


def _grant(graph: AttackGraph, who: str, rid: str, scope, edge_kind: str) -> None:
    """A role assignment. Tenant-wide (or a role that cannot be scoped) is membership of the role; a user-management or
    application role scoped to an administrative unit or to one object only reaches that scope, so it is kept aside and
    turned into edges to exactly those objects once every file is loaded (`_scoped_roles`)."""
    sc = str(scope or "/").strip().upper()
    if sc in ("/", "") or not (rid in RESET_ROLES or rid in SECRET_ROLES or _can(graph, rid, "reset") or _can(graph, rid, "secret")):
        _edge(graph, who, rid, edge_kind)
    elif who:
        graph.meta.setdefault("scoped_roles", []).append({"who": who, "role": rid, "scope": sc, "eligible": edge_kind != "MemberOf"})


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
            _grant(graph, _id(ra.get("principalId")), rid, ra.get("directoryScopeId") or d.get("directoryScopeId"), "MemberOf")
    elif kind in ("AZRoleEligibilityScheduleInstance", "AZRoleEligibility") and isinstance(d, dict):
        rid = _id(d.get("roleDefinitionId"))
        _ensure(graph, rid, NodeType.AZ_ROLE, KNOWN_ROLES.get(rid, ""))
        _grant(graph, _id(d.get("principalId")), rid, d.get("directoryScopeId"), "AZEligibleRole")
    elif kind == "AZAdministrativeUnit" and isinstance(d, dict):
        au = _id(d.get("id"))
        if au:
            graph.meta.setdefault("admin_units", []).append({"id": au, "members": [_member_id(m) or _id(m.get("id")) for m in d.get("members") or [] if isinstance(m, dict)]})
    elif kind == "AZApp" and isinstance(d, dict):
        pass    # the app -> service principal link comes from the service principal's appId (finalize)
    elif kind == "AZAppRoleAssignment" and isinstance(d, dict):
        who, role = _id(d.get("principalId")), _id(d.get("appRoleId"))
        if who and "GRAPH" in str(d.get("resourceDisplayName", "")).upper() or who and not d.get("resourceDisplayName"):
            node = graph.get_node(who)
            if node is None:
                _ensure(graph, who, NodeType.AZ_SP)
                node = graph.get_node(who)
            perms = node.properties.setdefault("_graph_perms", [])
            if role in GRANT_ROLE_PERMS or role in ADD_SECRET_PERMS or role in ADD_MEMBER_PERMS or role in RESET_PW_PERMS:
                perms.append(role)
    elif kind == "AZKeyVaultAccessPolicy" and isinstance(d, dict):
        who, vault = _id(d.get("objectId")), _id(d.get("keyVaultId"))
        perms = d.get("permissions") or {}
        if who and vault:
            for field, edge in (("secrets", "AZGetSecrets"), ("keys", "AZGetKeys"), ("certificates", "AZGetCertificates")):
                if any(str(p).lower() in ("get", "all") for p in perms.get(field) or []):
                    _ensure(graph, vault, NodeType.AZ_KEYVAULT)
                    _ensure(graph, who, NodeType.UNKNOWN)
                    _edge(graph, who, vault, edge)
    elif kind in ("AZSubscription", "AZResourceGroup", "AZVM", "AZKeyVault") + _RESOURCE_KINDS and isinstance(d, dict):
        _resource(kind, d, graph)
    elif kind.endswith("RoleAssignment") and kind[:-len("RoleAssignment")] in _RESOURCE_KINDS and isinstance(d, dict):
        _resource_assignments(d, graph)
    else:
        m = _RBAC_KIND.match(kind)
        if m and isinstance(d, dict):
            _rbac(m.group(1), m.group(2), d, graph)


_RBAC_KIND = re.compile(r"^AZ(Subscription|ResourceGroup|ManagementGroup|VM|KeyVault)(Owner|Contributor|UserAccessAdmin|"
                        r"VMContributor|AvereContributor|KVContributor|AdminLogin|RoleAssignment)$")
_SCOPE_KEY = {"Subscription": "subscriptionId", "ResourceGroup": "resourceGroupId", "ManagementGroup": "managementGroupId",
              "VM": "virtualMachineId", "KeyVault": "keyVaultId"}
_ROLE_EDGE = {"Owner": "AZOwner", "Contributor": "AZContributor", "VMContributor": "AZContributor", "AvereContributor": "AZContributor",
              "KVContributor": "AZContributor", "UserAccessAdmin": "AZUserAccessAdmin", "AdminLogin": "AZVMAdminLogin"}
_ROLE_DEF_EDGE = {   # well-known built-in role definition ids, for the generic RoleAssignment kinds
    "8E3AF657-A8FF-443C-A75C-2FE8C4BCB635": "AZOwner", "B24988AC-6180-42A0-AB88-20F7382DD24C": "AZContributor",
    "18D7D88D-D35E-4FB5-A5C3-7773C20A72D9": "AZUserAccessAdmin", "9980E02C-C2BE-4D73-94E8-173B1DC7CF3C": "AZContributor",
    "1C0163C0-47E6-4577-8991-EA5C82E286E4": "AZVMAdminLogin"}


def _principal_of(entry) -> str:
    # the principal id inside a role-assignment wrapper, whatever the wrapper key is called (owner, contributor, ...)
    if not isinstance(entry, dict):
        return ""
    for v in entry.values():
        if isinstance(v, dict):
            props = v.get("properties")
            if isinstance(props, dict) and props.get("principalId"):
                return _id(props["principalId"])
            if v.get("principalId"):
                return _id(v["principalId"])
    return _id(entry.get("principalId"))


def _rbac(scope_kind: str, role: str, d: dict, graph: AttackGraph) -> None:
    scope = _sub(d.get(_SCOPE_KEY[scope_kind])) if scope_kind == "Subscription" else _id(d.get(_SCOPE_KEY[scope_kind]))
    if not scope:
        return
    entries = [x for v in d.values() if isinstance(v, list) for x in v]
    for e in entries:
        who = _principal_of(e)
        edge = _ROLE_EDGE.get(role)
        if role == "RoleAssignment":
            rid = ""
            for v in (e.values() if isinstance(e, dict) else []):
                if isinstance(v, dict) and isinstance(v.get("properties"), dict):
                    rid = _id(v["properties"].get("roleDefinitionId", "")).rsplit("/", 1)[-1]
            edge = _ROLE_DEF_EDGE.get(rid)
            if edge is None and rid:
                graph.meta.setdefault("azure_unevaluated_roles", []).append(rid)
        if who and edge:
            _ensure(graph, scope, {"Subscription": NodeType.AZ_SUBSCRIPTION, "ResourceGroup": NodeType.AZ_RG,
                                   "ManagementGroup": NodeType.AZ_MGMTGROUP, "VM": NodeType.AZ_VM, "KeyVault": NodeType.AZ_KEYVAULT}[scope_kind])
            _edge(graph, who, scope, edge)


_RESOURCE_KINDS = ("AZFunctionApp", "AZWebApp", "AZAutomationAccount", "AZLogicApp", "AZVMScaleSet", "AZManagedCluster", "AZContainerRegistry")


def _resource_assignments(d: dict, graph: AttackGraph) -> None:
    """Role assignments on a compute resource: {assignees: [{assignee: {properties: {principalId}}, objectId, roleDefinitionId}]}."""
    for e in d.get("assignees") or []:
        if not isinstance(e, dict):
            continue
        who, scope = _principal_of(e), _id(e.get("objectId"))
        rid = _id(e.get("roleDefinitionId")).rsplit("/", 1)[-1]
        edge = _ROLE_DEF_EDGE.get(rid)
        if edge is None and rid:
            graph.meta.setdefault("azure_unevaluated_roles", []).append(rid)
        if who and scope and edge:
            _ensure(graph, scope, NodeType.AZ_RESOURCE)
            _edge(graph, who, scope, edge)


def _resource(kind: str, d: dict, graph: AttackGraph) -> None:
    oid = _sub(d.get("id") or d.get("subscriptionId")) if kind == "AZSubscription" else _id(d.get("id"))
    if kind == "AZResourceGroup":
        _edge(graph, _sub(d.get("subscriptionId")), oid, "AZContains")
    elif kind in ("AZVM", "AZKeyVault") + _RESOURCE_KINDS:
        _edge(graph, _id(d.get("resourceGroupId")), oid, "AZContains")
    if kind == "AZVM" or kind in _RESOURCE_KINDS:
        ident = d.get("identity") or {}
        principals = [ident.get("principalId")] + [(u or {}).get("principalId") for u in (ident.get("userAssignedIdentities") or {}).values()]
        for p in principals:
            if p:
                _ensure(graph, _id(p), NodeType.AZ_SP)
                _edge(graph, oid, _id(p), "AZManagedIdentity")


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
    # an SP holding a dangerous Graph permission is about to get an outgoing edge, so it already leads somewhere
    graph._onward_memo = {n.object_id: True for n in graph.nodes_by_type(NodeType.AZ_SP) if n.properties.get("_graph_perms")}
    # (the memo also keeps this linear: the question is asked for every holder-victim pair)
    try:
        _graph_permissions(graph)
        _fan_out(graph)
        _scoped_roles(graph)
    finally:
        graph._onward_memo = None


def _graph_permissions(graph: AttackGraph) -> None:
    ga = "62E90394-69F5-4237-9190-012177145E10"
    for n in graph.nodes_by_type(NodeType.AZ_SP):
        perms = set(n.properties.get("_graph_perms") or [])
        if perms & set(GRANT_ROLE_PERMS):
            _ensure(graph, ga, NodeType.AZ_ROLE, TIER0_ROLES[ga])
            _edge(graph, n.object_id, ga, "AZMGGrantRole")
    privileged = set()
    for rid in TIER0_ROLES:
        if graph.get_node(rid) is not None:
            privileged |= {u for u, _, d in graph.in_edges(rid) if d.get("edge_type") == "MemberOf"}
    for n in graph.nodes_by_type(NodeType.AZ_SP):
        perms = set(n.properties.get("_graph_perms") or [])
        if perms & set(ADD_MEMBER_PERMS):
            for gr in graph.nodes_by_type(NodeType.AZ_GROUP):           # role-assignable groups are protected from this permission
                if not gr.properties.get("isAssignableToRole") and gr.object_id != n.object_id and _has_onward(graph, gr.object_id):
                    _edge(graph, n.object_id, gr.object_id, "AZMGAddMember")
        if perms & set(RESET_PW_PERMS):
            for u in graph.nodes_by_type(NodeType.AZ_USER):             # privileged users cannot be reset by these permissions
                if u.object_id not in privileged and _has_onward(graph, u.object_id):
                    _edge(graph, n.object_id, u.object_id, "AZMGResetPassword")
    for n in graph.nodes_by_type(NodeType.AZ_SP):
        if set(n.properties.get("_graph_perms") or []) & set(ADD_SECRET_PERMS):
            for t in graph.nodes_by_type(NodeType.AZ_APP) + graph.nodes_by_type(NodeType.AZ_SP):
                if t.object_id != n.object_id and _has_onward(graph, t.object_id):
                    _edge(graph, n.object_id, t.object_id, "AZMGAddSecret")


def _has_onward(graph: AttackGraph, node_id: str) -> bool:
    memo = getattr(graph, "_onward_memo", None)
    if memo is not None:
        got = memo.get(node_id)
        if got is None:
            got = memo[node_id] = _has_onward_scan(graph, node_id)
        return got
    return _has_onward_scan(graph, node_id)


def _has_onward_scan(graph: AttackGraph, node_id: str) -> bool:
    return any(d.get("edge_type") in _ATTACK_KINDS or d.get("edge_type") == "MemberOf" for _, _, d in graph.out_edges(node_id))


def _fan_out(graph: AttackGraph) -> None:
    """role -> victim edges, but only to objects that lead somewhere (they have an outgoing attack or membership edge)."""
    privileged = set()
    for rid in TIER0_ROLES:
        if graph.get_node(rid) is not None:
            privileged |= {u for u, _, d in graph.in_edges(rid) if d.get("edge_type") == "MemberOf"}
    users = [u for u in graph.nodes_by_type(NodeType.AZ_USER) if u.object_id not in privileged and _has_onward(graph, u.object_id)]
    objects = [n for n in graph.nodes_by_type(NodeType.AZ_APP) + graph.nodes_by_type(NodeType.AZ_SP) if _has_onward(graph, n.object_id)]
    for rid in [r.object_id for r in graph.nodes_by_type(NodeType.AZ_ROLE) if r.object_id in RESET_ROLES or _can(graph, r.object_id, "reset")]:
        if graph.get_node(rid) is not None:
            for u in users:
                _edge(graph, rid, u.object_id, "AZResetPassword")
    for rid in [r.object_id for r in graph.nodes_by_type(NodeType.AZ_ROLE) if r.object_id in SECRET_ROLES or _can(graph, r.object_id, "secret")]:
        if graph.get_node(rid) is not None:
            for n in objects:
                _edge(graph, rid, n.object_id, "AZAddSecret")


def _scoped_roles(graph: AttackGraph) -> None:
    """Edges for role assignments scoped to an administrative unit or a single object (see `_grant`)."""
    scoped = graph.meta.get("scoped_roles") or []
    if not scoped:
        return
    units = {u["id"]: u["members"] for u in graph.meta.get("admin_units", [])}
    privileged = set()
    for rid in TIER0_ROLES:
        if graph.get_node(rid) is not None:
            privileged |= {u for u, _, d in graph.in_edges(rid) if d.get("edge_type") == "MemberOf"}
    unresolved = 0
    for s in scoped:
        reset = s["role"] in RESET_ROLES or _can(graph, s["role"], "reset")
        kind = "AZResetPassword" if reset else "AZAddSecret"
        scope = s["scope"]
        if scope.startswith("/ADMINISTRATIVEUNITS/"):
            members = units.get(scope.rsplit("/", 1)[-1])
            if members is None:
                unresolved += 1
                continue
            victims = [m for m in members if graph.get_node(m) is not None]
        else:
            victims = [scope.rsplit("/", 1)[-1]]              # scoped to one object (a user or an application)
        for v in victims:
            n = graph.get_node(v)
            if n is None or v == s["who"]:
                continue
            if reset and (n.node_type != NodeType.AZ_USER or v in privileged):
                continue
            if not reset and n.node_type not in (NodeType.AZ_APP, NodeType.AZ_SP):
                continue
            if _has_onward(graph, v):
                _edge(graph, s["who"], v, kind)
    graph.meta["scoped_roles_unresolved"] = unresolved
