"""Entra Conditional Access: which identities a policy really covers, evaluated against the collected tenant.

Input is the Microsoft Graph policy list (`GET /identity/conditionalAccess/policies`, or `Get-MgIdentityConditionalAccessPolicy
| ConvertTo-Json -Depth 10`, in which case the keys are PascalCase and are accepted too): the raw `{"value": [...]}` response, a bare list, or
`{"meta": {"type": "conditional_access"}, "data": [...]}`.
Put the file next to the AzureHound output.

What is evaluated: the include / exclude lists for users, groups and roles (group and role membership resolved through the
graph, nested groups included), the target applications ("All"), the grant controls (MFA, authentication strength, block)
and the policy state (enabled, report-only, disabled). What is NOT evaluated: locations, device platforms, risk levels,
device filters and session controls: a policy that depends on them is treated as covering the user only when it also
does not narrow by them, so coverage is never over-stated.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .graph import AttackGraph, NodeType


def _camel(v):
    """Graph REST returns camelCase; the Graph PowerShell SDK serializes the same objects in PascalCase. Accept both."""
    if isinstance(v, dict):
        return {(k[:1].lower() + k[1:] if isinstance(k, str) else k): _camel(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_camel(x) for x in v]
    return v


def _items(data: dict) -> list:
    got = data.get("data") if "data" in data else data.get("value")
    return [_camel(p) for p in (got or []) if isinstance(p, dict)]


def is_ca_file(data: dict) -> bool:
    if str((data.get("meta") or {}).get("type", "")).lower() == "conditional_access":
        return True
    items = _items(data)
    return bool(items) and all("conditions" in x and "grantControls" in x for x in items)


def policies_of(data: dict) -> list[dict]:
    return _items(data)


@dataclass
class Policy:
    id: str
    name: str
    state: str                        # enabled | enabledForReportingButNotEnforced | disabled
    raw: dict = field(repr=False, default_factory=dict)

    @property
    def enforced(self) -> bool:
        return self.state == "enabled"

    @property
    def report_only(self) -> bool:
        return self.state == "enabledForReportingButNotEnforced"

    def users(self) -> dict:
        return (self.raw.get("conditions") or {}).get("users") or {}

    def controls(self) -> list[str]:
        g = self.raw.get("grantControls") or {}
        return [str(c).lower() for c in (g.get("builtInControls") or [])]

    def requires_mfa(self) -> bool:
        g = self.raw.get("grantControls") or {}
        c = self.controls()
        if g.get("authenticationStrength"):
            return True
        if "mfa" not in c:
            return False
        return str(g.get("operator", "OR")).upper() == "AND" or len(c) == 1      # OR with another control does not force MFA

    def blocks(self) -> bool:
        return "block" in self.controls()

    def all_apps(self) -> bool:
        apps = ((self.raw.get("conditions") or {}).get("applications") or {})
        return "All" in (apps.get("includeApplications") or []) and not apps.get("excludeApplications")

    def narrowed(self) -> bool:
        """Conditions this module does not evaluate that would limit when the policy applies."""
        c = self.raw.get("conditions") or {}
        locs = c.get("locations") or {}
        return bool(c.get("platforms") or c.get("signInRiskLevels") or c.get("userRiskLevels") or c.get("devices")
                    or (locs.get("includeLocations") and "All" not in locs.get("includeLocations"))
                    or c.get("servicePrincipalRiskLevels"))

    def legacy_clients(self) -> bool:
        types = {str(t).lower() for t in ((self.raw.get("conditions") or {}).get("clientAppTypes") or [])}
        return {"exchangeactivesync", "other"} <= types


def load(raw: list[dict]) -> list[Policy]:
    return [Policy(str(p.get("id", "")), str(p.get("displayName", p.get("id", ""))), str(p.get("state", "disabled")), p) for p in raw]


def _identity(graph: AttackGraph, user_id: str) -> tuple[set[str], set[str]]:
    """(ids of every group the user is in, ids of every role they hold), through nested membership."""
    groups, roles, stack, seen = set(), set(), [user_id], {user_id}
    while stack:
        cur = stack.pop()
        for _, t, d in graph.out_edges(cur):
            if d.get("edge_type") != "MemberOf" or t in seen:
                continue
            seen.add(t)
            node = graph.get_node(t)
            if node is not None and node.node_type == NodeType.AZ_ROLE:
                roles.add(t.upper())
            else:
                groups.add(t.upper())
                stack.append(t)
    return groups, roles


def applies(policy: Policy, user_id: str, groups: set[str], roles: set[str]) -> bool:
    u = policy.users()
    uid = user_id.upper()
    inc = {str(x).upper() for x in (u.get("includeUsers") or [])}
    inc_g = {str(x).upper() for x in (u.get("includeGroups") or [])}
    inc_r = {str(x).upper() for x in (u.get("includeRoles") or [])}
    exc = {str(x).upper() for x in (u.get("excludeUsers") or [])}
    exc_g = {str(x).upper() for x in (u.get("excludeGroups") or [])}
    exc_r = {str(x).upper() for x in (u.get("excludeRoles") or [])}
    included = "ALL" in inc or uid in inc or bool(groups & inc_g) or bool(roles & inc_r)
    excluded = uid in exc or bool(groups & exc_g) or bool(roles & exc_r)
    return included and not excluded


def privileged_users(graph: AttackGraph) -> list[str]:
    """Entra users in (or PIM-eligible for) a Tier 0 directory role."""
    from .edges import TIER0_AZ_ROLE_IDS
    out = []
    for u in graph.nodes_by_type(NodeType.AZ_USER):
        groups, roles = _identity(graph, u.object_id)
        eligible = {t.upper() for _, t, d in graph.out_edges(u.object_id) if d.get("edge_type") == "AZEligibleRole"}
        if (roles | eligible) & set(TIER0_AZ_ROLE_IDS):
            out.append(u.object_id)
    return out


def evaluate(graph: AttackGraph, policies: list[Policy]) -> dict:
    """Coverage facts the audit rules report on."""
    priv = privileged_users(graph)
    mfa = [p for p in policies if p.requires_mfa() and p.all_apps()]
    uncovered, excluded_from, report_only_only = [], {}, []
    for uid in priv:
        groups, roles = _identity(graph, uid)
        enforced = [p for p in mfa if p.enforced and not p.narrowed() and applies(p, uid, groups, roles)]
        if not enforced:
            uncovered.append(uid)
            if any(p.report_only and applies(p, uid, groups, roles) for p in mfa):
                report_only_only.append(uid)
        for p in mfa:
            if p.enforced and not applies(p, uid, groups, roles):
                u = p.users()
                if "ALL" in {str(x).upper() for x in (u.get("includeUsers") or [])}:
                    excluded_from.setdefault(p.name, []).append(uid)
    legacy_blocked = any(p.enforced and p.blocks() and p.legacy_clients() and
                         "ALL" in {str(x).upper() for x in (p.users().get("includeUsers") or [])} for p in policies)
    return {"privileged": priv, "uncovered": uncovered, "report_only_only": report_only_only,
            "excluded": excluded_from, "legacy_blocked": legacy_blocked, "policies": len(policies),
            "enforced": sum(1 for p in policies if p.enforced), "mfa_policies": len(mfa)}
