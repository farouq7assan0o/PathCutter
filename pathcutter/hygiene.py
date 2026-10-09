"""`pathcutter audit`: AD hygiene findings from collected attributes (the things attack-path analysis does not show).

Attack paths answer "how could an attacker get to Tier 0". These rules answer "what is wrong with the objects
themselves": roastable accounts, credentials sitting in attributes, unconstrained delegation, stale privileged
accounts, missing LAPS, old operating systems, unfiltered trusts, and the AD CS and everyone-can-write findings that
the graph derives. Each rule is one decorated function; adding a rule is adding a function and a test.

Time-based rules (stale, password age) measure against the newest activity in the collection, not today's date, so an
old export is judged as of when it was collected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from .graph import AttackGraph, NodeType

SEVERITIES = ["info", "low", "medium", "high", "critical"]
DAY = 86400


@dataclass
class HygieneFinding:
    rule: str
    title: str
    severity: str
    why: str
    fix: str
    mitre: str = ""
    objects: list[str] = field(default_factory=list)       # display names, sorted
    total: int = 0

    def to_dict(self) -> dict:
        return {"rule": self.rule, "title": self.title, "severity": self.severity, "why": self.why, "fix": self.fix,
                "mitre": self.mitre, "total": self.total, "objects": self.objects}


class Context:
    def __init__(self, graph: AttackGraph):
        self.graph = graph
        self.users = [n for n in graph.nodes_by_type(NodeType.USER)]
        self.computers = graph.nodes_by_type(NodeType.COMPUTER)
        self.t0 = graph.tier0_nodes
        stamps = [v for n in self.users + self.computers for k in ("lastlogontimestamp", "lastlogon", "pwdlastset")
                  if isinstance((v := n.properties.get(k)), (int, float)) and v > 0]
        self.now = max(stamps) if stamps else 0                 # the collection's own clock
        self.protected_members = self._members_of_named("PROTECTED USERS")

    def _members_of_named(self, name: str) -> set[str]:
        out: set[str] = set()
        for n in self.graph.nodes_by_type(NodeType.GROUP):
            if n.display_name.upper() == name:
                out |= self.graph._recursive_members(n.object_id)
        return out

    def age_days(self, ts) -> float | None:
        if not isinstance(ts, (int, float)) or ts <= 0 or not self.now:
            return None
        return (self.now - ts) / DAY

    def is_priv(self, n) -> bool:
        return n.object_id in self.t0 or bool(n.admin_count)

    def has(self, n, key) -> bool:
        return bool(n.properties.get(key))


RULES: list[Callable[[Context], list[HygieneFinding]]] = []


def rule(fn):
    RULES.append(fn)
    return fn


def _f(rule_id, title, severity, why, fix, mitre, nodes) -> list[HygieneFinding]:
    names = sorted({getattr(n, "display_name", str(n)) for n in nodes})
    if not names:
        return []
    return [HygieneFinding(rule_id, title, severity, why, fix, mitre, names[:25], len(names))]


def _enabled(n) -> bool:
    return n.enabled is not False


# ---------------------------------------------------------------------------------------------- accounts

@rule
def keyvault_secret_readers(ctx):
    g = ctx.graph
    readers: dict[str, set[str]] = {}
    for u, v, d in g.all_edges():
        if d.get("edge_type") == "AZGetSecrets":
            readers.setdefault(v, set()).add(u)
    if not readers:
        return []
    n = sum(len(s) for s in readers.values())
    names = sorted(g.get_node_name(v) for v in readers)
    return [HygieneFinding("keyvault-secret-readers", f"{n} principal(s) can read secrets in {len(readers)} key vault(s) through access policies", "info",
                           "A secret in a key vault is often the credential of another account or service. Whoever can read it holds that identity; "
                           "access policies are separate from Azure RBAC, so role reviews do not show them.",
                           "Review each policy entry; prefer Azure RBAC data roles scoped to the single secret or vault.", "T1555", names[:25], len(readers))]


@rule
def azure_roles_unevaluated(ctx):
    ids = ctx.graph.meta.get("azure_unevaluated_roles") or []
    if not ids:
        return []
    return [HygieneFinding("azure-roles-unevaluated", f"{len(ids)} Azure role assignment(s) use a role definition that is not evaluated ({len(set(ids))} distinct)", "info",
                           "Only Owner, Contributor, User Access Administrator and VM Administrator Login are turned into edges. Custom roles (their "
                           "permissions are not in the export) and other built-in roles are not, and Azure deny assignments are never collected, "
                           "so a custom role that can write role assignments or run code on VMs is invisible here.",
                           "Review custom role definitions with Microsoft.Authorization/roleAssignments/write or Microsoft.Compute/virtualMachines/runCommand actions.",
                           "T1098", sorted(set(ids))[:10], len(ids))]


@rule
def scoped_roles_unresolved(ctx):
    n = ctx.graph.meta.get("scoped_roles_unresolved", 0)
    if not n:
        return []
    return [HygieneFinding("entra-scoped-roles-unresolved", f"{n} Entra role assignment(s) are scoped to an administrative unit whose members were not collected", "info",
                           "A helpdesk or application role scoped to an administrative unit only reaches that unit, so it is not treated as tenant-wide. "
                           "Without the unit's members the reachable accounts are unknown and the assignment adds no edges: exposure from it is a floor.",
                           "Collect administrative units (AzureHound 'AZAdministrativeUnit' with members), or review those assignments by hand.", "T1098", [], n)]


@rule
def delegation_neutralized(ctx):
    out = []
    for r in ctx.graph.meta.get("restrictions", []):
        if r.get("kind") == "protected-users":
            out.append(HygieneFinding("protected-users-neutralizes-delegation",
                                      f"{r['count']} delegation edge(s) ignored because every administrator of the target is protected", "info",
                                      "Constrained and resource-based delegation cannot impersonate Protected Users or accounts marked sensitive. "
                                      "These edges are not in the attack graph. This holds only while every administrator of the target stays protected.",
                                      "Keep all administrators of these hosts in Protected Users; add a new administrator only after protecting the account.",
                                      "T1134.001", sorted({ctx.graph.get_node_name(e["target"]) for e in r["edges"]})[:25], r["count"]))
    return out


@rule
def kerberoastable(ctx):
    bad = [n for n in ctx.users if _enabled(n) and ctx.has(n, "hasspn") and n.display_name.upper() != "KRBTGT"
           and not ctx.has(n, "gmsa") and not ctx.has(n, "msa")]
    priv = [n for n in bad if ctx.is_priv(n)]
    return (_f("kerberoast-privileged", "Privileged accounts with a service principal name (Kerberoastable)", "critical",
               "Any user can request a ticket for the SPN and crack the password offline; for a privileged account that is a direct route to Tier 0.",
               "Remove the SPN, use a group-managed service account, or set a 25+ character random password and AES-only.", "T1558.003", priv)
            + _f("kerberoast", "Accounts with a service principal name (Kerberoastable)", "medium",
                 "Any user can request a ticket for the SPN and crack the password offline.",
                 "Use gMSA, or 25+ character random passwords with AES encryption only.", "T1558.003", [n for n in bad if n not in priv]))


@rule
def asrep(ctx):
    bad = [n for n in ctx.users if _enabled(n) and ctx.has(n, "dontreqpreauth")]
    priv = [n for n in bad if ctx.is_priv(n)]
    return (_f("asrep-privileged", "Privileged accounts without Kerberos pre-authentication (AS-REP roastable)", "critical",
               "Anyone can request an encrypted blob for the account without a password and crack it offline.",
               "Clear 'Do not require Kerberos preauthentication' (Set-ADAccountControl -DoesNotRequirePreAuth $false).", "T1558.004", priv)
            + _f("asrep", "Accounts without Kerberos pre-authentication (AS-REP roastable)", "high",
                 "Anyone can request an encrypted blob for the account without a password and crack it offline.",
                 "Clear 'Do not require Kerberos preauthentication'.", "T1558.004", [n for n in bad if n not in priv]))


@rule
def password_not_required(ctx):
    return _f("passwd-notreqd", "Accounts that do not require a password", "high",
              "PASSWD_NOTREQD lets the account have an empty password.", "Set-ADUser -PasswordNotRequired $false, then set a password.",
              "T1078.002", [n for n in ctx.users if _enabled(n) and ctx.has(n, "passwordnotreqd")])


@rule
def privileged_never_expires(ctx):
    return _f("priv-pwd-never-expires", "Privileged accounts whose password never expires", "medium",
              "A password that never changes stays valid for every credential theft that ever happened.",
              "Rotate it and clear 'Password never expires' (use gMSA for services).", "T1078.002",
              [n for n in ctx.users if _enabled(n) and ctx.has(n, "pwdneverexpires") and ctx.is_priv(n)])


_PWD_IN_TEXT = re.compile(r"(?i)\b(pass(word)?|pwd|passwd|cred(ential)?s?|secret|temp(orary)? pw)\b\s*(is|:|=)\s*\S+")


@rule
def password_in_description(ctx):
    bad = [n for n in ctx.users + ctx.computers if isinstance(n.properties.get("description"), str)
           and _PWD_IN_TEXT.search(n.properties["description"])]
    return _f("pwd-in-description", "Passwords written in the description attribute", "critical",
              "The description is readable by every authenticated user. This is among the most common real-world domain compromises.",
              "Rotate the password immediately and clear the description.", "T1552.001", bad)


@rule
def credential_attributes(ctx):
    keys = ("userpassword", "unixpassword", "sfupassword", "unicodepassword")
    return _f("pwd-attributes", "Password material stored in directory attributes", "critical",
              "userPassword, unixUserPassword, msSFU30Password and unicodePwd are readable by authenticated users when populated.",
              "Clear the attribute and rotate the credential.", "T1552.001",
              [n for n in ctx.users if any(n.properties.get(k) for k in keys)])


@rule
def stale_privileged(ctx):
    bad = []
    for n in ctx.users:
        if _enabled(n) and ctx.is_priv(n):
            a = ctx.age_days(n.properties.get("lastlogontimestamp"))
            if a is not None and a > 90 and n.display_name.upper() not in ("KRBTGT",):
                bad.append(n)
    return _f("stale-privileged", "Enabled privileged accounts unused for more than 90 days", "medium",
              "Dormant privileged accounts are never noticed when abused.", "Disable or remove them.", "T1078.002", bad)


@rule
def krbtgt_age(ctx):
    out = []
    for n in ctx.users:
        if n.display_name.upper() == "KRBTGT":
            a = ctx.age_days(n.properties.get("pwdlastset"))
            if a is not None and a > 180:
                out.append(n)
    return _f("krbtgt-old", "krbtgt password older than 180 days", "high",
              "A stolen krbtgt key forges tickets (golden ticket) until the password is reset twice.",
              "Reset krbtgt twice, 10+ hours apart (use Microsoft's New-KrbtgtKeys.ps1).", "T1558.001", out)


@rule
def privileged_not_protected(ctx):
    bad = [n for n in ctx.users if _enabled(n) and n.object_id in ctx.t0 and not ctx.has(n, "sensitive")
           and n.object_id not in ctx.protected_members and n.display_name.upper() not in ("KRBTGT",)]
    return _f("priv-not-protected", "Tier 0 accounts that can still be delegated and are not in Protected Users", "medium",
              "Without 'Account is sensitive and cannot be delegated' or Protected Users, delegation attacks and credential caching apply.",
              "Add admin accounts to Protected Users (not service accounts) or set the sensitive flag.", "T1550", bad)


@rule
def sid_history(ctx):
    return _f("sid-history", "Objects carrying SID history", "medium",
              "SID history is honoured in access checks; a leftover or planted entry silently grants another principal's access.",
              "Remove the foreign SIDs once migration is complete.", "T1134.005",
              [n for n in ctx.users + ctx.computers if n.properties.get("sidhistory")])


@rule
def orphaned_admincount(ctx):
    priv_members: set[str] = set()
    for n in ctx.graph.nodes_by_type(NodeType.GROUP):
        if n.object_id in ctx.t0 or n.display_name.upper() in ("ACCOUNT OPERATORS", "BACKUP OPERATORS", "SERVER OPERATORS", "PRINT OPERATORS"):
            priv_members |= ctx.graph._recursive_members(n.object_id)
    bad = [n for n in ctx.users if n.admin_count and n.object_id not in ctx.t0 and n.object_id not in priv_members
           and n.display_name.upper() != "KRBTGT"]
    return _f("admincount-orphan", "adminCount=1 on accounts that are no longer in a protected group", "low",
              "SDProp stops managing their ACL, leaving inheritance disabled and often leftover rights.",
              "Clear adminCount and re-enable inheritance on the object.", "T1098", bad)


# ---------------------------------------------------------------------------------------------- delegation

@rule
def unconstrained(ctx):
    dcs = {n.object_id for n in ctx.computers if n.properties.get("isdc")}
    bad = [n for n in ctx.users + ctx.computers if _enabled(n) and ctx.has(n, "unconstraineddelegation") and n.object_id not in dcs]
    return _f("unconstrained-delegation", "Non-DC accounts trusted for unconstrained delegation", "high",
              "Anything that authenticates to them leaves a forwardable TGT in memory; with a coerced DC that is a domain compromise.",
              "Switch to constrained delegation or RBCD; remove the TRUSTED_FOR_DELEGATION flag.", "T1558", bad)


@rule
def constrained_protocol_transition(ctx):
    bad = [n for n in ctx.users + ctx.computers if _enabled(n) and ctx.has(n, "trustedtoauth")]
    return _f("protocol-transition", "Accounts allowed to delegate with protocol transition (S4U2self)", "medium",
              "They can obtain a ticket to the allowed services as any user without that user's involvement.",
              "Prefer Kerberos-only constrained delegation or RBCD; restrict the allowed-to-delegate list.", "T1558", bad)


# ---------------------------------------------------------------------------------------------- computers

_OLD_OS = re.compile(r"(?i)(2000|2003|2008|2012|xp\b|vista|windows 7|windows 8\b|windows 8\.1)")


@rule
def old_os(ctx):
    return _f("old-os", "Computers running unsupported Windows versions", "high",
              "No security updates: remotely exploitable flaws stay open.", "Upgrade or isolate the hosts.", "T1210",
              [n for n in ctx.computers if _enabled(n) and isinstance(n.properties.get("operatingsystem"), str)
               and _OLD_OS.search(n.properties["operatingsystem"])])


@rule
def no_laps(ctx):
    dcs = {n.object_id for n in ctx.computers if n.properties.get("isdc")}
    collected = [n for n in ctx.computers if _enabled(n) and n.object_id not in dcs and "haslaps" in n.properties]
    return _f("no-laps", "Computers without LAPS", "medium",
              "A shared local administrator password makes one stolen hash a path to every machine.",
              "Deploy Windows LAPS and have it manage the local administrator account.", "T1550.002",
              [n for n in collected if not n.properties.get("haslaps")])


@rule
def stale_computers(ctx):
    bad = []
    for n in ctx.computers:
        a = ctx.age_days(n.properties.get("lastlogontimestamp"))
        if _enabled(n) and a is not None and a > 90 and not n.properties.get("isdc"):
            bad.append(n)
    return _f("stale-computers", "Enabled computer accounts unused for more than 90 days", "low",
              "Abandoned machine accounts keep their passwords and group memberships and are easy to take over.",
              "Disable and later remove them.", "T1078.002", bad)


# ---------------------------------------------------------------------------------------------- domain and graph

@rule
def old_functional_level(ctx):
    bad = [n for n in ctx.graph.nodes_by_type(NodeType.DOMAIN)
           if re.search(r"(2000|2003|2008)", str(n.properties.get("functionallevel") or ""))]
    return _f("old-functional-level", "Domain functional level of Windows Server 2008 or older", "medium",
              "It disables modern protections (AES, gMSA, Protected Users, authentication silos).", "Raise the functional level.", "T1078", bad)


@rule
def unfiltered_trusts(ctx):
    out = []
    for u, v, d in ctx.graph.all_edges():
        if d.get("edge_type") == "TrustedBy" and d.get("sid_filtering") is False and d.get("trust_type") in ("External", "Forest"):
            out.append(ctx.graph.get_node(v) or ctx.graph.get_node(u))
    return _f("trust-no-sid-filtering", "External or forest trusts without SID filtering", "high",
              "SID history from the trusted side is honoured: a compromised partner domain becomes a path into this one.",
              "netdom trust <trusting> /domain:<trusted> /quarantine:yes", "T1134.005", [n for n in out if n is not None])


_EVERYONE = ("EVERYONE", "AUTHENTICATED USERS", "DOMAIN USERS", "DOMAIN COMPUTERS", "USERS")


@rule
def broad_principals_with_rights(ctx):
    g = ctx.graph
    findings: dict[str, set[str]] = {}
    adcs: dict[str, set[str]] = {}
    from .pathfinder import _ATTACK_EDGES
    for u, v, d in g.all_edges():
        et = d.get("edge_type")
        if et in _ATTACK_EDGES and et not in ("MemberOf", "HasSession", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "TrustedBy"):
            src = g.get_node(u)
            everyone = src is not None and src.display_name.upper() in _EVERYONE
            if everyone and et.startswith(("ADCS", "GoldenCert")):
                adcs.setdefault(src.display_name, set()).add(et)
            elif everyone and v not in ctx.t0:
                findings.setdefault(f"{src.display_name} -> {et}", set()).add(g.get_node(v).display_name if g.get_node(v) else v)
    out: list[HygieneFinding] = []
    for who, kinds in sorted(adcs.items()):
        out.append(HygieneFinding("adcs-everyone", f"{who} can escalate to domain admin through AD CS ({', '.join(sorted(kinds))})", "critical",
                                  "Every account in that group can obtain a certificate that authenticates as any principal.",
                                  "Fix the template or CA setting behind each technique (see `pathcutter syntax edges`), then re-collect.",
                                  "T1649", [], len(kinds)))
    for key, targets in sorted(findings.items()):
        kind = key.split(" -> ")[1]
        sev = "critical" if kind.startswith(("ADCSESC", "GoldenCert", "GenericAll", "WriteDacl", "WriteOwner", "Owns", "DCSync")) else "high"
        out.append(HygieneFinding("broad-rights", f"Everyone-like group holds {kind}: {key.split(' -> ')[0]}", sev,
                                  "Every user (or computer) in the domain has this right, so every account is an attacker's foothold.",
                                  "Remove the ACE from the broad group and grant it to a narrow, named group.", "T1098",
                                  sorted(targets)[:25], len(targets)))
    return out


# ---------------------------------------------------------------------------------------------- privileged structure

def _members(ctx, group_names) -> list:
    out = []
    for n in ctx.graph.nodes_by_type(NodeType.GROUP):
        if n.display_name.upper() in group_names:
            out += [ctx.graph.get_node(m) for m in ctx.graph._recursive_members(n.object_id) if ctx.graph.get_node(m)]
    return out


@rule
def schema_enterprise_admins(ctx):
    bad = [m for m in _members(ctx, {"SCHEMA ADMINS", "ENTERPRISE ADMINS"}) if m.display_name.upper() != "ADMINISTRATOR"]
    return _f("ea-sa-populated", "Schema Admins / Enterprise Admins have members other than the built-in Administrator", "high",
              "These forest-wide groups should be empty except while a forest operation is under way.",
              "Remove the members; add them temporarily when needed.", "T1078.002", bad)


@rule
def many_domain_admins(ctx):
    das = [m for m in _members(ctx, {"DOMAIN ADMINS"}) if m.node_type == NodeType.USER and m.display_name.upper() not in ("ADMINISTRATOR",)]
    return _f("many-domain-admins", f"{len(das)} accounts in Domain Admins", "medium",
              "Every Domain Admin is a credential that, once stolen, owns the domain. More than a handful is almost always excess.",
              "Remove day-to-day accounts; use just-in-time elevation.", "T1078.002", das) if len(das) > 5 else []


@rule
def guest_enabled(ctx):
    return _f("guest-enabled", "The Guest account is enabled", "medium", "Anonymous-style access with whatever rights Guest has been given.",
              "Disable the Guest account.", "T1078.002",
              [n for n in ctx.users if n.display_name.upper() == "GUEST" and _enabled(n)])


@rule
def service_accounts_privileged(ctx):
    bad = [m for m in _members(ctx, {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "BACKUP OPERATORS", "ACCOUNT OPERATORS", "SERVER OPERATORS"})
           if m.node_type == NodeType.USER and ctx.has(m, "hasspn") and _enabled(m)]
    return _f("svc-privileged", "Service accounts (with an SPN) in privileged groups", "high",
              "Their passwords are roastable and often reused across the machines they run on.",
              "Use a gMSA with only the rights the service needs.", "T1558.003", bad)


@rule
def non_t0_with_dcsync_or_domain_control(ctx):
    g = ctx.graph
    dcsync, domctl, sdholder = {}, {}, {}
    for u, v, d in g.all_edges():
        et = d.get("edge_type")
        src, dst = g.get_node(u), g.get_node(v)
        if src is None or dst is None or u in ctx.t0:
            continue
        if et == "DCSync":
            dcsync[u] = src
        elif dst.node_type == NodeType.DOMAIN and et in ("GenericAll", "WriteDacl", "WriteOwner", "Owns", "GenericWrite"):
            domctl[u] = src
        elif dst.display_name.upper() == "ADMINSDHOLDER" and et in ("GenericAll", "WriteDacl", "WriteOwner", "Owns", "GenericWrite"):
            sdholder[u] = src
    return (_f("dcsync-nonpriv", "Non-privileged principals can replicate the directory (DCSync)", "critical",
               "They can read every password hash in the domain.", "Remove the replication rights from the domain root ACL.", "T1003.006", dcsync.values())
            + _f("domain-control-nonpriv", "Non-privileged principals hold write access on the domain object", "critical",
                 "WriteDacl or GenericAll on the domain grants DCSync to themselves.", "Remove the ACE from the domain root.", "T1098", domctl.values())
            + _f("adminsdholder-nonpriv", "Non-privileged principals can modify AdminSDHolder", "critical",
                 "SDProp copies its ACL onto every protected account within an hour: a persistent backdoor over all admins.",
                 "Remove the ACE from CN=AdminSDHolder.", "T1098", sdholder.values()))


# ---------------------------------------------------------------------------------------------- NTLM relay surface (when collected)

@rule
def smb_signing(ctx):
    dcs = {n.object_id for n in ctx.computers if n.properties.get("isdc")}
    off = [n for n in ctx.computers if _enabled(n) and n.properties.get("smbsigning") is False]
    return (_f("smb-signing-dc", "Domain controllers that do not require SMB signing", "critical",
               "Coerced authentication can be relayed to them.", "Require SMB signing (Microsoft network server: Digitally sign communications (always)).",
               "T1557.001", [n for n in off if n.object_id in dcs])
            + _f("smb-signing", "Servers and workstations that do not require SMB signing", "medium",
                 "NTLM relay to SMB is possible when the host's own account is not required to sign.", "Require SMB signing by GPO.", "T1557.001",
                 [n for n in off if n.object_id not in dcs]))


@rule
def ldap_signing(ctx):
    return _f("ldap-signing", "Domain controllers that do not require LDAP signing or channel binding", "high",
              "NTLM relay to LDAP writes RBCD or shadow credentials on any computer account.",
              "Set LDAP server signing to Require signing and LDAP channel binding to Always.", "T1557",
              [n for n in ctx.computers if n.properties.get("isdc") and n.properties.get("ldapsigning") is False])


@rule
def webclient(ctx):
    return _f("webclient", "Hosts running the WebClient service", "medium",
              "It allows coercion over HTTP, which relays to LDAP even where SMB signing is enforced.",
              "Disable the WebClient service where WebDAV is not needed.", "T1557",
              [n for n in ctx.computers if _enabled(n) and n.properties.get("webclientrunning") is True])


# ---------------------------------------------------------------------------------------------- Entra conditional access

@rule
def conditional_access(ctx):
    g = ctx.graph
    from . import conditional_access as ca
    entra = bool(g.nodes_by_type(NodeType.AZ_USER))
    raw = g.meta.get("conditional_access")
    if not entra:
        return []
    if not raw:
        return [HygieneFinding("ca-not-collected", "Entra data was collected without Conditional Access policies", "info",
                               "Whether administrators are forced to use MFA cannot be assessed.",
                               "Export them: Get-MgIdentityConditionalAccessPolicy -All | ConvertTo-Json -Depth 10 > ca.json, and add the file to the collection.",
                               "T1078.004", [], 0)]
    pol = ca.load(raw)
    res = ca.evaluate(g, pol)
    name = lambda i: (g.get_node(i).display_name if g.get_node(i) else i)           # noqa: E731
    out: list[HygieneFinding] = []
    if res["privileged"] and len(res["uncovered"]) == len(res["privileged"]):
        out.append(HygieneFinding("ca-no-admin-mfa", "No enforced Conditional Access policy requires MFA for Entra administrators", "critical",
                                  "A phished or sprayed administrator password is enough to take the tenant.",
                                  "Create a policy: users = directory roles (all privileged roles), apps = All, grant = require authentication strength / MFA.",
                                  "T1078.004", sorted(name(u) for u in res["privileged"])[:25], len(res["privileged"])))
    elif res["uncovered"]:
        out.append(HygieneFinding("ca-admin-uncovered", "Entra administrators not covered by an enforced MFA policy for all cloud apps", "high",
                                  "These administrators can sign in with a password alone (or the covering policy is report-only / narrowed by conditions).",
                                  "Include their roles or groups in the MFA policy and remove them from its exclusions.",
                                  "T1078.004", sorted(name(u) for u in res["uncovered"])[:25], len(res["uncovered"])))
    for pname, users in sorted(res["excluded"].items()):
        out.append(HygieneFinding("ca-admin-excluded", f"Administrators are excluded from the MFA policy '{pname}'", "high",
                                  "Exclusions of privileged accounts (often break-glass accounts that became permanent) are the usual gap.",
                                  "Keep exactly two monitored break-glass accounts excluded; cover every other administrator.",
                                  "T1078.004", sorted(name(u) for u in users)[:25], len(users)))
    if res["report_only_only"]:
        out.append(HygieneFinding("ca-report-only", "MFA for administrators exists only in report-only mode", "medium",
                                  "A report-only policy logs what would happen and enforces nothing.",
                                  "Switch the policy to On after reviewing the sign-in impact.", "T1078.004",
                                  sorted(name(u) for u in res["report_only_only"])[:25], len(res["report_only_only"])))
    if not res["legacy_blocked"]:
        out.append(HygieneFinding("ca-legacy-auth", "Legacy authentication is not blocked by Conditional Access", "high",
                                  "Basic-auth protocols (IMAP, POP, SMTP, EWS) ignore MFA, so password spraying bypasses it.",
                                  "Create a policy: all users, client apps = Exchange ActiveSync + other clients, grant = block.",
                                  "T1110.003", [], 0))
    return out


# ---------------------------------------------------------------------------------------------- entry

def audit(graph: AttackGraph) -> list[HygieneFinding]:
    ctx = Context(graph)
    out: list[HygieneFinding] = []
    for fn in RULES:
        out.extend(fn(ctx))
    out.sort(key=lambda f: (-SEVERITIES.index(f.severity), -f.total, f.rule))
    return out


def render(findings: list[HygieneFinding], min_severity: str = "info", names: int = 6) -> str:
    floor = SEVERITIES.index(min_severity)
    rows = [f for f in findings if SEVERITIES.index(f.severity) >= floor]
    counts = {s: sum(1 for f in rows if f.severity == s) for s in reversed(SEVERITIES)}
    out = ["", "  pathcutter audit", "  " + "-" * 60,
           "  " + "   ".join(f"{n} {s}" for s, n in counts.items() if n) or "  nothing found", ""]
    for f in rows:
        shown = ", ".join(f.objects[:names]) + (f" and {f.total - names} more" if f.total > names else "")
        out.append(f"  [{f.severity:<8}] {f.title}  ({f.total})")
        out.append(f"             {shown}")
        out.append(f"             why: {f.why}")
        out.append(f"             fix: {f.fix}" + (f"   [{f.mitre}]" if f.mitre else ""))
    out.append("")
    out.append("  These are attribute findings; `pathcutter analyze` shows which of them lead to Tier 0.")
    return "\n".join(out) + "\n"
