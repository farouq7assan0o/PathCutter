"""Detections for the attack paths you have NOT fixed.

Fixing every path is rarely possible: the business needs the helpdesk group, the backup service account,
the delegation. For what remains, PathCutter turns each residual choke point into a detection scoped to
the exact objects involved, instead of a generic "monitor Domain Admins" checklist.

Everything is built from one small intermediate representation (event ids + field conditions) and
compiled to Sigma, Splunk SPL, Microsoft Sentinel KQL and Elastic KQL, so the four outputs always agree.
All names that end up in a rule come from AD (attacker-controllable), so every compiler quotes strictly.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field

from .edges import get_edge_type
from .exposure import compute_exposure
from .graph import AttackGraph, NodeType

NAMESPACE = uuid.UUID("5f0d6c1e-2b7a-4c52-9d0e-7a6f2b3c9a10")
MAX_OBJECTS_PER_RULE = 200

# audit prerequisites: key -> (auditpol subcategory, what else has to be true)
AUDIT = {
    "group-mgmt": ("Security Group Management", ""),
    "user-mgmt": ("User Account Management", ""),
    "ds-changes": ("Directory Service Changes", "Event 5136 is only written for objects whose SACL audits the write (Everyone, Write All Properties). Configure the SACL on the domain root or the OUs you care about."),
    "ds-access": ("Directory Service Access", "Event 4662 needs a SACL on the object. For DCSync, audit 'Control Access' on the domain root."),
    "logon": ("Logon", ""),
    "special-logon": ("Special Logon", ""),
    "kerberos-service": ("Kerberos Service Ticket Operations", ""),
    "certification": ("Certification Services", "Also enable auditing on the CA itself (certutil -setreg CA\\AuditFilter 127)."),
}


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class Cond:
    field: str
    values: list[str]
    negate: bool = False
    op: str = "eq"           # eq | contains | startswith | endswith

    def __post_init__(self) -> None:
        # Names come from AD. Control characters have no business in a rule value and would split a query
        # across lines, so they are neutralised here for every compiler at once.
        self.values = [_CONTROL.sub(" ", v) for v in self.values]


@dataclass
class Rule:
    key: str
    title: str
    description: str
    level: str
    event_ids: list[int]
    where: list[Cond]
    objects: list[str] = field(default_factory=list)
    covers: list[dict] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    audit: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    test_command: str = ""
    expected: str = ""
    response: list[str] = field(default_factory=list)
    part: int = 1

    @property
    def id(self) -> str:
        blob = json.dumps([self.key, self.part, self.title, self.event_ids,
                           [(c.field, c.values, c.negate, c.op) for c in self.where]], sort_keys=True)
        return str(uuid.uuid5(NAMESPACE, blob))

    @property
    def slug(self) -> str:
        return f"pathcutter_{self.key.lower()}" + (f"_{self.part}" if self.part > 1 else "")


# -------------------------------------------------------------------- helpers

def sam(graph: AttackGraph, node_id: str) -> str:
    """The name Windows writes in events for this object (users/groups: sAMAccountName, computers: HOST$)."""
    n = graph.get_node(node_id)
    if n is None:
        return node_id
    if n.node_type == NodeType.COMPUTER:
        return n.display_name.split(".")[0] + "$"
    return n.display_name


def _host(graph: AttackGraph, node_id: str) -> str:
    n = graph.get_node(node_id)
    return n.display_name.split(".")[0] if n else node_id


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for i in items:
        k = i.lower()
        if k not in seen:
            seen.add(k)
            out.append(i)
    return out


def actors_of(graph: AttackGraph, source_id: str, limit: int = 12) -> list[str]:
    """Who can abuse an edge: the source, plus every transitive member if it is a group."""
    out = [sam(graph, source_id)]
    n = graph.get_node(source_id)
    if n and n.node_type == NodeType.GROUP:
        seen, stack = {source_id}, [source_id]
        while stack and len(out) < limit * 3:
            cur = stack.pop()
            for u, _, d in graph.in_edges(cur):
                if d.get("edge_type") == "MemberOf" and u not in seen:
                    seen.add(u)
                    m = graph.get_node(u)
                    if m and m.node_type != NodeType.GROUP:
                        out.append(sam(graph, u))
                    elif m:
                        stack.append(u)
    return _dedupe(out)[:limit]


def _tags(*edge_names: str, tactic: str = "") -> list[str]:
    tags = ["attack." + tactic] if tactic else []
    for e in edge_names:
        info = get_edge_type(e)
        if info and info.mitre:
            tags.append("attack." + info.mitre.lower().replace(" ", ""))
    return list(dict.fromkeys(tags))


def _cn(names: list[str]) -> list[str]:
    return [f"CN={n.rstrip('$')}," for n in names]


# ---------------------------------------------------------------- rule kinds

def _make(key: str, objects: list[str], builder, covers=None, actors=None) -> list[Rule]:
    objs = _dedupe(objects)
    rules = []
    for i in range(0, len(objs), MAX_OBJECTS_PER_RULE):
        chunk = objs[i:i + MAX_OBJECTS_PER_RULE]
        r = builder(chunk)
        r.key, r.part, r.objects = key, i // MAX_OBJECTS_PER_RULE + 1, chunk
        r.covers, r.actors = covers or [], actors or []
        rules.append(r)
    return rules


def _group_builder(title: str, desc: str, level: str, fp: str):
    def b(chunk: list[str]) -> Rule:
        return Rule("", title, desc, level, [4728, 4732, 4756], [Cond("TargetUserName", chunk)],
                    tags=["attack.privilege_escalation", "attack.persistence", "attack.t1098"], audit=["group-mgmt"],
                    falsepositives=["Approved joiner/mover/leaver changes: tune with an allowlist of change-management accounts.", fp],
                    test_command="Add-ADGroupMember -Identity '<monitored group>' -Members '<test user>'; "
                                 "Remove-ADGroupMember -Identity '<monitored group>' -Members '<test user>' -Confirm:$false",
                    expected="Event 4728/4732/4756 on a domain controller: TargetUserName = the group, MemberSid = the test user",
                    response=["Confirm a change ticket exists for the member added.",
                              "If not, remove the member and treat the SubjectUserName account as compromised.",
                              "Re-run `pathcutter check` with that member added to see what it exposed."])
    return b


def _ds_builder(title: str, desc: str, level: str, attrs: list[str], edges: list[str], test: str, extra: list[Cond] | None = None):
    def b(chunk: list[str]) -> Rule:
        where = [Cond("ObjectDN", _cn(chunk), op="contains")] + (extra or [])
        if attrs:
            where.append(Cond("AttributeLDAPDisplayName", attrs))
        return Rule("", title, desc, level, [5136], where, tags=_tags(*edges, tactic="privilege_escalation"),
                    audit=["ds-changes"], falsepositives=["Directory administration and provisioning tools: tune by SubjectUserName."],
                    test_command=test,
                    expected="Event 5136 on a domain controller for the object, with the attribute in AttributeLDAPDisplayName",
                    response=["Identify SubjectUserName and whether the change was approved.",
                              "Revert the change and rotate credentials of the affected object.",
                              "Review what else SubjectUserName modified in the same window."])
    return b


def _password_builder(chunk: list[str]) -> Rule:
    return Rule("", "Password reset on an account controlled by a residual attack path",
                "Someone reset the password of an account that residual attack paths pass through, without knowing the old password.",
                "high", [4724], [Cond("TargetUserName", chunk), Cond("SubjectUserName", chunk, negate=True)],
                tags=_tags("ForceChangePassword", tactic="credential_access"), audit=["user-mgmt"],
                falsepositives=["Helpdesk password resets of the account (tune with a helpdesk allowlist)."],
                test_command="Set-ADAccountPassword -Identity '<test user>' -Reset -NewPassword (Read-Host -AsSecureString)",
                expected="Event 4724 on a domain controller: TargetUserName = the account, SubjectUserName = the resetter",
                response=["Verify the reset with the account owner.", "Expire sessions and rotate the credential again.",
                          "Review what the account can reach (`pathcutter graph`)."])


def _dcsync_builder(chunk: list[str]) -> Rule:
    return Rule("", "Directory replication requested by a non-domain-controller (DCSync)",
                "DS-Replication-Get-Changes(-All) was exercised by an account that is not a domain controller.", "critical",
                [4662], [Cond("Properties", ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                                             "89e95b76-444d-4c62-991a-0facbeda640c"], op="contains"),
                         Cond("SubjectUserName", ["$"], negate=True, op="endswith")],
                tags=_tags("DCSync", tactic="credential_access"), audit=["ds-access"],
                falsepositives=["Azure AD Connect / MSOL_ accounts and other directory synchronisation products."],
                test_command="mimikatz # lsadump::dcsync /user:krbtgt   (lab only, from a non-DC)",
                expected="Event 4662 with the replication GUIDs in Properties and a user SubjectUserName",
                response=["Treat the account as compromised.", "Rotate krbtgt twice.", "Hunt for the host the request came from."])


def _managed_password_builder(chunk: list[str]) -> Rule:
    return Rule("", "Managed password (gMSA/LAPS) read on an object controlled by a residual attack path",
                "msDS-ManagedPassword or the LAPS password attribute was read.", "high", [4662],
                [Cond("ObjectName", _cn(chunk), op="contains"),
                 Cond("Properties", ["e362ed86-b728-0842-b27d-2dea7a9df218", "ms-Mcs-AdmPwd", "msLAPS-Password"], op="contains")],
                tags=_tags("ReadGMSAPassword", tactic="credential_access"), audit=["ds-access"],
                falsepositives=["Hosts that legitimately retrieve their own gMSA password."],
                test_command="Get-ADServiceAccount <gMSA> -Properties 'msDS-ManagedPassword'   (lab)",
                expected="Event 4662 for the object with the password attribute GUID in Properties",
                response=["Confirm the reader is an authorised host.", "Rotate the managed password.", "Review logons using the account."])


LOGON_KINDS = [
    ("ADMIN_LOGON", ["AdminTo", "SQLAdmin", "ExecuteDCOM"], [3, 2, 9], [4624, 4672], "high",
     "Remote administrative logon to a host reachable by a residual attack path",
     "A network logon with administrative privileges reached a host that attack paths pass through."),
    ("RDP_LOGON", ["CanRDP"], [10, 7, 12], [4624], "medium",
     "RDP logon to a host reachable by a residual attack path",
     "An interactive remote logon reached a host that attack paths pass through."),
    ("PSREMOTE_LOGON", ["CanPSRemote"], [3], [4624], "medium",
     "PowerShell remoting logon to a host reachable by a residual attack path",
     "A network logon (WinRM) reached a host that attack paths pass through."),
]


def _logon_builder(edges, ltypes, events, level, title, desc):
    def b(chunk: list[str]) -> Rule:
        return Rule("", title, desc, level, events,
                    [Cond("Computer", chunk, op="startswith"), Cond("LogonType", [str(x) for x in ltypes]),
                     Cond("TargetUserName", ["$", "ANONYMOUS LOGON"], negate=True, op="endswith")],
                    tags=_tags(*edges, tactic="lateral_movement"), audit=["logon", "special-logon"],
                    falsepositives=["Administrators and management tooling that legitimately use these rights."],
                    test_command="Enter-PSSession -ComputerName <host>   (or mstsc /v:<host>) from a lab account",
                    expected="Event 4624 on the host with the matching LogonType (and 4672 for administrative rights)",
                    response=["Check the source IpAddress and whether the account normally logs on here.",
                              "Review processes started in the session (4688 / Sysmon).", "Isolate the host if unexpected."])
    return b


def _delegation_builder(chunk: list[str]) -> Rule:
    return Rule("", "Constrained delegation (S4U2Proxy) used toward a residual attack-path target",
                "A service ticket was obtained through delegation for a service on a host that attack paths pass through.",
                "high", [4769], [Cond("ServiceName", chunk, op="startswith"), Cond("TransitedServices", ["-", ""], negate=True)],
                tags=_tags("AllowedToDelegate", tactic="privilege_escalation"), audit=["kerberos-service"],
                falsepositives=["Legitimate constrained-delegation applications (web front ends, SQL)."],
                test_command="Rubeus.exe s4u /user:<svc> /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/<host>   (lab)",
                expected="Event 4769 on a domain controller with TransitedServices populated",
                response=["Identify the delegating account and the impersonated user.", "Review the host for the session that followed.",
                          "Remove or constrain the delegation if it is not required."])


def _gpo_builder(chunk: list[str]) -> Rule:
    return Rule("", "Group Policy object changed on a GPO controlled by a residual attack path",
                "A GPO that links to a high-value scope was modified.", "high", [5136],
                [Cond("ObjectClass", ["groupPolicyContainer"]), Cond("ObjectDN", _cn(chunk), op="contains")],
                tags=_tags("GPOControlsObject", tactic="privilege_escalation"), audit=["ds-changes"],
                falsepositives=["Planned GPO edits by the policy team."],
                test_command="Set-GPRegistryValue -Name '<GPO>' -Key 'HKLM\\Software\\Test' -ValueName t -Type String -Value x   (lab)",
                expected="Event 5136 for the groupPolicyContainer object (versionNumber change)",
                response=["Compare the GPO to its last approved version.", "Check scheduled tasks and scripts it pushes.", "Restore from backup if unapproved."])


def _adcs_builder(chunk: list[str]) -> Rule:
    return Rule("", "Certificate issued from a template or CA controlled by a residual attack path",
                "A certificate was requested or issued for a template/CA that attack paths pass through (ADCS abuse).", "high",
                [4886, 4887], [Cond("CertificateTemplate", chunk, op="contains")],
                tags=_tags("Enroll", "ManageCA", tactic="privilege_escalation"), audit=["certification"],
                falsepositives=["Normal certificate enrolment."],
                test_command="certreq -new request.inf request.req; certreq -submit request.req   (lab)",
                expected="Event 4886/4887 on the CA with the template name",
                response=["Compare the requester with the SAN in the issued certificate.", "Revoke the certificate if unexpected.",
                          "Review the template permissions with `pathcutter graph`."])


def build_rules(graph: AttackGraph, points: list[dict], include_watches: bool = True) -> list[Rule]:
    """points: [{source_id, target_id, edge_type, paths}] - the residual choke points to cover."""
    rules: list[Rule] = []
    by_edge: dict[str, list[dict]] = {}
    for p in points:
        by_edge.setdefault(p["edge_type"], []).append(p)

    def collect(edges: list[str], name=sam):
        objs, covers, actors = [], [], []
        for e in edges:
            for p in by_edge.get(e, []):
                objs.append(name(graph, p["target_id"]))
                covers.append({"source": sam(graph, p["source_id"]), "edge": e, "target": sam(graph, p["target_id"]),
                               "paths": p.get("paths", 0)})
                actors += actors_of(graph, p["source_id"])
        return objs, covers, _dedupe(actors)[:15]

    if include_watches:
        t0_groups = [sam(graph, n) for n in graph.tier0_nodes if graph.get_node(n) and graph.get_node(n).node_type == NodeType.GROUP]
        rules += _make("T0_GROUP_MEMBERSHIP", t0_groups, _group_builder(
            "Member added to a Tier 0 group", "A principal was added to a Tier 0 group: it becomes a domain-wide administrator.",
            "critical", "Break-glass use and onboarding of new administrators."))
        exposed = compute_exposure(graph).exposed()
        exposed_groups = [sam(graph, n) for n in exposed if graph.get_node(n) and graph.get_node(n).node_type == NodeType.GROUP]
        rules += _make("EXPOSED_GROUP_MEMBERSHIP", exposed_groups, _group_builder(
            "Member added to a group that can reach Tier 0",
            "A principal joined a group with an attack path to Tier 0 and so inherits that path (the runtime twin of `pathcutter check`).",
            "high", "Normal staffing changes: alert on the unexpected."))

    objs, covers, actors = collect(["AddMember", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns"])
    group_names = {sam(graph, n.object_id) for n in graph.nodes_by_type(NodeType.GROUP)}
    groups = [o for o in objs if o in group_names]
    rules += _make("ADD_MEMBER_ABUSE", groups, _group_builder(
        "Membership change on a group controlled by a residual attack path",
        "Someone who holds AddMember/GenericAll over this group changed its membership.", "high", "Legitimate group administration."),
        covers=[c for c in covers if c["target"] in groups], actors=actors)

    objs, covers, actors = collect(["WriteDacl", "WriteOwner", "Owns", "GenericAll"])
    rules += _make("ACL_CHANGE", objs, _ds_builder(
        "DACL or owner changed on an object controlled by a residual attack path",
        "nTSecurityDescriptor was modified on an object that residual attack paths pass through.", "high",
        ["nTSecurityDescriptor"], ["WriteDacl", "WriteOwner"],
        "$acl = Get-Acl 'AD:\\<object DN>'; Set-Acl 'AD:\\<object DN>' $acl   (lab)"), covers=covers, actors=actors)

    objs, covers, actors = collect(["GenericWrite", "GenericAll", "WriteSPN", "AddAllowedToAct", "AllowedToAct", "WriteKeyCredentialLink"])
    rules += _make("SENSITIVE_ATTRIBUTE_WRITE", objs, _ds_builder(
        "Security-relevant attribute written on an object controlled by a residual attack path",
        "servicePrincipalName, RBCD, shadow-credential, delegation, script or UAC attributes were modified.", "high",
        ["servicePrincipalName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink",
         "msDS-AllowedToDelegateTo", "scriptPath", "userAccountControl"], ["WriteSPN", "AddAllowedToAct", "WriteKeyCredentialLink"],
        "Set-ADUser <test user> -ServicePrincipalNames @{Add='http/pc-test'}   (lab)"), covers=covers, actors=actors)

    objs, covers, actors = collect(["ForceChangePassword", "GenericAll"])
    user_names = {sam(graph, n.object_id) for n in graph.nodes_by_type(NodeType.USER)}
    users = [o for o in objs if o in user_names]
    rules += _make("PASSWORD_RESET", users, _password_builder, covers=[c for c in covers if c["target"] in users], actors=actors)

    objs, covers, actors = collect(["DCSync"])
    rules += _make("DCSYNC", ["domain"] if objs else [], _dcsync_builder, covers=covers, actors=actors)

    objs, covers, actors = collect(["ReadGMSAPassword", "ReadLAPSPassword"])
    rules += _make("MANAGED_PASSWORD_READ", objs, _managed_password_builder, covers=covers, actors=actors)

    for key, edges, ltypes, events, level, title, desc in LOGON_KINDS:
        objs, covers, actors = collect(edges, name=_host)
        rules += _make(key, objs, _logon_builder(edges, ltypes, events, level, title, desc), covers=covers, actors=actors)

    objs, covers, actors = collect(["AllowedToDelegate"], name=_host)
    rules += _make("DELEGATION_USE", objs, _delegation_builder, covers=covers, actors=actors)
    objs, covers, actors = collect(["GPOControlsObject"])
    rules += _make("GPO_CHANGE", objs, _gpo_builder, covers=covers, actors=actors)
    objs, covers, actors = collect(["Enroll", "AutoEnroll", "ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag", "WritePKINameFlag"])
    rules += _make("ADCS_ISSUANCE", objs, _adcs_builder, covers=covers, actors=actors)
    return rules


# ------------------------------------------------------------------ compilers

def _yaml_str(v: str) -> str:
    return json.dumps(v, ensure_ascii=True)


_SIGMA_MOD = {"eq": "", "contains": "|contains", "startswith": "|startswith", "endswith": "|endswith"}


def to_sigma(rule: Rule) -> str:
    sel = ["    EventID:"] + [f"        - {i}" for i in rule.event_ids]
    flt: list[str] = []
    for c in rule.where:
        block = [f"    {c.field}{_SIGMA_MOD[c.op]}:"] + [f"        - {_yaml_str(v)}" for v in c.values]
        (flt if c.negate else sel).extend(block)
    scope = ", ".join(rule.objects[:8]) + (" ..." if len(rule.objects) > 8 else "")
    out = [
        f"title: {_yaml_str(rule.title + (f' (part {rule.part})' if rule.part > 1 else ''))}",
        f"id: {rule.id}",
        "status: experimental",
        f"description: {_yaml_str(rule.description + ' Scoped by PathCutter to: ' + scope)}",
        "references:", "    - https://github.com/farouq7assan0o/PathCutter",
        "author: PathCutter", "tags:",
    ] + [f"    - {t}" for t in rule.tags] + ["logsource:", "    product: windows", "    service: security", "detection:",
                                              "    selection:"] + ["    " + s for s in sel]
    cond = "selection"
    if flt:
        out += ["    filter_exclude:"] + ["    " + s for s in flt]
        cond += " and not filter_exclude"
    out += [f"    condition: {cond}", "falsepositives:"] + [f"    - {_yaml_str(f)}" for f in rule.falsepositives if f]
    out.append(f"level: {rule.level}")
    return "\n".join(out) + "\n"


def _spl_q(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _spl_value(c: Cond, v: str) -> str:
    if c.op == "contains":
        return _spl_q("*" + v + "*")
    if c.op == "startswith":
        return _spl_q(v + "*")
    if c.op == "endswith":
        return _spl_q("*" + v)
    return _spl_q(v)


def to_spl(rule: Rule, index: str = "wineventlog") -> str:
    parts = [f"index={index}", 'sourcetype="XmlWinEventLog:Security"',
             f"EventCode IN ({', '.join(str(i) for i in rule.event_ids)})"]
    for c in rule.where:
        vals = [_spl_value(c, v) for v in c.values]
        expr = f"{c.field}={vals[0]}" if len(vals) == 1 else f"{c.field} IN ({', '.join(vals)})"
        parts.append(f"NOT {expr}" if c.negate else expr)
    return (" ".join(parts) + "\n| stats count min(_time) as first_seen max(_time) as last_seen "
            "values(SubjectUserName) as actor values(TargetUserName) as target by host, EventCode")


def _kql_q(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


_KQL_COLUMNS = {"TargetUserName", "SubjectUserName", "TargetDomainName", "SubjectDomainName", "LogonType", "MemberName",
                "MemberSid", "TargetSid", "IpAddress", "WorkstationName", "ObjectName", "ObjectType", "Properties",
                "AccessMask", "ServiceName", "TransitedServices", "Computer", "CertificateTemplate"}
_KQL_OP = {"contains": "contains", "startswith": "startswith", "endswith": "endswith"}


def to_kql(rule: Rule) -> str:
    lines = ["SecurityEvent", f"| where EventID in ({', '.join(str(i) for i in rule.event_ids)})"]
    extra = list(dict.fromkeys(c.field for c in rule.where if c.field not in _KQL_COLUMNS))
    if extra:
        lines += ["| extend ed = parse_xml(EventData).EventData.Data",
                  '| mv-apply d = ed on (summarize bag = make_bag(bag_pack(tostring(d["@Name"]), tostring(d["#text"]))))',
                  "| extend " + ", ".join(f"{f} = tostring(bag.{f})" for f in extra)]
    for c in rule.where:
        if c.op == "eq":
            expr = f"{c.field} in~ ({', '.join(_kql_q(v) for v in c.values)})"
        else:
            expr = "(" + " or ".join(f"{c.field} {_KQL_OP[c.op]} {_kql_q(v)}" for v in c.values) + ")"
        lines.append(f"| where not({expr})" if c.negate else f"| where {expr}")
    cols = ["TimeGenerated", "Computer", "EventID", "SubjectUserName", "TargetUserName"] + extra
    lines.append("| project " + ", ".join(dict.fromkeys(cols)))
    return "\n".join(lines)


_ELASTIC_SPECIAL = re.compile(r'([\\"*?():<>{}\[\]])')


def _elastic_val(c: Cond, v: str) -> str:
    esc = _ELASTIC_SPECIAL.sub(r"\\\1", v)
    if c.op == "contains":
        return "*" + esc + "*"
    if c.op == "startswith":
        return esc + "*"
    if c.op == "endswith":
        return "*" + esc
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_elastic(rule: Rule) -> str:
    ids = " or ".join(f'"{i}"' for i in rule.event_ids)
    parts = [f'event.code : ({ids}) and winlog.channel : "Security"']
    for c in rule.where:
        expr = f"winlog.event_data.{c.field} : ({' or '.join(_elastic_val(c, v) for v in c.values)})"
        parts.append(f"not {expr}" if c.negate else expr)
    return " and ".join(parts)
