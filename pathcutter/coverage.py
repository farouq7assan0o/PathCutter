"""Detection coverage per attack path: which steps you could see, which you would be told about, which are blind.

Fixing every path is rarely possible, so the paths that remain matter in two ways: can they be cut, and would anyone notice
them being used. A path that can be neither cut nor seen is the real top risk. This module answers the second question from
what you tell it you have:

  telemetry   the log sources you collect (Windows audit categories, EDR, Defender for Identity, Entra and Azure logs)
  rules       the detections you run, by PathCutter edge type or ATT&CK technique

Each attack step becomes one of
  detected   the telemetry exists AND a rule covers the step
  visible    the telemetry exists but nothing alerts on it (a hunting opportunity, not a detection)
  blind      the telemetry is not collected, so the step leaves no trace you could search

and each path takes the best status of its steps (an attacker is stopped by the first step that alerts), together with the hop at
which it would first be detected. A requirement is a statement about log sources, not a promise: "visible" means the data
would be there, and still depends on SACLs, audit policy details and retention that this module cannot see.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .edges import get_edge_type

# ----------------------------------------------------------------------------------------------- vocabulary
TELEMETRY: dict[str, str] = {
    "group-mgmt": "Windows Security: Security Group Management (4728, 4732, 4756)",
    "user-mgmt": "Windows Security: User Account Management (4720-4738, 4723, 4724)",
    "ds-changes": "Windows Security: Directory Service Changes (5136, 5137, 5141) with a SACL on the objects",
    "ds-access": "Windows Security: Directory Service Access (4662) with a SACL on the objects",
    "logon": "Windows Security: Logon (4624, 4625, 4648)",
    "special-logon": "Windows Security: Special Logon (4672)",
    "kerberos-service": "Windows Security: Kerberos Service Ticket Operations (4768, 4769) on the domain controllers",
    "certification": "Windows Security: Certification Services (4886, 4887) with CA auditing enabled",
    "process-creation": "Process creation with command line (4688 or Sysmon 1)",
    "sysmon": "Sysmon, including process access to lsass (event 10)",
    "edr": "An EDR agent on the endpoints (e.g. Defender for Endpoint)",
    "mdi": "Defender for Identity sensors on the domain controllers",
    "entra-audit": "Entra ID audit logs (role, group, application and credential changes, PIM)",
    "entra-signin": "Entra ID user sign-in logs",
    "entra-workload-signin": "Entra ID service principal / workload identity sign-in logs",
    "azure-activity": "Azure Activity Log (role assignments, resource operations)",
    "keyvault-audit": "Azure Key Vault diagnostic logs",
}

# edge -> options, each (any-of telemetry keys, quality, what you would see)
_ACL = [(("ds-changes",), "medium", "5136 on the changed attribute or security descriptor (needs a SACL)"),
        (("ds-access",), "low", "4662 object access (needs a SACL and is noisy)"),
        (("mdi",), "medium", "Defender for Identity sensitive-object modification alerts")]
OBSERVABLE: dict[str, list[tuple[tuple[str, ...], str, str]]] = {
    "AddMember": [(("group-mgmt",), "high", "4728 / 4732 / 4756 membership change"), (("mdi",), "medium", "MDI group membership change")],
    "ForceChangePassword": [(("user-mgmt",), "high", "4724 password reset by another account")],
    "WriteSPN": [(("ds-changes",), "medium", "5136 servicePrincipalName"), (("kerberos-service",), "low", "4769 for the new SPN (noisy)")],
    "AddAllowedToAct": [(("ds-changes",), "medium", "5136 msDS-AllowedToActOnBehalfOfOtherIdentity")],
    "WriteKeyCredentialLink": [(("ds-changes",), "medium", "5136 msDS-KeyCredentialLink"), (("kerberos-service",), "low", "4768 with PKINIT")],
    "AllowedToAct": [(("kerberos-service",), "medium", "4769 with transited services (S4U)")],
    "AllowedToDelegate": [(("kerberos-service",), "medium", "4769 with transited services or a forwardable TGT")],
    "DCSync": [(("ds-access",), "high", "4662 with the replication GUIDs from a non-DC"), (("mdi",), "high", "MDI DCSync alert")],
    "HasSession": [(("edr",), "high", "credential theft from memory (lsass access) in the EDR"),
                   (("sysmon",), "medium", "Sysmon 10 process access to lsass")],
    "AdminTo": [(("logon", "special-logon"), "medium", "4624 type 3 or 10 with 4672"), (("edr",), "medium", "remote execution on the host")],
    "CanRDP": [(("logon",), "medium", "4624 type 10 / 4778")],
    "CanPSRemote": [(("logon",), "medium", "4624 type 3 from WinRM"), (("process-creation",), "medium", "wsmprovhost child processes")],
    "ExecuteDCOM": [(("logon",), "medium", "4624 type 3"), (("process-creation",), "medium", "mmc / dllhost child processes")],
    "SQLAdmin": [(("logon",), "low", "4624 and SQL audit (not collected here)")],
    "GPOControlsObject": [(("ds-changes",), "high", "5136 / 5137 on the groupPolicyContainer")],
    "GPOUserRight": [(("special-logon",), "low", "4672 special privileges assigned at logon")],
    "ReadLAPSPassword": [(("ds-access",), "low", "4662 read of ms-Mcs-AdmPwd (needs a SACL)")],
    "ReadGMSAPassword": [(("ds-access",), "low", "4662 read of msDS-ManagedPassword (needs a SACL)")],
    "HasSIDHistory": [(("user-mgmt",), "medium", "4765 / 4766 SID history added")],
    "GoldenCert": [(("edr",), "low", "CA private key export on the CA host"), (("certification",), "low", "CA key operations")],
    "SyncedTo": [(("entra-audit",), "medium", "changes on the synchronised account")],
    "TrustedBy": [(("kerberos-service",), "low", "cross-domain ticket requests")],
    # cloud
    "AZAddSecret": [(("entra-audit",), "high", "Add service principal credentials / Update application: secrets")],
    "AZMGAddSecret": [(("entra-audit",), "high", "Add service principal credentials / Update application: secrets")],
    "AZResetPassword": [(("entra-audit",), "high", "Reset user password")],
    "AZMGResetPassword": [(("entra-audit",), "high", "Reset user password")],
    "AZMGGrantRole": [(("entra-audit",), "high", "Add app role assignment / Add member to role")],
    "AZMGAddMember": [(("entra-audit",), "high", "Add member to group")],
    "AZEligibleRole": [(("entra-audit",), "high", "PIM: role activation and eligibility changes")],
    "AZOwns": [(("entra-audit",), "medium", "Add owner / credential changes on the owned object")],
    "AZOwner": [(("azure-activity",), "high", "Microsoft.Authorization/roleAssignments/write and resource operations")],
    "AZContributor": [(("azure-activity",), "high", "write and action operations on the resource")],
    "AZUserAccessAdmin": [(("azure-activity",), "high", "Microsoft.Authorization/roleAssignments/write")],
    "AZVMAdminLogin": [(("azure-activity",), "medium", "sign-in to the VM"), (("logon",), "medium", "4624 on the VM")],
    "AZManagedIdentity": [(("entra-workload-signin",), "medium", "managed identity sign-ins")],
    "AZAuthenticatesTo": [(("entra-workload-signin",), "high", "service principal sign-ins using the federated credential")],
    "AZGetSecrets": [(("keyvault-audit",), "high", "SecretGet / SecretList")],
    "AZGetKeys": [(("keyvault-audit",), "high", "KeyGet / KeyList")],
    "AZGetCertificates": [(("keyvault-audit",), "high", "CertificateGet / CertificateList")],
}
for _e in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns"):
    OBSERVABLE.setdefault(_e, _ACL)
for _e in ("ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5", "ADCSESC6", "ADCSESC7", "ADCSESC8", "ADCSESC9", "ADCSESC10",
           "ADCSESC11", "ADCSESC13", "ADCSESC15", "ADCSESC16", "Enroll", "ManageCA", "ManageCertificates"):
    OBSERVABLE.setdefault(_e, [(("certification",), "high", "4886 / 4887 on the CA for the template and requester")])
_FALLBACK = [(("ds-changes",), "low", "5136 directory changes (no specific detection is known for this step)")]
_STRUCTURE = {"MemberOf", "Contains", "AZContains", "AZRunsAs"}       # not actions: nothing to observe

# what the detection pack generated by `pathcutter detect` covers when deployed (see detections.build_rules)
PACK_EDGES = {
    "AddMember", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WriteSPN", "AddAllowedToAct", "AllowedToAct",
    "WriteKeyCredentialLink", "ForceChangePassword", "DCSync", "ReadGMSAPassword", "ReadLAPSPassword", "AdminTo", "SQLAdmin",
    "ExecuteDCOM", "CanRDP", "CanPSRemote", "AllowedToDelegate", "GPOControlsObject", "Enroll", "AutoEnroll", "ManageCA",
    "ManageCertificates", "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5", "ADCSESC6", "ADCSESC7", "ADCSESC8", "ADCSESC9",
    "ADCSESC10", "ADCSESC11", "ADCSESC13", "ADCSESC15", "ADCSESC16",
}
_RANK = {"detected": 2, "visible": 1, "blind": 0}
_Q = {"high": 3, "medium": 2, "low": 1}


# ----------------------------------------------------------------------------------------------- inventory
@dataclass
class Inventory:
    telemetry: set[str] = field(default_factory=set)
    rule_edges: set[str] = field(default_factory=set)
    rule_techniques: set[str] = field(default_factory=set)
    names: list[str] = field(default_factory=list)
    unknown_telemetry: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Inventory":
        inv = cls()
        for t in d.get("telemetry", []) or []:
            t = str(t)
            if t in TELEMETRY:
                inv.telemetry.add(t)
            else:
                inv.unknown_telemetry.append(t)
        for r in d.get("rules", []) or []:
            inv.rule_edges |= {str(e) for e in r.get("edges", []) or []}
            inv.rule_techniques |= {str(t).upper() for t in r.get("techniques", []) or []}
            if r.get("name"):
                inv.names.append(str(r["name"]))
        return inv

    @classmethod
    def load(cls, path) -> "Inventory":
        with open(path, encoding="utf-8-sig") as f:
            return cls.from_dict(json.load(f))

    def with_pack(self) -> "Inventory":
        """The same inventory plus the rules `pathcutter detect` would add."""
        out = Inventory(set(self.telemetry), set(self.rule_edges) | PACK_EDGES, set(self.rule_techniques), list(self.names),
                        list(self.unknown_telemetry))
        return out

    def covers(self, edge_type: str) -> bool:
        if edge_type in self.rule_edges:
            return True
        info = get_edge_type(edge_type)
        mitre = (info.mitre if info else "") or ""
        return bool(mitre) and any(mitre.upper() == t or mitre.upper().startswith(t + ".") or t.startswith(mitre.upper() + ".")
                                   for t in self.rule_techniques)


# ----------------------------------------------------------------------------------------------- evaluation
def step_status(edge_type: str, inv: Inventory) -> dict:
    """Status of one attack step: {edge, status, quality, via, missing, why}."""
    options = OBSERVABLE.get(edge_type, _FALLBACK)
    have = [(keys, q, why) for keys, q, why in options if all(k in inv.telemetry for k in keys)]
    if have:
        keys, q, why = max(have, key=lambda o: _Q[o[1]])
        status = "detected" if inv.covers(edge_type) else "visible"
        return {"edge": edge_type, "status": status, "quality": q, "via": list(keys), "why": why, "missing": []}
    best = max(options, key=lambda o: _Q[o[1]])
    return {"edge": edge_type, "status": "blind", "quality": best[1], "via": [], "why": best[2],
            "missing": [k for k in best[0] if k not in inv.telemetry]}


def path_coverage(edge_types: list[str], inv: Inventory) -> dict:
    steps = [step_status(e, inv) for e in edge_types if e not in _STRUCTURE]
    if not steps:
        return {"status": "blind", "first_detected": None, "steps": [], "hops": 0}
    status = max((s["status"] for s in steps), key=lambda s: _RANK[s])
    first = next((i + 1 for i, s in enumerate(steps) if s["status"] == "detected"), None)
    return {"status": status, "first_detected": first, "steps": steps, "hops": len(steps)}


@dataclass
class CoverageReport:
    paths_total: int
    counts: dict
    paths: list[dict]                       # one per path: source, target, status, first_detected, steps
    by_edge: dict                           # edge type -> {"paths", "status", "why", "missing"}
    enable: list[dict]                      # telemetry to switch on, greedy by blind paths made visible
    write_rules: list[dict]                 # edge types visible but with no rule, by paths
    inventory: Inventory
    truncated: bool = False


def analyse(graph, inv: Inventory, max_paths: int = 10000, max_depth: int = 20, paths=None) -> CoverageReport:
    from .pathfinder import find_all_paths
    rep = paths if paths is not None else find_all_paths(graph, graph.tier0_nodes, max_depth, max_paths)
    per_path, by_edge = [], {}
    counts = {"detected": 0, "visible": 0, "blind": 0}
    for p in rep.paths:
        ets = [e.get("edge_type", "?") for e in p.edges]
        cov = path_coverage(ets, inv)
        counts[cov["status"]] += 1
        src, tgt = graph.get_node(p.source), graph.get_node(p.target)
        per_path.append({"source": src.display_name if src else p.source, "target": tgt.display_name if tgt else p.target,
                         "status": cov["status"], "first_detected": cov["first_detected"], "hops": cov["hops"],
                         "edges": ets, "steps": cov["steps"]})
        for s in cov["steps"]:
            b = by_edge.setdefault(s["edge"], {"paths": 0, "status": s["status"], "why": s["why"], "missing": s["missing"], "quality": s["quality"]})
            b["paths"] += 1
    enable = _greedy_enable(per_path, inv)
    write_rules = sorted(({"edge": e, "paths": b["paths"], "via": b["why"]} for e, b in by_edge.items() if b["status"] == "visible"),
                         key=lambda r: -r["paths"])
    return CoverageReport(len(per_path), counts, per_path, by_edge, enable, write_rules, inv,
                          truncated=bool(getattr(rep, "total_paths", 0) >= max_paths))


def _greedy_enable(per_path: list[dict], inv: Inventory) -> list[dict]:
    """Which telemetry to switch on, in order, to move the most blind paths to visible."""
    blind = [p for p in per_path if p["status"] == "blind"]
    chosen: list[dict] = []
    enabled = set(inv.telemetry)
    remaining = blind
    for _ in range(len(TELEMETRY)):
        gain: dict[str, int] = {}
        qual: dict[str, int] = {}
        for p in remaining:
            best_q: dict[str, int] = {}
            for s in p["steps"]:
                for opt_keys, q, _w in OBSERVABLE.get(s["edge"], _FALLBACK):
                    missing = [k for k in opt_keys if k not in enabled]
                    if len(missing) == 1:
                        best_q[missing[0]] = max(best_q.get(missing[0], 0), _Q[q])
            for k, qv in best_q.items():
                gain[k] = gain.get(k, 0) + 1
                qual[k] = qual.get(k, 0) + qv
        if not gain:
            break
        key = max(gain, key=lambda k: (gain[k], qual[k], k))        # most paths first, then the better-quality signal
        chosen.append({"telemetry": key, "describes": TELEMETRY[key], "paths_made_visible": gain[key]})
        enabled.add(key)
        still = []
        for p in remaining:
            if not any(all(k in enabled for k in ks) for s in p["steps"] for ks, _q, _w in OBSERVABLE.get(s["edge"], _FALLBACK)):
                still.append(p)
        remaining = still
        if not remaining:
            break
    return chosen


# ----------------------------------------------------------------------------------------------- output
def render(rep: CoverageReport, top: int = 8) -> str:
    n = rep.paths_total or 1
    c = rep.counts
    out = ["pathcutter coverage", "=" * 60,
           f"Attack paths     : {rep.paths_total}" + ("  (capped: lower bound)" if rep.truncated else ""),
           f"  detected       : {c['detected']:>5}  ({c['detected'] * 100 // n}%)   at least one step would alert",
           f"  visible only   : {c['visible']:>5}  ({c['visible'] * 100 // n}%)   the data exists, nothing alerts on it",
           f"  BLIND          : {c['blind']:>5}  ({c['blind'] * 100 // n}%)   no step leaves a log you collect", ""]
    if rep.inventory.unknown_telemetry:
        out.append("Unknown telemetry names ignored: " + ", ".join(rep.inventory.unknown_telemetry) + "  (see --template)")
        out.append("")
    blind = [p for p in rep.paths if p["status"] == "blind"]
    if blind:
        out.append("Paths nobody would see:")
        groups: dict[tuple, int] = {}
        for p in blind:
            groups[(p["source"], p["target"], " > ".join(p["edges"]))] = groups.get((p["source"], p["target"], " > ".join(p["edges"])), 0) + 1
        for (s, t, e), k in list(groups.items())[:top]:
            out.append(f"  {s}  ->  {t}   [{e}]" + (f"   x{k}" if k > 1 else ""))
        if len(groups) > top:
            out.append(f"  ... and {len(groups) - top} more")
        out.append("")
    if rep.enable:
        out.append("Switch these on, in this order (each makes the most still-blind paths visible):")
        for e in rep.enable[:top]:
            out.append(f"  + {e['telemetry']:<22} {e['paths_made_visible']:>4} path(s)   {e['describes']}")
        out.append("")
    if rep.write_rules:
        out.append("Visible but no rule covers them (generate with `pathcutter detect`, or write your own):")
        for r in rep.write_rules[:top]:
            out.append(f"  ! {r['edge']:<24} {r['paths']:>4} path(s)   {r['via']}")
        out.append("")
    late = [p for p in rep.paths if p["status"] == "detected" and p["first_detected"] and p["first_detected"] > 1]
    if late:
        out.append(f"{len(late)} detected path(s) only alert after the first hop: the attacker has already acted once.")
    out.append("Status describes log sources and rule coverage you declared; audit SACLs, filtering and retention are not visible here.")
    return "\n".join(out) + "\n"


def to_dict(rep: CoverageReport) -> dict:
    return {"paths_total": rep.paths_total, "counts": rep.counts, "truncated": rep.truncated,
            "by_edge": rep.by_edge, "enable": rep.enable, "write_rules": rep.write_rules,
            "paths": [{k: p[k] for k in ("source", "target", "status", "first_detected", "hops", "edges")} for p in rep.paths[:2000]]}


def template() -> dict:
    return {"telemetry": [], "rules": [{"name": "example: group change alert", "edges": ["AddMember"], "techniques": ["T1098"]}],
            "available_telemetry": TELEMETRY}
