"""Shadow Tier 0: objects that can push code or credentials to real Tier 0, so they ARE Tier 0.

In real breaches the path to Domain Admin rarely runs through a clever ACL. It runs through the system that can deploy to
every machine, or read every credential: the software-deployment server, the backup server, the hypervisor that holds the DC
virtual disks, the EDR console that runs scripts everywhere, the directory-sync account that can replicate hashes, the
privileged-access vault that stores the Tier 0 passwords. BloodHound's graph does not see these, because the privilege lives
in another product's console, not in an AD ACL. PathCutter marks their AD groups and service accounts as Tier 0 so a path
*to* them is a path to domain takeover.

Two kinds of evidence:
  derived   no name needed: a principal that already holds DCSync, or GenericAll / WriteDacl / Owns / full GPO control on the
            domain object, is domain-takeover-equivalent. This is as certain as the ACL it rests on.
  by-name   a group or service account whose name matches a known high-privilege product role (SCCM, Veeam, VMware, Defender
            console, Entra Connect, CyberArk, ...). Names are org-specific, so every match is REPORTED, never silent, the
            policy file can add or remove patterns, and it can be turned off entirely.

Everything added here is recorded in graph.meta["shadow_tier0"] with its reason and evidence, so `audit` and the report explain
each one, and `pathcutter/evidence.py` labels a by-name match as lower confidence than a directory fact.
"""
from __future__ import annotations

import re

from .graph import AttackGraph, NodeType

# (name regex, short product, reason, mitre). Matched against a group's or service account's display name, case-insensitive.
PATTERNS: list[tuple[str, str, str, str]] = [
    (r"\b(?:SCCM|MECM|CONFIGMGR|CONFIGURATION MANAGER|ENDPOINT MANAGER)\b", "SCCM/MECM",
     "software-deployment admins can push code to every managed computer, including domain controllers", "T1072"),
    (r"\b(?:ALTIRIS|BIGFIX|TANIUM|PDQ DEPLOY|LANDESK|IVANTI|MANAGEENGINE|DESKTOP CENTRAL|NINJAONE|ACTION1|KASEYA|CONNECTWISE)\b", "deployment",
     "endpoint-management admins can run code on every managed computer", "T1072"),
    (r"\b(?:VEEAM|COMMVAULT|NETBACKUP|RUBRIK|COHESITY|BACULA|BACKUP EXEC|ACRONIS|AZURE BACKUP|DPM|AVAMAR|NETWORKER|BACKUP ADMIN)", "backup",
     "backup admins can restore or mount a domain controller's data and read its secrets", "T1003"),
    (r"\b(?:VMWARE|VSPHERE|VCENTER|ESX|HYPER-?V|PROXMOX|NUTANIX|CITRIX HYPERVISOR|XENSERVER|RHEV|OVIRT)\b", "hypervisor",
     "hypervisor admins can access the virtual disk or memory of a domain controller VM", "T1003"),
    (r"\b(?:CROWDSTRIKE|SENTINELONE|CARBON BLACK|CYLANCE|DEFENDER FOR ENDPOINT|MDE|EDR ADMIN|COForepoint|CORTEX XDR|SOPHOS CENTRAL)\b", "EDR",
     "EDR console admins can run scripts or live-response on every endpoint", "T1072"),
    (r"\b(?:CYBERARK|THYCOTIC|DELINEA|BEYONDTRUST|HASHICORP VAULT|SECRET SERVER|PASSWORD ?VAULT|PAM ADMIN|PRIVILEGED ACCESS)\b", "PAM",
     "privileged-access-management admins can check out the stored Tier 0 credentials", "T1555"),
    (r"\b(?:AAD ?CONNECT|AZURE AD CONNECT|ENTRA CONNECT|DIRSYNC|ADSYNC)\b", "Entra Connect",
     "the directory-synchronisation service can read and write across the on-premises directory (DCSync-capable)", "T1003.006"),
    (r"\b(?:WSUS|UPDATE SERVICES)\b", "WSUS",
     "update-service admins can approve a malicious update to every computer, including domain controllers", "T1072"),
]
# service-account name prefixes that are the directory-sync identity (it holds replication rights = DCSync)
SYNC_ACCOUNT = re.compile(r"^(MSOL_|AAD_|SYNC_|ADSYNC|AZUREADSSOACC)", re.I)

_DOMAIN_TAKEOVER_EDGES = {"DCSync", "GenericAll", "WriteDacl", "Owns", "GenericWrite", "AllExtendedRights"}


def _compiled(extra: list[tuple[str, str, str, str]] | None):
    pats = list(PATTERNS) + list(extra or [])
    return [(re.compile(rx, re.I), prod, why, mitre) for rx, prod, why, mitre in pats]


def derive_shadow_tier0(graph: AttackGraph, extra_patterns=None, by_name: bool = True) -> list[dict]:
    """Mark Shadow Tier 0 objects and return the list that was added (for reporting). Idempotent."""
    found: list[dict] = []
    seen = set(graph.tier0_nodes)

    def mark(node, reason, product, mitre, evidence):
        if node.object_id in seen:
            return
        node.properties["_shadow_t0"] = reason
        seen.add(node.object_id)
        found.append({"id": node.object_id, "name": node.display_name, "type": node.node_type.value,
                      "product": product, "reason": reason, "mitre": mitre, "evidence": evidence})

    # derived: domain-takeover rights on the domain object are Tier 0 by capability, whatever the principal is named
    domain_ids = {n.object_id for n in graph.nodes_by_type(NodeType.DOMAIN)}
    for u, v, d in graph.all_edges():
        if v in domain_ids and d.get("edge_type") in _DOMAIN_TAKEOVER_EDGES:
            n = graph.get_node(u)
            if n is not None and n.node_type in (NodeType.GROUP, NodeType.USER, NodeType.COMPUTER) and not n.properties.get("isdc"):
                et = d["edge_type"]
                mark(n, f"holds {et} on the domain object, which is domain takeover (DCSync-equivalent)", "directory",
                     "T1003.006" if et == "DCSync" else "T1484", "derived")

    if by_name:
        compiled = _compiled(extra_patterns)
        for n in graph.nodes_by_type(NodeType.GROUP) + graph.nodes_by_type(NodeType.USER):
            name = n.display_name
            if n.node_type == NodeType.USER and SYNC_ACCOUNT.match(name.split("@")[0].split("\\")[-1]):
                mark(n, "directory-synchronisation service account (replication rights = DCSync-capable)", "Entra Connect", "T1003.006", "by-name")
                continue
            for rx, product, why, mitre in compiled:
                if rx.search(name):
                    mark(n, why, product, mitre, "by-name")
                    break

    if found:
        graph.meta.setdefault("shadow_tier0", [])
        have = {s["id"] for s in graph.meta["shadow_tier0"]}
        graph.meta["shadow_tier0"] += [f for f in found if f["id"] not in have]
    return found


def strip_by_name(graph: AttackGraph) -> int:
    """Undo the by-name Shadow Tier 0 marks (keep the derived ones), then re-tier. Returns how many were removed."""
    items = graph.meta.get("shadow_tier0") or []
    byname = [s for s in items if s["evidence"] == "by-name"]
    for s in byname:
        n = graph.get_node(s["id"])
        if n is not None:
            n.properties.pop("_shadow_t0", None)
            graph._seed_t0.discard(s["id"])
    graph.meta["shadow_tier0"] = [s for s in items if s["evidence"] != "by-name"]
    if byname:
        graph.retier()
    return len(byname)
