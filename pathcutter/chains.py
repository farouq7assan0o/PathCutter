"""Composite attack chain detection - multi-hop abuse patterns that are more than the sum of their edges.

Recognizes patterns like:
- Kerberoasting: WriteSPN -> Set SPN -> Kerberoast -> Crack -> Use creds
- Shadow Credentials: WriteKeyCredentialLink -> PKINIT -> NT hash
- RBCD: AddAllowedToAct + own computer account -> impersonate
- GPO abuse: Write GPO -> GPO linked to OU -> code execution on targets
- ACL chaining: WriteDacl -> grant GenericAll -> abuse target
- DCSync path: any path to an account with GetChanges+GetChangesAll
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .graph import AttackGraph, NodeType
from .pathfinder import PathReport, AttackPath


@dataclass
class AttackChain:
    """A recognized composite attack pattern."""
    chain_type: str
    description: str
    severity: str  # critical, high, medium
    mitre: list[str]
    involved_nodes: list[str]
    involved_edges: list[str]
    paths: list[AttackPath]
    remediation: str

    @property
    def node_names(self) -> list[str]:
        return self.involved_nodes

    @property
    def path_count(self) -> int:
        return len(self.paths)


def detect_chains(graph: AttackGraph, path_report: PathReport) -> list[AttackChain]:
    """Detect all composite attack chains in the path report."""
    chains: list[AttackChain] = []

    chains.extend(_detect_kerberoast_paths(graph, path_report))
    chains.extend(_detect_shadow_credentials(graph, path_report))
    chains.extend(_detect_rbcd_chains(graph, path_report))
    chains.extend(_detect_dcsync_paths(graph, path_report))
    chains.extend(_detect_acl_chains(graph, path_report))
    chains.extend(_detect_gpo_abuse(graph, path_report))
    chains.extend(_detect_disabled_account_abuse(graph, path_report))
    chains.extend(_detect_delegation_chains(graph, path_report))

    return sorted(chains, key=lambda c: {"critical": 0, "high": 1, "medium": 2}.get(c.severity, 3))


def _detect_kerberoast_paths(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect paths where WriteSPN enables Kerberoasting."""
    chains = []
    kerberoastable = set()

    for node in graph.all_nodes():
        if node.properties.get("hasspn") or node.properties.get("serviceprincipalnames"):
            kerberoastable.add(node.object_id)

    writespn_targets = set()
    for u, v, data in graph.all_edges():
        if data.get("edge_type") == "WriteSPN":
            writespn_targets.add(v)

    targets = kerberoastable | writespn_targets
    if not targets:
        return []

    matching_paths = []
    for path in report.paths:
        for i, edge in enumerate(path.edges):
            if edge.get("edge_type") == "WriteSPN":
                matching_paths.append(path)
                break
            if path.nodes[i + 1] in kerberoastable and edge.get("edge_type") in (
                "GenericAll", "GenericWrite", "WriteSPN"
            ):
                matching_paths.append(path)
                break

    if matching_paths:
        target_names = []
        for t in writespn_targets | kerberoastable:
            node = graph.get_node(t)
            if node:
                target_names.append(node.name)

        chains.append(AttackChain(
            chain_type="kerberoast",
            description=f"Kerberoasting path: {len(matching_paths)} paths can set/abuse SPNs on {len(target_names)} accounts to crack passwords offline",
            severity="high",
            mitre=["T1558.003"],
            involved_nodes=target_names[:10],
            involved_edges=["WriteSPN", "GenericWrite", "GenericAll"],
            paths=matching_paths,
            remediation="Remove WriteSPN/GenericWrite permissions on service accounts. Set strong passwords (25+ chars) on kerberoastable accounts. Use gMSA where possible.",
        ))

    return chains


def _detect_shadow_credentials(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect WriteKeyCredentialLink abuse paths."""
    matching = [p for p in report.paths if "WriteKeyCredentialLink" in p.edge_types]
    if not matching:
        return []

    targets = set()
    for p in matching:
        for i, e in enumerate(p.edges):
            if e.get("edge_type") == "WriteKeyCredentialLink":
                targets.add(p.nodes[i + 1])

    target_names = [graph.get_node_name(t) for t in targets]

    return [AttackChain(
        chain_type="shadow_credentials",
        description=f"Shadow Credentials: {len(matching)} paths can write msDS-KeyCredentialLink on {len(targets)} targets for PKINIT-based authentication",
        severity="critical",
        mitre=["T1556"],
        involved_nodes=target_names,
        involved_edges=["WriteKeyCredentialLink"],
        paths=matching,
        remediation="Remove WriteProperty on msDS-KeyCredentialLink. Monitor Event ID 4768 for PKINIT from unexpected sources.",
    )]


def _detect_rbcd_chains(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect Resource-Based Constrained Delegation abuse chains."""
    matching = [p for p in report.paths
                if "AddAllowedToAct" in p.edge_types or "AllowedToAct" in p.edge_types]
    if not matching:
        return []

    return [AttackChain(
        chain_type="rbcd",
        description=f"RBCD abuse: {len(matching)} paths can configure resource-based constrained delegation to impersonate privileged users",
        severity="critical",
        mitre=["T1134.001"],
        involved_nodes=[],
        involved_edges=["AddAllowedToAct", "AllowedToAct"],
        paths=matching,
        remediation="Remove WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity. Restrict computer account creation (ms-DS-MachineAccountQuota = 0).",
    )]


def _detect_dcsync_paths(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect paths to accounts with DCSync rights."""
    dcsync_sources = set()
    for u, v, data in graph.all_edges():
        if data.get("edge_type") == "DCSync":
            dcsync_sources.add(u)

    if not dcsync_sources:
        return []

    matching = []
    for p in report.paths:
        for nid in p.nodes:
            if nid in dcsync_sources:
                matching.append(p)
                break

    if not matching:
        return []

    source_names = [graph.get_node_name(s) for s in dcsync_sources]
    return [AttackChain(
        chain_type="dcsync",
        description=f"DCSync path: {len(matching)} paths reach {len(dcsync_sources)} accounts with domain replication rights - full domain compromise",
        severity="critical",
        mitre=["T1003.006"],
        involved_nodes=source_names,
        involved_edges=["DCSync", "GetChanges", "GetChangesAll"],
        paths=matching,
        remediation="Remove Replicating Directory Changes rights from non-DC accounts. Only DCs and ADConnect (if used) should have these.",
    )]


def _detect_acl_chains(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect ACL chaining: WriteDacl -> grant self GenericAll -> abuse."""
    acl_chain_edges = {"WriteDacl", "WriteOwner", "Owns"}
    matching = []
    for p in report.paths:
        types = set(p.edge_types)
        if types & acl_chain_edges and types & {"GenericAll", "GenericWrite", "AddMember", "ForceChangePassword"}:
            matching.append(p)

    if not matching:
        return []

    return [AttackChain(
        chain_type="acl_chain",
        description=f"ACL chaining: {len(matching)} paths use ownership/DACL modification to escalate permissions before abusing the target",
        severity="high",
        mitre=["T1222.001"],
        involved_nodes=[],
        involved_edges=list(acl_chain_edges),
        paths=matching,
        remediation="Review object ownership. Domain Admins should own all Tier 0 objects. Remove WriteDacl/WriteOwner from non-admin principals.",
    )]


def _detect_gpo_abuse(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect GPO-based attack paths."""
    matching = [p for p in report.paths if "GPOControlsObject" in p.edge_types]
    if not matching:
        return []

    return [AttackChain(
        chain_type="gpo_abuse",
        description=f"GPO abuse: {len(matching)} paths abuse GPO write permissions to push malicious settings/scripts to linked OUs",
        severity="high",
        mitre=["T1484.001"],
        involved_nodes=[],
        involved_edges=["GPOControlsObject", "GenericWrite", "GenericAll"],
        paths=matching,
        remediation="Restrict GPO edit permissions to Tier 0 admins only. Monitor GPO changes with Event IDs 5136/5137.",
    )]


def _detect_disabled_account_abuse(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect paths that abuse permissions held by disabled accounts."""
    disabled = set()
    for node in graph.all_nodes():
        if not node.enabled and node.node_type in (NodeType.USER, NodeType.COMPUTER):
            disabled.add(node.object_id)

    if not disabled:
        return []

    matching = []
    disabled_in_paths = set()
    for p in report.paths:
        for nid in p.nodes:
            if nid in disabled:
                matching.append(p)
                disabled_in_paths.add(nid)
                break

    if not matching:
        return []

    names = [graph.get_node_name(d) for d in disabled_in_paths]
    return [AttackChain(
        chain_type="disabled_account",
        description=f"Disabled account abuse: {len(disabled_in_paths)} disabled accounts still have exploitable permissions in {len(matching)} attack paths",
        severity="medium",
        mitre=["T1078.002"],
        involved_nodes=names,
        involved_edges=[],
        paths=matching,
        remediation="Remove all ACL entries for disabled accounts. Move disabled accounts to a 'Disabled' OU with no delegated permissions.",
    )]


def _detect_delegation_chains(graph: AttackGraph, report: PathReport) -> list[AttackChain]:
    """Detect unconstrained delegation abuse paths."""
    unconstrained = set()
    for node in graph.all_nodes():
        if node.properties.get("unconstraineddelegation") and node.node_type == NodeType.COMPUTER:
            dc_sids = {n.object_id for n in graph.all_nodes()
                      if n.node_type == NodeType.COMPUTER and "DC" in n.name.upper().split(".")[0]}
            if node.object_id not in dc_sids:
                unconstrained.add(node.object_id)

    if not unconstrained:
        return []

    matching = [p for p in report.paths if any(n in unconstrained for n in p.nodes)]
    if not matching:
        return []

    names = [graph.get_node_name(u) for u in unconstrained]
    return [AttackChain(
        chain_type="unconstrained_delegation",
        description=f"Unconstrained delegation: {len(unconstrained)} non-DC computers ({', '.join(names[:3])}) can capture TGTs from any authenticating user",
        severity="critical",
        mitre=["T1558"],
        involved_nodes=names,
        involved_edges=["AllowedToDelegate"],
        paths=matching,
        remediation="Disable unconstrained delegation on non-DC systems. Use constrained delegation or RBCD instead. Add sensitive accounts to 'Protected Users' group.",
    )]
