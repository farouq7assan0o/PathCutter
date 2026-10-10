"""NTLM relay edge derivation from SharpHound computer properties.

SharpHound collects SMB signing, LDAP signing and WebClient status on computers. Combined with domain controller
membership and Protected Users, this lets us derive two relay attack edges:

  CoerceAndRelayNTLMToSMB   attacker coerces a machine to authenticate and relays to a target with SMB signing off
  CoerceAndRelayNTLMToLDAP  attacker coerces a WebClient-enabled machine and relays to a DC with LDAP signing off

Conditions mirror BloodHound CE's analysis (SpecterOps/BloodHound integration harnesses, Apache-2.0).

SMB relay:  source domain's Authenticated Users -> every computer in that domain where smbsigning is False,
            excluding domain controllers.
LDAP relay: same source group -> every computer with webclientrunning=True in a domain whose DCs have
            ldapsigning=False.
"""
from __future__ import annotations

from .graph import ADEdge, AttackGraph, NodeType


def derive_relay_edges(graph: AttackGraph) -> int:
    from .ingest import find_dc_sids
    dcs = set(find_dc_sids(graph))
    added = 0

    domain_sid_to_auth_users: dict[str, str] = {}
    auth_users_nodes: dict[str, str] = {}
    for n in graph.all_nodes():
        oid = n.object_id.upper()
        if oid.endswith("-S-1-5-11") or oid == "S-1-5-11":
            prefix = oid.rsplit("-S-1-5-11", 1)[0] if "-S-1-5-11" in oid else ""
            if prefix:
                auth_users_nodes[prefix] = n.object_id

    for d in graph.nodes_by_type(NodeType.DOMAIN):
        dsid = str(d.properties.get("domainsid") or "").upper()
        dname = d.object_id.upper()
        au = auth_users_nodes.get(dname) or auth_users_nodes.get(dsid)
        if au and dsid:
            domain_sid_to_auth_users[dsid] = au

    dc_by_domain: dict[str, list] = {}
    for dc_id in dcs:
        dc = graph.get_node(dc_id)
        if dc is None:
            continue
        dsid = str(dc.properties.get("domainsid") or dc_id.rsplit("-", 1)[0]).upper()
        dc_by_domain.setdefault(dsid, []).append(dc)

    ldap_unsigned_domains: set[str] = set()
    for dsid, dc_list in dc_by_domain.items():
        if any(dc.properties.get("ldapsigning") is False for dc in dc_list):
            ldap_unsigned_domains.add(dsid)

    for comp in graph.nodes_by_type(NodeType.COMPUTER):
        if comp.object_id in dcs:
            continue
        dsid = str(comp.properties.get("domainsid") or comp.object_id.rsplit("-", 1)[0]).upper()
        src = domain_sid_to_auth_users.get(dsid)
        if src is None:
            continue

        if comp.properties.get("smbsigning") is False:
            if not graph.has_edge_type(src, comp.object_id, "CoerceAndRelayNTLMToSMB"):
                graph.add_edge(ADEdge(source_id=src, target_id=comp.object_id,
                                      edge_type="CoerceAndRelayNTLMToSMB",
                                      properties={"derived": True}))
                added += 1

        if comp.properties.get("webclientrunning") is True and dsid in ldap_unsigned_domains:
            if not graph.has_edge_type(src, comp.object_id, "CoerceAndRelayNTLMToLDAP"):
                graph.add_edge(ADEdge(source_id=src, target_id=comp.object_id,
                                      edge_type="CoerceAndRelayNTLMToLDAP",
                                      properties={"derived": True}))
                added += 1

    if added:
        graph.meta["relay_edges"] = added
    return added
