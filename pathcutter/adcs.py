"""Active Directory Certificate Services attack edges, derived from collected template and CA data.

SharpHound collects templates, CAs, their ACLs and the registry flags that matter; it does not compute which
principals can use them. This module does, for the escalation techniques whose conditions are fully determined by
collected data:

  ADCSESC1  enroll in a published template that lets the requester name the subject and allows authentication
  ADCSESC4  control a published, enrollable template (it can be turned into an ESC1 template)
  ADCSESC6  enroll in an authentication template on a CA that accepts a requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)
  ADCSESC7  ManageCA / ManageCertificates on a trusted CA

Each edge runs principal -> domain (the domain object is Tier 0), so the existing exposure search needs no special case.
Not derived, and said so by `pathcutter syntax model`: ESC2/ESC3 (enrollment agents), ESC5, ESC8 (relay to HTTP
enrollment, not visible in LDAP data), ESC9/10/16 (domain controller registry settings are not collected), ESC11, ESC13-15.

A CA is trusted for authentication when its certificate is in the NTAuth store (BloodHound's rule). When no NTAuth
store was collected the CA is assumed trusted, which can only over-report.
"""
from __future__ import annotations

from .graph import ADEdge, AttackGraph, NodeType

_ENROLL = {"Enroll", "GenericAll"}
_CONTROL = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WritePKINameFlag", "WritePKIEnrollmentFlag"}
_MANAGE = {"ManageCA", "ManageCertificates", "GenericAll", "WriteDacl", "WriteOwner", "Owns"}
_MAX_CROSS = 2000        # cap for the rare "member of group A and of group B" intersection


def _holders(graph: AttackGraph, target: str, types: set[str]) -> set[str]:
    return {u for u, _, d in graph.in_edges(target) if d.get("edge_type") in types}


def _down(graph: AttackGraph, principals: set[str]) -> set[str]:
    """The principals and everyone nested under them (a group's rights are held by its members)."""
    out = set(principals)
    for p in principals:
        node = graph.get_node(p)
        if node is not None and node.node_type in (NodeType.GROUP, NodeType.UNKNOWN):
            out |= graph._recursive_members(p)
    return out


def _both(graph: AttackGraph, a: set[str], b: set[str]) -> set[str]:
    """Principals that hold BOTH rights (each set is a list of direct holders): the highest such principals.

    p qualifies when it holds one right directly and is covered by the other through nesting; the unusual case of a user
    reaching each right through two unrelated groups is resolved on the (bounded) intersection of the two closures."""
    da, db = _down(graph, a), _down(graph, b)
    out = {p for p in a if p in db} | {p for p in b if p in da}
    if not out:
        cross = da & db
        if len(cross) <= _MAX_CROSS:
            out = cross
    return out


def trusted_cas(graph: AttackGraph) -> list:
    ntauth: set[str] = set()
    have_store = False
    for n in graph.nodes_by_type(NodeType.NTAUTH_STORE):
        have_store = True
        ntauth |= {str(t).upper() for t in n.properties.get("certthumbprints") or []}
    out = []
    for ca in graph.nodes_by_type(NodeType.ENTERPRISE_CA):
        thumb = str(ca.properties.get("certthumbprint") or "").upper()
        if not have_store or not thumb or thumb in ntauth:
            out.append(ca)
    return out


def auth_template(p: dict) -> bool:
    """Client authentication possible, no approval step, no authorized-signature requirement."""
    return (bool(p.get("authenticationenabled")) and not p.get("requiresmanagerapproval")
            and not (p.get("authorizedsignatures") or 0))


def derive_adcs_edges(graph: AttackGraph) -> dict[str, int]:
    """Add ADCSESC* edges (principal -> its domain). Returns how many of each were added."""
    counts = {"ADCSESC1": 0, "ADCSESC4": 0, "ADCSESC6": 0, "ADCSESC7": 0}
    domains = {n.name.upper(): n.object_id for n in graph.nodes_by_type(NodeType.DOMAIN)}
    added: set[tuple[str, str, str]] = set()

    def emit(src: str, dom: str, kind: str) -> None:
        if src in graph.tier0_nodes or (src, dom, kind) in added:
            return
        added.add((src, dom, kind))
        graph.add_edge(ADEdge(src, dom, kind))
        counts[kind] += 1

    templates = {n.object_id: n for n in graph.nodes_by_type(NodeType.CERT_TEMPLATE)}
    for ca in trusted_cas(graph):
        dom = domains.get(str(ca.domain).upper())
        if dom is None:
            continue
        enabled = [templates[t] for t in (ca.properties.get("_enabled_templates") or []) if t in templates]
        ca_enrollers = _holders(graph, ca.object_id, _ENROLL)
        san_open = bool(ca.properties.get("_san_enabled")) and bool(ca.properties.get("_san_collected"))
        for src in _holders(graph, ca.object_id, _MANAGE - {"GenericAll", "WriteDacl", "WriteOwner", "Owns"}):
            if enabled:
                emit(src, dom, "ADCSESC7")
        for t in enabled:
            p = t.properties
            enrollers = _holders(graph, t.object_id, _ENROLL)
            can_enroll = _both(graph, enrollers, ca_enrollers)
            if auth_template(p) and p.get("enrolleesuppliessubject"):
                for src in can_enroll:
                    emit(src, dom, "ADCSESC1")
            if san_open and auth_template(p):
                for src in can_enroll:
                    emit(src, dom, "ADCSESC6")
            for src in _both(graph, _holders(graph, t.object_id, _CONTROL), ca_enrollers):
                emit(src, dom, "ADCSESC4")
    return counts
