"""Active Directory Certificate Services attack edges, derived from collected template and CA data.

SharpHound collects templates, CAs, their ACLs and the registry flags that matter; it does not compute which
principals can use them. This module does, for the escalation techniques whose conditions are fully determined by
collected data:

  ADCSESC1  enroll in a published template that lets the requester name the subject and allows authentication
  ADCSESC4  control a published, enrollable template (it can be turned into an ESC1 template)
  ADCSESC6  enroll in an authentication template on a CA that accepts a requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)
  ADCSESC7  ManageCA / ManageCertificates on a trusted CA
  ADCSESC3  enrollment-agent template + an agent-enrollable authentication template on the same trusted CA
  ADCSESC5  control of the NTAuth store or an enterprise CA object
  GoldenCert  local administrator of the host of a trusted CA (the CA key can be extracted)
  ADCSESC15 schema-version-1 template with an enrollee-supplied subject (EKUwu, CVE-2024-49019): assumes an unpatched CA
  ADCSESC13 an issuance policy linked to a group: enrolling gives that group's membership (edge principal -> group)
  ADCSESC10 same as ESC9 with weak mapping instead of a missing security extension (needs DC registry data)
  ADCSESC9  UPN-change attack: GenericWrite over an account that can enroll in a no-security-extension template,
            while a domain controller does not enforce strong certificate binding (needs DC registry data)

Each edge runs principal -> domain (the domain object is Tier 0), so the existing exposure search needs no special case.
Not derived, and said so by `pathcutter syntax model`: ESC2 (no direct edge: it feeds ESC3), ESC8 and ESC11 (relay to
enrollment endpoints: not visible in LDAP data), ESC10/16 (certificate mapping settings), ESC13-15.

A CA is trusted for authentication when its certificate is in the NTAuth store (BloodHound's rule). When no NTAuth
store was collected the CA is assumed trusted, which can only over-report.
"""
from __future__ import annotations

from .graph import ADEdge, AttackGraph, NodeType

_ENROLL = {"Enroll", "GenericAll"}
_CONTROL = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WritePKINameFlag", "WritePKIEnrollmentFlag"}
_MANAGE = {"ManageCA", "ManageCertificates", "GenericAll", "WriteDacl", "WriteOwner", "Owns"}
_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"
_PKI_CONTROL = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns"}
_MAX_CROSS = 2000        # cap for the rare "member of group A and of group B" intersection


def _holders(graph: AttackGraph, target: str, types: set[str]) -> set[str]:
    return {u for u, _, d in graph.in_edges(target) if d.get("edge_type") in types}


def _down(graph: AttackGraph, principals: set[str]) -> set[str]:
    """The principals and everyone nested under them (a group's rights are held by its members). Unbounded: use only on
    small inputs; the derivations use `_both`, which never expands a large group."""
    out = set(principals)
    for p in principals:
        node = graph.get_node(p)
        if node is not None and node.node_type in (NodeType.GROUP, NodeType.UNKNOWN):
            out |= graph._recursive_members(p)
    return out


def _ancestors(graph: AttackGraph, node: str, cache: dict) -> set[str]:
    """The node and every group it belongs to, transitively (small, cached)."""
    got = cache.get(node)
    if got is None:
        got, stack = {node}, [node]
        while stack:
            cur = stack.pop()
            for _, t, d in graph.out_edges(cur):
                if d.get("edge_type") == "MemberOf" and t not in got:
                    got.add(t)
                    stack.append(t)
        cache[node] = got
    return got


def _members_bounded(graph: AttackGraph, holders: set[str], cap: int) -> set[str] | None:
    """Everyone nested under the holders, or None if there are more than `cap` of them."""
    seen, stack = set(), list(holders)
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        kids = graph._group_members.get(cur, ())
        if len(seen) + len(kids) > cap:              # never materialize a large group
            return None
        stack.extend(kids)
    return seen


def _both(graph: AttackGraph, a: set[str], b: set[str], cache: dict | None = None) -> set[str]:
    """Principals that hold BOTH rights, where a and b are the direct holders of each: the highest such principals.

    p qualifies when it holds one right directly and is covered by the other through nesting. A user who reaches each right
    through a different group is found too, as long as at least one of the two groups is small enough to enumerate (a user in
    two unrelated groups of a million members is not: such a right is granted to one of the supersets in practice).
    Never expands a large group, so it stays linear in the number of holders."""
    cache = {} if cache is None else cache
    out = {p for p in a if _ancestors(graph, p, cache) & b} | {p for p in b if _ancestors(graph, p, cache) & a}
    def small(holders):
        key = ("down", frozenset(holders))
        if key not in cache:
            cache[key] = _members_bounded(graph, holders, _MAX_CROSS)
        return cache[key]
    small_a, small_b = small(a), small(b)
    side = small_a if small_a is not None else small_b
    if side is not None:
        other = b if side is small_a else a
        for x in side:
            anc = _ancestors(graph, x, cache)
            if anc & other and not (anc & out) and x not in out:
                out.add(x)
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
    counts = {"ADCSESC1": 0, "ADCSESC3": 0, "ADCSESC4": 0, "ADCSESC5": 0, "ADCSESC6": 0, "ADCSESC7": 0, "ADCSESC9": 0,
              "ADCSESC15": 0, "ADCSESC13": 0, "ADCSESC10": 0, "GoldenCert": 0}
    domains = {n.name.upper(): n.object_id for n in graph.nodes_by_type(NodeType.DOMAIN)}
    added: set[tuple[str, str, str]] = set()

    policies = {}
    for pol in graph.nodes_by_type(NodeType.ISSUANCE_POLICY):
        if pol.properties.get("_group_link") and pol.properties.get("oid"):
            policies[str(pol.properties["oid"])] = str(pol.properties["_group_link"])

    def emit(src: str, dom: str, kind: str) -> None:
        if src in graph.tier0_nodes or (src, dom, kind) in added:
            return
        added.add((src, dom, kind))
        graph.add_edge(ADEdge(src, dom, kind))
        counts[kind] += 1

    templates = {n.object_id: n for n in graph.nodes_by_type(NodeType.CERT_TEMPLATE)}
    cache: dict = {}
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
            can_enroll = _both(graph, enrollers, ca_enrollers, cache)
            if auth_template(p) and p.get("enrolleesuppliessubject"):
                for src in can_enroll:
                    emit(src, dom, "ADCSESC1")
            if ((p.get("schemaversion") or 1) == 1 and p.get("enrolleesuppliessubject") and not p.get("requiresmanagerapproval")
                    and not (p.get("authorizedsignatures") or 0)):
                for src in can_enroll:
                    emit(src, dom, "ADCSESC15")
            if policies and auth_template(p):
                for oid in p.get("issuancepolicies") or []:
                    group = policies.get(str(oid))
                    if group is not None and graph.get_node(group) is not None:
                        for src in can_enroll:
                            emit(src, group, "ADCSESC13")
            if san_open and auth_template(p):
                for src in can_enroll:
                    emit(src, dom, "ADCSESC6")
            for src in _both(graph, _holders(graph, t.object_id, _CONTROL), ca_enrollers, cache):
                emit(src, dom, "ADCSESC4")
        # ESC3: an agent template plus a template that accepts an agent's co-signature, both enrollable on this CA
        if ca.properties.get("_agent_collected") and not ca.properties.get("_agent_restrictions"):
            agents = [t for t in enabled if _is_agent_template(t.properties)]
            targets = [t for t in enabled if _accepts_agent(t.properties)]
            for a in agents:
                for b in targets:
                    if a.object_id == b.object_id:
                        continue
                    both = _both(graph, _holders(graph, a.object_id, _ENROLL), _holders(graph, b.object_id, _ENROLL), cache)
                    for src in _both(graph, both, ca_enrollers, cache):
                        emit(src, dom, "ADCSESC3")
        # golden certificate: the machine that holds the CA key can forge any certificate (BloodHound models it the same
        # way: host -> domain; whoever administers the host then reaches it through AdminTo)
        host = ca.properties.get("_host")
        if host and host not in graph.tier0_nodes and graph.get_node(host) is not None:
            emit(host, dom, "GoldenCert")
        # ESC9: needs the template flag AND a domain controller that does not enforce strong binding
        if _weak_binding(graph, dom):
            for t in enabled:
                p = t.properties
                if p.get("nosecurityextension") and auth_template(p):
                    enrollers = _holders(graph, t.object_id, _ENROLL)
                    for src, v in _user_writes(graph):           # a victim is a user that can enroll, reached through the writes
                        if _ancestors(graph, v, cache) & enrollers:
                            emit(src, dom, "ADCSESC9")
        # ESC10: weak mapping on a domain controller (binding not enforced, or UPN mapping enabled) and any authentication template
        if _weak_mapping(graph):
            for t in enabled:
                if auth_template(t.properties):
                    enrollers = _holders(graph, t.object_id, _ENROLL)
                    for src, v in _user_writes(graph):
                        if _ancestors(graph, v, cache) & enrollers:
                            emit(src, dom, "ADCSESC10")
    # ESC5: control of the objects the PKI trust hangs from
    for store in graph.nodes_by_type(NodeType.NTAUTH_STORE) + graph.nodes_by_type(NodeType.ENTERPRISE_CA):
        d = domains.get(str(store.domain).upper())
        if d is None:
            continue
        for src in _holders(graph, store.object_id, _PKI_CONTROL):
            emit(src, d, "ADCSESC5")
    return counts


def _user_writes(graph: AttackGraph) -> list[tuple[str, str]]:
    """(principal, user) for every GenericWrite / GenericAll a principal holds over a user; computed once per graph version."""
    key = (graph.edge_count, graph.node_count)
    cached = getattr(graph, "_user_writes_cache", None)
    if cached and cached[0] == key:
        return cached[1]
    out = []
    for u, v, d in graph.all_edges():
        if d.get("edge_type") in ("GenericWrite", "GenericAll"):
            n = graph.get_node(v)
            if n is not None and n.node_type == NodeType.USER:
                out.append((u, v))
    graph._user_writes_cache = (key, out)
    return out


def _is_agent_template(p: dict) -> bool:
    ekus = set(p.get("effectiveekus") or p.get("ekus") or [])
    return _AGENT_EKU in ekus and not p.get("requiresmanagerapproval") and not (p.get("authorizedsignatures") or 0)


def _accepts_agent(p: dict) -> bool:
    if not (p.get("authenticationenabled") and not p.get("requiresmanagerapproval") and not p.get("enrolleesuppliessubject")):
        return False
    if (p.get("schemaversion") or 1) == 1:
        return True
    return (p.get("authorizedsignatures") or 0) == 1 and _AGENT_EKU in set(p.get("applicationpolicies") or [])


def _weak_mapping(graph: AttackGraph) -> bool:
    """ESC10 preconditions on a collected domain controller: StrongCertificateBindingEnforcement = 0, or UPN mapping (0x4) enabled."""
    for n in graph.nodes_by_type(NodeType.COMPUTER):
        if not n.properties.get("isdc"):
            continue
        if n.properties.get("_strong_binding") == 0:
            return True
        cm = n.properties.get("_cert_mapping")
        if isinstance(cm, int) and cm & 0x4:
            return True
    return False


def _weak_binding(graph: AttackGraph, dom: str) -> bool:
    """True when a collected domain controller of this domain does not enforce strong certificate binding (value != 2)."""
    for n in graph.nodes_by_type(NodeType.COMPUTER):
        v = n.properties.get("_strong_binding")
        if v is not None and n.properties.get("isdc") and v != 2:
            return True
    return False
