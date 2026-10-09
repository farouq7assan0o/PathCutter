"""SharpHound JSON parser - ingests BloodHound collection data into an AttackGraph."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from . import rights as _rights
from .graph import AttackGraph, ADNode, ADEdge, NodeType


# SharpHound type string -> NodeType
_TYPE_MAP = {
    "users": NodeType.USER,
    "computers": NodeType.COMPUTER,
    "groups": NodeType.GROUP,
    "domains": NodeType.DOMAIN,
    "gpos": NodeType.GPO,
    "ous": NodeType.OU,
    "containers": NodeType.CONTAINER,
    "certtemplates": NodeType.CERT_TEMPLATE,
    "enterprisecas": NodeType.ENTERPRISE_CA,
    "rootcas": NodeType.ROOT_CA,
    "aiacas": NodeType.AIACA,
    "ntauthstores": NodeType.NTAUTH_STORE,
    "issuancepolicies": NodeType.ISSUANCE_POLICY,
}

# BloodHound CE kind string -> NodeType
_KIND_MAP = {
    "User": NodeType.USER,
    "Computer": NodeType.COMPUTER,
    "Group": NodeType.GROUP,
    "Domain": NodeType.DOMAIN,
    "GPO": NodeType.GPO,
    "OU": NodeType.OU,
    "Container": NodeType.CONTAINER,
    "Base": NodeType.UNKNOWN,
}

# SharpHound ACE right name -> our edge type name
_ACE_MAP = _rights.collector_ace()

# Well-known SID -> friendly name
_WELL_KNOWN_SIDS = {
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-1-0": "Everyone",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    "S-1-5-7": "NT AUTHORITY\\ANONYMOUS LOGON",
}


def _unwrap_results(value) -> list:
    """Handle SharpHound fields that may be a list or a dict with 'Results' key."""
    if isinstance(value, dict):
        return value.get("Results", [])
    if isinstance(value, list):
        return value
    return []


_CE_KIND_MAP = {
    "User": NodeType.USER,
    "Computer": NodeType.COMPUTER,
    "Group": NodeType.GROUP,
    "Domain": NodeType.DOMAIN,
    "GPO": NodeType.GPO,
    "OU": NodeType.OU,
    "Container": NodeType.CONTAINER,
    "CertTemplate": NodeType.CERT_TEMPLATE,
    "EnterpriseCA": NodeType.ENTERPRISE_CA,
    "AIACA": NodeType.AIACA,
    "RootCA": NodeType.ROOT_CA,
    "NTAuthStore": NodeType.NTAUTH_STORE,
    "IssuancePolicy": NodeType.ISSUANCE_POLICY,
}

_CE_EDGE_MAP = _rights.collector_edge()


def _detect_format(data: dict) -> str:
    """Detect whether this is SharpHound v4 (legacy) or v5 (CE) format.

    v4 (SharpHound legacy): meta has 'type' field, objects have Properties/ObjectIdentifier/Aces.
    v5 (BloodHound CE): objects have a 'kind' field indicating object type.
    The meta 'version' field is the collector version, not the format version.
    """
    meta = data.get("meta", {})
    # Check if objects have 'kind' field (v5 CE format)
    items = data.get("data", [])
    if items and isinstance(items, list) and isinstance(items[0], dict):
        if "kind" in items[0]:
            return "v5"
    # v4: meta has 'type' indicating file type
    if "type" in meta:
        return "v4"
    if "methods" in meta:
        return "v4"
    return "v4"


def _extract_domain(name: str) -> str:
    """Extract domain from FQDN like user@domain.local or DOMAIN.LOCAL."""
    if "@" in name:
        return name.split("@")[-1].upper()
    parts = name.split(".")
    if len(parts) > 1:
        return ".".join(parts[1:]).upper() if parts[0] != parts[0].upper() else name.upper()
    return ""


def _parse_v4_file(data: dict, graph: AttackGraph, file_type: str) -> int:
    """Parse a SharpHound v4 JSON file and add nodes/edges to graph. Returns count of nodes added."""
    meta = data.get("meta", {})
    type_str = meta.get("type", file_type).lower()
    node_type = _TYPE_MAP.get(type_str, NodeType.UNKNOWN)
    count = 0

    for obj in data.get("data", []):
        oid = obj.get("ObjectIdentifier", "")
        if not oid:
            continue

        props = obj.get("Properties", {})
        name = props.get("name", oid)
        domain = props.get("domain", _extract_domain(name))
        enabled = props.get("enabled", True)
        admin_count = props.get("admincount", False)

        node = ADNode(
            object_id=oid,
            name=name,
            node_type=node_type,
            domain=domain,
            enabled=enabled if enabled is not None else True,
            admin_count=admin_count if admin_count else False,
            properties={k: v for k, v in props.items()
                        if k not in ("name", "domain", "enabled", "admincount")},
        )
        graph.add_node(node)
        count += 1

        # ACEs -> edges
        for ace in obj.get("Aces", []):
            principal_sid = ace.get("PrincipalSID", "")
            right = ace.get("RightName", "")
            inherited = ace.get("IsInherited", False)

            if not principal_sid or not right:
                continue

            edge_name = _ACE_MAP.get(right) or _CE_EDGE_MAP.get(right)
            if edge_name:
                graph.add_edge(ADEdge(
                    source_id=principal_sid,
                    target_id=oid,
                    edge_type=edge_name,
                    inherited=inherited,
                ))

        # Group members -> MemberOf edges (inverted: member -> group)
        members_raw = obj.get("Members", [])
        for member in _unwrap_results(members_raw):
            member_sid = member.get("MemberId", member.get("ObjectIdentifier", ""))
            if member_sid:
                graph.add_edge(ADEdge(
                    source_id=member_sid,
                    target_id=oid,
                    edge_type="MemberOf",
                ))

        _modern_relationships(obj, oid, graph)

        # Local admins (computers)
        for la in _unwrap_results(obj.get("LocalAdmins", [])):
            la_sid = la.get("MemberId", la.get("ObjectIdentifier", ""))
            if la_sid:
                graph.add_edge(ADEdge(source_id=la_sid, target_id=oid, edge_type="AdminTo"))

        # Remote Desktop Users
        for rdp in _unwrap_results(obj.get("RemoteDesktopUsers", [])):
            rdp_sid = rdp.get("MemberId", rdp.get("ObjectIdentifier", ""))
            if rdp_sid:
                graph.add_edge(ADEdge(source_id=rdp_sid, target_id=oid, edge_type="CanRDP"))

        # PSRemote users
        for ps in _unwrap_results(obj.get("PSRemoteUsers", [])):
            ps_sid = ps.get("MemberId", ps.get("ObjectIdentifier", ""))
            if ps_sid:
                graph.add_edge(ADEdge(source_id=ps_sid, target_id=oid, edge_type="CanPSRemote"))

        # DCOM users
        for dcom in _unwrap_results(obj.get("DcomUsers", [])):
            dcom_sid = dcom.get("MemberId", dcom.get("ObjectIdentifier", ""))
            if dcom_sid:
                graph.add_edge(ADEdge(source_id=dcom_sid, target_id=oid, edge_type="ExecuteDCOM"))

        # Delegation (unconstrained delegation is resolved after every file is loaded; see load_sharphound)
        for target in _unwrap_results(obj.get("AllowedToDelegate", [])):
            target_sid = target.get("ObjectIdentifier", target) if isinstance(target, dict) else target
            if target_sid:
                graph.add_edge(ADEdge(source_id=oid, target_id=target_sid, edge_type="AllowedToDelegate"))

        for target in _unwrap_results(obj.get("AllowedToAct", [])):
            target_sid = target.get("ObjectIdentifier", target) if isinstance(target, dict) else target
            if target_sid:
                graph.add_edge(ADEdge(source_id=target_sid, target_id=oid, edge_type="AllowedToAct"))

        # GPO effects
        for link in _unwrap_results(obj.get("Links", [])):
            gpo_guid = link.get("GUID", link.get("ObjectIdentifier", ""))
            if gpo_guid:
                graph.add_edge(ADEdge(source_id=gpo_guid, target_id=oid, edge_type="GPOControlsObject"))

        # OU/Container containment
        for child in _unwrap_results(obj.get("ChildObjects", [])):
            child_id = child.get("ObjectIdentifier", "")
            if child_id:
                graph.add_edge(ADEdge(source_id=oid, target_id=child_id, edge_type="Contains"))

        # SQL Admins
        for sql in _unwrap_results(obj.get("SQLAdmins", [])):
            sql_sid = sql.get("MemberId", sql.get("ObjectIdentifier", ""))
            if sql_sid:
                graph.add_edge(ADEdge(source_id=sql_sid, target_id=oid, edge_type="SQLAdmin"))

        # Domain trusts
        for trust in obj.get("Trusts", []):
            target_id = trust.get("TargetDomainSid", "")
            if target_id:
                graph.add_edge(ADEdge(source_id=oid, target_id=target_id, edge_type="TrustedBy",
                                      properties=_trust_props(trust)))

    return count


def _parse_v5_file(data: dict, graph: AttackGraph) -> int:
    """Parse a BloodHound CE (v5) format file. Returns count of nodes added."""
    count = 0
    items = data.get("data", [])

    for obj in items:
        kind = obj.get("kind", "")
        oid = obj.get("ObjectIdentifier", obj.get("object_id", ""))
        if not oid:
            continue

        node_type = _CE_KIND_MAP.get(kind, NodeType.UNKNOWN)
        props = obj.get("Properties", obj.get("properties", {}))
        name = props.get("name", oid)
        domain = props.get("domain", _extract_domain(name))
        enabled = props.get("enabled", True)
        admin_count = props.get("admincount", False)

        node = ADNode(
            object_id=oid,
            name=name,
            node_type=node_type,
            domain=domain,
            enabled=enabled if enabled is not None else True,
            admin_count=admin_count if admin_count else False,
            properties={k: v for k, v in props.items()
                        if k not in ("name", "domain", "enabled", "admincount")},
        )
        graph.add_node(node)
        count += 1

        # v5 ACEs
        for ace in obj.get("Aces", []):
            principal_sid = ace.get("PrincipalSID", ace.get("principal", ""))
            right = ace.get("RightName", ace.get("right_name", ""))
            inherited = ace.get("IsInherited", ace.get("is_inherited", False))

            if not principal_sid or not right:
                continue

            edge_name = _CE_EDGE_MAP.get(right) or _ACE_MAP.get(right)
            if edge_name:
                graph.add_edge(ADEdge(
                    source_id=principal_sid,
                    target_id=oid,
                    edge_type=edge_name,
                    inherited=inherited,
                ))

        # v5 edges array (some CE exports put edges in a separate section)
        for edge in obj.get("Edges", obj.get("edges", [])):
            src = edge.get("SourceSID", edge.get("source", ""))
            tgt = edge.get("TargetSID", edge.get("target", ""))
            kind_edge = edge.get("Kind", edge.get("kind", ""))
            if src and tgt and kind_edge:
                mapped = _CE_EDGE_MAP.get(kind_edge, kind_edge)
                graph.add_edge(ADEdge(source_id=src, target_id=tgt, edge_type=mapped))

        # Group members
        for member in _unwrap_results(obj.get("Members", [])):
            member_sid = member.get("MemberId", member.get("ObjectIdentifier", ""))
            if member_sid:
                graph.add_edge(ADEdge(source_id=member_sid, target_id=oid, edge_type="MemberOf"))

        # Same secondary edge types as v4
        for la in _unwrap_results(obj.get("LocalAdmins", [])):
            sid = la.get("MemberId", la.get("ObjectIdentifier", ""))
            if sid:
                graph.add_edge(ADEdge(source_id=sid, target_id=oid, edge_type="AdminTo"))

        _modern_relationships(obj, oid, graph)

        for target in _unwrap_results(obj.get("AllowedToDelegate", [])):
            target_sid = target.get("ObjectIdentifier", target) if isinstance(target, dict) else target
            if target_sid:
                graph.add_edge(ADEdge(source_id=oid, target_id=target_sid, edge_type="AllowedToDelegate"))

        for target in _unwrap_results(obj.get("AllowedToAct", [])):
            target_sid = target.get("ObjectIdentifier", target) if isinstance(target, dict) else target
            if target_sid:
                graph.add_edge(ADEdge(source_id=target_sid, target_id=oid, edge_type="AllowedToAct"))

        for child in _unwrap_results(obj.get("ChildObjects", [])):
            child_id = child.get("ObjectIdentifier", "")
            if child_id:
                graph.add_edge(ADEdge(source_id=oid, target_id=child_id, edge_type="Contains"))

        for trust in obj.get("Trusts", []):
            target_id = trust.get("TargetDomainSid", "")
            if target_id:
                graph.add_edge(ADEdge(source_id=oid, target_id=target_id, edge_type="TrustedBy",
                                      properties=_trust_props(trust)))

    return count


def _parse_v5_edges_file(data: dict, graph: AttackGraph) -> int:
    """Parse a standalone CE edges file (contains only relationship data)."""
    count = 0
    for edge in data.get("data", []):
        src = edge.get("SourceSID", edge.get("source", edge.get("ID_start", "")))
        tgt = edge.get("TargetSID", edge.get("target", edge.get("ID_end", "")))
        kind = edge.get("Kind", edge.get("kind", edge.get("label", "")))
        if src and tgt and kind:
            mapped = _CE_EDGE_MAP.get(kind, kind)
            graph.add_edge(ADEdge(source_id=src, target_id=tgt, edge_type=mapped))
            count += 1
    return count


_LOCAL_GROUP_EDGE = _rights.local_group_rid()
_GPO_CHANGE_EDGE = _rights.gpo_changes()


def _principal_id(value) -> str:
    if isinstance(value, dict):
        return value.get("ObjectIdentifier") or value.get("MemberId") or value.get("UserSID") or value.get("UserId") or ""
    return value if isinstance(value, str) else ""


def _modern_relationships(obj: dict, oid: str, graph: AttackGraph) -> None:
    """Relationships that current collectors (SharpHound 2.x, BloodHound.py CE) put on the object itself."""
    node = graph.get_node(oid)
    if obj.get("IsDC") and node is not None:
        node.properties["isdc"] = True

    primary = obj.get("PrimaryGroupSID")
    if primary:                                   # membership by primary group is not listed in Group.Members
        graph.add_edge(ADEdge(source_id=oid, target_id=primary, edge_type="MemberOf"))

    for entry in obj.get("LocalGroups") or []:    # local groups of a computer, keyed by well-known RID
        edge = _LOCAL_GROUP_EDGE.get(str(entry.get("ObjectIdentifier", "")).rsplit("-", 1)[-1])
        if not edge:
            continue
        for member in _unwrap_results(entry):
            mid = _principal_id(member)
            if mid:
                graph.add_edge(ADEdge(source_id=mid, target_id=oid, edge_type=edge))

    for key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
        for sess in _unwrap_results(obj.get(key)):
            user = _principal_id(sess) if not isinstance(sess, dict) else (sess.get("UserSID") or sess.get("UserId") or "")
            if user:
                graph.add_edge(ADEdge(source_id=oid, target_id=user, edge_type="HasSession"))

    for hist in obj.get("HasSIDHistory") or []:
        hid = _principal_id(hist)
        if hid:
            graph.add_edge(ADEdge(source_id=oid, target_id=hid, edge_type="HasSIDHistory"))

    for smsa in obj.get("DumpSMSAPassword") or []:
        sid = _principal_id(smsa)
        if sid:
            graph.add_edge(ADEdge(source_id=oid, target_id=sid, edge_type="ReadGMSAPassword"))

    changes = obj.get("GPOChanges") or {}          # local-group rights pushed to computers by linked GPOs
    affected = [_principal_id(a) for a in changes.get("AffectedComputers") or []]
    for key, edge in _GPO_CHANGE_EDGE.items():
        for member in changes.get(key) or []:
            mid = _principal_id(member)
            for comp in affected:
                if mid and comp:
                    graph.add_edge(ADEdge(source_id=mid, target_id=comp, edge_type=edge))


_WELL_KNOWN_RID = {
    "498": "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS", "500": "ADMINISTRATOR", "501": "GUEST", "502": "KRBTGT",
    "512": "DOMAIN ADMINS", "513": "DOMAIN USERS", "514": "DOMAIN GUESTS", "515": "DOMAIN COMPUTERS",
    "516": "DOMAIN CONTROLLERS", "517": "CERT PUBLISHERS", "518": "SCHEMA ADMINS", "519": "ENTERPRISE ADMINS",
    "520": "GROUP POLICY CREATOR OWNERS", "521": "READ-ONLY DOMAIN CONTROLLERS", "525": "PROTECTED USERS",
    "526": "KEY ADMINS", "527": "ENTERPRISE KEY ADMINS",
}
_WELL_KNOWN_SUFFIX = {
    "S-1-1-0": "EVERYONE", "S-1-3-0": "CREATOR OWNER", "S-1-5-9": "ENTERPRISE DOMAIN CONTROLLERS",
    "S-1-5-10": "SELF", "S-1-5-11": "AUTHENTICATED USERS", "S-1-5-18": "LOCAL SYSTEM", "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-32-544": "ADMINISTRATORS", "S-1-5-32-545": "USERS", "S-1-5-32-548": "ACCOUNT OPERATORS",
    "S-1-5-32-549": "SERVER OPERATORS", "S-1-5-32-550": "PRINT OPERATORS", "S-1-5-32-551": "BACKUP OPERATORS",
    "S-1-5-32-554": "PRE-WINDOWS 2000 COMPATIBLE ACCESS", "S-1-5-32-555": "REMOTE DESKTOP USERS",
    "S-1-5-32-560": "WINDOWS AUTHORIZATION ACCESS GROUP", "S-1-5-32-562": "DISTRIBUTED COM USERS",
    "S-1-5-32-580": "REMOTE MANAGEMENT USERS",
}


def _name_uncollected_principals(graph: AttackGraph) -> None:
    """ACEs reference principals (SYSTEM, Everyone, builtin groups, domains we did not collect) that have no
    object of their own. Give them a real name and type so reports read sensibly instead of 'Unknown'."""
    known = {n.object_id for n in graph.all_nodes()}
    for oid in list(graph.graph.nodes):
        if oid in known or not isinstance(oid, str):
            continue
        domain, _, sid = oid.rpartition("-S-1-")
        sid = "S-1-" + sid if domain else oid
        domain = domain.upper() if domain else ""
        name = _WELL_KNOWN_SUFFIX.get(sid)
        if name is None and sid.startswith("S-1-5-21-"):
            name = _WELL_KNOWN_RID.get(sid.rsplit("-", 1)[-1])
        if name is None:
            continue
        graph.add_node(ADNode(object_id=oid, name=f"{name}@{domain}" if domain else name, node_type=NodeType.GROUP,
                              domain=domain))


def _add_implicit_memberships(graph: AttackGraph) -> None:
    """Every user and computer is implicitly a member of Everyone and Authenticated Users, so an ACE granted to either is
    a right held by everyone. Domain Users / Domain Computers already contain every principal (primary group), so linking
    just those two keeps this to a handful of edges per domain instead of one per object."""
    domains = {n.name.upper(): n.object_id for n in graph.nodes_by_type(NodeType.DOMAIN)}
    for oid in list(graph.graph.nodes):
        if not isinstance(oid, str) or not (oid.endswith("-S-1-1-0") or oid.endswith("-S-1-5-11") or oid in ("S-1-1-0", "S-1-5-11")):
            continue
        prefix = oid.rpartition("-S-1-")[0].upper()
        sids = [domains[prefix]] if prefix in domains else (list(domains.values()) if not prefix else [])
        for dsid in sids:
            for rid in ("513", "515"):
                member = f"{dsid}-{rid}"
                if graph.get_node(member) is not None and not graph.has_edge_type(member, oid, "MemberOf"):
                    graph.add_edge(ADEdge(source_id=member, target_id=oid, edge_type="MemberOf"))


def find_dc_sids(graph: AttackGraph) -> list[str]:
    """Domain controller computers: computers that are members of a Domain Controllers group.

    Must run after every file is loaded, because membership edges arrive with the group files.
    """
    dc_groups = {n.object_id for n in graph.all_nodes()
                 if n.object_id.endswith("-516") or n.name.upper().split("@")[0] == "DOMAIN CONTROLLERS"}
    dcs = []
    for node in graph.nodes_by_type(NodeType.COMPUTER):
        if node.properties.get("isdc") or any(t in dc_groups for _, t, d in graph.out_edges(node.object_id) if d.get("edge_type") == "MemberOf"):
            dcs.append(node.object_id)
    return dcs


def _link_unconstrained_delegation(graph: AttackGraph) -> None:
    """A host trusted for unconstrained delegation can capture the TGT of anything that authenticates to
    it, so it is treated as able to act as every domain controller (edge AllowedToDelegate host -> DC)."""
    dcs = set(find_dc_sids(graph))
    if not dcs:
        return
    for node in graph.all_nodes():
        if node.object_id in dcs or not node.properties.get("unconstraineddelegation"):
            continue
        for dc in dcs:
            if not graph.has_edge_type(node.object_id, dc, "AllowedToDelegate"):
                graph.add_edge(ADEdge(source_id=node.object_id, target_id=dc, edge_type="AllowedToDelegate"))


def _guess_file_type(filename: str) -> str:
    """Guess SharpHound file type from filename."""
    lower = filename.lower()
    if "denies" in lower:
        return "denies"
    for key in _TYPE_MAP:
        if key in lower:
            return key
    return "unknown"


_TRANSIENT_EDGES = ("HasSession",)          # seen at one moment: how often they were seen is information


def _merge_into(into: AttackGraph, other: AttackGraph) -> None:
    """Union of two raw collections of the same environment. Sessions count how many collections saw them."""
    for n in other.all_nodes():
        cur = into.get_node(n.object_id)
        if cur is None:
            into.add_node(n)
        else:
            if cur.node_type == NodeType.UNKNOWN and n.node_type != NodeType.UNKNOWN:
                cur.node_type, cur.name = n.node_type, n.name
            for k, v in n.properties.items():
                if v not in (None, "", [], {}):
                    cur.properties[k] = v
    for u, v, d in other.all_edges():
        et = d.get("edge_type", "")
        existing = into.graph.get_edge_data(u, v) or {}
        key = next((k for k, dd in existing.items() if dd.get("edge_type") == et), None)
        if key is None:
            props = {k: val for k, val in d.items() if k not in ("edge_type", "inherited", "weight")}
            if et in _TRANSIENT_EDGES:
                props["seen"] = 1
            into.add_edge(ADEdge(u, v, et, d.get("inherited", False), props))
        elif et in _TRANSIENT_EDGES:
            existing[key]["seen"] = existing[key].get("seen", 1) + 1
    into.denies |= other.denies
    for k, v in other.meta.items():
        if isinstance(v, list):
            into.meta.setdefault(k, [])
            into.meta[k] += [x for x in v if x not in into.meta[k]]


def load_sharphound(path) -> AttackGraph:
    """Load a SharpHound export (ZIP file or directory of JSON files) into an AttackGraph.

    Pass a list of paths to combine several collections of the same environment (for example sessions collected on
    different days): objects and edges are unioned and every session edge records in how many collections it was seen.
    """
    if isinstance(path, (list, tuple)):
        if not path:
            raise ValueError("no input given")
        if len(path) > 1:
            merged = _load_raw(Path(path[0]))
            merged.meta["collections"] = len(path)
            for _, _, d in merged.all_edges():
                if d.get("edge_type") in _TRANSIENT_EDGES:
                    d["seen"] = 1
            for p in path[1:]:
                _merge_into(merged, _load_raw(Path(p)))
            return _finish(merged)
        path = path[0]
    return _finish(_load_raw(Path(path)))


def _load_raw(path: Path) -> AttackGraph:
    graph = AttackGraph()
    total_nodes = 0

    if path.is_file() and path.suffix.lower() == ".zip":
        total_nodes = _load_from_zip(path, graph)
    elif path.is_dir():
        total_nodes = _load_from_directory(path, graph)
    else:
        raise ValueError(f"Expected a .zip file or directory, got: {path}")
    return graph


def _finish(graph: AttackGraph) -> AttackGraph:
    # Ensure well-known SIDs have nodes
    for sid, name in _WELL_KNOWN_SIDS.items():
        if sid not in {n.object_id for n in graph.all_nodes()} and graph.graph.has_node(sid):
            graph.add_node(ADNode(
                object_id=sid,
                name=name,
                node_type=NodeType.GROUP,
            ))

    from . import azure
    azure.finalize_azure(graph)
    _name_uncollected_principals(graph)
    _add_implicit_memberships(graph)
    _link_unconstrained_delegation(graph)
    graph.classify_tiers()
    from .adcs import derive_adcs_edges
    derive_adcs_edges(graph)
    return graph


def _load_from_zip(zip_path: Path, graph: AttackGraph) -> int:
    total = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for entry in zf.namelist():
            if not entry.endswith(".json"):
                continue
            file_type = _guess_file_type(entry)
            with zf.open(entry) as f:
                try:
                    data = json.load(f)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if isinstance(data, dict) and ("data" in data or "value" in data):
                    total += _parse_one_file(data, graph, file_type)
    return total


def _load_from_directory(dir_path: Path, graph: AttackGraph) -> int:
    total = 0
    for json_file in sorted(dir_path.glob("*.json")):
        file_type = _guess_file_type(json_file.name)
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(data, dict) and ("data" in data or "value" in data):
            total += _parse_one_file(data, graph, file_type)
    return total


def _trust_props(trust: dict) -> dict:
    """Keep what the collector knows about a trust. Exposure still treats every trust as traversable (conservative);
    direction, transitivity and SID filtering are recorded so reports and `doctor` can say what they imply."""
    return {"trust_type": trust.get("TrustType"), "trust_direction": trust.get("TrustDirection"),
            "transitive": trust.get("IsTransitive"), "sid_filtering": trust.get("SidFilteringEnabled")}


def _parse_denies(data: dict, graph: AttackGraph) -> int:
    """Deny ACEs from the optional collector (tools/Export-AdDenyAces.ps1). SharpHound itself does not collect them.

    Each record: {"PrincipalSID", "RightName", "ObjectIdentifier"}. Rights are mapped like allow ACEs."""
    from .graph import Deny
    n = 0
    for rec in data.get("data", []):
        right = rec.get("RightName", "")
        edge = _ACE_MAP.get(right) or _CE_EDGE_MAP.get(right)
        who, obj = rec.get("PrincipalSID") or rec.get("PrincipalSid"), rec.get("ObjectIdentifier")
        if edge and who and obj:
            graph.denies.add(Deny(str(who), edge, str(obj)))
            n += 1
    return n


def _capture_ca_extras(data: dict, graph: AttackGraph) -> None:
    """Enterprise CA fields that are not Properties: the templates it publishes and its SAN-flag registry value."""
    for obj in data.get("data", []):
        if "EnabledCertTemplates" not in obj and "CARegistryData" not in obj:
            continue
        node = graph.get_node(obj.get("ObjectIdentifier", ""))
        if node is None:
            continue
        node.properties["_enabled_templates"] = [t.get("ObjectIdentifier") for t in (obj.get("EnabledCertTemplates") or [])
                                                 if isinstance(t, dict)]
        san = ((obj.get("CARegistryData") or {}).get("IsUserSpecifiesSanEnabled") or {})
        node.properties["_san_enabled"] = bool(san.get("Value"))
        node.properties["_san_collected"] = bool(san.get("Collected"))
        node.properties["_host"] = obj.get("HostingComputer")
        ear = ((obj.get("CARegistryData") or {}).get("EnrollmentAgentRestrictions") or {})
        node.properties["_agent_restrictions"] = len(ear.get("Restrictions") or [])
        node.properties["_agent_collected"] = bool(ear.get("Collected"))


def _capture_issuance_policies(data: dict, graph: AttackGraph) -> None:
    """Issuance policy objects: the OID and the group it is linked to (msDS-OIDToGroupLink), for ESC13."""
    for obj in data.get("data", []):
        node = graph.get_node(obj.get("ObjectIdentifier", ""))
        if node is None:
            continue
        link = (obj.get("GroupLink") or {}).get("ObjectIdentifier")
        node.properties["_group_link"] = link
        if link:
            graph.add_edge(ADEdge(node.object_id, str(link), "OIDGroupLink"))


def _capture_dc_registry(data: dict, graph: AttackGraph) -> None:
    """StrongCertificateBindingEnforcement from domain controllers (only newer collectors gather it)."""
    for obj in data.get("data", []):
        reg = obj.get("DCRegistryData")
        if not isinstance(reg, dict):
            continue
        node = graph.get_node(obj.get("ObjectIdentifier", ""))
        sb = reg.get("StrongCertificateBindingEnforcement")
        if node is not None and isinstance(sb, dict) and sb.get("Collected") and sb.get("Value") is not None:
            node.properties["_strong_binding"] = sb.get("Value")


def _parse_one_file(data: dict, graph: AttackGraph, file_type: str) -> int:
    """Route to v4 or v5 parser based on format detection."""
    if str((data.get("meta") or {}).get("type", "")).lower() == "denies" or file_type == "denies":
        _parse_denies(data, graph)
        return 0
    from . import azure, conditional_access
    if conditional_access.is_ca_file(data):
        graph.meta.setdefault("conditional_access", []).extend(conditional_access.policies_of(data))
        return 0
    if azure.is_azure_file(data):
        return azure.parse_azure_file(data, graph)
    n = _parse_known_file(data, graph, file_type)
    ftype = str((data.get("meta") or {}).get("type", "")).lower() or file_type
    if ftype == "issuancepolicies":
        _capture_issuance_policies(data, graph)
    if ftype == "enterprisecas":
        _capture_ca_extras(data, graph)
    elif ftype == "computers":
        _capture_dc_registry(data, graph)
    return n


def _parse_known_file(data: dict, graph: AttackGraph, file_type: str) -> int:
    fmt = _detect_format(data)
    if fmt == "v5":
        meta = data.get("meta", {})
        meta_type = meta.get("type", "").lower()
        if meta_type == "edges" or file_type == "edges":
            return _parse_v5_edges_file(data, graph)
        return _parse_v5_file(data, graph)
    return _parse_v4_file(data, graph, file_type)
