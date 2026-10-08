"""SharpHound JSON parser - ingests BloodHound collection data into an AttackGraph."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

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
_ACE_MAP = {
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteOwner": "WriteOwner",
    "WriteDacl": "WriteDacl",
    "Owns": "Owns",
    "ForceChangePassword": "ForceChangePassword",
    "AddMember": "AddMember",
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword",
    "WriteSPN": "WriteSPN",
    "AddAllowedToAct": "AddAllowedToAct",
    "WriteAccountRestrictions": "GenericWrite",
    "AllExtendedRights": "GenericAll",
    "User-Force-Change-Password": "ForceChangePassword",
    "Member": "AddMember",
    "WriteKeyCredentialLink": "WriteKeyCredentialLink",
    "AddSelf": "AddMember",
    "GetChanges": "DCSync",
    "GetChangesAll": "DCSync",
    "GetChangesInFilteredSet": "DCSync",
}

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
    "CertTemplate": NodeType.UNKNOWN,
    "EnterpriseCA": NodeType.UNKNOWN,
    "AIACA": NodeType.UNKNOWN,
    "RootCA": NodeType.UNKNOWN,
    "NTAuthStore": NodeType.UNKNOWN,
}

_CE_EDGE_MAP = {
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteOwner": "WriteOwner",
    "WriteDacl": "WriteDacl",
    "Owns": "Owns",
    "ForceChangePassword": "ForceChangePassword",
    "AddMember": "AddMember",
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword",
    "WriteSPN": "WriteSPN",
    "AddAllowedToAct": "AddAllowedToAct",
    "WriteKeyCredentialLink": "WriteKeyCredentialLink",
    "DCSync": "DCSync",
    "MemberOf": "MemberOf",
    "AdminTo": "AdminTo",
    "HasSession": "HasSession",
    "CanRDP": "CanRDP",
    "CanPSRemote": "CanPSRemote",
    "ExecuteDCOM": "ExecuteDCOM",
    "SQLAdmin": "SQLAdmin",
    "AllowedToDelegate": "AllowedToDelegate",
    "AllowedToAct": "AllowedToAct",
    "GPLink": "GPOControlsObject",
    "Contains": "Contains",
    "TrustedBy": "TrustedBy",
    "Enroll": "Enroll",
    "AutoEnroll": "AutoEnroll",
    "ManageCA": "ManageCA",
    "ManageCertificates": "ManageCertificates",
    "WritePKIEnrollmentFlag": "WritePKIEnrollmentFlag",
    "WritePKINameFlag": "WritePKINameFlag",
    "HasSIDHistory": "GenericAll",
    "GetChanges": "DCSync",
    "GetChangesAll": "DCSync",
    "GetChangesInFilteredSet": "DCSync",
    "AZResetPassword": "ForceChangePassword",
    "AZAddMembers": "AddMember",
    "AZGlobalAdmin": "GenericAll",
    "AZPrivilegedRoleAdmin": "GenericAll",
}


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

            edge_name = _ACE_MAP.get(right)
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

        # Sessions (computers)
        for sess in _unwrap_results(obj.get("Sessions", [])):
            user_sid = sess.get("UserId", sess.get("UserSID", ""))
            if user_sid:
                graph.add_edge(ADEdge(source_id=user_sid, target_id=oid, edge_type="HasSession"))

        # Delegation
        if props.get("unconstraineddelegation"):
            for target_sid in _find_dc_sids(graph):
                graph.add_edge(ADEdge(source_id=oid, target_id=target_sid, edge_type="AllowedToDelegate"))

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
            target_guid = link.get("GUID", link.get("ObjectIdentifier", ""))
            if target_guid:
                graph.add_edge(ADEdge(source_id=oid, target_id=target_guid, edge_type="GPOControlsObject"))

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
                graph.add_edge(ADEdge(source_id=oid, target_id=target_id, edge_type="TrustedBy"))

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

        for sess in _unwrap_results(obj.get("Sessions", [])):
            user_sid = sess.get("UserId", sess.get("UserSID", ""))
            if user_sid:
                graph.add_edge(ADEdge(source_id=user_sid, target_id=oid, edge_type="HasSession"))

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
                graph.add_edge(ADEdge(source_id=oid, target_id=target_id, edge_type="TrustedBy"))

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


def _find_dc_sids(graph: AttackGraph) -> list[str]:
    """Find SIDs of Domain Controller computers already in the graph."""
    dc_sids = []
    for node in graph.nodes_by_type(NodeType.COMPUTER):
        if node.object_id.endswith("-516"):  # Domain Controllers group
            dc_sids.append(node.object_id)
    return dc_sids


def _guess_file_type(filename: str) -> str:
    """Guess SharpHound file type from filename."""
    lower = filename.lower()
    for key in _TYPE_MAP:
        if key in lower:
            return key
    return "unknown"


def load_sharphound(path: str | Path) -> AttackGraph:
    """Load a SharpHound export (ZIP file or directory of JSON files) into an AttackGraph."""
    path = Path(path)
    graph = AttackGraph()
    total_nodes = 0

    if path.is_file() and path.suffix.lower() == ".zip":
        total_nodes = _load_from_zip(path, graph)
    elif path.is_dir():
        total_nodes = _load_from_directory(path, graph)
    else:
        raise ValueError(f"Expected a .zip file or directory, got: {path}")

    # Ensure well-known SIDs have nodes
    for sid, name in _WELL_KNOWN_SIDS.items():
        if sid not in {n.object_id for n in graph.all_nodes()} and graph.graph.has_node(sid):
            graph.add_node(ADNode(
                object_id=sid,
                name=name,
                node_type=NodeType.GROUP,
            ))

    graph.classify_tiers()
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
                if isinstance(data, dict) and "data" in data:
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
        if isinstance(data, dict) and "data" in data:
            total += _parse_one_file(data, graph, file_type)
    return total


def _parse_one_file(data: dict, graph: AttackGraph, file_type: str) -> int:
    """Route to v4 or v5 parser based on format detection."""
    fmt = _detect_format(data)
    if fmt == "v5":
        meta = data.get("meta", {})
        meta_type = meta.get("type", "").lower()
        if meta_type == "edges" or file_type == "edges":
            return _parse_v5_edges_file(data, graph)
        return _parse_v5_file(data, graph)
    return _parse_v4_file(data, graph, file_type)
