"""Native ingestion of AD Explorer snapshots (Sysinternals), exported to NDJSON by ADExplorerSnapshot.py Objects mode.

AD Explorer is Microsoft-signed, so it collects a full LDAP snapshot of a domain where SharpHound is blocked by EDR.
`ADExplorerSnapshot.py -m Objects snapshot.dat` writes one JSON object per line with every LDAP attribute (SIDs and
GUIDs already resolved to strings, memberships as DNs). This module reads that file, parses the binary security
descriptors into the same ACL edges SharpHound emits, and produces SharpHound-v4-shaped file dicts that the normal
ingest consumes. The result is sessions-free and local-group-free (LDAP only), so exposure is a floor; `doctor` says so.
"""
from __future__ import annotations

import base64
import json
import re
import uuid
from pathlib import Path

from .rights import property_guids

# ---- access mask bits (ADS rights) --------------------------------------------------------------------------------
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_OWNER = 0x00080000
WRITE_DACL = 0x00040000
DS_CONTROL_ACCESS = 0x00000100
DS_WRITE_PROP = 0x00000020
DS_SELF = 0x00000008
FULL_CONTROL = 0x000F01FF
_INHERITED_ACE = 0x10
_ZERO_GUID = "00000000-0000-0000-0000-000000000000"
_MEMBER_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"
# trustees SharpHound drops from ACEs: they are relative/non-principal and never useful attack sources
_SKIP_SID = {"S-1-3-0", "S-1-5-18", "S-1-5-10", "S-1-5-9", "S-1-5-7", "S-1-0-0", "S-1-5-5"}


def _skip(sid: str) -> bool:
    return sid in _SKIP_SID or sid.startswith("S-1-5-5-")        # logon sessions

# extended-right GUID -> RightName PathCutter understands (DCSync is derived from the two replication rights)
_EXT_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet",
}
# write-property GUID -> RightName, from the declarative rights table (member, SPN, RBCD, key credential, PKI flags)
_WRITE_PROPS = {g.lower(): e for g, e, k in
                ((p["guid"], p["edge"], p["kind"]) for p in __import__("json").load(
                    open(Path(__file__).parent / "data" / "rights.json", encoding="utf-8"))["properties"]
                 if p.get("guid") and p.get("kind") == "write_property")}

_SCHEMA_CONFIG = re.compile(r",CN=(Schema|Configuration),", re.I)


def is_adexplorer_ndjson(path) -> bool:
    p = Path(path)
    if p.is_dir():
        return any(is_adexplorer_ndjson(f) for f in p.glob("*.ndjson"))
    if p.suffix.lower() != ".ndjson" or not p.is_file():
        return False
    try:
        with open(p, encoding="utf-8") as fh:
            first = fh.readline()
        o = json.loads(first)
        return isinstance(o, dict) and "distinguishedName" in o and "objectClass" in o
    except (ValueError, OSError):
        return False


# ---- binary helpers -----------------------------------------------------------------------------------------------

def _sid(b: bytes, off: int = 0) -> str:
    rev = b[off]
    cnt = b[off + 1]
    auth = int.from_bytes(b[off + 2:off + 8], "big")
    subs = [int.from_bytes(b[off + 8 + 4 * i:off + 12 + 4 * i], "little") for i in range(cnt)]
    return "S-%d-%d%s" % (rev, auth, "".join("-%d" % s for s in subs))


def _sid_len(b: bytes, off: int = 0) -> int:
    return 8 + 4 * b[off + 1]


def _guid(b: bytes, off: int) -> str:
    return str(uuid.UUID(bytes_le=bytes(b[off:off + 16])))


def _rights_for(mask: int, otype: str | None) -> list[str]:
    """SharpHound-style mapping of one allowed ACE to BloodHound right names."""
    out: list[str] = []
    if otype is None or otype == _ZERO_GUID:
        if mask & GENERIC_ALL or (mask & FULL_CONTROL) == FULL_CONTROL:
            return ["GenericAll"]
        if mask & WRITE_OWNER:
            out.append("WriteOwner")
        if mask & WRITE_DACL:
            out.append("WriteDacl")
        if mask & (GENERIC_WRITE | DS_WRITE_PROP):
            out.append("GenericWrite")
        if mask & DS_CONTROL_ACCESS:
            out.append("AllExtendedRights")
    else:
        g = otype.lower()
        if mask & DS_CONTROL_ACCESS:
            r = _EXT_RIGHTS.get(g)
            if r:
                out.append(r)
            elif mask & GENERIC_ALL:
                out.append("GenericAll")
        if mask & DS_WRITE_PROP:
            r = _WRITE_PROPS.get(g)
            if r:
                out.append(r)
        if mask & DS_SELF and g == _MEMBER_GUID:
            out.append("AddSelf")
    return out


def _parse_sd(blob: str) -> tuple[str | None, list[tuple[str, str, bool]]]:
    """Return (owner SID, [(trustee SID, RightName, inherited)]) from a base64 security descriptor."""
    try:
        sd = base64.b64decode(blob)
    except Exception:
        return None, []
    if len(sd) < 20:
        return None, []
    owner_off = int.from_bytes(sd[4:8], "little")
    dacl_off = int.from_bytes(sd[16:20], "little")
    owner = _sid(sd, owner_off) if owner_off and owner_off + 8 <= len(sd) else None
    aces: list[tuple[str, str, bool]] = []
    if dacl_off and dacl_off + 8 <= len(sd):
        count = int.from_bytes(sd[dacl_off + 4:dacl_off + 6], "little")
        pos = dacl_off + 8
        for _ in range(count):
            if pos + 4 > len(sd):
                break
            atype = sd[pos]
            aflags = sd[pos + 1]
            asize = int.from_bytes(sd[pos + 2:pos + 4], "little")
            if asize < 4 or pos + asize > len(sd):
                break
            body = sd[pos + 4:pos + asize]
            if atype in (0x00, 0x05) and len(body) >= 4:          # ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT
                mask = int.from_bytes(body[0:4], "little")
                otype = None
                try:
                    if atype == 0x00:
                        sid = _sid(body, 4)
                    else:
                        flags = int.from_bytes(body[4:8], "little")
                        o = 8
                        if flags & 0x1:
                            otype = _guid(body, o); o += 16
                        if flags & 0x2:
                            o += 16
                        sid = _sid(body, o)
                    for right in _rights_for(mask, otype):
                        aces.append((sid, right, bool(aflags & _INHERITED_ACE)))
                except (IndexError, ValueError):
                    pass
            pos += asize
    return owner, aces


# ---- object classification ----------------------------------------------------------------------------------------

_TYPE_BY_CLASS = [
    ("computer", "computers"), ("groupManagedServiceAccount", "users"), ("msDS-GroupManagedServiceAccount", "users"),
    ("user", "users"), ("inetOrgPerson", "users"), ("group", "groups"), ("domainDNS", "domains"),
    ("organizationalUnit", "ous"), ("groupPolicyContainer", "gpos"), ("foreignSecurityPrincipal", "users"),
    ("trustedDomain", "domains"),
]


def _classify(classes: list[str]) -> str | None:
    cl = set(classes)
    for name, ft in _TYPE_BY_CLASS:
        if name in cl:
            return ft
    if "container" in cl or "builtinDomain" in cl or "lostAndFound" in cl:
        return "containers"
    return None


def _one(v):
    return v[0] if isinstance(v, list) and v else (v if not isinstance(v, list) else None)


def load_ndjson(path) -> list[dict]:
    """Read every AD Explorer Objects NDJSON file in `path` into SharpHound-v4 file dicts (one per object type)."""
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.glob("*.ndjson"))
    objs: list[dict] = []
    for f in files:
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if line:
                try:
                    objs.append(json.loads(line))
                except ValueError:
                    pass
    return _build(objs)


def _build(objs: list[dict]) -> list[dict]:
    # domain DN + SID
    domain_dn = ""
    domain_sid = ""
    for o in objs:
        if "domainDNS" in o.get("objectClass", []):
            domain_dn = _one(o.get("distinguishedName")) or ""
            domain_sid = _one(o.get("objectSid")) or ""
            break
    dsuffix = domain_dn.upper()

    def in_domain(dn: str) -> bool:
        up = dn.upper()
        return up.endswith(dsuffix) and not _SCHEMA_CONFIG.search("," + dn)

    # pass 1: DN -> ObjectIdentifier (SID for principals, GUID for OU/GPO/container)
    dn2id: dict[str, str] = {}
    kept: list[tuple[dict, str, str]] = []           # (obj, file_type, object_id)
    for o in objs:
        dn = _one(o.get("distinguishedName")) or ""
        ft = _classify(o.get("objectClass", []))
        if not ft or not dn or not in_domain(dn):
            continue
        sid = _one(o.get("objectSid"))
        guid = _one(o.get("objectGUID"))
        oid = (sid or (guid or "").upper()) if ft in ("users", "groups", "computers", "domains") else (guid or "").upper()
        if not oid:
            continue
        dn2id[dn.upper()] = oid
        kept.append((o, ft, oid))

    buckets: dict[str, list[dict]] = {"users": [], "groups": [], "computers": [], "domains": [], "ous": [], "gpos": [], "containers": []}
    primary_members: dict[str, list[str]] = {}       # group SID -> [member SID]

    for o, ft, oid in kept:
        dn = _one(o.get("distinguishedName")) or ""
        name = _one(o.get("sAMAccountName")) or _one(o.get("name")) or _one(o.get("cn")) or dn
        if ft in ("domains",) and domain_dn:
            name = _dn_to_domain(domain_dn)
        elif "@" not in str(name) and ft in ("users", "groups", "computers"):
            name = f"{name}@{_dn_to_domain(domain_dn)}" if domain_dn else name
        uac = _one(o.get("userAccountControl")) or 0
        props = {
            "name": str(name).upper(),
            "domain": _dn_to_domain(domain_dn),
            "distinguishedname": dn,
            "enabled": not (isinstance(uac, int) and uac & 0x2),             # ACCOUNTDISABLE
            "admincount": bool(_one(o.get("adminCount"))),
            "samaccountname": _one(o.get("sAMAccountName")),
            "description": _one(o.get("description")),
            "unconstraineddelegation": bool(isinstance(uac, int) and uac & 0x80000),   # TRUSTED_FOR_DELEGATION
            "dontreqpreauth": bool(isinstance(uac, int) and uac & 0x400000),
            "hasspn": bool(o.get("servicePrincipalName")),
            "pwdlastset": _one(o.get("pwdLastSet")),
            "lastlogontimestamp": _one(o.get("lastLogonTimestamp")),
        }
        if ft == "computers":
            props["dnshostname"] = _one(o.get("dNSHostName")) or _one(o.get("dnsHostName"))
            if "CN=DOMAIN CONTROLLERS" in dn.upper() or (isinstance(uac, int) and uac & 0x2000):
                props["isdc"] = True                                          # SERVER_TRUST_ACCOUNT

        record = {"ObjectIdentifier": oid, "Properties": {k: v for k, v in props.items() if v is not None}}

        # security descriptor -> owner + ACEs
        owner, aces = _parse_sd(_one(o.get("nTSecurityDescriptor")) or "")
        ace_list = []
        if owner and owner != oid and not _skip(owner):
            ace_list.append({"PrincipalSID": owner, "RightName": "Owns", "IsInherited": False})
        for sid, right, inh in aces:
            if sid != oid and not _skip(sid):
                ace_list.append({"PrincipalSID": sid, "RightName": right, "IsInherited": inh})
        record["Aces"] = ace_list

        # group membership from the member attribute (DN -> id)
        if ft == "groups":
            members = []
            for mdn in o.get("member", []) or []:
                mid = dn2id.get(str(mdn).upper())
                if mid:
                    members.append({"MemberId": mid})
            record["Members"] = members

        # primary group (users/computers)
        pg = _one(o.get("primaryGroupID"))
        if ft in ("users", "computers") and isinstance(pg, int) and domain_sid:
            primary_members.setdefault(f"{domain_sid}-{pg}", []).append(oid)

        # GPO links (on OUs and the domain)
        links = _parse_gplink(_one(o.get("gPLink")) or "", dn2id)
        if links:
            record["Links"] = links

        buckets[ft].append(record)

    # merge primary-group memberships into the group records
    by_id = {r["ObjectIdentifier"]: r for r in buckets["groups"]}
    for gsid, mids in primary_members.items():
        g = by_id.get(gsid)
        if g is not None:
            seen = {m["MemberId"] for m in g["Members"]}
            g["Members"].extend({"MemberId": m} for m in mids if m not in seen)

    out = []
    for ft, recs in buckets.items():
        if recs:
            out.append({"meta": {"type": ft, "version": 4, "count": len(recs)}, "data": recs})
    return out


_GPLINK = re.compile(r"\[LDAP://(cn=\{[0-9a-fA-F-]+\}[^;]*);(\d)\]")


def _parse_gplink(gplink: str, dn2id: dict) -> list[dict]:
    out = []
    for m in _GPLINK.finditer(gplink or ""):
        gid = dn2id.get(m.group(1).upper())
        if gid and int(m.group(2)) & 0x1 == 0:            # bit0 set = link disabled
            out.append({"GUID": gid, "IsEnforced": bool(int(m.group(2)) & 0x2)})
    return out


def _dn_to_domain(dn: str) -> str:
    return ".".join(p[3:] for p in dn.split(",") if p.upper().startswith("DC=")).upper()


_LS_EDGE = {"LocalAdmins": "AdminTo", "RemoteDesktopUsers": "CanRDP", "DcomUsers": "ExecuteDCOM", "PSRemoteUsers": "CanPSRemote"}


def apply_local_sessions(graph, folder) -> int:
    """Read any *_localsessions.json (tools/Export-AdLocalSessions.ps1) in `folder` and add host-side edges:
    local-group membership (principal -> computer) and sessions (computer -> user). Hosts are matched by FQDN or name."""
    from pathlib import Path as _P
    from .graph import ADEdge, NodeType
    folder = _P(folder)
    files = [folder] if folder.is_file() else list(folder.glob("*_localsessions.json")) + list(folder.glob("*localsessions*.json"))
    files = [f for f in files if f.is_file() and f.name.lower().endswith(".json")]
    if not files:
        return 0
    by_host: dict[str, str] = {}
    for n in graph.nodes_by_type(NodeType.COMPUTER):
        dns = str(n.properties.get("dnshostname") or "").upper()
        short = n.display_name.split("@")[0].rstrip("$").upper()
        if dns:
            by_host[dns] = n.object_id
        by_host.setdefault(short, n.object_id)
    added = 0
    for f in files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8-sig"))
        except (ValueError, OSError):
            continue
        for rec in doc.get("data", []):
            cid = by_host.get(str(rec.get("FQDN") or "").upper()) or by_host.get(str(rec.get("Computer") or "").upper())
            if not cid:
                continue
            for key, edge in _LS_EDGE.items():
                for sid in rec.get(key, []) or []:
                    if sid and graph.get_node(sid) is not None:
                        graph.add_edge(ADEdge(source_id=sid, target_id=cid, edge_type=edge))
                        added += 1
            for sid in rec.get("Sessions", []) or []:
                if sid and graph.get_node(sid) is not None:
                    graph.add_edge(ADEdge(source_id=cid, target_id=sid, edge_type="HasSession"))
                    added += 1
    return added


def apply_sidecars(graph, folder) -> None:
    """Parse the optional *_denies.json / *_gporights.json / *_adcsrelay.json sidecars that sit in or beside an AD
    Explorer NDJSON folder, so one `analyze` picks up Deny ACEs, GPO user rights and CA relay settings too."""
    from pathlib import Path as _P
    from . import ingest
    folder = _P(folder)
    dirs = [folder] + ([folder.parent] if folder.parent != folder else [])
    seen = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.json")):
            low = f.name.lower()
            ft = "denies" if "denies" in low else "gporights" if "gporights" in low else "adcsrelay" if "adcsrelay" in low else None
            if ft is None or f in seen:
                continue
            seen.add(f)
            try:
                ingest._parse_one_file(json.loads(f.read_text(encoding="utf-8-sig")), graph, ft)
            except (ValueError, OSError):
                pass
