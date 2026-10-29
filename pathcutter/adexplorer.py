"""Native ingestion of AD Explorer snapshots (Sysinternals), exported to NDJSON by ADExplorerSnapshot.py Objects mode.

AD Explorer is Microsoft-signed, so it collects a full LDAP snapshot of a domain where SharpHound is blocked by EDR.
`ADExplorerSnapshot.py -m Objects snapshot.dat` writes one JSON object per line with every LDAP attribute (SIDs and
GUIDs already resolved to strings, memberships as DNs). This module reads that file, parses the binary security
descriptors into the same ACL edges SharpHound emits, and produces SharpHound-v4-shaped file dicts that the normal
ingest consumes.

When the snapshot includes the Configuration partition (snapshot the directory from its root, or the Configuration NC,
not only the domain NC) this also reads AD Certificate Services objects - certificate templates, enterprise CAs, the
NTAuth store and issuance policies - so the ADCS escalations that are fully determined by the directory (ESC1, ESC4,
ESC5, ESC15, ESC13 and golden certificate) derive from a signed-tool snapshot. What lives only in the CA or DC registry
(the EDITF SAN flag, the ManageCA role, enrollment-agent restrictions, strong-binding enforcement) is not in LDAP, so
ESC6/7/3/9/10/16 stay off unless the matching sidecar is also collected - never guessed. trustedDomain objects become
trust edges, gMSA msDS-GroupMSAMembership becomes ReadGMSAPassword, and a targeted read of a LAPS password attribute
(its per-forest GUID resolved from the schema partition) becomes ReadLAPSPassword.

The result is still sessions-free and local-group-free (LDAP only), so exposure is a floor; `doctor` says so, and
`tools/Export-AdLocalSessions.ps1` next to the snapshot adds the session and local-admin edges.
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
DS_READ_PROP = 0x00000010
DS_SELF = 0x00000008
FULL_CONTROL = 0x000F01FF
_INHERITED_ACE = 0x10
_ZERO_GUID = "00000000-0000-0000-0000-000000000000"
_MEMBER_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# AD CS / certificate template constants (verified against MS-CRTD and MS-ADSC)
_ENROLL_RIGHT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"          # Certificate-Enrollment extended right
_AUTOENROLL_RIGHT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"       # Certificate-AutoEnrollment extended right
_MANAGED_PW_GUID = "e362ed86-b728-0842-b27d-2dea7a9df218"        # msDS-ManagedPassword (gMSA), fixed schemaIDGUID
_NAMEFLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001                 # msPKI-Certificate-Name-Flag
_ENROLLFLAG_PEND_ALL_REQUESTS = 0x00000002                       # msPKI-Enrollment-Flag (manager approval)
_ENROLLFLAG_NO_SECURITY_EXTENSION = 0x00080000                   # msPKI-Enrollment-Flag (ESC9/16 input)
# EKU OIDs that allow client authentication (so a certificate can log on); empty EKU or Any Purpose also authenticate
_AUTH_EKUS = {"1.3.6.1.5.5.7.3.2",          # Client Authentication
              "1.3.6.1.5.2.3.4",            # PKINIT Client Authentication
              "1.3.6.1.4.1.311.20.2.2",     # Smart Card Logon
              "2.5.29.37.0"}                # Any Purpose
# lDAPDisplayName (lowercase) of the LAPS password attributes; their schemaIDGUIDs are resolved from the schema partition
_LAPS_ATTR_NAMES = {"ms-mcs-admpwd", "mslaps-password", "mslaps-encryptedpassword"}
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
    _ENROLL_RIGHT: "Enroll",
    _AUTOENROLL_RIGHT: "AutoEnroll",
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


def _rights_for(mask: int, otype: str | None, read_props: dict | None = None) -> list[str]:
    """SharpHound-style mapping of one allowed ACE to BloodHound right names.

    read_props maps an attribute's schemaIDGUID (lowercase) to a read edge (ReadLAPSPassword / ReadGMSAPassword) so a
    targeted ReadProperty on that attribute is recognised."""
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
        if mask & DS_READ_PROP and read_props:
            r = read_props.get(g)
            if r:
                out.append(r)
        if mask & DS_SELF and g == _MEMBER_GUID:
            out.append("AddSelf")
    return out


def _parse_sd(blob: str, read_props: dict | None = None) -> tuple[str | None, list[tuple[str, str, bool]]]:
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
                    for right in _rights_for(mask, otype, read_props):
                        aces.append((sid, right, bool(aflags & _INHERITED_ACE)))
                except (IndexError, ValueError):
                    pass
            pos += asize
    return owner, aces


def _sd_trustees(blob: str) -> list[str]:
    """Every principal SID with an allow ACE in a security descriptor's DACL (used for msDS-GroupMSAMembership:
    anyone listed there may retrieve the gMSA password)."""
    _owner, aces = _parse_sd(blob, read_props=None)
    # _parse_sd only emits a right when the mask maps to something; for the membership SD every allow entry counts,
    # so re-parse for raw trustees regardless of the specific right.
    try:
        sd = base64.b64decode(blob)
    except Exception:
        return []
    if len(sd) < 20:
        return []
    dacl_off = int.from_bytes(sd[16:20], "little")
    out: list[str] = []
    if dacl_off and dacl_off + 8 <= len(sd):
        count = int.from_bytes(sd[dacl_off + 4:dacl_off + 6], "little")
        pos = dacl_off + 8
        for _ in range(count):
            if pos + 4 > len(sd):
                break
            atype = sd[pos]
            asize = int.from_bytes(sd[pos + 2:pos + 4], "little")
            if asize < 4 or pos + asize > len(sd):
                break
            body = sd[pos + 4:pos + asize]
            if atype in (0x00, 0x05) and len(body) >= 4:
                try:
                    if atype == 0x00:
                        sid = _sid(body, 4)
                    else:
                        flags = int.from_bytes(body[4:8], "little")
                        o = 8 + (16 if flags & 0x1 else 0) + (16 if flags & 0x2 else 0)
                        sid = _sid(body, o)
                    if not _skip(sid):
                        out.append(sid)
                except (IndexError, ValueError):
                    pass
            pos += asize
    return out


def _guid_from_value(v) -> str | None:
    """A schemaIDGUID / objectGUID as AD Explorer stores it: a GUID string, or base64 of the little-endian 16 bytes."""
    s = _one(v)
    if not s:
        return None
    s = str(s)
    if re.fullmatch(r"[0-9a-fA-F-]{36}", s):
        return s.lower()
    try:
        return str(uuid.UUID(bytes_le=base64.b64decode(s))).lower()
    except Exception:
        return None


def _thumbprint(cert_b64) -> str | None:
    """SHA1 thumbprint (upper hex, no separators) of a base64 DER certificate, as SharpHound records it."""
    import hashlib
    s = _one(cert_b64)
    if not s:
        return None
    try:
        return hashlib.sha1(base64.b64decode(str(s))).hexdigest().upper()
    except Exception:
        return None


def _maybe_sid(v) -> str | None:
    """A domain SID as a string, or base64 of its binary form."""
    s = _one(v)
    if not s:
        return None
    s = str(s)
    if s.upper().startswith("S-1-"):
        return s
    try:
        b = base64.b64decode(s)
        return _sid(b, 0) if len(b) >= 8 else None
    except Exception:
        return None


# ---- object classification ----------------------------------------------------------------------------------------

_TYPE_BY_CLASS = [
    ("computer", "computers"), ("groupManagedServiceAccount", "users"), ("msDS-GroupManagedServiceAccount", "users"),
    ("user", "users"), ("inetOrgPerson", "users"), ("group", "groups"), ("domainDNS", "domains"),
    ("organizationalUnit", "ous"), ("groupPolicyContainer", "gpos"), ("foreignSecurityPrincipal", "users"),
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
    domain_name = _dn_to_domain(domain_dn)

    def in_domain(dn: str) -> bool:
        up = dn.upper()
        return up.endswith(dsuffix) and not _SCHEMA_CONFIG.search("," + dn)

    # LAPS password attributes have per-forest schemaIDGUIDs: resolve them from the schema partition if it was snapshotted,
    # so a targeted ReadProperty on one becomes a ReadLAPSPassword edge. msDS-ManagedPassword (gMSA) has a fixed GUID.
    read_props: dict[str, str] = {_MANAGED_PW_GUID: "ReadGMSAPassword"}
    for o in objs:
        if "attributeSchema" in o.get("objectClass", []):
            ldn = str(_one(o.get("lDAPDisplayName")) or "").lower()
            if ldn in _LAPS_ATTR_NAMES:
                g = _guid_from_value(o.get("schemaIDGUID"))
                if g:
                    read_props[g] = "ReadLAPSPassword"

    # trustedDomain objects -> a Trusts list attached to the domain record (SharpHound shape), so _trusts() draws the edges
    trusts: list[dict] = []
    for o in objs:
        if "trustedDomain" not in o.get("objectClass", []):
            continue
        ta = int(_one(o.get("trustAttributes")) or 0)
        td = int(_one(o.get("trustDirection")) or 0)
        tsid = _maybe_sid(o.get("securityIdentifier"))
        tname = str(_one(o.get("name")) or _one(o.get("cn")) or _one(o.get("flatName")) or "").upper()
        if not (tsid or tname):
            continue
        trusts.append({
            "TargetDomainSid": tsid or tname,
            "TargetDomainName": tname or tsid,
            "TrustDirection": {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(td, "Bidirectional"),
            "TrustType": _one(o.get("trustType")),
            "IsTransitive": not (ta & 0x1),            # TRUST_ATTRIBUTE_NON_TRANSITIVE
            "SidFilteringEnabled": bool(ta & 0x4),     # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
        })

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
        if ft == "ous":
            gpoptions = _one(o.get("gPOptions"))
            if gpoptions is not None:
                try:
                    props["blocksinheritance"] = bool(int(gpoptions) & 1)         # gPOptions bit 0 = block inheritance
                except (TypeError, ValueError):
                    pass
        if ft == "domains":
            maq = _one(o.get("ms-DS-MachineAccountQuota"))
            if maq is not None:
                try:
                    props["machineaccountquota"] = int(maq)
                except (TypeError, ValueError):
                    pass
        if ft in ("users", "computers"):
            enc = _one(o.get("msDS-SupportedEncryptionTypes"))
            if enc is not None:
                try:
                    props["supportedencryptiontypes"] = int(enc)             # raw bitmask; hygiene._enc_class handles it
                except (TypeError, ValueError):
                    pass

        record = {"ObjectIdentifier": oid, "Properties": {k: v for k, v in props.items() if v is not None}}

        # security descriptor -> owner + ACEs
        owner, aces = _parse_sd(_one(o.get("nTSecurityDescriptor")) or "", read_props)
        ace_list = []
        if owner and owner != oid and not _skip(owner):
            ace_list.append({"PrincipalSID": owner, "RightName": "Owns", "IsInherited": False})
        for sid, right, inh in aces:
            if sid != oid and not _skip(sid):
                ace_list.append({"PrincipalSID": sid, "RightName": right, "IsInherited": inh})
        # gMSA: everyone in msDS-GroupMSAMembership may retrieve the managed password (ReadGMSAPassword)
        gmsa_blob = _one(o.get("msDS-GroupMSAMembership")) or _one(o.get("msds-groupmsamembership"))
        if gmsa_blob:
            for sid in _sd_trustees(gmsa_blob):
                if sid != oid:
                    ace_list.append({"PrincipalSID": sid, "RightName": "ReadGMSAPassword", "IsInherited": False})
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

        # trusts hang off the domain record so the normal _trusts() machinery draws them
        if ft == "domains" and trusts:
            record["Trusts"] = trusts

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

    # AD CS objects from the Configuration partition (templates, CAs, NTAuth store, issuance policies), if snapshotted
    host_by_dns = {str(r["Properties"].get("dnshostname") or "").upper(): r["ObjectIdentifier"]
                   for r in buckets["computers"] if r["Properties"].get("dnshostname")}
    for data in _config_records(objs, dn2id, domain_name, host_by_dns):
        out.append(data)
    return out


def _vals(v) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


def _config_records(objs: list[dict], dn2id: dict, domain: str, host_by_dns: dict) -> list[dict]:
    """Build SharpHound-shaped AD CS file dicts from Configuration-partition objects so derive_adcs_edges() can run on
    an AD Explorer snapshot. Emits certtemplates, enterprisecas, ntauthstores, rootcas, aiacas and issuancepolicies.

    What LDAP alone cannot provide is omitted, never faked: the CA registry (EDITF SAN flag, ManageCA role, enrollment-
    agent restrictions) and DC binding registry are not in the directory, so ESC6/ESC7/ESC3/ESC9/ESC10/ESC16 stay off
    unless the matching sidecar is also present. ESC1/ESC4/ESC5/ESC15, GoldenCert and ESC13 derive from the snapshot."""
    buckets: dict[str, list[dict]] = {"certtemplates": [], "enterprisecas": [], "ntauthstores": [], "rootcas": [],
                                      "aiacas": [], "issuancepolicies": []}
    name2guid: dict[str, str] = {}

    def aces_of(o: dict) -> list[dict]:
        owner, aces = _parse_sd(_one(o.get("nTSecurityDescriptor")) or "")
        out = []
        if owner and not _skip(owner):
            out.append({"PrincipalSID": owner, "RightName": "Owns", "IsInherited": False})
        for sid, right, inh in aces:
            if not _skip(sid):
                out.append({"PrincipalSID": sid, "RightName": right, "IsInherited": inh})
        return out

    for o in objs:
        classes = o.get("objectClass", [])
        dn = (_one(o.get("distinguishedName")) or "").upper()
        guid = (_guid_from_value(o.get("objectGUID")) or "").upper()
        cn = str(_one(o.get("cn")) or _one(o.get("name")) or "").strip()
        if not guid or not cn:
            continue
        if "pKICertificateTemplate" in classes:
            nameflag = int(_one(o.get("msPKI-Certificate-Name-Flag")) or 0)
            enrollflag = int(_one(o.get("msPKI-Enrollment-Flag")) or 0)
            ekus = [str(e) for e in _vals(o.get("pKIExtendedKeyUsage"))]
            props = {
                "name": f"{cn}@{domain}".upper(), "domain": domain,
                "enrolleesuppliessubject": bool(nameflag & _NAMEFLAG_ENROLLEE_SUPPLIES_SUBJECT),
                "requiresmanagerapproval": bool(enrollflag & _ENROLLFLAG_PEND_ALL_REQUESTS),
                "nosecurityextension": bool(enrollflag & _ENROLLFLAG_NO_SECURITY_EXTENSION),
                "schemaversion": int(_one(o.get("msPKI-Template-Schema-Version")) or 1),
                "authorizedsignatures": int(_one(o.get("msPKI-RA-Signature")) or 0),
                "authenticationenabled": (not ekus) or any(e in _AUTH_EKUS for e in ekus),
                "ekus": ekus, "effectiveekus": ekus,
                "applicationpolicies": [str(e) for e in _vals(o.get("msPKI-Certificate-Application-Policy"))],
                "issuancepolicies": [str(e) for e in _vals(o.get("msPKI-Certificate-Policy"))],
            }
            name2guid[cn.lower()] = guid
            buckets["certtemplates"].append({"ObjectIdentifier": guid, "Properties": props, "Aces": aces_of(o)})
        elif "pKIEnrollmentService" in classes:
            host = _one(o.get("dNSHostName")) or _one(o.get("dnsHostName"))
            rec = {"ObjectIdentifier": guid, "Aces": aces_of(o),
                   "Properties": {"name": f"{cn}@{domain}".upper(), "domain": domain, "caname": cn,
                                  "dnshostname": host, "certthumbprint": _thumbprint(o.get("cACertificate"))},
                   "_tmpl_names": [str(t) for t in _vals(o.get("certificateTemplates"))]}
            hid = host_by_dns.get(str(host or "").upper())
            if hid:
                rec["HostingComputer"] = hid
            buckets["enterprisecas"].append(rec)
        elif "certificationAuthority" in classes:
            thumbs = [t for t in (_thumbprint(c) for c in _vals(o.get("cACertificate"))) if t]
            props = {"name": f"{cn}@{domain}".upper(), "domain": domain, "certthumbprints": thumbs}
            ft = "ntauthstores" if "CN=NTAUTHCERTIFICATES" in dn else "aiacas" if ",CN=AIA," in dn else "rootcas"
            buckets[ft].append({"ObjectIdentifier": guid, "Properties": props, "Aces": aces_of(o)})
        elif "msPKI-Enterprise-Oid" in classes and o.get("msDS-OIDToGroupLink"):
            gid = dn2id.get(str(_one(o.get("msDS-OIDToGroupLink")) or "").upper())
            rec = {"ObjectIdentifier": guid, "Aces": aces_of(o),
                   "Properties": {"name": f"{cn}@{domain}".upper(), "domain": domain,
                                  "oid": _one(o.get("msPKI-Cert-Template-OID"))}}
            if gid:
                rec["GroupLink"] = {"ObjectIdentifier": gid}
            buckets["issuancepolicies"].append(rec)

    # resolve each CA's published template names to the template GUIDs (EnabledCertTemplates), then drop the helper field
    for rec in buckets["enterprisecas"]:
        rec["EnabledCertTemplates"] = [{"ObjectIdentifier": name2guid[n.lower()]}
                                       for n in rec.pop("_tmpl_names", []) if n.lower() in name2guid]

    return [{"meta": {"type": ft, "version": 4, "count": len(recs)}, "data": recs}
            for ft, recs in buckets.items() if recs]


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
