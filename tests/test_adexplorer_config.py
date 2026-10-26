"""AD Explorer ingestion of the Configuration partition and related data: AD CS (ESC paths), trusts, LAPS and gMSA.

These build a tiny AD Explorer NDJSON snapshot with real binary security descriptors, run it through the normal
load_sharphound pipeline, and assert that the derived edges appear - the same chain that runs on a real snapshot.
"""
import base64
import json
import struct
import uuid

from pathcutter.adexplorer import _AUTOENROLL_RIGHT, _ENROLL_RIGHT
from pathcutter.ingest import load_sharphound

DOMAIN_SID = "S-1-5-21-1-2-3"
DU = f"{DOMAIN_SID}-513"          # Domain Users
_ADMPWD_GUID = "ac9bc5b8-6d2a-4d19-9f1a-000000000001"   # arbitrary per-forest schemaIDGUID for ms-Mcs-AdmPwd


# ---- binary security descriptor builder (self-relative) ----------------------------------------------------------

def _sid_bytes(s: str) -> bytes:
    parts = s.split("-")
    rev = int(parts[1])
    auth = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    out = bytes([rev, len(subs)]) + auth.to_bytes(6, "big")
    for sub in subs:
        out += struct.pack("<I", sub)
    return out


def _ace_object(mask: int, right_guid: str, sid: str) -> bytes:
    guid_le = uuid.UUID(right_guid).bytes_le
    sidb = _sid_bytes(sid)
    body = struct.pack("<I", mask) + struct.pack("<I", 0x1) + guid_le + sidb   # flags 0x1 = object type present
    ace = bytes([0x05, 0x00]) + struct.pack("<H", 4 + len(body)) + body         # ACCESS_ALLOWED_OBJECT
    return ace


def _ace_allowed(mask: int, sid: str) -> bytes:
    sidb = _sid_bytes(sid)
    body = struct.pack("<I", mask) + sidb
    return bytes([0x00, 0x00]) + struct.pack("<H", 4 + len(body)) + body        # ACCESS_ALLOWED


def _sd(aces: list[bytes]) -> str:
    acl = b"".join(aces)
    acl_hdr = bytes([0x04, 0x00]) + struct.pack("<H", 8 + len(acl)) + struct.pack("<H", len(aces)) + b"\x00\x00"
    dacl = acl_hdr + acl
    header = bytes([0x01, 0x00]) + struct.pack("<H", 0x8004)      # revision, control (SE_DACL_PRESENT|SE_SELF_RELATIVE)
    header += struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", 20)  # owner/grp/sacl=0, dacl=20
    return base64.b64encode(header + dacl).decode()


DS_CONTROL_ACCESS = 0x100
DS_READ_PROP = 0x10
GENERIC_ALL = 0x10000000


def _write(tmp_path, objs):
    f = tmp_path / "snapshot.ndjson"
    f.write_text("\n".join(json.dumps(o) for o in objs), encoding="utf-8")
    return load_sharphound(str(tmp_path))


def _base_objs():
    return [
        {"objectClass": ["domainDNS"], "distinguishedName": "DC=test,DC=local", "objectSid": DOMAIN_SID, "name": "test.local"},
        {"objectClass": ["group"], "distinguishedName": "CN=Domain Users,CN=Users,DC=test,DC=local",
         "objectSid": DU, "sAMAccountName": "Domain Users", "cn": "Domain Users"},
    ]


def _has_edge(g, etype):
    return any(d.get("edge_type") == etype for _, _, d in g.all_edges())


def test_esc1_from_a_snapshot():
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    tmpl_guid = str(uuid.uuid4())
    ca_guid = str(uuid.uuid4())
    enroll_sd = _sd([_ace_object(DS_CONTROL_ACCESS, _ENROLL_RIGHT, DU)])
    objs = _base_objs() + [
        {"objectClass": ["top", "pKICertificateTemplate"],
         "distinguishedName": "CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local",
         "objectGUID": tmpl_guid, "cn": "VulnTemplate",
         "msPKI-Certificate-Name-Flag": 0x00000001,          # ENROLLEE_SUPPLIES_SUBJECT
         "msPKI-Enrollment-Flag": 0, "msPKI-RA-Signature": 0, "msPKI-Template-Schema-Version": 2,
         "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],        # Client Authentication
         "nTSecurityDescriptor": enroll_sd},
        {"objectClass": ["top", "pKIEnrollmentService"],
         "distinguishedName": "CN=test-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local",
         "objectGUID": ca_guid, "cn": "test-CA", "dNSHostName": "ca.test.local",
         "certificateTemplates": ["VulnTemplate"], "nTSecurityDescriptor": enroll_sd},
    ]
    g = _write(tmp, objs)
    assert _has_edge(g, "ADCSESC1"), "expected an ADCSESC1 edge from the snapshot's template + CA"
    # it runs principal -> domain
    assert any(u == DU for u, _v, d in g.all_edges() if d.get("edge_type") == "ADCSESC1")


def test_esc15_schema_v1_template():
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    enroll_sd = _sd([_ace_object(DS_CONTROL_ACCESS, _ENROLL_RIGHT, DU)])
    objs = _base_objs() + [
        {"objectClass": ["pKICertificateTemplate"],
         "distinguishedName": "CN=V1,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local",
         "objectGUID": str(uuid.uuid4()), "cn": "V1", "msPKI-Certificate-Name-Flag": 0x1,
         "msPKI-Enrollment-Flag": 0, "msPKI-RA-Signature": 0, "msPKI-Template-Schema-Version": 1,
         "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"], "nTSecurityDescriptor": enroll_sd},
        {"objectClass": ["pKIEnrollmentService"],
         "distinguishedName": "CN=test-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local",
         "objectGUID": str(uuid.uuid4()), "cn": "test-CA", "dNSHostName": "ca.test.local",
         "certificateTemplates": ["V1"], "nTSecurityDescriptor": enroll_sd},
    ]
    g = _write(tmp, objs)
    assert _has_edge(g, "ADCSESC15")


def test_esc5_control_of_ntauth_store():
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    ctrl_sd = _sd([_ace_allowed(GENERIC_ALL, DU)])
    objs = _base_objs() + [
        {"objectClass": ["certificationAuthority"],
         "distinguishedName": "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local",
         "objectGUID": str(uuid.uuid4()), "cn": "NTAuthCertificates", "nTSecurityDescriptor": ctrl_sd},
    ]
    g = _write(tmp, objs)
    assert _has_edge(g, "ADCSESC5")


def test_trust_edge_from_trusteddomain():
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    objs = _base_objs() + [
        {"objectClass": ["trustedDomain"], "distinguishedName": "CN=partner.local,CN=System,DC=test,DC=local",
         "name": "partner.local", "flatName": "PARTNER", "securityIdentifier": "S-1-5-21-9-9-9",
         "trustDirection": 3, "trustType": 2, "trustAttributes": 0x4},     # bidirectional, SID filtering on
    ]
    g = _write(tmp, objs)
    assert _has_edge(g, "TrustedBy")
    # SID filtering recorded
    props = next(d for _, _, d in g.all_edges() if d.get("edge_type") == "TrustedBy")
    assert props.get("sid_filtering") is True


def test_readgmsapassword_from_membership():
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    member_sid = f"{DOMAIN_SID}-1104"
    gmsa_sd = _sd([_ace_allowed(GENERIC_ALL, member_sid)])
    objs = _base_objs() + [
        {"objectClass": ["user"], "distinguishedName": "CN=svc,CN=Users,DC=test,DC=local",
         "objectSid": member_sid, "sAMAccountName": "svc", "cn": "svc"},
        {"objectClass": ["msDS-GroupManagedServiceAccount"], "distinguishedName": "CN=gmsa01,CN=Managed Service Accounts,DC=test,DC=local",
         "objectSid": f"{DOMAIN_SID}-1105", "sAMAccountName": "gmsa01$", "cn": "gmsa01",
         "msDS-GroupMSAMembership": gmsa_sd},
    ]
    g = _write(tmp, objs)
    assert _has_edge(g, "ReadGMSAPassword")
    assert any(u == member_sid for u, _v, d in g.all_edges() if d.get("edge_type") == "ReadGMSAPassword")


def test_readlapspassword_via_schema_guid():
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    reader = f"{DOMAIN_SID}-1106"
    laps_sd = _sd([_ace_object(DS_READ_PROP, _ADMPWD_GUID, reader)])
    # schemaIDGUID stored the way AD Explorer does: base64 of the little-endian GUID bytes
    schema_guid_b64 = base64.b64encode(uuid.UUID(_ADMPWD_GUID).bytes_le).decode()
    objs = _base_objs() + [
        {"objectClass": ["user"], "distinguishedName": "CN=helpdesk,CN=Users,DC=test,DC=local",
         "objectSid": reader, "sAMAccountName": "helpdesk", "cn": "helpdesk"},
        {"objectClass": ["attributeSchema"], "distinguishedName": "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=test,DC=local",
         "lDAPDisplayName": "ms-Mcs-AdmPwd", "schemaIDGUID": schema_guid_b64},
        {"objectClass": ["computer"], "distinguishedName": "CN=WS01,CN=Computers,DC=test,DC=local",
         "objectSid": f"{DOMAIN_SID}-1107", "sAMAccountName": "WS01$", "cn": "WS01",
         "dNSHostName": "ws01.test.local", "nTSecurityDescriptor": laps_sd},
    ]
    g = _write(tmp, objs)
    assert _has_edge(g, "ReadLAPSPassword")


def test_no_config_partition_is_harmless():
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    g = _write(tmp, _base_objs())
    assert not _has_edge(g, "ADCSESC1")
    assert g.node_count >= 2
