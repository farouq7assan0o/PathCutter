"""Native AD Explorer snapshot ingestion (ADExplorerSnapshot.py Objects NDJSON), including security-descriptor parsing."""
import base64
import json
import struct

from pathcutter.adexplorer import _parse_sd, is_adexplorer_ndjson, load_ndjson
from pathcutter.ingest import load_sharphound


def _sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    rev = int(parts[1]); auth = int(parts[2]); subs = [int(x) for x in parts[3:]]
    return bytes([rev, len(subs)]) + auth.to_bytes(6, "big") + b"".join(s.to_bytes(4, "little") for s in subs)


def _sd(owner: str, aces: list[tuple[int, str, str | None]]) -> str:
    """Build a base64 security descriptor with the given owner and (mask, trustee, objectType-guid-or-None) ACEs."""
    import uuid as _uuid
    ace_blobs = []
    for mask, sid, otype in aces:
        sidb = _sid_bytes(sid)
        if otype is None:
            body = struct.pack("<I", mask) + sidb
            atype = 0x00
        else:
            body = struct.pack("<II", mask, 0x1) + _uuid.UUID(otype).bytes_le + sidb
            atype = 0x05
        ace_blobs.append(bytes([atype, 0x00]) + struct.pack("<H", 4 + len(body)) + body)
    dacl = b"".join(ace_blobs)
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(dacl), len(ace_blobs), 0) + dacl
    ownerb = _sid_bytes(owner)
    # header(20) + owner + acl ; owner at 20, dacl at 20+len(owner)
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(ownerb))
    return base64.b64encode(header + ownerb + acl).decode()


DOM = "S-1-5-21-1-2-3"


def _obj(**kw):
    return {k: (v if isinstance(v, list) else [v]) for k, v in kw.items()}


def _write(tmp_path, objs):
    f = tmp_path / "snap_objects.ndjson"
    f.write_text("\n".join(json.dumps(o) for o in objs), encoding="utf-8")
    return tmp_path


def test_sd_parser_extracts_owner_and_rights():
    blob = _sd(f"{DOM}-512", [(0x10000000, f"{DOM}-1105", None),                       # GenericAll
                              (0x00000020, f"{DOM}-1106", "bf9679c0-0de6-11d0-a285-00aa003049e2")])  # AddMember
    owner, aces = _parse_sd(blob)
    assert owner == f"{DOM}-512"
    assert (f"{DOM}-1105", "GenericAll", False) in aces
    assert (f"{DOM}-1106", "AddMember", False) in aces


def test_ingest_builds_graph_with_acl_edge_and_membership(tmp_path):
    objs = [
        _obj(distinguishedName="DC=corp,DC=local", objectClass=["top", "domain", "domainDNS"], objectSid=DOM, objectGUID="11111111-1111-1111-1111-111111111111"),
        _obj(distinguishedName="CN=Domain Admins,CN=Users,DC=corp,DC=local", objectClass=["top", "group"],
             objectSid=f"{DOM}-512", sAMAccountName="Domain Admins", objectGUID="22222222-2222-2222-2222-222222222222",
             member=["CN=alice,CN=Users,DC=corp,DC=local"]),
        _obj(distinguishedName="CN=alice,CN=Users,DC=corp,DC=local", objectClass=["top", "person", "user"],
             objectSid=f"{DOM}-1105", sAMAccountName="alice", objectGUID="33333333-3333-3333-3333-333333333333",
             primaryGroupID=513, userAccountControl=512),
        _obj(distinguishedName="CN=bob,CN=Users,DC=corp,DC=local", objectClass=["top", "person", "user"],
             objectSid=f"{DOM}-1106", sAMAccountName="bob", objectGUID="44444444-4444-4444-4444-444444444444",
             userAccountControl=512,
             nTSecurityDescriptor=_sd(f"{DOM}-1106", [(0x10000000, f"{DOM}-1105", None)])),   # alice GenericAll over bob
    ]
    d = _write(tmp_path, objs)
    assert is_adexplorer_ndjson(d)
    g = load_sharphound(d)
    assert g.has_edge_type(f"{DOM}-1105", f"{DOM}-1106", "GenericAll")       # alice -> bob
    assert g.has_edge_type(f"{DOM}-1105", f"{DOM}-512", "MemberOf")          # alice in Domain Admins
    # Domain Admins is Tier 0; alice is a member, so alice is Tier 0
    assert f"{DOM}-1105" in g.tier0_nodes


def test_noise_trustees_are_dropped(tmp_path):
    objs = [
        _obj(distinguishedName="DC=corp,DC=local", objectClass=["domainDNS"], objectSid=DOM, objectGUID="11111111-1111-1111-1111-111111111111"),
        _obj(distinguishedName="CN=srv,CN=Computers,DC=corp,DC=local", objectClass=["top", "computer"],
             objectSid=f"{DOM}-1200", sAMAccountName="srv$", objectGUID="55555555-5555-5555-5555-555555555555",
             nTSecurityDescriptor=_sd("S-1-5-18", [(0x10000000, "S-1-5-18", None), (0x10000000, "S-1-3-0", None)])),
    ]
    g = load_sharphound(_write(tmp_path, objs))
    assert not any(d["edge_type"] in ("GenericAll", "Owns") for _, _, d in g.all_edges())
