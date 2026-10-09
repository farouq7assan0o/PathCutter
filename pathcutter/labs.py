"""Reference lab environments rebuilt as SharpHound v4 JSON.

`goad-sevenkingdoms` models the sevenkingdoms.local domain of GOAD (Game of Active Directory,
Orange Cyberdefense), reconstructed from its published lab definition: users, nested groups, the
12 documented ACLs (including the famous 8-hop ACL abuse chain from `tywin.lannister` to the domain
controller), local group rights on the DC, an OU, AdminSDHolder, and a cross-domain group member.

This is a faithful *reconstruction of the lab definition*, not a capture from a running lab, and is
not affiliated with or endorsed by the GOAD project. It gives PathCutter a realistic, public,
well-documented environment whose attack paths are known in advance, so results can be checked
against ground truth instead of against our own synthetic generator.
"""
from __future__ import annotations

import json
from pathlib import Path

DOMAIN = "SEVENKINGDOMS.LOCAL"
ESSOS = "ESSOS.LOCAL"
_SK = "S-1-5-21-1101001-2202002-3303003"      # sevenkingdoms.local
_ES = "S-1-5-21-5505005-6606006-7707007"      # essos.local

LABS = {"goad-sevenkingdoms": "GOAD sevenkingdoms.local: nested groups and the documented ACL chain to the DC"}

_USERS = {   # name -> groups (membership as in the published lab definition)
    "tywin.lannister": ["Lannister"], "jaime.lannister": ["Lannister"],
    "cersei.lannister": ["Lannister", "Baratheon", "Domain Admins", "Small Council"],
    "tyron.lannister": ["Lannister"],
    "robert.baratheon": ["Baratheon", "Domain Admins", "Small Council"],
    "joffrey.baratheon": ["Baratheon", "Lannister"],
    "renly.baratheon": ["Baratheon", "Small Council"], "stannis.baratheon": ["Baratheon", "Small Council"],
    "petyer.baelish": ["Small Council"], "lord.varys": ["Small Council"], "maester.pycelle": ["Small Council"],
    "administrator": ["Domain Admins"],
}
_GROUPS = ["Lannister", "Baratheon", "Small Council", "DragonStone", "KingsGuard", "DragonRider",
           "AcrossTheNarrowSea", "Domain Admins", "Domain Controllers"]
_CROWNLANDS_GROUPS = ["Small Council", "DragonStone", "KingsGuard", "DragonRider"]
_DC = "kingslanding"

# (principal, right as SharpHound names it, target) - the 12 ACLs of the lab definition
_ACLS = [
    ("tywin.lannister", "ForceChangePassword", "jaime.lannister"),
    ("jaime.lannister", "GenericWrite", "joffrey.baratheon"),
    ("joffrey.baratheon", "WriteDacl", "tyron.lannister"),
    ("tyron.lannister", "AddSelf", "Small Council"),
    ("Small Council", "AddMember", "DragonStone"),
    ("DragonStone", "WriteOwner", "KingsGuard"),
    ("KingsGuard", "GenericAll", "stannis.baratheon"),
    ("stannis.baratheon", "GenericAll", _DC),
    ("AcrossTheNarrowSea", "GenericAll", _DC),
    ("lord.varys", "GenericAll", "Domain Admins"),
    ("lord.varys", "GenericAll", "AdminSDHolder"),
    ("renly.baratheon", "WriteDacl", "OU Crownlands"),
]


def _ids() -> dict[str, str]:
    ids: dict[str, str] = {}
    for i, name in enumerate(_USERS):
        ids[name] = f"{_SK}-{1100 + i}"
    ids["administrator"] = f"{_SK}-500"
    for i, g in enumerate(_GROUPS):
        ids[g] = f"{_SK}-{1200 + i}"
    ids["Domain Admins"], ids["Domain Controllers"] = f"{_SK}-512", f"{_SK}-516"
    ids[_DC] = f"{_SK}-1000"
    ids["daenerys.targaryen"] = f"{_ES}-1113"
    ids["OU Crownlands"] = "6A1D2A3B-0000-4000-8000-0000000000C1"
    ids["AdminSDHolder"] = "6A1D2A3B-0000-4000-8000-0000000000A5"
    ids["domain"] = _SK
    return ids


def goad_sevenkingdoms() -> dict[str, dict]:
    ids = _ids()
    acl_by_target: dict[str, list] = {}
    for principal, right, target in _ACLS:
        acl_by_target.setdefault(target, []).append(
            {"PrincipalSID": ids[principal], "RightName": right, "IsInherited": False,
             "PrincipalType": "Group" if principal in _GROUPS else "User"})

    def meta(kind: str, n: int) -> dict:
        return {"type": kind, "version": 4, "count": n, "methods": 0}

    def user(name: str, domain: str = DOMAIN) -> dict:
        return {"ObjectIdentifier": ids[name], "Aces": acl_by_target.get(name, []),
                "Properties": {"name": f"{name.upper()}@{domain}", "domain": domain, "enabled": True,
                               "admincount": "Domain Admins" in _USERS.get(name, []),
                               "distinguishedname": f"CN={name},DC=sevenkingdoms,DC=local"}}

    users = [user(n) for n in _USERS] + [user("daenerys.targaryen", ESSOS)]

    members: dict[str, list] = {g: [] for g in _GROUPS}
    for name, groups in _USERS.items():
        for g in groups:
            members[g].append({"MemberId": ids[name], "MemberType": "User"})
    members["AcrossTheNarrowSea"].append({"MemberId": ids["daenerys.targaryen"], "MemberType": "User"})
    members["Domain Controllers"].append({"MemberId": ids[_DC], "MemberType": "Computer"})
    groups = [{"ObjectIdentifier": ids[g], "Members": members[g], "Aces": acl_by_target.get(g, []),
               "Properties": {"name": f"{g.upper()}@{DOMAIN}", "domain": DOMAIN, "admincount": g in
                              ("Domain Admins", "Domain Controllers")}} for g in _GROUPS]

    computers = [{
        "ObjectIdentifier": ids[_DC], "Aces": acl_by_target.get(_DC, []),
        "LocalAdmins": [{"MemberId": ids[n]} for n in ("robert.baratheon", "cersei.lannister", "DragonRider")],
        "RemoteDesktopUsers": [{"MemberId": ids["Small Council"]}, {"MemberId": ids["Baratheon"]}],
        "Properties": {"name": f"{_DC.upper()}.{DOMAIN}", "domain": DOMAIN, "enabled": True,
                       "operatingsystem": "Windows Server 2019 Standard"}}]

    ous = [{"ObjectIdentifier": ids["OU Crownlands"], "Aces": acl_by_target.get("OU Crownlands", []),
            "ChildObjects": [{"ObjectIdentifier": ids[g], "ObjectType": "Group"} for g in _CROWNLANDS_GROUPS],
            "Properties": {"name": f"CROWNLANDS@{DOMAIN}", "domain": DOMAIN}}]
    containers = [{"ObjectIdentifier": ids["AdminSDHolder"], "Aces": acl_by_target.get("AdminSDHolder", []),
                   "Properties": {"name": f"ADMINSDHOLDER@{DOMAIN}", "domain": DOMAIN}}]
    domains = [{"ObjectIdentifier": ids["domain"], "Aces": [],
                "Properties": {"name": DOMAIN, "domain": DOMAIN, "functionallevel": "2016"}}]

    return {
        "20240601000000_users.json": {"meta": meta("users", len(users)), "data": users},
        "20240601000000_groups.json": {"meta": meta("groups", len(groups)), "data": groups},
        "20240601000000_computers.json": {"meta": meta("computers", len(computers)), "data": computers},
        "20240601000000_ous.json": {"meta": meta("ous", len(ous)), "data": ous},
        "20240601000000_containers.json": {"meta": meta("containers", len(containers)), "data": containers},
        "20240601000000_domains.json": {"meta": meta("domains", len(domains)), "data": domains},
    }


def lab_ids(name: str = "goad-sevenkingdoms") -> dict[str, str]:
    """Name -> object id for the lab (for tests and documentation)."""
    if name not in LABS:
        raise KeyError(name)
    return _ids()


def write_lab(name: str, out_dir: str | Path) -> Path:
    if name != "goad-sevenkingdoms":
        raise KeyError(f"unknown lab '{name}' (available: {', '.join(LABS)})")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for fname, doc in goad_sevenkingdoms().items():
        (out / fname).write_text(json.dumps(doc, indent=1), encoding="utf-8")
    return out
