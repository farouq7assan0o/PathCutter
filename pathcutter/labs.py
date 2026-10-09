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

LABS = {"goad-sevenkingdoms": "GOAD sevenkingdoms.local: nested groups and the documented ACL chain to the DC",
        "hybrid-sevenkingdoms": "the GOAD lab plus an Entra tenant: synced users, a cloud role chain to Global Administrator, scoped roles, a function app"}

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


_TENANT = "7e5e0000-0000-4000-8000-000000000001"
_HYBRID_GA = "62e90394-69f5-4237-9190-012177145e10"
_HYBRID_APPADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
_HYBRID_HELPDESK = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
_HYBRID_GRANT_PERM = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"        # RoleManagement.ReadWrite.Directory


def hybrid_sevenkingdoms() -> dict[str, dict]:
    """The GOAD lab plus an Entra tenant, with the chains known in advance (see tests/test_labs.py):

    * jaime.lannister (AD) is synced to a cloud account that is Application Administrator -> adds a secret to the Deploy app's
      service principal -> that principal holds RoleManagement.ReadWrite.Directory -> Global Administrator.
    * a Helpdesk Administrator scoped to the Sales administrative unit reaches only its members (sales.rep, who owns the Deploy
      app), not other.rep, who owns it too: helpdesk.sales -> sales.rep -> Deploy app -> its service principal -> Global Administrator.
    * a function app's managed identity is a service principal; whoever owns the resource group reaches it.
    """
    ids, files = _ids(), goad_sevenkingdoms()
    u = lambda i, upn, **kw: {"kind": "AZUser", "data": {"id": i, "userPrincipalName": upn, "displayName": upn.split("@")[0],    # noqa: E731
                                                       "tenantId": _TENANT, "accountEnabled": True, **kw}}
    items = [
        u("c0000001-0000-4000-8000-000000000001", "jaime.lannister@sevenkingdoms.cloud",
          onPremisesSecurityIdentifier=ids["jaime.lannister"], onPremisesSyncEnabled=True),
        u("c0000001-0000-4000-8000-000000000002", "tyron.lannister@sevenkingdoms.cloud",
          onPremisesSecurityIdentifier=ids["tyron.lannister"], onPremisesSyncEnabled=True),
        u("c0000001-0000-4000-8000-000000000003", "cloud.admin@sevenkingdoms.cloud"),
        u("c0000001-0000-4000-8000-000000000004", "helpdesk.sales@sevenkingdoms.cloud"),
        u("c0000001-0000-4000-8000-000000000005", "sales.rep@sevenkingdoms.cloud"),
        u("c0000001-0000-4000-8000-000000000006", "other.rep@sevenkingdoms.cloud"),
        {"kind": "AZAppOwner", "data": {"appId": "a0000001-0000-4000-8000-000000000001", "owners": [
            {"owner": {"id": "c0000001-0000-4000-8000-000000000005"}}, {"owner": {"id": "c0000001-0000-4000-8000-000000000006"}}]}},
        {"kind": "AZApp", "data": {"id": "a0000001-0000-4000-8000-000000000001", "appId": "d0000001-0000-4000-8000-00000000000a",
                                   "displayName": "Deploy", "tenantId": _TENANT}},
        {"kind": "AZServicePrincipal", "data": {"id": "5b000001-0000-4000-8000-000000000001", "appId": "d0000001-0000-4000-8000-00000000000a",
                                                "displayName": "Deploy", "tenantId": _TENANT}},
        {"kind": "AZAppRoleAssignment", "data": {"principalId": "5b000001-0000-4000-8000-000000000001", "appRoleId": _HYBRID_GRANT_PERM,
                                                 "resourceDisplayName": "Microsoft Graph"}},
        {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": _HYBRID_GA, "roleAssignments": [
            {"principalId": "c0000001-0000-4000-8000-000000000003", "roleDefinitionId": _HYBRID_GA, "directoryScopeId": "/"}]}},
        {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": _HYBRID_APPADMIN, "roleAssignments": [
            {"principalId": "c0000001-0000-4000-8000-000000000001", "roleDefinitionId": _HYBRID_APPADMIN, "directoryScopeId": "/"}]}},
        {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": _HYBRID_HELPDESK, "roleAssignments": [
            {"principalId": "c0000001-0000-4000-8000-000000000004", "roleDefinitionId": _HYBRID_HELPDESK,
             "directoryScopeId": "/administrativeUnits/ad000001-0000-4000-8000-000000000001"}]}},
        {"kind": "AZAdministrativeUnit", "data": {"id": "ad000001-0000-4000-8000-000000000001", "displayName": "Sales",
                                                  "members": [{"id": "c0000001-0000-4000-8000-000000000005"}]}},
    ]
    files["20240601000000_azure.json"] = {"meta": {"type": "azure", "version": 5, "count": len(items)}, "data": items}
    return files


def lab_ids(name: str = "goad-sevenkingdoms") -> dict[str, str]:
    """Name -> object id for the lab (for tests and documentation)."""
    if name not in LABS:
        raise KeyError(name)
    return _ids()


def write_lab(name: str, out_dir: str | Path) -> Path:
    if name not in LABS:
        raise KeyError(f"unknown lab '{name}' (available: {', '.join(LABS)})")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for fname, doc in (hybrid_sevenkingdoms() if name == "hybrid-sevenkingdoms" else goad_sevenkingdoms()).items():
        (out / fname).write_text(json.dumps(doc, indent=1), encoding="utf-8")
    return out
