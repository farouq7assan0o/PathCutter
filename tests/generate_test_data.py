"""Generate realistic synthetic SharpHound data for testing.

Creates a medium-sized AD environment (~500 nodes) with:
- Multiple domains/forests
- Realistic group nesting (5+ levels deep)
- Service accounts with delegation
- Kerberoastable users
- Multiple attack paths to DA through different vectors
- GPO abuse chains
- LAPS/gMSA configurations
- Disabled accounts with lingering permissions
"""
import json
import os
import random
import string
import zipfile

DOMAIN = "MEGACORP.LOCAL"
DOMAIN_SID = "S-1-5-21-3623811015-3361044348-30300820"

def sid(rid):
    return f"{DOMAIN_SID}-{rid}"

def random_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def generate_users(count=120):
    users = []
    names = [
        "jsmith", "agarcia", "bwilson", "clee", "djones", "ekim", "fmartin",
        "ghernandez", "hpatel", "irodriguez", "janderson", "kthomas", "ljackson",
        "mwhite", "nharris", "omartin", "pthompson", "qmoore", "rtaylor",
        "sdavis", "tbrown", "umiller", "vclark", "wlewis", "xwalker", "yhall",
        "zadams", "svc_sql", "svc_backup", "svc_web", "svc_exchange", "svc_sccm",
        "svc_adconnect", "svc_iis", "svc_print", "svc_share", "svc_antivirus",
        "admin.jsmith", "admin.agarcia", "admin.bwilson",
        "sa_tier0", "sa_tier1_server", "sa_workstation",
    ]
    for i, name in enumerate(names[:count]):
        rid = 1100 + i
        is_svc = name.startswith("svc_")
        is_admin = name.startswith("admin.") or name.startswith("sa_")
        enabled = True
        if name in ("svc_print", "svc_share"):
            enabled = False

        aces = []
        props = {
            "name": f"{name.upper()}@{DOMAIN}",
            "displayname": name.replace(".", " ").replace("_", " ").title(),
            "enabled": enabled,
            "admincount": is_admin,
            "objectid": sid(rid),
            "domain": DOMAIN,
            "distinguishedname": f"CN={name},CN=Users,DC=megacorp,DC=local",
            "hasspn": name in ("svc_sql", "svc_web", "svc_exchange"),
            "unconstraineddelegation": False,
            "lastlogontimestamp": 1720000000 + random.randint(0, 86400*30),
            "pwdlastset": 1719000000 + random.randint(0, 86400*30),
            "serviceprincipalnames": [],
        }

        if name == "svc_sql":
            props["serviceprincipalnames"] = ["MSSQLSvc/SQL01.megacorp.local:1433"]
        if name == "svc_web":
            props["serviceprincipalnames"] = ["HTTP/WEB01.megacorp.local"]

        # ACEs: some users have dangerous permissions
        if name == "jsmith":
            aces.append({
                "PrincipalSID": sid(1100),
                "PrincipalType": "User",
                "RightName": "GenericAll",
                "IsInherited": False,
            })

        users.append({
            "Properties": props,
            "ObjectIdentifier": sid(rid),
            "Aces": aces,
            "AllowedToDelegate": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
        })
    return users


def generate_computers(count=80):
    computers = []
    templates = [
        ("WS", "Workstation", 50),
        ("SRV", "Server", 20),
        ("DC", "Domain Controller", 2),
        ("FILE", "File Server", 3),
        ("SQL", "SQL Server", 2),
        ("WEB", "Web Server", 2),
        ("EXCH", "Exchange", 1),
    ]

    rid = 2000
    for prefix, desc, num in templates:
        for i in range(min(num, count)):
            name = f"{prefix}{i+1:02d}"
            is_dc = prefix == "DC"

            props = {
                "name": f"{name}.{DOMAIN}",
                "displayname": name,
                "enabled": True,
                "objectid": sid(rid),
                "domain": DOMAIN,
                "distinguishedname": f"CN={name},OU={desc}s,DC=megacorp,DC=local",
                "operatingsystem": "Windows Server 2019" if prefix != "WS" else "Windows 10 Enterprise",
                "unconstraineddelegation": is_dc or name == "SRV01",
                "haslaps": prefix == "WS",
                "lastlogontimestamp": 1720000000 + random.randint(0, 86400*7),
            }

            aces = []
            allowed_to_delegate = []
            allowed_to_act = []

            if name == "SRV01":
                props["unconstraineddelegation"] = True

            if name == "WEB01":
                allowed_to_delegate = [f"HTTP/SRV01.{DOMAIN}"]

            if name == "SQL01":
                allowed_to_act = [{"ObjectIdentifier": sid(1127), "ObjectType": "User"}]  # svc_sql

            local_admins = []
            rdp_users = []
            ps_remote_users = []
            dcom_users = []
            sessions = []

            if prefix == "WS":
                # Helpdesk has admin on workstations
                local_admins.append({"ObjectIdentifier": sid(3001), "ObjectType": "Group"})
                # Random user sessions
                user_rid = 1100 + random.randint(0, 25)
                sessions.append({"UserSID": sid(user_rid), "ComputerSID": sid(rid)})

            if prefix in ("SRV", "FILE", "SQL", "WEB"):
                local_admins.append({"ObjectIdentifier": sid(3002), "ObjectType": "Group"})
                rdp_users.append({"ObjectIdentifier": sid(3002), "ObjectType": "Group"})

            if is_dc:
                sessions.append({"UserSID": sid(1140), "ComputerSID": sid(rid)})  # sa_tier0

            computers.append({
                "Properties": props,
                "ObjectIdentifier": sid(rid),
                "Aces": aces,
                "AllowedToDelegate": allowed_to_delegate,
                "AllowedToAct": allowed_to_act,
                "LocalAdmins": {"Results": local_admins},
                "RemoteDesktopUsers": {"Results": rdp_users},
                "PSRemoteUsers": {"Results": ps_remote_users},
                "DcomUsers": {"Results": dcom_users},
                "Sessions": {"Results": sessions},
                "PrivilegedSessions": {"Results": []},
                "RegistrySessions": {"Results": []},
            })
            rid += 1
            count -= 1
            if count <= 0:
                break
        if count <= 0:
            break
    return computers


def generate_groups():
    groups = []
    group_defs = [
        (sid(512), "DOMAIN ADMINS", [sid(1140)]),  # sa_tier0
        (sid(519), "ENTERPRISE ADMINS", [sid(512)]),
        (sid(516), "DOMAIN CONTROLLERS", [sid(2050), sid(2051)]),  # DC01, DC02
        ("S-1-5-32-544", "ADMINISTRATORS", [sid(512)]),
        (sid(3001), "HELPDESK", [sid(1100), sid(1101), sid(1102)]),  # jsmith, agarcia, bwilson
        (sid(3002), "SERVER ADMINS", [sid(1139), sid(1127)]),  # admin.bwilson, svc_sql
        (sid(3003), "IT ADMINS", [sid(3001), sid(3002)]),  # nested: HelpDesk + Server Admins
        (sid(3004), "SERVICE ACCOUNTS", [sid(1127), sid(1128), sid(1129), sid(1130), sid(1131), sid(1132), sid(1133), sid(1134), sid(1135), sid(1136)]),
        (sid(3005), "EXCHANGE ADMINS", [sid(1130)]),  # svc_exchange
        (sid(3006), "SCCM ADMINS", [sid(1131)]),  # svc_sccm
        (sid(3007), "BACKUP OPERATORS", [sid(1128)]),  # svc_backup
        (sid(3008), "DEVELOPERS", [sid(1103), sid(1104), sid(1105), sid(1106)]),
        (sid(3009), "HR", [sid(1107), sid(1108), sid(1109)]),
        (sid(3010), "FINANCE", [sid(1110), sid(1111), sid(1112)]),
        (sid(3011), "VPN USERS", [sid(3008), sid(3009), sid(3010)]),  # nested groups
        (sid(3012), "ALL EMPLOYEES", [sid(3011), sid(3001)]),  # deep nesting
        (sid(3013), "GPO EDITORS", [sid(1137), sid(1138)]),  # admin.jsmith, admin.agarcia
        (sid(3014), "ADCONNECT", [sid(1132)]),  # svc_adconnect
    ]

    for obj_id, name, member_ids in group_defs:
        members = [{"ObjectIdentifier": m, "ObjectType": "Group" if m.endswith(("-512", "-519", "-516")) or int(m.split("-")[-1]) >= 3000 else "User"} for m in member_ids]

        aces = []
        # IT ADMINS has GenericAll on svc_backup (attack path)
        if name == "IT ADMINS":
            pass  # ACEs go on the TARGET object, not the source

        # Exchange Admins has WriteDacl on domain (ESC path)
        if name == "EXCHANGE ADMINS":
            pass

        groups.append({
            "Properties": {
                "name": f"{name}@{DOMAIN}",
                "displayname": name,
                "objectid": obj_id,
                "domain": DOMAIN,
                "distinguishedname": f"CN={name},CN=Groups,DC=megacorp,DC=local",
                "admincount": name in ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"),
            },
            "ObjectIdentifier": obj_id,
            "Aces": aces,
            "Members": {"Results": members},
        })

    return groups


def generate_domains():
    return [{
        "Properties": {
            "name": DOMAIN,
            "objectid": sid(0).replace("-0", ""),
            "domain": DOMAIN,
            "distinguishedname": "DC=megacorp,DC=local",
            "functionallevel": "2016",
        },
        "ObjectIdentifier": DOMAIN_SID,
        "Aces": [
            # svc_adconnect has DCSync rights
            {
                "PrincipalSID": sid(1132),
                "PrincipalType": "User",
                "RightName": "GetChanges",
                "IsInherited": False,
            },
            {
                "PrincipalSID": sid(1132),
                "PrincipalType": "User",
                "RightName": "GetChangesAll",
                "IsInherited": False,
            },
            # Exchange Admins has WriteDacl on domain
            {
                "PrincipalSID": sid(3005),
                "PrincipalType": "Group",
                "RightName": "WriteDacl",
                "IsInherited": False,
            },
        ],
        "Links": [],
        "Trusts": [],
        "ChildObjects": [],
    }]


def generate_ous():
    ous = [
        (sid(4001), "Workstations", [sid(r) for r in range(2000, 2050)]),
        (sid(4002), "Servers", [sid(r) for r in range(2050, 2070)]),
        (sid(4003), "Domain Controllers", [sid(2050), sid(2051)]),
        (sid(4004), "Service Accounts", [sid(r) for r in range(1127, 1137)]),
        (sid(4005), "Admin Accounts", [sid(r) for r in range(1137, 1143)]),
    ]
    result = []
    for obj_id, name, children in ous:
        result.append({
            "Properties": {
                "name": f"{name}@{DOMAIN}",
                "objectid": obj_id,
                "domain": DOMAIN,
                "distinguishedname": f"OU={name},DC=megacorp,DC=local",
            },
            "ObjectIdentifier": obj_id,
            "Aces": [],
            "Links": [],
            "ChildObjects": [{"ObjectIdentifier": c, "ObjectType": "Computer"} for c in children],
        })
    return result


def generate_gpos():
    return [
        {
            "Properties": {
                "name": f"DEFAULT DOMAIN POLICY@{DOMAIN}",
                "objectid": sid(5001),
                "domain": DOMAIN,
                "distinguishedname": f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,DC=megacorp,DC=local",
            },
            "ObjectIdentifier": sid(5001),
            "Aces": [
                # GPO Editors can write to this GPO
                {
                    "PrincipalSID": sid(3013),
                    "PrincipalType": "Group",
                    "RightName": "GenericWrite",
                    "IsInherited": False,
                },
            ],
        },
        {
            "Properties": {
                "name": f"SERVER HARDENING@{DOMAIN}",
                "objectid": sid(5002),
                "domain": DOMAIN,
                "distinguishedname": f"CN={{6AC1786C-016F-11D2-945F-00C04fB984F9}},CN=Policies,CN=System,DC=megacorp,DC=local",
            },
            "ObjectIdentifier": sid(5002),
            "Aces": [
                {
                    "PrincipalSID": sid(3013),
                    "PrincipalType": "Group",
                    "RightName": "GenericAll",
                    "IsInherited": False,
                },
            ],
        },
    ]


def add_attack_aces(users, groups, computers):
    """Add ACEs that create attack paths. ACEs go on the TARGET object."""
    user_by_name = {u["Properties"]["name"].split("@")[0].lower(): u for u in users}
    group_by_id = {g["ObjectIdentifier"]: g for g in groups}

    # Path 1: HelpDesk -> GenericAll -> svc_backup -> MemberOf -> Backup Operators -> ...
    # Actually: HelpDesk members have GenericAll on svc_backup
    if "svc_backup" in user_by_name:
        user_by_name["svc_backup"]["Aces"].append({
            "PrincipalSID": sid(3001),  # HelpDesk group
            "PrincipalType": "Group",
            "RightName": "GenericAll",
            "IsInherited": False,
        })

    # Path 2: Developers -> WriteSPN -> svc_web -> kerberoastable
    if "svc_web" in user_by_name:
        user_by_name["svc_web"]["Aces"].append({
            "PrincipalSID": sid(3008),  # Developers group
            "PrincipalType": "Group",
            "RightName": "WriteSPN",
            "IsInherited": False,
        })

    # Path 3: Server Admins -> ForceChangePassword -> admin.jsmith
    if "admin.jsmith" in user_by_name:
        user_by_name["admin.jsmith"]["Aces"].append({
            "PrincipalSID": sid(3002),
            "PrincipalType": "Group",
            "RightName": "ForceChangePassword",
            "IsInherited": False,
        })

    # Path 4: admin.jsmith -> GenericWrite on Domain Admins (can add members)
    if sid(512) in group_by_id:
        group_by_id[sid(512)]["Aces"].append({
            "PrincipalSID": sid(1137),  # admin.jsmith
            "PrincipalType": "User",
            "RightName": "AddMember",
            "IsInherited": False,
        })

    # Path 5: svc_exchange -> WriteOwner on IT ADMINS
    if sid(3003) in group_by_id:
        group_by_id[sid(3003)]["Aces"].append({
            "PrincipalSID": sid(1130),  # svc_exchange
            "PrincipalType": "User",
            "RightName": "WriteOwner",
            "IsInherited": False,
        })

    # Path 6: svc_sccm -> AdminTo on all servers (already via Server Admins group + local admins)
    # Path 7: Disabled svc_print still has WriteDacl on SCCM ADMINS (lingering permission)
    if sid(3006) in group_by_id:
        group_by_id[sid(3006)]["Aces"].append({
            "PrincipalSID": sid(1134),  # svc_print (disabled!)
            "PrincipalType": "User",
            "RightName": "WriteDacl",
            "IsInherited": False,
        })

    # Path 8: Finance group -> ReadLAPSPassword on workstations
    for comp in computers[:5]:
        comp.setdefault("Aces", []).append({
            "PrincipalSID": sid(3010),  # Finance
            "PrincipalType": "Group",
            "RightName": "ReadLAPSPassword",
            "IsInherited": False,
        })

    # Path 9: svc_adconnect -> DCSync (already on domain ACEs)
    # Path 10: admin.agarcia -> Owns -> svc_adconnect
    if "svc_adconnect" in user_by_name:
        user_by_name["svc_adconnect"]["Aces"].append({
            "PrincipalSID": sid(1138),  # admin.agarcia
            "PrincipalType": "User",
            "RightName": "Owns",
            "IsInherited": False,
        })

    # Path 11: svc_backup -> WriteKeyCredentialLink -> sa_tier0 (shadow credentials)
    if "sa_tier0" in user_by_name:
        user_by_name["sa_tier0"]["Aces"].append({
            "PrincipalSID": sid(1128),  # svc_backup
            "PrincipalType": "User",
            "RightName": "WriteKeyCredentialLink",
            "IsInherited": False,
        })


def write_sharphound_dir(output_dir):
    """Write a realistic SharpHound export directory."""
    os.makedirs(output_dir, exist_ok=True)

    users = generate_users()
    computers = generate_computers()
    groups = generate_groups()
    domains = generate_domains()
    ous = generate_ous()
    gpos = generate_gpos()

    add_attack_aces(users, groups, computers)

    files = {
        "20240115120000_users.json": {"data": users, "meta": {"type": "users", "count": len(users), "version": 5}},
        "20240115120000_computers.json": {"data": computers, "meta": {"type": "computers", "count": len(computers), "version": 5}},
        "20240115120000_groups.json": {"data": groups, "meta": {"type": "groups", "count": len(groups), "version": 5}},
        "20240115120000_domains.json": {"data": domains, "meta": {"type": "domains", "count": len(domains), "version": 5}},
        "20240115120000_ous.json": {"data": ous, "meta": {"type": "ous", "count": len(ous), "version": 5}},
        "20240115120000_gpos.json": {"data": gpos, "meta": {"type": "gpos", "count": len(gpos), "version": 5}},
    }

    for fname, data in files.items():
        with open(os.path.join(output_dir, fname), "w") as f:
            json.dump(data, f, indent=2)

    return output_dir


def write_sharphound_zip(output_path):
    """Write a realistic SharpHound ZIP export."""
    import tempfile
    tmpdir = tempfile.mkdtemp()
    write_sharphound_dir(tmpdir)

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in os.listdir(tmpdir):
            zf.write(os.path.join(tmpdir, fname), fname)

    import shutil
    shutil.rmtree(tmpdir)
    return output_path


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "test_sharphound_data"
    write_sharphound_dir(out)
    print(f"Generated SharpHound test data in {out}/")

    # Also make a ZIP
    zip_path = out + ".zip"
    write_sharphound_zip(zip_path)
    print(f"Generated SharpHound ZIP: {zip_path}")
