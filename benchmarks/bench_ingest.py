"""Ingest benchmark: write N synthetic objects as SharpHound-style JSON, then time load_sharphound.
python benchmarks/bench_ingest.py 200000"""
import json
import os
import random
import sys
import tempfile
import time

from pathcutter.ingest import load_sharphound


def write(n, d):
    rng = random.Random(1)
    nu, ng = int(n * .8), max(5, int(n * .05))
    nc = n - nu - ng
    sid = lambda r: f"S-1-5-21-111-222-333-{r}"      # noqa: E731
    groups = [{"ObjectIdentifier": sid(1000 + i), "Properties": {"name": f"G{i}@CORP.LOCAL", "domain": "CORP.LOCAL"},
               "Members": [], "Aces": [{"PrincipalSID": sid(1000 + rng.randrange(ng)), "PrincipalType": "Group", "RightName": "GenericAll", "IsInherited": False}]
               if rng.random() < .3 else []} for i in range(ng)]
    users = []
    base = 1000 + ng
    for i in range(nu):
        g = groups[rng.randrange(ng)]
        g["Members"].append({"ObjectIdentifier": sid(base + i), "ObjectType": "User"})
        users.append({"ObjectIdentifier": sid(base + i), "Properties": {"name": f"U{i}@CORP.LOCAL", "domain": "CORP.LOCAL", "enabled": True},
                      "Aces": [{"PrincipalSID": sid(1000 + rng.randrange(ng)), "PrincipalType": "Group", "RightName": "WriteDacl", "IsInherited": False}] if rng.random() < .1 else []})
    comps = [{"ObjectIdentifier": sid(base + nu + i), "Properties": {"name": f"C{i}.CORP.LOCAL", "domain": "CORP.LOCAL"},
              "LocalAdmins": {"Results": [{"ObjectIdentifier": sid(1000 + rng.randrange(ng)), "ObjectType": "Group"}], "Collected": True}}
             for i in range(nc)]
    da = {"ObjectIdentifier": sid(512), "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "domain": "CORP.LOCAL"}, "Members": []}
    groups.append(da)
    for name, items in (("groups", groups), ("users", users), ("computers", comps)):
        with open(os.path.join(d, f"20260101_{name}.json"), "w") as f:
            json.dump({"meta": {"type": name, "version": 4, "count": len(items)}, "data": items}, f)


if __name__ == "__main__":
    for n in [int(a) for a in sys.argv[1:]]:
        with tempfile.TemporaryDirectory() as d:
            t = time.time(); write(n, d); w = time.time() - t
            size = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d)) / 2**20
            t = time.time(); g = load_sharphound(d); lt = time.time() - t
            print(f"n={n:>9,} files={size:7.1f} MiB write={w:5.1f}s load={lt:6.1f}s -> {g.node_count:,} nodes {g.edge_count:,} edges", flush=True)
