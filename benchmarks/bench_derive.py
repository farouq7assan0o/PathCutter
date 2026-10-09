"""AD CS / DCSync derivation at scale: python bench_derive.py 1000000 200 (objects, templates)"""
import sys
import time

from bench_scale import synth
from pathcutter.adcs import derive_adcs_edges
from pathcutter.derived import derive_dcsync
from pathcutter.graph import ADEdge, ADNode, NodeType

n, nt = int(sys.argv[1]), int(sys.argv[2])
g = synth(n)
g.add_node(ADNode("dom", "X.LOCAL", NodeType.DOMAIN, "X.LOCAL"))
g.add_node(ADNode("authusers", "AUTHENTICATED USERS@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
g.add_node(ADNode("nt", "NTAUTH@X.LOCAL", NodeType.NTAUTH_STORE, "X.LOCAL", properties={"certthumbprints": ["AA"]}))
ids = []
for i in range(nt):
    g.add_node(ADNode(f"t{i}", f"T{i}@X.LOCAL", NodeType.CERT_TEMPLATE, "X.LOCAL", properties={
        "enrolleesuppliessubject": True, "authenticationenabled": True, "requiresmanagerapproval": False, "authorizedsignatures": 0}))
    g.add_edge(ADEdge("authusers", f"t{i}", "Enroll"))
    ids.append(f"t{i}")
g.add_node(ADNode("ca", "CA@X.LOCAL", NodeType.ENTERPRISE_CA, "X.LOCAL", properties={"certthumbprint": "AA", "_enabled_templates": ids}))
g.add_edge(ADEdge("authusers", "ca", "Enroll"))
for i in range(0, int(n * 0.8), 1):          # every user is an authenticated user (as Domain Users -> Authenticated Users does)
    g.add_edge(ADEdge(f"u{i}", "authusers", "MemberOf"))
g.classify_tiers()
t = time.time(); c = derive_adcs_edges(g); print(f"adcs derive: {time.time() - t:.1f}s {({k: v for k, v in c.items() if v})}")
t = time.time(); derive_dcsync(g); print(f"dcsync derive: {time.time() - t:.1f}s")
