"""Performance benchmark - generate a large synthetic graph and measure analysis time.

Target from CLAUDE.md: analyze a 50k-node environment in under 60 seconds.
"""
import time
import random
import sys

from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType
from pathcutter.pathfinder import find_all_paths
from pathcutter.scoring import score_nodes, score_posture
from pathcutter.choke import find_chokepoints
from pathcutter.chains import detect_chains


def build_large_graph(num_users=5000, num_computers=3000, num_groups=200,
                      num_acl_edges=8000, num_session_edges=4000) -> AttackGraph:
    """Build a realistic large AD graph."""
    g = AttackGraph()
    random.seed(42)
    randchoice = random.choice
    randint = random.randint
    randrand = random.random

    domain = "MEGACORP.LOCAL"
    all_users = []
    all_computers = []
    all_groups = []

    # -- Nodes (bulk) --
    nodes = []
    edges = []

    t0_groups = [
        ("S-DA", "DOMAIN ADMINS"),
        ("S-EA", "ENTERPRISE ADMINS"),
        ("S-SA", "SCHEMA ADMINS"),
        ("S-BA", "ADMINISTRATORS"),
    ]
    for sid, name in t0_groups:
        nodes.append(ADNode(sid, f"{name}@{domain}", NodeType.GROUP))
        all_groups.append(sid)

    for i in range(3):
        sid = f"S-DC-{i}"
        nodes.append(ADNode(sid, f"DC{i+1}.{domain}", NodeType.COMPUTER))
        edges.append(ADEdge(sid, "S-DA", "MemberOf"))
        all_computers.append(sid)

    for i in range(num_groups):
        sid = f"S-G-{i}"
        nodes.append(ADNode(sid, f"GROUP_{i}@{domain}", NodeType.GROUP))
        all_groups.append(sid)
        if i > 10 and randrand() < 0.15:
            parent = randchoice(all_groups[:i])
            edges.append(ADEdge(sid, parent, "MemberOf"))

    svc_count = num_users // 20
    for i in range(svc_count):
        sid = f"S-SVC-{i}"
        props = {"hasspn": True} if randrand() < 0.5 else {}
        if randrand() < 0.1:
            props["dontreqpreauth"] = True
        nodes.append(ADNode(sid, f"SVC_{i}@{domain}", NodeType.USER, properties=props))
        all_users.append(sid)
        edges.append(ADEdge(sid, randchoice(all_groups), "MemberOf"))

    for i in range(num_users - svc_count):
        sid = f"S-U-{i}"
        nodes.append(ADNode(sid, f"USER_{i}@{domain}", NodeType.USER))
        all_users.append(sid)
        grp_count = randint(1, 3)
        for _ in range(grp_count):
            edges.append(ADEdge(sid, randchoice(all_groups), "MemberOf"))

    for i in range(num_computers):
        sid = f"S-C-{i}"
        nodes.append(ADNode(sid, f"WS{i}.{domain}", NodeType.COMPUTER))
        all_computers.append(sid)

    g.add_nodes_bulk(nodes)

    # -- Attack edges (pre-concat source pools once) --
    acl_types = ["GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
                 "ForceChangePassword", "AddMember", "WriteSPN",
                 "WriteKeyCredentialLink", "AddAllowedToAct", "ReadLAPSPassword"]
    session_types = ["HasSession", "AdminTo", "CanRDP"]

    acl_src_pool = all_users + all_groups
    acl_tgt_pool = all_users + all_groups + all_computers

    for _ in range(num_acl_edges):
        src = randchoice(acl_src_pool)
        tgt = randchoice(acl_tgt_pool)
        if src != tgt:
            edges.append(ADEdge(src, tgt, randchoice(acl_types)))

    for _ in range(num_session_edges):
        edges.append(ADEdge(randchoice(all_users), randchoice(all_computers), randchoice(session_types)))

    for i in range(5):
        edges.append(ADEdge(randchoice(all_users), "S-DA", "DCSync"))

    for i in range(20):
        comp = randchoice(all_computers)
        tgt = randchoice(all_computers)
        if comp != tgt:
            edges.append(ADEdge(comp, tgt, "AllowedToDelegate"))

    g.add_edges_bulk(edges)
    g.classify_tiers()
    return g


def benchmark(node_count_target=10000):
    """Run a full analysis pipeline and time it."""
    # Scale parameters to hit target node count
    ratio = node_count_target / 8200  # base params give ~8200 nodes
    num_users = int(5000 * ratio)
    num_computers = int(3000 * ratio)
    num_groups = int(200 * ratio)
    num_acl = int(8000 * ratio)
    num_sessions = int(4000 * ratio)

    print(f"Building graph targeting ~{node_count_target} nodes...")
    t0 = time.time()
    g = build_large_graph(num_users, num_computers, num_groups, num_acl, num_sessions)
    build_time = time.time() - t0
    print(f"  Built: {g.node_count} nodes, {g.edge_count} edges in {build_time:.1f}s")

    print("Finding attack paths...")
    t1 = time.time()
    targets = g.tier0_nodes
    report = find_all_paths(g, targets, max_depth=10, max_paths=5000)
    path_time = time.time() - t1
    print(f"  Found: {report.total_paths} paths from {report.unique_sources} sources in {path_time:.1f}s")

    print("Scoring...")
    t2 = time.time()
    posture = score_posture(g, report)
    scores = score_nodes(g, report)
    score_time = time.time() - t2
    print(f"  Score: {posture.score}/100 (Grade {posture.grade}) in {score_time:.1f}s")

    print("Finding chokepoints...")
    t3 = time.time()
    choke = find_chokepoints(g, report, max_fixes=20)
    choke_time = time.time() - t3
    print(f"  Fixes: {len(choke.fixes)}, {choke.elimination_pct:.0f}% elimination in {choke_time:.1f}s")

    print("Detecting chains...")
    t4 = time.time()
    chains = detect_chains(g, report)
    chain_time = time.time() - t4
    print(f"  Chains: {len(chains)} detected in {chain_time:.1f}s")

    total = time.time() - t0
    print(f"\n{'='*50}")
    print(f"  TOTAL: {total:.1f}s for {g.node_count} nodes")
    print(f"  Build: {build_time:.1f}s | Paths: {path_time:.1f}s | Score: {score_time:.1f}s | Choke: {choke_time:.1f}s | Chains: {chain_time:.1f}s")
    print(f"  Target: <60s for 50k nodes. {'PASS' if total < 60 else 'FAIL'}")
    print(f"{'='*50}")

    return total


if __name__ == "__main__":
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    benchmark(target)
