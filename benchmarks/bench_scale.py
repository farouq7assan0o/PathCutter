"""Scale benchmark: synthetic AD-shaped graphs of N objects. Usage: python benchmarks/bench_scale.py 10000 100000"""
import random
import sys
import time
import tracemalloc

from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType


def synth(n: int, seed: int = 1) -> AttackGraph:
    """~n objects: 80% users, 5% groups, 15% computers; nested groups, ACL edges, admin edges, a Tier 0 core."""
    rng = random.Random(seed)
    g = AttackGraph()
    nu, ng = int(n * 0.8), max(5, int(n * 0.05))
    nc = n - nu - ng
    nodes = [ADNode("DA", "DOMAIN ADMINS@X", NodeType.GROUP, "x")]
    nodes += [ADNode(f"g{i}", f"G{i}@X", NodeType.GROUP, "x") for i in range(ng)]
    nodes += [ADNode(f"u{i}", f"U{i}@X", NodeType.USER, "x") for i in range(nu)]
    nodes += [ADNode(f"c{i}", f"C{i}.X", NodeType.COMPUTER, "x") for i in range(nc)]
    g.add_nodes_bulk(nodes)
    edges = []
    for i in range(nu):
        for _ in range(rng.randint(1, 3)):
            edges.append(ADEdge(f"u{i}", f"g{rng.randrange(ng)}", "MemberOf"))
    for i in range(ng):
        if rng.random() < 0.6:
            edges.append(ADEdge(f"g{i}", f"g{rng.randrange(ng)}", "MemberOf"))
    for i in range(nc):
        edges.append(ADEdge(f"g{rng.randrange(ng)}", f"c{i}", "AdminTo"))
        if rng.random() < 0.5:
            edges.append(ADEdge(f"c{i}", f"u{rng.randrange(nu)}", "HasSession"))
    for _ in range(int(n * 0.1)):
        edges.append(ADEdge(f"g{rng.randrange(ng)}", f"u{rng.randrange(nu)}", rng.choice(["GenericAll", "WriteDacl", "ForceChangePassword"])))
    core = [f"u{rng.randrange(nu)}" for _ in range(5)]
    for u in core:
        edges.append(ADEdge(u, "DA", "MemberOf"))
        for _ in range(max(3, n // 5000)):          # a handful of real paths into the Tier 0 core, scaling with size
            edges.append(ADEdge(f"g{rng.randrange(ng)}", u, rng.choice(["GenericAll", "WriteDacl", "ForceChangePassword"])))
    g.add_edges_bulk(edges)
    g.classify_tiers()
    return g


def main():
    for n in [int(a) for a in sys.argv[1:]] or [10000, 100000]:
        t = time.time(); g = synth(n); build = time.time() - t
        t = time.time(); e = compute_exposure(g); expo = time.time() - t
        t = time.time(); c = g.clone(); clone = time.time() - t
        t = time.time(); c.retier(); retier = time.time() - t
        print(f"n={n:>9,} edges={g.edge_count:>10,} build={build:6.1f}s exposure={expo:6.1f}s clone={clone:6.1f}s retier={retier:6.1f}s exposed={len(e.exposed()):,}", flush=True)


if __name__ == "__main__":
    main()
