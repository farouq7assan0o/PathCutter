"""Massively parallel differential fuzzing. Not collected by pytest; run it for as long as you like.

    python tests/fuzz.py --seeds 1000000 --workers 8          # ~ minutes per million on a laptop
    python tests/fuzz.py --start 123456 --seeds 1             # reproduce one failing seed

Every seed builds a random AD-shaped graph and checks, against independent implementations:
  engine    production exposure == reference exposure (sets, hops, unverified)
  oracle    reference exposure == brute-force simple-path oracle (small graphs)
  fork      incremental exposure after added edges == full recomputation
  deny      identity-sensitive exposure with random denies == forward oracle
  probe     a journaled in-place trial restores the graph exactly
Exit code 1 and the failing seeds are printed if anything disagrees.
"""
import argparse
import multiprocessing as mp
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from oracle import oracle_hops                                   # noqa: E402
from pathcutter import exposure, exposure_ref                    # noqa: E402
from pathcutter.exposure import fork_with_added_edges           # noqa: E402
from pathcutter.graph import ADEdge, ADNode, NodeType            # noqa: E402
from test_deny import add_random_denies, oracle_hops_deny        # noqa: E402
from test_probe import scramble, state                            # noqa: E402
from test_proof_random import random_graph                       # noqa: E402

TYPES = ["MemberOf", "GenericAll", "WriteDacl", "ForceChangePassword", "AdminTo", "HasSession", "Contains", "GenericWrite"]


def check(seed: int):
    rng = random.Random(seed)
    g = random_graph(seed, dag=(seed % 4 == 0), n=rng.randint(5, 11), p=0.12 + rng.random() * 0.3)
    g.retier()
    a, b = exposure.compute_exposure(g), exposure_ref.compute_exposure(g)
    if a.exposed() != b.exposed() or {n: a.hops(n) for n in a.exposed()} != {n: b.hops(n) for n in b.exposed()}:
        return "engine"
    if not b.unverified and {n: b.hops(n) for n in b.exposed()} != oracle_hops(g):
        return "oracle"
    ids = list(g.graph.nodes)
    h = g.clone()
    added = []
    for _ in range(rng.randint(1, 3)):
        u, v = rng.choice(ids), rng.choice(ids)
        if u != v:
            et = rng.choice(TYPES)
            h.add_edge(ADEdge(u, v, et))
            added.append((u, v, et))
    h.retier()
    if frozenset(h.tier0_nodes) == a.tier0:
        f, full = fork_with_added_edges(a, h, added), exposure.compute_exposure(h)
        if f.exposed() != full.exposed() or {n: f.hops(n) for n in f.exposed()} != {n: full.hops(n) for n in full.exposed()}:
            return "fork"
    d = add_random_denies(g.clone(), seed)
    e = exposure.compute_exposure(d)
    if not e.unverified and {n: e.hops(n) for n in e.exposed()} != oracle_hops_deny(d):
        return "deny"
    c = g.clone()
    before = state(c)
    with c.probe():
        scramble(c, rng)
    if state(c) != before:
        return "probe"
    return None


def run(rng_):
    lo, hi = rng_
    bad = []
    for s in range(lo, hi):
        try:
            r = check(s)
        except Exception as exc:                                 # a crash is a failure too
            r = f"crash: {type(exc).__name__}: {exc}"
        if r:
            bad.append((s, r))
    return hi - lo, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=20000)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--chunk", type=int, default=500)
    a = ap.parse_args()
    chunks = [(s, min(s + a.chunk, a.start + a.seeds)) for s in range(a.start, a.start + a.seeds, a.chunk)]
    t, done, bad = time.time(), 0, []
    with mp.Pool(a.workers) as pool:
        for n, b in pool.imap_unordered(run, chunks):
            done += n
            bad += b
            if done % (a.chunk * a.workers * 4) < a.chunk or done == a.seeds:
                print(f"{done:>10,} / {a.seeds:,} seeds  {done / (time.time() - t):8.0f}/s  failures: {len(bad)}", flush=True)
    for s, why in sorted(bad)[:30]:
        print(f"FAIL seed {s}: {why}   (python tests/fuzz.py --start {s} --seeds 1)")
    print(f"{'FAILED' if bad else 'OK'}: {a.seeds:,} seeds in {time.time() - t:.0f}s")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
