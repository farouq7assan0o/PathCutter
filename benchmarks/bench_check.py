"""End-to-end `check` benchmark on a synthetic graph: python benchmarks/bench_check.py 200000 10"""
import sys
import time

from bench_scale import synth
from pathcutter.changes import load_changes, resolve_changes
from pathcutter.impact import analyze_impact

n, k = int(sys.argv[1]), int(sys.argv[2])
t = time.time(); g = synth(n); print(f"build {time.time() - t:.1f}s")
adds = [f"add-member u{i} g{i}" for i in range(10, 10 + k)]
rems = [f"remove-member u{i} g{i % 50}" for i in range(100, 100 + k // 2)]
for label, lines in (("adds", adds), ("adds+removes", adds + rems)):
    specs, _ = load_changes(inline=lines)
    rc, err = resolve_changes(g, specs)
    t = time.time(); rep = analyze_impact(g, rc); print(f"{label:>13}: {len(rc)} changes in {time.time() - t:.1f}s  verdict-inputs: {len(rep.findings)} findings")
