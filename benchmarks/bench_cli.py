"""Wall-clock time of every command on N synthetic objects: python bench_cli.py 100000"""
import os
import subprocess
import sys
import tempfile
import time

from bench_ingest import write

n = int(sys.argv[1])
with tempfile.TemporaryDirectory() as d:
    write(n, d)
    snap = os.path.join(d, "b.pcsnap")
    cmds = [
        ("snapshot", ["snapshot", d, "-o", snap]),
        ("doctor", ["doctor", d]),
        ("audit", ["audit", d]),
        ("score", ["score", d]),
        ("analyze", ["analyze", d, "--top", "5"]),
        ("export", ["export", d, "--compact"]),
        ("check (3 changes)", ["check", "--baseline", snap, "--change", "add-member U10 G1", "--change", "add-member U11 G2", "--change", "remove-member U12 G3", "--fail-on", "never"]),
        ("detect", ["detect", snap, "-o", os.path.join(d, "det")]),
        ("anonymize", ["anonymize", d, "-o", os.path.join(d, "a.zip")]),
    ]
    for name, args in cmds:
        t = time.time()
        r = subprocess.run([sys.executable, "-m", "pathcutter", *args], capture_output=True, text=True, timeout=1800)
        print(f"{name:<20} {time.time() - t:7.1f}s  exit {r.returncode}", flush=True)
