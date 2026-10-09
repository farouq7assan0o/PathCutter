import tempfile, time, os, sys
sys.path.insert(0,'..')
from bench_ingest import write
from pathcutter.ingest import load_sharphound
n=int(sys.argv[1])
with tempfile.TemporaryDirectory() as d:
    write(n, d)
    t=time.time(); g=load_sharphound(d); print("load",round(time.time()-t,1), flush=True)
    import cProfile, pstats
    from pathcutter.hygiene import audit
    pr=cProfile.Profile(); pr.enable(); f=audit(g); pr.disable()
    print("audit findings", len(f), flush=True)
    pstats.Stats(pr).sort_stats('cumulative').print_stats(8)
