import tempfile, time, os, sys
sys.path.insert(0,'..')
from bench_ingest import write
from pathcutter.toolkit import diagnose, anonymize
from pathcutter.hygiene import audit
from pathcutter.ingest import load_sharphound
n=int(sys.argv[1])
with tempfile.TemporaryDirectory() as d:
    write(n, d)
    t=time.time(); g=load_sharphound(d); print("load",round(time.time()-t,1), flush=True)
    t=time.time(); f=audit(g); print("audit",round(time.time()-t,1), flush=True)
    t=time.time(); r=diagnose(d); print("doctor",round(time.time()-t,1), flush=True)
    t=time.time(); anonymize(d, os.path.join(d,'a.zip'), 's'); print("anonymize",round(time.time()-t,1), flush=True)
