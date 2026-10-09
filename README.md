# PathCutter

**AD Attack Path Risk Engine** - find what to fix, in what order, with the exact commands to do it.

PathCutter answers the question no tool answers well:
> "What 5 changes eliminate 80% of attack paths to Domain Admin?"

## What it does

- **Quantified risk**: scores your AD posture 0-100 with a letter grade
- **Minimum fix set**: greedy set cover finds the fewest changes that cut the most paths
- **Copy-paste remediation**: every fix comes with exact PowerShell, safety assessment, and rollback
- **Before/after diff**: re-collect SharpHound, run `pathcutter diff`, see risk drop
- **Interactive HTML report**: D3 attack graph, path explorer, detection guidance
- **Attack chain detection**: shadow credentials, unconstrained delegation, ADCS abuse, kerberoasting, LAPS/gMSA, AS-REP roasting

Input: SharpHound JSON exports (every pentest already generates these).
No Neo4j. No database. CLI-first. Offline. CI/CD friendly.

## Install

```bash
pip install -e .
```

Requires Python 3.10+ and NetworkX.

## Usage

```bash
# Full analysis with HTML report
pathcutter analyze <sharphound-zip-or-dir> --html -o ./report --top 10

# Quick risk score
pathcutter score <sharphound-dir>

# Generate remediation PowerShell script
pathcutter fix <sharphound-dir> --top 10 -o remediation.ps1

# Show attack paths to a specific target
pathcutter graph <sharphound-dir> --target "DOMAIN ADMINS"

# Compare before/after snapshots
pathcutter diff <old-snapshot> <new-snapshot>

# CI/CD export with threshold gating
pathcutter export <sharphound-dir> --fail-above 50 --fail-exposure 30 -o report.json

# Generate a demo environment (no SharpHound data needed)
pathcutter demo --size medium -o ./demo
```

## Example output

```
[*] Risk Score: 73/100 (Grade: D)
    Exposure: 34.2% of Tier 2 can reach Tier 0
    312 paths from 47 unique sources

[*] Top 5 Fixes (81% path elimination):
    #    Fix                                          Cut    Cumul
    1    HELPDESK -> SVC_BACKUP [GenericAll]           87     28%
    2    IT_ADMINS -> DC01 [AdminTo]                   64     48%
    3    SVC_SQL -> SA_TIER0 [AllowedToDelegate]       52     65%
    4    JSMITH -> SERVER_ADMINS [AddMember]            31     75%
    5    HR_GROUP -> ADMIN.JONES [ForceChangePassword]  19     81%
```

## HTML Report

The interactive report includes:

- **Overview**: risk score gauge, exposure metrics, node/edge distribution charts
- **Riskiest Nodes**: sortable table with risk scores, blast radius, searchable
- **Remediation**: priority-ordered fixes with safety assessment, copy-paste PowerShell
- **Attack Chains**: detected composite attack patterns (shadow creds, delegation, ADCS)
- **Defend**: MITRE coverage, detection difficulty breakdown, log sources, per-edge guidance
- **What If**: toggle fixes on/off to see projected risk score, path elimination, and exposure in real-time
- **Path Explorer**: browse and inspect individual attack paths with SVG path diagrams
- **Attack Graph**: Canvas-rendered graph built for large environments:
  - Scales to thousands of nodes: viewport culling, quadtree hit-testing, sprite nodes, time-sliced layout (the page never freezes), and an adaptive fast mode while you pan or zoom
  - Leaf users/computers that share one identical edge collapse into labelled clusters, so a 12,000-object domain shows ~1,600 readable nodes
  - Shaped nodes per type, Tier 0 diamonds, risk halos, minimap, PNG export
  - Click a node: its neighbourhood plus its shortest path to Tier 0 light up; one-click path to Tier 0, or set a path start and end to find the shortest attack path between any two objects
  - Simulate fixes on the graph: a slider applies the top-N remediations, removed edges show as red ghosts, and objects that can no longer reach Tier 0 are ringed green (stays in sync with the What If tab)
  - Locate any recommended fix as a pulsing edge on the graph
  - Search (also finds users inside clusters), edge-type filter, structural-edge toggle, tier layout
- Use `--graph-nodes N` on `analyze` to change how many nodes the graph draws (default 6000)
- **Keyboard shortcuts**: 1-8 jump to tabs, arrow keys navigate, / focuses search, ? shows help

## CI/CD Integration

```bash
# Fail the pipeline if risk score exceeds 50
pathcutter export <sharphound-dir> --fail-above 50 -o report.json
echo $?  # exit code 2 = gate failed, 0 = passed

# Fail if more than 30% of Tier 2 nodes are exposed
pathcutter export <sharphound-dir> --fail-exposure 30 --compact
```

The export command outputs structured JSON with posture scores, top fixes, attack chains, and gate pass/fail status.

## Supported formats

- SharpHound v4 (legacy) JSON exports
- BloodHound CE v5 JSON exports
- ZIP archives or extracted directories

## Edge types

30+ edge types with MITRE ATT&CK mappings:

| Category | Edges |
|----------|-------|
| ACL | GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword, AddMember, Owns, WriteSPN |
| Delegation | AllowedToDelegate, AllowedToAct, AddAllowedToAct |
| Session | AdminTo, HasSession, CanRDP, CanPSRemote, ExecuteDCOM, SQLAdmin |
| Domain | DCSync, GPOControlsObject, ReadLAPSPassword, ReadGMSAPassword |
| ADCS | Enroll, AutoEnroll, ManageCA, ManageCertificates, WritePKIEnrollmentFlag, WritePKINameFlag |
| Special | WriteKeyCredentialLink (Shadow Credentials) |

## Performance

- 41k nodes, 100k+ edges: full analysis in ~6 seconds
- Bulk graph operations for fast construction
- BFS scoring capped at top 100 nodes for efficiency
- Target: 50k-node environment in under 60 seconds

## Testing

```bash
python -m pytest tests/ -v
```

139 tests covering ingestion, graph construction, pathfinding, scoring, chokepoint analysis, chain detection, remediation, diffing, and CLI commands.

## Architecture

```
SharpHound JSON --> ingest.py --> graph.py --> pathfinder.py --> scoring.py
                                                    |
                                              choke.py (minimum fix set)
                                                    |
                                         remediate.py (PowerShell + safety)
                                                    |
                                    report.py (HTML dashboard + D3 graph)
                                                    |
                                         diff.py (before/after comparison)
```

## License

MIT
