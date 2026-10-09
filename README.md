# PathCutter

**AD Attack Path Risk Engine** - find what to fix, in what order, with the exact commands to do it.

PathCutter answers the question no tool answers well:
> "What 5 changes eliminate 80% of attack paths to Domain Admin?"

## New: stop attack paths before they are created

Almost every AD security tool tells you about damage that already exists. `pathcutter check` evaluates a
**proposed** change (a ticket, a PowerShell script, a pull request) against your latest collection and
tells you, before it ships, who would gain a route to Domain Admin, with the exact path, and which existing
weakness to fix first so the change becomes safe. It exits non-zero when the answer is "don't", so it works
as a CI gate.

```bash
pathcutter demo --size medium -o ./demo --snapshot demo.pcsnap         # try it with no SharpHound data
pathcutter check --baseline demo.pcsnap \
    --change 'add-member jsmith "BACKUP OPERATORS"' \
    --change 'add-member kpatel HELPDESK' --html review.html
```

```
Verdict  : BLOCK - 1 blocking finding (1 critical)

#1  add jsmith to group BACKUP OPERATORS   [BLOCK]
    [critical] Tier 0 promotion: JSMITH would become Tier 0
      path : JSMITH -[MemberOf]-> BACKUP OPERATORS

#2  add kpatel to group HELPDESK   [REVIEW]
    [medium] Shorter path: Attack paths get shorter for 1 object
      path : KPATEL -[+MemberOf]-> HELPDESK -[WriteSPN]-> SVC_EXCHANGE
```

When a change opens a brand-new route, the finding also lists who is exposed and a `fix first:` line naming the
existing edge to remove so the change becomes safe (`+` marks the edge the change itself adds).

- **Exact, not sampled**: reachability to Tier 0 is computed by reverse search, not capped path counting
- **Understands AD semantics**: group-membership changes promote and demote principals; it catches effects that only appear when changes are combined; a risky change that another change in the set cancels is not a blocker
- **Never skips silently**: a name it cannot resolve, or PowerShell it cannot model, is an error or a flagged finding, not a pass
- **Governance built in**: policy file, crown-jewel assets, and waivers with reason, approver and expiry
- **Fits your pipeline**: exit codes, SARIF annotations on the change file, PR-comment Markdown, offline HTML review page
- **Reads your real automation**: a PowerShell static analysis that follows variables, loops, pipelines, ACL grants, delegation, GPO rights and baseline group expansion, and reports (never skips) anything it cannot model. It can even verify PathCutter's own `fix` script before you run it

Full guide: [docs/ad-change-gate.md](docs/ad-change-gate.md). CI examples: [examples/github-actions](examples/github-actions).

### For the paths you cannot fix: detections

Some paths stay (the business needs that group). `pathcutter detect` turns each *residual* choke point into a
detection scoped to the exact objects involved, in Sigma, Splunk SPL, Sentinel KQL and Elastic KQL, with the audit
prerequisites, the principals who can abuse each edge, and a lab test command:

```bash
pathcutter detect baseline.pcsnap --assume-fixed 5 -o detections/     # I will fix the top 5; watch what remains
```

See [docs/detections.md](docs/detections.md).

### Trust the data, then share it safely

```bash
pathcutter doctor export.zip        # what is this collection missing? (sessions, local groups, ACLs, AD CS, unfiltered trusts)
pathcutter anonymize export.zip -o shareable.zip   # pseudonyms, no free text, identical attack paths
```

`check` also understands what a plain graph cannot: **Deny ACEs** (identity-sensitive; collect them with
`tools/Export-AdDenyAces.ps1`), **time-bound JIT/PAM grants** (`ttl=4h`, `-MemberTimeToLive`), **declared compensating
controls** (Conditional Access, PIM, vaulting: lower severity, never hide, always labeled unverified), SDProp and
revocation-lag notes. `pathcutter syntax model` lists what is modeled and what is not.

### Does it actually work?

Validated against a rebuilt GOAD lab with hand-derived hop counts, an independent brute-force oracle on thousands
of random graphs, and metamorphic properties of the gate. See [docs/validation.md](docs/validation.md) for what is
proven, what bugs that found, and what is *not* validated. `pathcutter -h` and `pathcutter syntax` explain how to
build every command.

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

# Save a reusable baseline, then check proposed AD changes against it before they ship
pathcutter snapshot <sharphound-zip-or-dir> -o baseline.pcsnap
pathcutter check --baseline baseline.pcsnap --changes ad-changes/ --policy policy.json --html review.html
# exit codes: 0 pass | 1 could not run | 2 blocked | 3 needs review (with --fail-on review)
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

5,100+ tests (a large share randomized, against an independent oracle and real SharpHound output, with the PowerShell extractor cross-checked against the real PowerShell parser) covering ingestion, graph construction, pathfinding, scoring, chokepoint analysis, chain detection, remediation, diffing, the report generators, and the whole AD change gate (parsing, resolution, exposure, impact, policy and waivers, snapshots, every output format, CLI exit codes).

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
