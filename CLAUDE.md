# Pathcutter - AD Attack Path Risk Engine

## What this is

Pathcutter answers the question no tool answers well:
**"What 5 changes eliminate 80% of attack paths to Domain Admin?"**

BloodHound shows you graphs. Pathcutter tells you what to fix, in what order, with the exact commands to do it, and then proves the fix worked.

Input: SharpHound JSON exports (every pentest already generates these).
Output: ranked remediation plan with copy-paste PowerShell, interactive HTML risk report, before/after diff.

No Neo4j. No database. CLI-first. Offline. CI/CD friendly.

## The problem this solves

After every red team engagement, the report says "fix your AD ACLs." The client has:
- 300+ attack paths to Domain Admin
- No idea which ones matter most
- No idea which fix eliminates the most paths
- No way to verify the fix worked

BloodHound CE is visualization. PlumHound does canned queries. GoodHound is abandoned.
Nobody does **quantified risk + automated remediation + verification** in one tool.

## Architecture

```
SharpHound / AzureHound / AD Explorer --> ingest.py (+ azure.py, adcs.py, adexplorer.py, derived.py)
                                                    |
                                               graph.py  (tier classification, incl. shadow_tier0.py)
                                                    |
                   +--------------------------------+--------------------------------+
                   |                                |                                |
            pathfinder.py                     exposure.py                       impact.py
         (paths, reachability)         (exact reverse search to Tier 0)   (change-gate: what-if)
                   |                                |                                |
               scoring.py                     choke.py (minimum fix set)       policy.py (gate verdict)
                   |                                |
        analysis layers over paths          remediate.py (PowerShell + rollback)
        evidence.py  confidence per step            |
        cost.py      attacker effort / noise   report.py (HTML + JSON + MD),  diff.py (before/after)
        coverage.py  detected/visible/blind    hygiene.py / toolkit.py (audit, doctor, anonymize)
        breach.py    assume-breach, outward     detections.py (Sigma/SPL/KQL)
```

Python. No heavy dependencies. NetworkX for graph algorithms.

### Module responsibilities

1. **ingest.py** - Parse SharpHound JSON zip/directory exports
   - Handle all SharpHound node types: users, computers, groups, domains, GPOs, OUs, containers
   - Normalize ACEs into typed edges
   - Handle BloodHound CE export format (different JSON schema from legacy)
   - Output: list of nodes (typed, with properties) and edges (typed, with metadata)

2. **graph.py** - Build the attack graph
   - Directed multigraph (multiple edge types between same nodes)
   - Node types: User, Computer, Group, Domain, GPO, OU, Container
   - Edge types: see EDGE TYPES section below
   - Tier classification: mark Tier 0 (DA, EA, DC, KRBTGT, AdminSDHolder), Tier 1 (server admins, service accounts with delegation), Tier 2 (workstations, standard users)
   - Implicit edge expansion: if User is MemberOf Group that has GenericAll on another Group, the user inherits that capability through transitive group membership - expand these

3. **pathfinder.py** - Find attack paths
   - all_paths_to_targets(graph, targets) - BFS/DFS all paths to Tier 0 from every node
   - shortest_paths(graph, source, targets) - Dijkstra with edge-weight = 1/exploitability
   - paths_through_node(graph, node) - all paths that traverse a specific node
   - reachable_from(graph, node) - blast radius: everything reachable if this node is compromised
   - IMPORTANT: cap path enumeration to avoid combinatorial explosion on large graphs. Use iterative deepening or path count limits. Real AD environments have 50k+ nodes.

4. **scoring.py** - Risk quantification
   - Node risk score = f(path_count_to_tier0, centrality, blast_radius, session_count, edge_exploitability)
   - Edge weight = exploitability score (see EDGE TYPES)
   - Overall AD risk score: normalized 0-100 based on path density, average path length, Tier 0 exposure
   - Tier breakdown: how many Tier 2 nodes can reach Tier 0

5. **choke.py** - Chokepoint analysis (THE KEY DIFFERENTIATOR)
   - Find nodes whose removal eliminates the most paths (vertex cut problem)
   - Find edges whose removal eliminates the most paths (edge cut / minimum cut)
   - Greedy set cover: iteratively pick the fix that eliminates the most remaining paths
   - Output: ordered list of fixes, each annotated with "eliminates N paths (X% of total)"
   - Cumulative impact: "fixing top 5 eliminates 247/312 paths (79%)"
   - This is the core value prop. Get this right.

6. **remediate.py** - Fix generation
   - For each edge type, generate the exact PowerShell/cmd to remove it
   - Group fixes by category: ACL cleanup, delegation fixes, group membership, GPO, credential hygiene
   - Risk assessment per fix: "removing this admin right may break X" (flag service accounts, flag production servers)
   - Generate a single remediation.ps1 script with safety checks and rollback

7. **diff.py** - Posture drift / remediation verification
   - Compare two SharpHound snapshots (before/after)
   - Report: paths eliminated, new paths created, risk score delta
   - Per-fix validation: "recommended removing GenericAll from HelpDesk -> mark it as fixed/not-fixed"
   - Regression detection: new paths introduced by other changes

8. **report.py** - Reporting
   - Interactive HTML dashboard:
     - Risk score gauge (0-100 with color)
     - Top 10 riskiest nodes with scores
     - Attack graph visualization (force-directed, D3.js)
     - Remediation priority table with PowerShell commands and copy buttons
     - Path explorer: click a node, see all paths through it
     - Before/after comparison view
   - JSON snapshot (machine-readable, for CI pipelines)
   - Executive summary markdown (for the pentest report appendix)

9. **cli.py** - CLI (full command list: `pathcutter -h`)
   - `pathcutter analyze <export>` - full analysis (risk score, paths, minimum fix set, HTML report)
   - `pathcutter score <export>` - quick risk score; `pathcutter graph <export> --target <node>` - paths to one target
   - `pathcutter breach <export> --from <object>` - assume-breach: what this object reaches, cheapest / stealthiest route
   - `pathcutter fix <export> --top N` - remediation script; `pathcutter diff <old> <new>` - before/after
   - `pathcutter doctor | audit | anonymize <export>` - trust, hygiene, shareable copy
   - `pathcutter snapshot <export> -o b.pcsnap` then `pathcutter check --baseline b.pcsnap --changes ...` - the change gate
   - `pathcutter detect <baseline>` - detections for residual paths; `pathcutter coverage <baseline> --telemetry f.json`
   - Flags: `--html`, `--json`, `--markdown`, `-o <dir>`, `--max-depth`, `--also`, `--no-shadow-tier0`

### Modules added since the original design (same principles: exact, never silent, honest about limits)

Collectors and planes
- **azure.py / adcs.py / derived.py** - Microsoft Entra ID and Azure RBAC ingestion; AD CS (ESC1-16, golden cert) derived
  from template / CA / NTAuth / DC data; other derived edges (DCSync from two replication rights, etc.).
- **adexplorer.py** - reads a Sysinternals AD Explorer snapshot exported to NDJSON (`ADExplorerSnapshot.py -m Objects`),
  parsing the binary security descriptors into the same ACL edges SharpHound emits. For domains where EDR blocks SharpHound.
- **shadow_tier0.py** - management-plane objects that can push code or credentials to real Tier 0 (SCCM, backup, hypervisor,
  EDR console, PAM, Entra Connect) are marked Tier 0. Derived matches (domain-takeover rights) are certain; by-name matches
  are reported and can be disabled. Applied during tier classification in graph.py.

The change gate
- **changes.py / impact.py / policy.py / extractors/** - `pathcutter check`: parse a proposed change (line, file, PowerShell,
  Terraform, Ansible, DSC), measure its exact effect on who can reach Tier 0 (marginal and combined), and return a gate verdict.
- **snapshot.py** - reusable `.pcsnap` baselines so `check` runs in seconds.

Reading a path (layers over the enumerated paths; they label, never hide)
- **evidence.py** - confidence per step (high observed / medium derived / low assumed); a path is its weakest step, a finding
  its strongest path.
- **cost.py** - attacker economics: effort (from exploitability) and noise (from detection difficulty) per step, summed per
  path, with fragile and cross-plane flags; `cheapest` / `stealthiest` / `rank(profile)` selection.
- **coverage.py (+ coverage_cli.py)** - `pathcutter coverage`: from declared telemetry and rules, each step is detected /
  visible / blind, and which telemetry to switch on to light up the most blind paths.
- **breach.py (+ breach_cli.py)** - `pathcutter breach --from OBJECT`: assume-breach, working OUTWARD from one object to the
  Tier 0 it reaches, with the cheapest and stealthiest route to each.

Detections and sharing
- **detections.py / detect_pack.py / detect_cli.py** - `pathcutter detect`: Sigma / SPL / Sentinel-KQL / Elastic rules scoped
  to the objects on the paths you have not fixed.
- **hygiene.py / toolkit.py** - `audit` (attribute-level findings), `doctor` (collection completeness), `anonymize` (shareable
  copy with identical paths).

## Edge types and abuse chains

Every edge needs: attack technique, MITRE ID, exploitability score (1-10), fix command, detection difficulty.

### ACL-based edges (the big ones)
| Edge | Abuse | MITRE | Exploitability | Fix |
|------|-------|-------|----------------|-----|
| GenericAll | Full control - change password, write attributes, write DACL | T1222.001 | 9 | `Remove-ADPermission` or `Set-ACL` to remove the ACE |
| GenericWrite | Write any attribute - set SPN for kerberoast, write to scriptPath | T1222.001 | 8 | Remove the ACE |
| WriteOwner | Take ownership then WriteDACL | T1222.001 | 8 | Remove the ACE |
| WriteDACL | Modify the DACL to grant yourself GenericAll | T1222.001 | 8 | Remove the ACE |
| ForceChangePassword | Reset password without knowing current | T1098 | 7 | Remove ExtendedRight on User-Force-Change-Password |
| AddMember | Add yourself to a group | T1098 | 8 | Remove WriteProp on member attribute |
| Owns | Object owner - implies WriteDACL | T1222.001 | 7 | Change owner to Domain Admins |
| WriteProperty (specific) | Write to specific attribute - msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD | T1134.001 | 7 | Remove specific WriteProp ACE |

### Kerberos delegation edges
| Edge | Abuse | MITRE | Exploitability | Fix |
|------|-------|-------|----------------|-----|
| AllowedToDelegate (unconstrained) | Dump TGTs from memory, impersonate any user | T1558 | 10 | `Set-ADComputer -TrustedForDelegation $false` |
| AllowedToDelegate (constrained) | S4U2Proxy to target SPN | T1134.001 | 6 | Remove msDS-AllowedToDelegateTo entries |
| AllowedToAct (RBCD) | Resource-based constrained delegation | T1134.001 | 7 | Clear msDS-AllowedToActOnBehalfOfOtherIdentity |

### Group/session edges
| Edge | Abuse | MITRE | Exploitability | Fix |
|------|-------|-------|----------------|-----|
| MemberOf | Group membership inheritance | - | - | Remove from group (careful with nested groups) |
| AdminTo | Local admin on machine | T1078 | 8 | Remove from local Administrators group via GPO |
| HasSession | User session on machine - credential harvesting | T1003 | 6 | Implement Tier model, restrict logon rights |
| CanRDP | RDP access to machine | T1021.001 | 5 | Remove from Remote Desktop Users |
| CanPSRemote | WinRM/PSRemote access | T1021.006 | 5 | Remove from Remote Management Users |
| ExecuteDCOM | DCOM execution rights | T1021.003 | 5 | Remove from Distributed COM Users |
| SQLAdmin | SQL Server sysadmin | T1505 | 7 | Remove sysadmin role |

### Domain-level edges
| Edge | Abuse | MITRE | Exploitability | Fix |
|------|-------|-------|----------------|-----|
| DCSync | GetChanges + GetChangesAll = dump all hashes | T1003.006 | 10 | Remove Replicating Directory Changes ACE |
| GPOControlsObject | GPO can push scripts/settings to linked OUs | T1484.001 | 7 | Restrict GPO edit rights |
| Contains | OU contains objects - for GPO inheritance | - | - | - |
| ReadLAPSPassword | Can read local admin password | T1003 | 7 | Remove ReadProp on ms-Mcs-AdmPwd |
| ReadGMSAPassword | Can read gMSA password | T1003 | 7 | Remove ReadProp on msDS-ManagedPassword |
| AddAllowedToAct | Can configure RBCD | T1134.001 | 7 | Remove WriteProp on msDS-AllowedToActOnBehalfOfOtherIdentity |

### Composite abuse chains (multi-hop)
These aren't single edges but patterns the pathfinder must recognize:
- **Kerberoasting path**: WriteSPN on user -> set SPN -> kerberoast -> crack password -> use creds
- **Shadow Credentials**: WriteProperty on msDS-KeyCredentialLink -> add key -> PKINIT -> NT hash
- **Resource-Based Constrained Delegation**: AddAllowedToAct on target + own a computer account -> impersonate any user to target
- **GPO abuse**: Write to GPO -> GPO linked to OU containing target -> scheduled task/script execution on target
- **Nested group unrolling**: A -> MemberOf -> B -> MemberOf -> C -> GenericAll -> Target (3 hops, but A can abuse Target)

## SharpHound JSON format

SharpHound exports a ZIP containing JSON files. Each file is a type:
- `*_users.json` - User objects with properties and ACEs
- `*_computers.json` - Computer objects
- `*_groups.json` - Group objects with members
- `*_domains.json` - Domain objects with trusts
- `*_gpos.json` - GPO objects
- `*_ous.json` - OU objects with linked GPOs
- `*_containers.json` - Container objects

Each JSON file has structure:
```json
{
  "data": [...],
  "meta": {"methods": 0, "type": "users", "count": 1234, "version": 5}
}
```

Each object in `data` has:
- `Properties` dict (name, displayname, enabled, admincount, etc.)
- `Aces` list (ACE entries with principal SID, right name, inherited flag)
- `ObjectIdentifier` (SID or GUID)
- Type-specific: `Members` for groups, `AllowedToDelegate` for computers, etc.

**BloodHound CE format** (v5+): different JSON structure with `kind` fields. Must handle both.

Handle SID resolution: some ACEs reference SIDs that map to well-known groups (S-1-5-32-544 = Administrators).

## Performance constraints

Real AD environments: 10k-200k nodes, millions of edges after group expansion.
- Lazy path enumeration - don't compute all paths upfront
- Use generators for path iteration
- Cache transitive group membership (compute once)
- Chokepoint analysis: approximate for large graphs (sample paths, not all paths)
- Target: analyze a 50k-node environment in under 60 seconds
- Memory: stream SharpHound JSON, don't load entire ZIP into memory

## Testing strategy

1. **Synthetic AD fixtures** - build test helpers that create small AD graphs with known paths
   - `tiny_graph()`: 10 nodes, 3 known paths to DA, 1 clear chokepoint
   - `delegation_graph()`: unconstrained/constrained/RBCD delegation chains
   - `nested_groups()`: 5-level group nesting with inherited permissions
   - `multi_path()`: multiple paths with different edge types to same target

2. **Algorithm correctness**
   - Path count assertions on synthetic graphs
   - Chokepoint removal assertions: "removing node X eliminates exactly Y paths"
   - Risk score ordering: higher risk nodes should have higher scores
   - Remediation: generated PowerShell should be syntactically valid

3. **Real data regression** (gitignored)
   - Test against real SharpHound exports (from authorized pentests or labs like GOAD)
   - GOAD (Game of Active Directory) exports are ideal - complex, publicly documented
   - Snap Labs data if available

4. **Edge cases**
   - Circular group membership (yes, AD allows this)
   - Orphaned ACEs (SID not in the dataset)
   - Disabled users (should still be in graph but flagged)
   - Empty SharpHound exports
   - SharpHound v4 vs v5 format differences

## What NOT to do

- Do NOT require Neo4j or any database. The whole point is lightweight CLI.
- Do NOT try to replicate BloodHound's UI. We are NOT a visualization tool. The HTML report has a graph but it's supplementary.
- Do NOT hardcode paths. Use the graph algorithms. A new edge type should "just work" once added to the edge definitions.
- Do NOT ignore performance. A 50k-node graph must complete in under 60 seconds. Profile early.
- Do NOT skip transitive group expansion. Most real attack paths go through 3+ nested groups. If you only check direct ACEs you miss 80% of paths.
- Do NOT generate unsafe remediation scripts. Every fix command must have a comment explaining what it does. Destructive actions (removing ACEs) must be clearly labeled.
- Do NOT output en-dashes, em-dashes, or smart quotes anywhere. Plain ASCII hyphen-minus `-` only.

## Dependencies

- `networkx` - graph algorithms (shortest path, centrality, cuts)
- `pyyaml` - optional config
- No other runtime dependencies. Keep it minimal.

## Build/test

```
pip install -e .
python -m pytest tests/ -v
pathcutter analyze <sharphound-export>
pathcutter analyze <sharphound-export> --html --top 10
pathcutter diff old-snapshot.json new-snapshot.json
```

## File layout

```
pathcutter/
  __init__.py  __main__.py  cli.py
  ingest.py          # SharpHound / BloodHound CE JSON parser
  adexplorer.py      # AD Explorer NDJSON ingestion (parses binary security descriptors)
  azure.py adcs.py derived.py   # Entra/Azure ingestion; AD CS and other derived edges
  graph.py           # Attack graph construction + tier classification
  edges.py           # Edge type registry (abuse, MITRE, exploitability, detection difficulty, fix templates)
  shadow_tier0.py    # management-plane objects treated as Tier 0
  pathfinder.py      # Path algorithms (BFS, shortest, all-paths, reachability)
  exposure.py exposure_ref.py fastindex.py   # exact reverse-search engine + its reference oracle
  scoring.py choke.py remediate.py   # risk score, minimum fix set, PowerShell fixes + rollback
  evidence.py cost.py coverage.py breach.py   # confidence, attacker cost, detection coverage, assume-breach
  changes.py impact.py policy.py snapshot.py extractors/   # the change gate and its inputs
  detections.py detect_pack.py   # Sigma/SPL/Sentinel/Elastic generation
  hygiene.py toolkit.py          # audit, doctor, anonymize
  report.py graph_view.js diff.py   # interactive HTML report + before/after
  *_cli.py helptext.py syntax_help.py   # per-command CLI wiring and reference text
tests/               # 16,000+ tests incl. a differential fuzzer and BloodHound-oracle checks
pyproject.toml  docs/  benchmarks/  tools/
```

## Priority order for building

1. **edges.py + graph.py** - edge type registry and graph model (foundation for everything)
2. **ingest.py** - parse real SharpHound data into the graph
3. **pathfinder.py** - find attack paths (this is where value starts)
4. **scoring.py** - quantify risk per node
5. **choke.py** - the killer feature: minimum fix set
6. **remediate.py** - generate the actual fix commands
7. **cli.py** - wire it all together
8. **report.py** - HTML dashboard with D3 graph
9. **diff.py** - before/after comparison

Build and test each module before moving to the next. Each module should have tests before moving on.

## Definition of done

The tool is done when you can:
1. Point it at a SharpHound ZIP from a real AD environment
2. Get back "your AD risk score is 73/100"
3. See "312 attack paths to Domain Admin from 47 unique starting nodes"
4. See "Fix these 5 things to eliminate 80% of paths" with exact PowerShell
5. Run the fixes, re-collect SharpHound, run diff, see "risk dropped from 73 to 21"
6. Open an HTML report that shows all of this with an interactive graph
7. All of this completes in under 60 seconds for a 50k-node AD environment
