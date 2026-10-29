# PathCutter

**Stop attack paths to Tier 0 before they exist, and fix the ones that do, in the right order.**
Active Directory, AD CS, Microsoft Entra ID and Azure RBAC in one graph. Offline, no database, CLI first.

```
 SharpHound / AzureHound  ──►  pathcutter doctor     can I trust this collection?
        (your export)     ──►  pathcutter analyze    what is wrong, and which 5 fixes remove most of it?
                          ──►  pathcutter audit      hygiene: roastable accounts, passwords in attributes, LAPS, MFA gaps
                          ──►  pathcutter breach      if THIS object leaks, what Tier 0 falls, cheapest / quietest route?
 proposed change          ──►  pathcutter check      would this open a path to Domain Admin?  (CI gate, exit code)
 paths you cannot fix     ──►  pathcutter detect     Sigma / SPL / KQL scoped to exactly those objects
                          ──►  pathcutter coverage   of those paths, which are detected, which only visible, which blind
```

- **Exact, not sampled.** Reachability to Tier 0 is a reverse search, not capped path counting. It is checked against a brute-force
  oracle on a million random graphs, and against BloodHound's own computed graph.
- **Never silent.** A name it cannot resolve, a script it cannot model, a collection gap: reported by name, never a quiet pass.
- **Honest about limits.** `pathcutter syntax model` lists what is modeled, what is only reported, and what is not modeled at all.

## Quick start

```bash
pip install pathcutter                             # Python 3.10+, NetworkX only; or `pip install -e .` from a checkout; add [yaml] for Ansible input
pathcutter demo --size medium -o demo --snapshot demo.pcsnap      # try everything with no real data
pathcutter demo --lab hybrid-sevenkingdoms -o hybrid               # a known AD + Entra lab: synced users, a cloud chain to Global Administrator
pathcutter -h                                      # every command, how to build it, examples
```

```bash
pathcutter doctor   export.zip                     # completeness verdict + the collector flag that fixes each gap
pathcutter analyze  export.zip --html -o report    # score, attack paths, the minimum fix set, an interactive report
pathcutter audit    export.zip --fail-on critical  # attribute-level findings with why and how to fix
pathcutter breach   export.zip --from "JSMITH@CORP.LOCAL"   # assume breach: what this one object reaches, and how
pathcutter analyze  export.zip --crown-jewels crown.json --html -o report  # weight by business value; exec summary + per-OU + PDF
pathcutter snapshot export.zip -o baseline.pcsnap  # a reusable baseline (nightly job)
pathcutter check --baseline baseline.pcsnap --changes ad-changes/ --policy policy.json --html review.html
pathcutter detect   baseline.pcsnap --assume-fixed 5 -o detections/
pathcutter coverage baseline.pcsnap --telemetry telemetry.json   # detected / visible / blind per residual path
pathcutter anonymize export.zip -o shareable.zip   # pseudonyms, no free text, identical attack paths
```

## The change gate: `pathcutter check`

Almost every AD tool reports damage that already exists. `check` evaluates a **proposed** change (a ticket, a script, a pull
request) against your latest collection and says, before it ships, who would gain a route to Domain Admin, with the exact path
and which existing weakness to fix first so the change becomes safe. It exits non-zero when the answer is "don't".

```
Verdict  : BLOCK - 1 blocking finding (1 critical)

#1  add jsmith to group BACKUP OPERATORS   [BLOCK]
    [critical] Tier 0 promotion: JSMITH would become Tier 0
      path : JSMITH -[MemberOf]-> BACKUP OPERATORS

#2  add kpatel to group HELPDESK   [REVIEW]
    [medium] Shorter path: Attack paths get shorter for 1 object
      path : KPATEL -[+MemberOf]-> HELPDESK -[WriteSPN]-> SVC_EXCHANGE
```

| Change source | How |
|---|---|
| a line, a file, JSON | `--change 'add-member alice HELPDESK'`, `--changes ad-changes/` |
| PowerShell | `--powershell deploy.ps1` (variables, loops, pipelines, splatting, ACL grants, delegation, GPO rights, baseline group expansion) |
| Terraform | `--terraform infra/` (HCL, or `terraform show -json` plans; `ad` and `azuread` providers) |
| Ansible | `--ansible playbooks/` (microsoft.ad / ansible.windows / community.windows, embedded PowerShell, vars and loops) |
| DSC | `--dsc configs/` (ActiveDirectoryDsc / PSDscResources) |

**Fix as code:** `pathcutter fix export.zip --pr -o ./pr` writes a branch-ready bundle - the remediation script, a `PR.md`
description with a per-fix safety table, a `fixes.changes` file that `pathcutter check --changes` re-verifies as a risk
*reduction*, and an `apply.sh` / `apply.ps1` that opens the PR with your own `gh` or `glab`. PathCutter never touches your
remote; the apply script does, and a human reviews and merges.

It understands what a plain graph cannot: **Deny ACEs** (identity-sensitive; collect them with `tools/Export-AdDenyAces.ps1`),
**time-bound JIT/PAM grants** (`ttl=4h`, `-MemberTimeToLive`), **declared compensating controls** (they lower severity, never hide,
always say "declared, not verified"), SDProp and revocation-lag notes, and governance: policy file, crown-jewel assets, waivers with
reason, approver and expiry. Outputs: terminal, HTML review page, Markdown for PR comments, SARIF, JSON. Exit codes:
`0` pass, `1` could not run, `2` blocked, `3` needs review. Guide: [docs/ad-change-gate.md](docs/ad-change-gate.md);
CI examples: [examples/github-actions](examples/github-actions).

## Reading a path: confidence, cost, coverage

Not every path deserves equal attention, and PathCutter says why for each one, without ever hiding an edge.

- **Confidence** (`evidence.py`) - every step is labelled high (read straight from the directory), medium (computed from
  collected settings, like DCSync from two replication rights or an AD CS escalation) or low (rests on an unverified
  assumption or a single sighting, like a one-collection session or unconstrained delegation that needs a coercion). A path
  is as strong as its weakest step; a finding takes the strongest of its paths, because an attacker picks the surest route.
- **Attacker cost** (`cost.py`) - fewest hops is not how an attacker chooses. Each attack step carries an **effort** (from
  its exploitability) and a **noise** level (from its detection difficulty); a path sums both, and is flagged *fragile* when
  a step needs an unverified precondition and *cross-plane* when it crosses between on-premises AD and the cloud. So a short
  but loud or fragile route is not mistaken for the easy one. The report shows "effort N . noise N" on every path.
- **Detection coverage** (`pathcutter coverage --telemetry FILE`) - from the log sources and rules you declare, each step is
  detected (data plus a rule), visible (data, no rule) or blind (no data); a path takes the best of its steps and the hop it
  would first alert on. The command also lists, greedily, which telemetry to switch on to light up the most blind paths.

## Assume breach: `pathcutter breach`

Every other view works inward from Tier 0. `breach --from OBJECT` starts from one object you name - a laptop, a service
account, a contractor - and works OUTWARD: its blast radius, which Tier 0 objects it can reach, and for each the cheapest
(least effort) and stealthiest (least noise) route, ranked for an `--profile opportunist | stealth | balanced` attacker.
Tier 0 reachable only past another Tier 0 is listed separately. Exit code 2 means the object can reach Tier 0, for gating.

```
Compromised      : MEDITRUST-DOCTO$  (Computer)
Tier 0 reachable : 28 of 40

  AZUREUSER  (User)   effort 5, noise 3, 1 step
      cheapest   : MEDITRUST-DOCTO$ -[HasSession]-> AZUREUSER
  (+27 further Tier 0 object(s) reachable only after owning one of the above)
```

(Real output from the MediTrust hybrid lab below: an internet-facing clinical workstation is one session hop from a Domain
Admin that is logged into it.)

## What it models

| Area | Covered |
|---|---|
| Active Directory | ACLs (allow and deny), nested groups, primary group, local admin / RDP / PSRemote / DCOM, sessions, GPO links, GPO-granted local-group rights and (with `tools/Export-AdGpoRights.ps1`) GPO user rights such as SeBackupPrivilege, delegation (unconstrained, constrained, RBCD), SID history, DCSync (both replication rights, also via two groups), shadow credentials, gMSA / LAPS reads, trusts, implicit Everyone / Authenticated Users membership |
| AD CS | ESC1, 2 (as a feeder of 3), 3, 4, 5, 6, 7, 9, 10, 13, 15 and golden certificate, derived from template, CA, NTAuth and DC registry data; ESC8, 11 and 16 once `tools/Export-AdCsRelay.ps1` has collected the CA relay settings |
| Microsoft Entra ID | users, groups, apps, service principals, directory roles, PIM eligibility **and its activation policy** (MFA / approval requirements, when AzureHound collected the role-management-policy assignments), ownership, password-reset and add-secret roles (also when scoped to an administrative unit or one object), dangerous Graph application permissions, the on-premises to cloud sync link, workload identity federation (CI/CD to cloud: the subject is parsed and rated, and a `*_cicd.json` sidecar adds the repo-to-app pipeline edge), Conditional Access coverage (in `audit`) |
| Azure | resource RBAC (subscriptions, resource groups, VMs, key vaults), the scope hierarchy, VM managed identities |
| Restrictions | Protected Users / "sensitive" accounts: delegation edges into hosts whose administrators are all protected are dropped, and `audit` says so |
| Tier 0 | the built-in list (by name **and** SID), domain objects, GPOs linked to the domain / DC OU, PKI trust anchors, published templates, Tier 0 Entra roles, plus your own crown jewels in the policy |
| Shadow Tier 0 | objects that take over domain controllers through their own product, not an AD ACL: software deployment (SCCM/MECM, WSUS, Tanium), backup, hypervisor, EDR console, PAM vault and directory-sync (Entra Connect / MSOL_) admins. Derived matches (DCSync / domain-object control) are certain; by-name matches are reported by `audit` and can be turned off with `analyze --no-shadow-tier0` (`shadow_tier0.py`) |

Not modeled, stated so nobody assumes otherwise: ESC14, the contents of custom Azure roles and Azure deny assignments (reported by `audit`
as unevaluated), whether MFA or PIM approval is really enforced at sign-in, network reachability, GPO content other than local groups and user rights.
NTLM relay (SMB / LDAP signing, WebClient) has an experimental derivation in `pathcutter/relay.py` that is **not applied**: against
BloodHound's own harnesses it over-reports, and no real collection available to this project carries the properties it needs.
**Collecting when EDR blocks SharpHound:** take a Sysinternals **AD Explorer** snapshot (Microsoft-signed, not flagged),
export it with `ADExplorerSnapshot.py -m Objects`, and PathCutter reads the NDJSON natively - parsing the security
descriptors into ACL edges itself. Add `tools/Export-AdLocalSessions.ps1` (plain PowerShell) for the local-admin and
session edges the LDAP snapshot lacks. Validated end to end on a live domain.

Entra and Azure support is checked against one real AzureHound collection (SpecterOps' PhantomCorp demo tenant, 12,879 objects) and, joined to their AD sample, the hybrid sync links. There is no independent oracle for it the way there is for AD: the tests assert known facts about that tenant, not BloodHound's own edge set.

## What is validated, and what still needs real data

| Area | Checked against | Status |
|---|---|---|
| AD graph, ACLs, groups, trusts, Tier 0 | BloodHound CE's computed edges (edge by edge), 4 public GOAD / SpecterOps collections, a differential fuzzer | strong |
| AD CS ESC1 / 3 / 4 / 6 / 9 / 10 / 13 / 15 | BloodHound's ADCS fixtures and independent re-derivation | good |
| Entra ID and Azure RBAC | one real AzureHound collection (SpecterOps' demo tenant); facts asserted, no independent oracle | partial |
| Hybrid AD + Entra, end to end | the MediTrust capstone lab: an AD Explorer snapshot of `meditrust.local` joined to a real `pcsedu.tech` tenant (875 nodes, 2,941 edges). `breach` found an ordinary clinical user two hops from Domain Admin (`JOHN.DOCTOR -[CanRDP]-> MEDITRUST-DOCTOR-PC -[HasSession]-> AZUREUSER`), the workstation one hop | real lab |
| ESC8 / 11 / 16, GPO user rights, Deny ACEs | PathCutter's own collectors, tested on synthetic data and in real PowerShell; never run on a live domain | unproven |
| NTLM relay, PIM enforcement, custom Azure roles, Conditional Access | no real data exists publicly | not applied or synthetic only |

If you can run a lab, [docs/test-data.md](docs/test-data.md) says exactly what to build and collect, and how to anonymise it first.

## Trusting the data

- `pathcutter doctor` inspects an export before you trust it: sessions and local groups collected on how many hosts, missing ACL / GPO /
  AD CS data, uncollected principals, unfiltered trusts, ESC8/11 blind spots, a single-moment session snapshot. Verdict: complete /
  usable with blind spots / not trustworthy. `--also` merges several collections (sessions record how often they were seen).
- `pathcutter anonymize` makes a shareable copy: salted pseudonyms for names, domains, SIDs and GUIDs, free text and password-like
  attributes dropped, file names replaced, built-in groups and Tier 0 markers kept. Property-tested to give identical attack paths.
- Validation: a rebuilt GOAD lab with hand-derived hop counts; three real GOAD collections and the SpecterOps sample; BloodHound CE's
  own test fixtures (ADCS and AD) as an edge-by-edge and Tier Zero oracle; a differential fuzzer; the PowerShell extractor against the
  real PowerShell parser. See [docs/validation.md](docs/validation.md) for what is proven and what is not.

## The analysis report

`pathcutter analyze --html` writes one self-contained file. It opens on what to do:

- **Executive summary** (one paragraph for leadership: grade, exposure, crown jewels reachable, top fixes) and, with
  `--crown-jewels`, a **Crown Jewels** card and a **risk-by-department (per-OU)** breakdown. The Overview **prints to PDF**
  cleanly (browser Print > Save as PDF becomes a one-page brief).
- **Fix these first**: the three best fixes, paths cut, safety. **Worst findings**: counts by severity and the top critical ones.
  **Can you trust this data?**: the collection verdict and its main gaps.
- Riskiest nodes, remediation with copy-paste commands and rollback notes, attack chains, defend (MITRE, log sources), **What If**
  (toggle fixes and watch the score), path explorer, and an interactive attack graph.
- Every path in the explorer carries a **confidence** badge (its weakest step) and an **attacker-cost** badge ("effort N . noise N",
  plus fragile / cross-plane flags); with `--telemetry` a **detection-coverage** card and a per-path detected / visible / blind badge.
- The graph is built for large environments: canvas rendering with viewport culling and a time-sliced layout (the page never stalls:
  worst main-thread block 15 ms on a 12,000-object domain), leaf users and computers collapse into labelled clusters, shapes and colours per
  type including CAs, templates, Entra and Azure objects, Tier 0 diamonds, shortest path between any two objects, on-graph fix simulation,
  search, edge filters, minimap, PNG export. Keys: `1`-`8` tabs, `/` search, `?` help.

## Scale

Measured on one laptop (`benchmarks/`): exposure over 1,000,000 objects about 4 s; a 10-change `check` on 1,000,000 objects about 20 s;
ingest of 1,000,000 objects about 22 s (peak memory about 2 GB); every command finishes in under 70 s at that size. `check` evaluates each
change in place on a journaled graph and updates only the states an edge touches, so cost follows the change, not the graph.

```bash
python -m pytest                                    # 16,000+ tests, about a minute
python tests/fuzz.py --seeds 1000000 --workers 8    # differential fuzzing: engine vs reference vs oracles
python benchmarks/bench_cli.py 1000000              # wall-clock of every command
```

## Deploy and run on a schedule

Three shapes, all offline: an analyst's machine (`pip install pathcutter`), a container
(`docker build -t pathcutter . && docker run --rm -v "$PWD/data:/data" pathcutter analyze /data/export.zip --html -o /data/report`,
non-root, reads the collection you mount and writes the report), and a scheduled job on a management server. `tools/nightly.ps1`
(Windows Task Scheduler) and `tools/nightly.sh` (cron / container) snapshot today's collection, write a dated report, and
diff it against the previous snapshot so you see what changed since the last run, with a retained history. Releases publish to
PyPI via Trusted Publishing (OIDC, no stored token). Full guide: [docs/deploy.md](docs/deploy.md).

## Extending

A new right is one entry in `pathcutter/data/rights.json`; a technique, rule or input is one function plus its test. Tests fail when
knowledge drifts between modules. See [docs/extending.md](docs/extending.md).

## Input formats

SharpHound legacy (v4) and BloodHound CE (v5, v6) JSON, ZIP or directory; **AD Explorer snapshots** (Sysinternals, exported to NDJSON by `ADExplorerSnapshot.py -m Objects`) read natively, for domains where EDR blocks SharpHound - including AD CS (ESC1/4/5/13/15 and golden certificate), trusts, LAPS and gMSA reads when the Configuration partition is in the snapshot (see [docs/collect-with-adexplorer.md](docs/collect-with-adexplorer.md)); AzureHound JSON; an optional `*_denies.json` from
`tools/Export-AdDenyAces.ps1`; an optional `*_adcsrelay.json` from `tools/Export-AdCsRelay.ps1`; an optional `*_gporights.json` from `tools/Export-AdGpoRights.ps1`; an optional `*_localsessions.json` from `tools/Export-AdLocalSessions.ps1` (local admins and sessions, to pair with an AD Explorer snapshot); an optional Conditional Access policy export (`Get-MgIdentityConditionalAccessPolicy`); an optional `*_cicd.json` from `tools/Export-GitHubActions.ps1` (the repositories and pushers behind workload identity federation).

## Layout

```
pathcutter/   ingest.py azure.py adcs.py derived.py   collectors -> graph, derived edges
              adexplorer.py                              AD Explorer NDJSON ingestion (EDR-blocked domains)
              exposure.py exposure_ref.py fastindex.py the engine and its executable specification
              pathfinder.py scoring.py choke.py          paths, risk score, minimum fix set
              shadow_tier0.py                            management-plane objects treated as Tier 0
              evidence.py cost.py coverage.py breach.py  confidence, attacker cost, detection coverage, assume-breach
              value.py prbundle.py cicd.py               crown jewels / business value; fix-as-code PRs; CI/CD-to-cloud
              changes.py impact.py policy.py extractors/   the change gate and its inputs
              hygiene.py toolkit.py detections.py          audit, doctor, anonymize, detect
              report.py graph_view.js                      the interactive report
docs/         ad-change-gate.md detections.md validation.md extending.md test-data.md
tests/ benchmarks/ tools/
```

## License

MIT. Test fixtures under `tests/data/real` and `tests/data/vendor` keep their own licenses (Unlicense, Apache-2.0); see the READMEs there.
