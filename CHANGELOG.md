# Changelog

## 0.7.0

### Added
- **Operationalisation** (`trend.py`, `acceptance.py`): posture over time and risk governance, so PathCutter is a
  continuous programme, not a point-in-time scan. `analyze --history posture.jsonl` appends one aggregate record per run
  (score, Tier 0 exposure, paths, crown jewels reachable, audit counts - no object names) and prints movement since the
  last run, which also lands in the HTML executive summary; `pathcutter trend posture.jsonl` renders the series with
  deltas and a sparkline. Audit findings carry a severity-based remediation **SLA** window (critical now / high 7d /
  medium 30d / low 90d). `audit --accept accepted.json` is a **risk-acceptance** workflow: an accepted finding (rule,
  optional object, reason, owner, expiry) is labelled and excluded from `--fail-on` until it expires, then resurfaces.
- **Modern BloodHound CE edges** (SharpHound v6/v7): PathCutter now ingests edges that current collections emit but it
  previously dropped, so paths are no longer silently under-reported - `CoerceToTGT` (unconstrained delegation: coerce a
  privileged computer or DC and capture its TGT), `WriteOwnerLimitedRights` / `OwnsLimitedRights` (owner control limited
  by an OWNER RIGHTS ACE), and the v7.4 trust split: `SameForestTrust` (traversable, mapped to the existing trust edge),
  `SpoofSIDHistory` and `AbuseTGTDelegation` (traversable cross-forest attack edges), and `CrossForestTrust` (the trust
  fact, recorded but non-traversable on its own). Each new edge has registry metadata, confidence labels and cost.
- **More from SharpHound** (`audit`): three hygiene findings from data SharpHound collects but PathCutter was not using -
  a non-zero **machine account quota** (`ms-DS-MachineAccountQuota`; any authenticated user can add computer accounts, a
  prerequisite for RBCD and shadow-credential attacks), **weak Kerberos encryption** (accounts allowing RC4/DES but not
  AES, with krbtgt and Tier 0 escalated; reads SharpHound's `supportedencryptiontypes` label list or a raw bitmask), and
  **Tier 0 credentials exposed on a lower-tier host** (a Domain-Admin-class session on a non-Tier-0 computer - the most
  common real-world escalation). The AD Explorer ingester now also reads `ms-DS-MachineAccountQuota` and
  `msDS-SupportedEncryptionTypes`, so these fire on signed-tool snapshots too. All three verified on the real MediTrust
  collection.
- **CI/CD to cloud** (`cicd.py`): PathCutter parses an Entra federated credential's subject into structured trust
  (provider, repo, branch/environment, pull_request, wildcard), so `audit` can flag a `pull_request` subject (high: any
  contributor via a PR) and a repo with no branch/environment pin (medium) on top of the existing wildcard/outside-issuer
  findings. An optional `*_cicd.json` sidecar (one entry per repository, optionally who can push; `tools/Export-GitHubActions.ps1`
  generates it from `gh`) adds a CI/CD source node with an edge to each application the repo can authenticate as, so the
  attack path reaches from the pipeline into the cloud. GitHub/ADO identities only connect to a pusher when their id maps
  to a collected object; unmapped logins are counted, never invented.
- **PIM activation policy** (Entra Privileged Identity Management): when AzureHound collected the role-management-policy
  assignments (`AZRoleManagementPolicyAssignment`), PathCutter reads what end-user activation of an eligible role
  requires and turns the `AZEligibleRole` edge from an assumption into a verdict - approval required -> low confidence
  and fragile; MFA but no approval -> medium; neither -> high (effectively a standing assignment). New `audit` findings
  flag roles activatable with no MFA/approval (high) or no approval (medium). Without the policy data the edge keeps its
  old low-confidence label.
- **Fix as code** (`prbundle.py`, `pathcutter fix --pr`): write a pull-request-ready remediation bundle instead of a bare
  script - `remediation.ps1`, `PR.md` (description with a per-fix safety table), `fixes.changes` (the fixes as change
  lines, so `pathcutter check --changes fixes.changes` confirms they REMOVE exposure), and `apply.sh` / `apply.ps1` that
  create the branch and open the PR with the reviewer's own `gh` (GitHub) or `glab` (GitLab, `--pr-platform gitlab`).
  PathCutter stays offline and never touches the git remote; the apply script does, with the reviewer's credentials, and
  a human merges. Change-line direction follows each edge's grammar (e.g. HasSession reverses), and a fix the DSL cannot
  express is written as a comment and confirmed by re-collection.
- **Packaging and deployment**: full PyPI metadata (PEP 639 SPDX license, classifiers, project URLs, readme) so
  `pip install pathcutter` works; a non-root **Dockerfile** and `.dockerignore`; a **release workflow** that publishes to
  PyPI via Trusted Publishing (OIDC, no stored token) on a version tag; and **scheduled-run scripts** `tools/nightly.ps1`
  (Windows Task Scheduler) and `tools/nightly.sh` (cron / container) that snapshot today's collection, write a dated
  report, and diff it against the previous snapshot with a retained history. `analyze`, `score`, `graph` and `diff` now
  also accept a `.pcsnap` snapshot, not only a raw export. New guide `docs/deploy.md`.
- **Crown jewels / business value** (`value.py`, `analyze --crown-jewels FILE`): name the assets whose compromise is a
  crisis even when it is not domain takeover (student records, finance ERP, research servers), by name/id or by OU, each
  with a value (critical/high/medium) and a label. They become targets and the report ranks who can reach each one by
  the cheapest route. PathCutter never invents value - an asset counts only because you declared it.
- **Leadership reporting**: the HTML report now opens with an **executive summary** (grade, exposure, crown jewels
  reachable, top fixes in one paragraph), a **Crown Jewels** card, and a **risk-by-department (per-OU)** breakdown, and
  it **prints cleanly to PDF** (a `@media print` stylesheet turns the Overview into a one-page brief; no new dependency).
- **AD Explorer snapshots now read the Configuration partition and more** (`adexplorer.py`): when the snapshot includes
  the Configuration NC, PathCutter reads AD Certificate Services objects (certificate templates, enterprise CAs, the
  NTAuth store, issuance policies) and derives the escalations determined by the directory alone - ESC1, ESC4, ESC5,
  ESC15, ESC13 and golden certificate - from a Microsoft-signed collection, no SharpHound needed. `trustedDomain`
  objects become trust edges (direction, transitivity, SID filtering from `trustAttributes`); `msDS-GroupMSAMembership`
  becomes `ReadGMSAPassword`; a targeted read of a LAPS password attribute (`ms-Mcs-AdmPwd` / `msLAPS-Password` /
  `msLAPS-EncryptedPassword`, the per-forest GUID resolved from the schema partition) becomes `ReadLAPSPassword`. What
  lives only in the CA/DC registry (EDITF SAN flag, ManageCA, enrollment-agent restrictions, strong-binding) stays off
  unless the matching sidecar is collected - never guessed. Sidecars (`*_denies.json`, `*_gporights.json`,
  `*_adcsrelay.json`, `*_localsessions.json`) are auto-merged when they sit in or beside the NDJSON folder. New guide:
  `docs/collect-with-adexplorer.md`.
- **Attacker cost model** (`cost.py`): every attack edge carries an effort (from its exploitability: higher = more work)
  and a noise level (from its detection difficulty: higher = easier to catch). A path sums both over its attack steps
  (structural MemberOf / Contains hops are free), and is flagged *fragile* when a step rests on an unverified precondition
  (coercion, PIM activation) and *cross-plane* when it crosses between on-premises AD and the cloud. `cheapest`,
  `stealthiest` and `rank(profile)` pick among routes; the HTML path explorer now shows "effort N . noise N" per path, so a
  short but loud or fragile route is not mistaken for the easy one.
- **Assume-breach mode** (`breach.py`, `pathcutter breach INPUT --from OBJECT`): starts from one compromised object and
  works OUTWARD (every other view works inward from Tier 0). Reports the blast radius, which Tier 0 objects are reachable,
  and for each the cheapest and stealthiest route (ranked by `--profile opportunist|stealth|balanced`). Tier 0 reachable
  only past another Tier 0 is listed separately. `--from` accepts an exact name, a short name or an object id (ambiguous
  names list the matches); exit code 2 means the object can reach Tier 0, for gating.
- **Native AD Explorer snapshot ingestion** (`adexplorer.py`): reads the NDJSON from `ADExplorerSnapshot.py -m Objects`,
  parsing the binary security descriptors into the same ACL edges SharpHound emits (GenericAll, WriteDacl, WriteOwner,
  AddMember, WriteSPN, ForceChangePassword, GetChanges/GetChangesAll, key-credential, RBCD, owner). This collects a real
  AD graph with a Microsoft-signed tool where EDR blocks SharpHound. Validated end to end on a live domain's snapshot.
- **Workload identity federation**, key vault access policies, scoped Entra roles, Azure compute resources, and the real
  AzureHound/Conditional Access validation from 0.6.0 (see below).

## 0.6.0

### Added
- **AD CS**: ESC8 and ESC11 (NTLM relay to CA web enrollment / RPC), ESC16 (CA without the security extension) from an
  optional `*_adcsrelay.json` written by `tools/Export-AdCsRelay.ps1`; ESC2 as a feeder of ESC3.
- **GPO user rights**: SeBackup / SeRestore / SeTakeOwnership / SeDebug / SeLoadDriver / SeTcb / SeCreateToken / SeSyncAgent
  from SYSVOL (`tools/Export-AdGpoRights.ps1`) become `GPOUserRight` edges to the computers the GPO applies to.
- **Restrictions** (`restrictions.py`): Protected Users and "sensitive" accounts remove delegation edges into hosts whose
  administrators are all protected. Recorded in the graph, listed by `audit`, noted by `check`.
- **Entra**: role assignments scoped to an administrative unit or one object reach only that scope instead of the whole
  tenant; unresolved units and unevaluated Azure role definitions are reported by `audit`.
- **`check` review page**: findings collapse (the worst start open), a "Fix first" line on each, Expand all, deferred rendering.
- **Validated on real Entra data** (SpecterOps' PhantomCorp AzureHound sample, added as a fixture). Fixes it drove: Azure compute resources
  (function / web apps, automation accounts, scale sets, AKS, logic apps) and their managed identities; role capabilities read from
  `allowedResourceActions` (custom roles, Partner Tier1 Support ...); `doctor` no longer asks an Entra-only export for domain controllers;
  structural links (`AZRunsAs`, `AZContains`) are never offered as fixes; the anonymizer keeps built-in role ids, Graph permission ids and
  "Microsoft Graph"; Entra ingest 3x faster.
- Key vault access policies are read (AZGetSecrets / AZGetKeys / AZGetCertificates), listed by `audit` and never walked; ESC14 is documented as
  subsumed by the GenericWrite edges already followed; the anonymizer test shares one copy per fixture.
- NTLM relay derivation (`relay.py`) is experimental and NOT applied when a collection loads: against BloodHound's own harnesses it
  over-reports (Protected Users, RestrictOutboundNTLM), which a strict xfail now records. The earlier "harness oracle" tests only read the
  harness JSON and were removed; the relay tests now build the harness graph, run the code and compare.
- **Workload identity federation** (`AZFederatedIdentityCredential` -> `AZAuthenticatesTo` edges, audit rules for wildcard subjects and
  external issuers), found missing on the first real tenant export and validated edge for edge against BloodHound's own fixture.
- **Attack graph**: a view switch (Attack paths only / + Context / Everything, remembered), a Move-nodes lock with pinned nodes
  (double-click releases), Re-layout, a collapsible legend, layout run only on what is drawn, the fit leaves room for the toolbar and
  the fix panel, search brings hidden objects into view. Links and nodes now carry an on-path flag.
- **Attack graph, for big estates**: "Paths to / from" pickers (and right-click "Only paths to/from here") keep only the attack-path edges
  that reach a chosen Tier 0 object or start at a chosen object; Tier 0 groups' default rights over everything are hidden outside attack
  paths (the 2,871-edge hairball of a 3-VM lab became 617), objects left with no relevant edge are hidden and counted; dragging a node
  pins it (yellow ring), no longer fights the auto-fit, and "Drag: pan only" turns node moving off.
- Overview: the node-type chart groups the tail as "Other (n types)" and its card grows with the chart.
- **Confidence on every path** (`evidence.py`): each edge is observed (high), derived (medium) or assumed / thin (low), and a path or
  finding is labelled with its weakest step: the single-snapshot session behind the MediTrust headline path reads "low", an ESC15
  edge "assumes an unpatched CA". Shown in `analyze` (path explorer badge), `check` (text and HTML) and the JSON.
- **`pathcutter coverage`**: from a list of the log sources and rules you have, each path is detected / visible only / blind, with the
  hop at which it would first alert, the telemetry to switch on (greedy by blind paths made visible) and the edges that have data but no
  rule. `--assume-pack` counts the `detect` rules as deployed, `--assume-fixed N` evaluates only what is left after the top fixes,
  `--fail-on-blind` is a CI gate. `analyze --telemetry` adds a "Would you see it?" card and a status on each path.
- **Shadow Tier 0** (`shadow_tier0.py`): objects that can deploy code or read credentials to real Tier 0 are treated as Tier 0,
  so a path TO them counts. DERIVED (holds DCSync or control of the domain object) is certain; BY-NAME (SCCM, Veeam, VMware,
  Hyper-V, Defender console, CyberArk, Entra Connect / MSOL_ sync accounts, WSUS ...) is reported by `audit`, extendable in the
  policy and disabled with `analyze --no-shadow-tier0`. It only ever adds targets, so exposure can rise, never fall silently.
- Engine: 20,000 differential fuzz seeds clean after these changes; ingest at 200k objects unchanged (4.9 s).

## 0.5.0

### Added
- **Scale**: integer-indexed exposure engine (1M objects: 10.3s -> about 4s), copy-on-write `clone()` (17s -> 1s at 1M),
  in-place `probe()` with exact rollback for per-change trials, incremental exposure for added edges. A 10-change
  `check` on 200k objects went 38s -> 3.8s, on 1M objects 58s -> 21s. `benchmarks/` holds the scripts.
- The original engine is kept as `exposure_ref.py`, an executable specification. `tests/fuzz.py` runs parallel
  differential fuzzing (engine vs reference vs brute-force oracle, incremental vs full, deny oracle, probe rollback):
  3,000 graphs/s per machine, 400,000 clean; it found two real bugs in the incremental engine on its first run.
- **AD CS escalation edges** ADCSESC1, ESC4, ESC6, ESC7 derived from template, CA and NTAuth data, with every
  condition tested on its own and an independent re-derivation from the raw JSON of a real collection.
- **Implicit membership** of Everyone and Authenticated Users: ACEs granted to them are now rights everyone holds
  (previously invisible). The domain object itself is Tier 0.
- **Azure resource RBAC** (subscriptions, resource groups, VMs, key vaults; Owner / Contributor / User Access Administrator /
  VM login; scope hierarchy; VM managed identities) and **Entra Conditional Access evaluation** in `audit`; **`--also`** merges
  several collections (sessions record how often they were seen); AD CS ESC15.
- **Decremental exposure update** for removed edges (only the states whose route used them are re-attached): a `check` with removals
  costs no more than one with additions. Fuzzed against full recomputation (300,000 clean).
- **`pathcutter audit`**: hygiene findings from collected attributes (Kerberoastable and AS-REP roastable accounts,
  passwords in descriptions and attributes, no-password accounts, stale privileged accounts, old krbtgt, unprotected
  Tier 0 accounts, SID history, orphaned adminCount, unconstrained delegation, protocol transition, unsupported OS,
  no LAPS, stale computers, old functional level, unfiltered trusts, AD CS and Everyone-like groups with dangerous rights).
- **Infrastructure-as-code change sources** for `check`: `--terraform` (HCL configuration or `terraform show -json` plans;
  `ad` and `azuread` providers), `--ansible` (microsoft.ad / ansible.windows / community.windows modules, embedded
  PowerShell, variables and loops), `--dsc` (ActiveDirectoryDsc / PSDscResources). New sources are one entry in
  `extractors.EXTRACTORS`. Anything it cannot evaluate (count/for_each, unresolved variables, inventory groups, roles) is
  reported by name, never skipped.
- **Microsoft Entra ID and hybrid identity** from AzureHound output (`pathcutter/azure.py`).
- **AD CS**: ESC3, ESC5, golden certificate, ESC9 added to ESC1/4/6/7.
- `data/rights.json`: the single declarative source for collector rights, PowerShell GUIDs and dsacls letters; the
  collector script's GUID table is generated from it (`tools/gen_collector_table.py`).
- CI workflow (Linux and Windows, Python 3.11 and 3.13) and a nightly 1M-seed fuzz job.
- Path enumeration (`analyze`, chokepoint ranking) now stops at the first Tier 0 target instead of crossing it, so fix
  recommendations no longer point at edges that leave Tier 0 groups; on the SpecterOps sample the top fix is now
  `EVERYONE -> T1_FABIAN` (2,781 paths), visible only because Everyone is now connected to every user.
- **Validated against BloodHound itself**: SpecterOps' own CE test fixture (raw collector output plus the edges and Tier Zero tags
  BloodHound computed) is vendored as an oracle (`tests/data/vendor`). Our ESC1 edges and Tier Zero set agree with it. That comparison
  showed us missing Tier Zero members, now added: DnsAdmins, Cryptographic Operators, Distributed COM Users, Performance Log Users,
  Incoming Forest Trust Builders, GPOs linked to the domain or the Domain Controllers OU, the PKI trust anchors (CAs, NTAuth store),
  and published certificate templates. Rights that only feed a derivation (Enroll, ManageCA, ...) are no longer walkable edges, so
  enrolling in a template is not control of it; golden certificate is now host -> domain like BloodHound's. Added ESC13 (issuance
  policy linked to a group).
- **A second BloodHound oracle (AD edges)**: SpecterOps' version 5 and 6 fixtures (raw output plus every edge BloodHound computed)
  are compared with our ingest edge by edge (`tests/test_vendor_oracle.py`). It found and fixed: ACEs a principal holds on itself
  were kept; DCSync was drawn from either replication right instead of both (so a principal holding only Get-Changes looked able to
  read every hash), and a user who gets the two rights through two different groups was missed; sessions delivered in their own
  file were ignored; containment stated only on the child (`ContainedBy`) was ignored; SQL admin rights (`SpnTargets`) were
  ignored; trusts followed one direction regardless of `TrustDirection` and the partner domains were nameless. Built-in groups are
  now Tier 0 by SID as well as by name (renamed or localized groups, domain-prefixed ids). The anonymizer also leaked partner
  domain names that appear only inside a trust; fixed.
- The attack graph viewer draws the new objects (certificate authorities and templates, Entra identities, applications, roles, Azure resources) and edges (ADCSESC*, Entra, RBAC) with their own shapes, colours and legend entries.
- AD CS / DCSync derivations never expand a large group (1,000,000 objects, 300 templates: 0.4 s, was minutes).
- The real-data fixtures had been excluded from git by `*.zip` in `.gitignore`, so CI skipped those tests; they are tracked now.
- `tests/test_registry.py` fails when edge-type knowledge drifts between modules (ingest, PowerShell rules, collector).

## 0.4.0

### Added
- **`pathcutter doctor`**: inspects a SharpHound/BloodHound export before you trust it. Reports what the collection
  is missing (sessions, local groups, ACLs, GPOs, AD CS, trusts without SID filtering), names the collector flag that
  fixes each gap, and gives a verdict (complete / usable with blind spots / not trustworthy). `--strict`, `--json`.
- **`pathcutter anonymize`**: a shareable copy of your own export. Names, domains, domain SIDs and GUIDs become
  salted pseudonyms; RIDs, memberships, rights and flags are kept, so exposure results are identical. Free text,
  e-mail, paths and password-ish attributes are dropped; file names are replaced. Property-tested on real data.
- **Deny ACEs**, identity-sensitive: a deny binds the denied principal's token and only at the hop where that
  identity acts. Exposure runs over (node, attack-edge, deny-signature) and is proven equal to a brute-force
  forward oracle on 1,500 random graphs with random denies. Sources: `deny` / `undeny` in the change language,
  `dsacls /D` and Deny access rules in PowerShell, and `tools/Export-AdDenyAces.ps1` (read-only collector; SharpHound
  does not collect denies). Denies persist in `.pcsnap` snapshots.
- **Time-bound (JIT/PAM) grants**: `ttl=4h` in the change language, `-MemberTimeToLive` in PowerShell. Flagged as
  temporary; with `jit_max_minutes` in the policy the severity drops one step. The exposure window is never hidden.
- **Declared compensating controls** in the policy (Conditional Access, MFA, PIM, vaulting, tiering, ...): owner and
  evidence required, optional expiry, lowers severity by 1-2 steps with floors, never suppresses, always labeled
  "declared, not verified". Expired controls stop applying and are flagged.
- **SDProp** and **revocation-lag** notes on the changes they affect; trust direction, type, transitivity and SID
  filtering are recorded on trust edges.
- `pathcutter syntax model`: what is modeled, what is reported only, and what is not modeled at all.
- Real-data regression tests (`tests/data/real/`: three GOAD SharpHound collections, the SpecterOps sample) and a
  cross-check of the PowerShell extractor against the real PowerShell parser (`tests/test_ps_ast.py`).

### Fixed (found by running real collector output through the ingest)
- `AddKeyCredentialLink` (shadow credentials) ACEs were dropped; local admin / RDP / PSRemote / DCOM data in
  `LocalGroups` (keyed by RID) was ignored; session edges ran user -> computer instead of computer -> user;
  domain controllers whose group membership comes only from `PrimaryGroupSID` / `IsDC` were not Tier 0;
  AD CS objects (templates, CAs) were typed Unknown and their rights ignored; GPO links pointed the wrong way;
  principals only referenced by ACEs were nameless.
- A PowerShell call to a modeled cmdlet that has no modeled effect is now reported as a note instead of nothing.

## 0.3.0

### Added
- **`pathcutter detect`: detections for the attack paths you cannot fix.** Applies the top N fixes virtually,
  picks the residual choke points that cover the most remaining paths, and generates Sigma, Splunk SPL,
  Microsoft Sentinel KQL and Elastic KQL scoped to those exact objects, plus two always-on watches (Tier 0 group
  membership; membership of any group that can reach Tier 0). Every pack includes the audit-policy
  prerequisites, the principals who can abuse each edge, a lab test command and response steps.
  `check --detections DIR` ships compensating detections with the risk a change set accepts. See `docs/detections.md`.
- **PowerShell extraction rewritten** as a statement-level static analysis: variables, `foreach` and
  `ForEach-Object` expansion, pipelines, splatting, `Invoke-Command`, `#pc:` directives, baseline-aware
  `Get-ADGroupMember` expansion, ACL grants (`dsacls`, `ActiveDirectoryAccessRule` + `Set-Acl`, PowerView,
  `Add-ADPermission`), delegation (RBCD, unconstrained, constrained, UAC bit), gMSA, GPO rights and links,
  create/delete/move, local groups, `net`/`dsmod`. Every AD-modifying cmdlet is modeled or reported.
- Change language: selectors `@members(G)`, `@members*(G)`, `@dcs`; verbs `move`, `delete`, `unconstrained`,
  `revoke-all`; idempotent create for scripts; waivers for fan-out changes must cover every expanded member.
- **Closed-loop remediation check**: `pathcutter fix` scripts carry `# pc: revoke` twins, so
  `check --powershell remediation.ps1` predicts a fix script's exact effect before it runs.
- **Help system**: a guided `pathcutter -h`, examples on every command, `pathcutter syntax [topic]` generated from
  the live registries, `pathcutter help <command>`.
- `pathcutter demo --lab goad-sevenkingdoms`: GOAD's `sevenkingdoms.local` rebuilt as SharpHound JSON.
- `docs/validation.md`: ground truth on the GOAD lab, an independent brute-force oracle, randomized differential
  and metamorphic tests (3,500+ tests in total).

### Fixed
- Unconstrained-delegation edges were never created at ingest (the DC lookup matched computers by the Domain
  Controllers *group* RID); they are now resolved after all files load.
- Exposure analysis over cyclic graphs reported routes that exist only by looping through a node (0.66% of
  reported exposures on dense random graphs); these are now re-verified exactly.
- Tier 0 list now includes AdminSDHolder and the domain-controller group variants.
- Capped path enumeration no longer presents arbitrary path add/remove counts as results.

## 0.2.0

### Added
- **`pathcutter check`: AD change gate.** Evaluate proposed Active Directory changes against a baseline
  *before* they are applied. Reports Tier 0 promotions, newly exposed objects, shortened paths, effects that
  appear only when changes are combined, and risk reductions, with the exact attack path for each. Suggests
  which existing edges to fix first so a blocked change becomes safe. Exit codes for CI (0 pass, 1 input
  error, 2 blocked, 3 review). See `docs/ad-change-gate.md`.
- `pathcutter snapshot`: save a reusable, hashed baseline (`.pcsnap`) from a SharpHound export.
- Change input as a small DSL, JSON, or PowerShell extraction (group membership, RBCD, `net group`);
  anything recognised but not modeled is reported, never skipped.
- Policy file: severity thresholds, exposure and score limits, extra Tier 0 assets, baseline freshness,
  and waivers with reason, approver and expiry.
- Outputs: text, JSON, Markdown (PR comments), SARIF 2.1.0 (code-scanning annotations), and a self-contained
  HTML review page.
- Interactive HTML report: Canvas attack graph for large environments, shortest path to Tier 0, on-graph fix
  simulation, What If tab, Defend tab, HTML diff, keyboard shortcuts, path diagrams.
- `pathcutter export` for CI gating on score/exposure, `pathcutter demo` (with `--snapshot`), `--size huge`.

### Fixed
- `python -m pathcutter` discarded the exit code, so CI gates (including `export --fail-above`) always
  looked successful.
- HTML reports embedded AD object names without escaping; a name containing `</script>` or markup could
  execute in the reader's browser.

### Changed
- `find_chokepoints` accepts `exclude_edges`.
- `AttackGraph` gained `clone()`, `remove_edge()`, `has_edge_type()` and `retier()`.

## 0.1.0
- Initial release: ingest, attack paths, scoring, chokepoint analysis, remediation scripts, diff, HTML report.
