# Changelog

## 0.5.0 (in progress)

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
- **`pathcutter audit`**: hygiene findings from collected attributes (Kerberoastable and AS-REP roastable accounts,
  passwords in descriptions and attributes, no-password accounts, stale privileged accounts, old krbtgt, unprotected
  Tier 0 accounts, SID history, orphaned adminCount, unconstrained delegation, protocol transition, unsupported OS,
  no LAPS, stale computers, old functional level, unfiltered trusts, AD CS and Everyone-like groups with dangerous rights).
- **Microsoft Entra ID and hybrid identity** from AzureHound output (`pathcutter/azure.py`).
- **AD CS**: ESC3, ESC5, golden certificate, ESC9 added to ESC1/4/6/7.
- `data/rights.json`: the single declarative source for collector rights, PowerShell GUIDs and dsacls letters; the
  collector script's GUID table is generated from it (`tools/gen_collector_table.py`).
- CI workflow (Linux and Windows, Python 3.11 and 3.13) and a nightly 1M-seed fuzz job.
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
