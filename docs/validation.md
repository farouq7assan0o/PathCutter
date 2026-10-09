# How PathCutter's results are validated

A security gate that is wrong is worse than none, so the claims here are checked, not asserted. Everything below
is reproducible with `python -m pytest tests/` (15,000+ tests, under a minute). See also `docs/extending.md`.

## 1. Ground truth on a public, documented environment

`pathcutter demo --lab goad-sevenkingdoms` rebuilds the `sevenkingdoms.local` domain of
[GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD) as SharpHound JSON, from the
project's published lab definition: users, nested groups, the 12 documented ACLs (including the well-known chain
`tywin -> jaime -> joffrey -> tyron -> Small Council -> DragonStone -> KingsGuard -> stannis -> kingslanding$`),
the RDP and local-admin rights on the DC, an OU, AdminSDHolder, and a cross-domain group member.

*This is a reconstruction of the published definition, not a capture from a running lab, and it is not
affiliated with or endorsed by the GOAD project.* It still matters: it is a realistic environment whose paths
are known in advance and which our own generator did not invent.

`tests/test_proof_goad.py` loads it through the **real ingest** and checks 17 hop counts that were derived **by
hand** from the lab definition before looking at program output (for example `varys` 1 hop via GenericAll on
Domain Admins; `KingsGuard` 2; `DragonStone` 3; `tywin` 4; cross-domain `daenerys` 2). It also checks that nothing
is exposed that the hand derivation did not predict.

Two findings came out of it that are worth knowing:

* The famous 8-hop ACL chain is **not** `tywin`'s shortest route to Tier 0. `joffrey` is a Baratheon member and
  Baratheon has RDP to the DC, so the real shortest path is 4 hops. Revoking the documented `stannis` GenericAll on
  the DC does not secure `stannis`, for the same reason. The gate reports this correctly.
* Control of `AdminSDHolder` (which `lord.varys` has) is Tier 0 control, but the built-in Tier 0 list omitted it.
  Fixed, along with the domain-controller group variants.

## 2. An independent brute-force oracle

`tests/oracle.py` is a deliberately naive reference (plain DFS over simple paths) that shares no code with the
production engine (`pathcutter/exposure.py`).

* 600 random acyclic graphs: the engine matches the oracle **exactly** (same exposed set, same minimum hops).
* 1,500 dense random **cyclic** graphs: exact match too. This needed a fix the test found: a reverse search over
  *walks* reported 0.66% of exposures that had no real simple attack path (a cycle that only helped by looping
  back through itself). Those are now re-verified exactly; if the search budget runs out the object stays
  flagged (and is listed as unverified) rather than silently dropped.
* The path the engine returns for every exposed node is a real path made of edges that exist.

## 3. Properties the gate must always satisfy

Checked over hundreds of random graphs and changes each (`tests/test_proof_random.py`):

* the gate's totals equal the oracle's before/after diff (promoted, newly exposed, newly secured);
* the baseline is never modified;
* re-checking a change that has already been applied is a no-op;
* the result does not depend on the order of the changes;
* if the gate says its "fix first" suggestion breaks 100% of the new paths, applying exactly those edges to the
  baseline really leaves none of the flagged objects exposed by the same change;
* the gate never suggests undoing the change under review as its own fix.

## 4. The closed loop on PathCutter's own output

`pathcutter fix` generates a remediation script. `tests/test_remediation_roundtrip.py` feeds it back through
`check --powershell` and verifies that its predicted effect equals applying the fixes directly (checked with the
oracle), and that every ACL fix template PathCutter can emit is parsed to the right revoke. This also found that
the generic template removes all of a principal's access entries on the object, which the gate now reports.

## 5. Security of the gate itself

The author of a change is the party being checked. Tests cover: HTML escaping and `</script>` neutralisation in
the review page (verified by mutation: disabling the escaping makes the tests fail), Markdown neutralisation of
links, images and `@mentions` in PR comments, strict quoting in all generated detection languages, bounded
input sizes, and that policy and waivers must come from a protected branch (see the CI example).

## 6. Real collector output

`tests/data/real/` holds output of real SharpHound runs against public labs (three GOAD domains, the SpecterOps
BloodHound sample data; attribution in the README there). Running them through the ingest found and fixed seven
real bugs that the synthetic generator could never have revealed (see CHANGELOG 0.4.0). They are now regression
tests: nothing loads untyped, ADCS and shadow-credential rights survive, session and GPO-link directions are
right, DCs are Tier 0, and the real SEVENKINGDOMS run agrees hop-for-hop with the independently hand-built lab
model on every shared object.

`tests/test_ps_ast.py` runs the PowerShell extractor next to the real PowerShell parser: nothing is reported
where the real AST sees no call, and no real call to a cmdlet we claim to understand produces nothing.

Deny ACEs are proven against a forward brute-force oracle with identity tracking
(`tests/test_deny.py`, 1,500 random graphs).

## 7. Scale and equivalence

* `exposure_ref.py` (the original engine) is the executable specification. The production engine, the incremental updates for added
  and removed edges, the identity-sensitive deny search and the in-place probe are fuzzed against it and against brute-force
  oracles: `python tests/fuzz.py --seeds 1000000` (about 3,000 graphs per second per machine). The fuzzer found two real bugs in the
  incremental update on its first run (a walk-only verdict that goes stale when an edge is added); both are fixed and pinned as
  regression seeds.
* Measured on one laptop (`benchmarks/`): exposure over 1,000,000 objects about 4 s; a 10-change `check` on 1,000,000 objects about
  20 s (was 58 s), on 200,000 objects 3.8 s (was 38 s); ingest of 1,000,000 objects about 22 s, peak memory about 2 GB.

## 8. New model areas and how each is checked

* AD CS (ESC1, 3, 4, 5, 6, 7, 9, 15, golden certificate): every condition has a test that removes it and expects no edge; the real
  SpecterOps collection, which contains deliberately vulnerable templates, is re-derived independently from the raw JSON.
* Entra ID / Azure RBAC / Graph application permissions: built from the AzureHound source models, then run against a real AzureHound
  collection (SpecterOps' PhantomCorp demo tenant: 230 users, 6,000+ applications, 116 roles, 3 subscriptions, VMs, function / web apps)
  and, with their AD sample, the 9 hybrid sync links. Running it found: compute resources with managed identities were missing,
  role capabilities were hard-coded instead of read from the role definition, the Overview asked an Entra export for domain
  controllers, "remove AZRunsAs" was offered as a fix, and the anonymizer broke Graph permission and built-in role ids. All fixed and
  pinned in `tests/test_entra_real.py`. There is no independent oracle for Entra the way there is for AD, so those tests assert known
  facts about the tenant (for example a role scoped to one service principal reaches only that object), not BloodHound's edge set.
* Conditional Access: evaluated per identity (users, groups, roles, nesting, MFA, authentication strength, state); conditions that are
  not evaluated make a policy count as *not* covering, so coverage is never over-stated.
* Infrastructure-as-code extractors (Terraform HCL and plan JSON, Ansible, DSC): fixtures in `tests/data/iac/` and end-to-end `check`
  runs against the real SEVENKINGDOMS collection.

## What is NOT validated

* Production exports. Real collector output from public labs IS tested (section 6), but no export from a real
  production directory was available: those are not public. Run `pathcutter doctor` on yours first, and use
  `pathcutter anonymize` if you want to share one for a bug report.
* A live running AD. The generated detections are tested for validity and consistency, not run against live
  event streams (use each rule's `test_command` in your own lab), and `Export-AdDenyAces.ps1` is tested offline
  (its right mapping and descriptor parsing in real PowerShell) but has not been pointed at a live domain.
* Whether MFA / PIM approval is really enforced at sign-in is not known to PathCutter (Conditional Access is evaluated and reported by
  `audit`; declared controls only lower severity); Protected Users and authentication silos are reported, not modeled as graph
  restrictions; replication delay and network reachability are not modeled. See `pathcutter syntax model`.
* Entra ID, Azure RBAC and Graph application permissions have been run on one public demo tenant only: no real production tenant, no
  Conditional Access export, no administrative-unit data (the sample has none).

## Performance (measured, one laptop)

| Operation | Environment | Time |
|---|---|---|
| `check`, 3 changes | 12,158 objects, 19,455 edges | 2.1 s |
| `detect`, assume 5 fixes | 12,158 objects | 1.5 s |
| baseline snapshot load | 12,158 objects | under 1 s |
