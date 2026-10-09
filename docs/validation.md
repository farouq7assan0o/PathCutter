# How PathCutter's results are validated

A security gate that is wrong is worse than none, so the claims here are checked, not asserted. Everything below
is reproducible with `python -m pytest tests/` (3,500+ tests, about 10 seconds).

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

## What is NOT validated

* Production exports. Real collector output from public labs IS tested (section 6), but no export from a real
  production directory was available: those are not public. Run `pathcutter doctor` on yours first, and use
  `pathcutter anonymize` if you want to share one for a bug report.
* A live running AD. The generated detections are tested for validity and consistency, not run against live
  event streams (use each rule's `test_command` in your own lab), and `Export-AdDenyAces.ps1` is tested offline
  (its right mapping and descriptor parsing in real PowerShell) but has not been pointed at a live domain.
* Conditional Access, MFA and PIM enforcement are not modeled (they can be declared as controls, which only lower
  severity); Protected Users, authentication silos and replication delay are not modeled. See
  `pathcutter syntax model`.

## Performance (measured, one laptop)

| Operation | Environment | Time |
|---|---|---|
| `check`, 3 changes | 12,158 objects, 19,455 edges | 2.1 s |
| `detect`, assume 5 fixes | 12,158 objects | 1.5 s |
| baseline snapshot load | 12,158 objects | under 1 s |
