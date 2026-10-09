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

## What is NOT validated

* Real SharpHound/BloodHound CE exports from production AD: none were available here. The ingest handles the
  v4 and CE shapes, but if your collector emits something unusual the safest check is
  `pathcutter analyze` on it first.
* A real running AD lab. The generated detections are tested for validity and consistency, not run against live
  event streams: use each rule's `test_command` in your own lab.
* Deny ACEs, conditional access, PAM/JIT elevation and replication delay are outside the model.

## Performance (measured, one laptop)

| Operation | Environment | Time |
|---|---|---|
| `check`, 3 changes | 12,158 objects, 19,455 edges | 2.1 s |
| `detect`, assume 5 fixes | 12,158 objects | 1.5 s |
| baseline snapshot load | 12,158 objects | under 1 s |
