# AD change gate: `pathcutter check`

Find out what a proposed Active Directory change does to your attack paths **before it ships**.

Most AD security tooling is retrospective: you collect, you analyze, you find the damage that already
exists. `pathcutter check` runs the other way round. Give it your latest collection and the changes a
ticket, script or pull request wants to make, and it tells you which principals would gain a route to
Tier 0, which would get an easier one, and which existing weakness to fix first so the change becomes
safe. It exits non-zero when the answer is "do not apply this", so it works as a CI gate.

```
SharpHound ZIP --> pathcutter snapshot --> baseline.pcsnap          (nightly, by the security team)
                                                 |
 ad-changes/pr-42.changes  ----------------------+--> pathcutter check --> verdict + report + exit code
 deploy.ps1 (AD automation) ---------------------+                          PASS / REVIEW / BLOCK
```

## 60 seconds, no SharpHound data needed

```bash
pip install -e .
pathcutter demo --size medium -o ./demo --snapshot demo.pcsnap

pathcutter check --baseline demo.pcsnap \
  --change 'add-member jsmith "BACKUP OPERATORS"' \
  --change 'add-member kpatel HELPDESK' \
  --html review.html
```

The first change promotes `jsmith` into a Tier 0 group, so the verdict is **BLOCK** and the exit code is 2.
Open `review.html` for the review page.

## What it tells you

| Finding | Meaning |
|---|---|
| `TIER0_PROMOTION` | A principal becomes a member of a Tier 0 group (directly or through nesting). |
| `NEW_EXPOSURE` | Objects that could **not** reach Tier 0 now can, with the exact path and who is affected. |
| `PATH_SHORTENED` | Objects that already had a route now have a shorter, easier one. |
| `COMBINED_EFFECT` | Changes that look harmless alone open a route only when applied together. |
| `RISK_REDUCTION` | The change removes routes to Tier 0 (good news, shown with credit). |
| `UNMODELED` | Part of a script was recognised as an AD change but could not be modeled. It is never skipped silently. |
| `NOOP` | The change does nothing (already present, or nothing to remove). Usually a stale baseline or a typo. |

For every blocking exposure it also computes **"fix these first"**: the existing edges which, if removed,
break most of the new paths, with the PowerShell to do it and a safety rating. Apply those, re-run the
check, and the same change passes.

### Severity

| Finding | Severity |
|---|---|
| `TIER0_PROMOTION` | always critical |
| `NEW_EXPOSURE` | critical if an account reaches Tier 0 in 2 hops or fewer, or 100+ accounts are exposed; high if 4 hops or fewer, or 10+ accounts; otherwise medium. Groups-only (latent) exposure is medium. If every exposed account is disabled the severity drops one level (not below medium). |
| `COMBINED_EFFECT` | at least high |
| `PATH_SHORTENED` | medium; high if the new path is 2 hops or fewer and 10+ objects are affected |
| `UNMODELED` | medium |
| `NOOP` | low |
| `RISK_REDUCTION` | info |

### Verdict and exit codes

| Verdict | When | Exit code |
|---|---|---|
| `BLOCK` | an unwaived finding of a blocking kind at or above `block_severity`, or a blocking policy limit is exceeded | **2** |
| `REVIEW` | unwaived findings at or above `review_severity` that do not block, a stale baseline, or warnings | 3 with `--fail-on review`, else 0 |
| `PASS` | no new route to Tier 0 | 0 |

Exit code **1** always means the check could not run (bad syntax, unknown object, unreadable baseline or
policy). A change that cannot be resolved is never skipped: a gate that ignores what it cannot read gives
false assurance. `--fail-on never` always exits 0 for a verdict (input errors still exit 1), which is
useful for a pilot.

## Describing changes

Put changes in a `.changes` file (one per line, `#` starts a note), pass them with `--change`, use a JSON
file, or let PathCutter read the PowerShell your automation already runs.

```
add-member alice "DOMAIN ADMINS"          # CHG-20417 weekend duty
remove-member svc_backup HELPDESK
grant SUPPORT GenericWrite SVC_SCOM       # any edge type, case-insensitive
revoke bob WriteDacl "SERVER ADMINS"
local-admin DEVOPS SRV01
delegate WEBAPP DC01
rbcd WEB01$ SRV01
grant-dcsync mallory
session carol WS042
create user newhire                       # an object that is not in the baseline yet
add-member newhire HELPDESK
```

Objects are matched by SID, `NAME@DOMAIN`, short name, `DOMAIN\name`, or (for computers) short host name,
`HOST$` or FQDN, case-insensitively. Names are checked against the type each end of the edge allows, so
`add-member alice HELPDESK` picks the group even if a user is also called HELPDESK. An unknown name is an
error with suggestions; an ambiguous one lists the candidates. Use `--on-unresolved assume-new` to treat
unknown names as brand-new objects with no existing permissions.

`--changes` also accepts a directory (every `.changes`, `.chg`, `.changes.json`, `.ps1` inside, in order).

JSON form:

```json
{"changes": [
  {"op": "add", "source": "alice", "edge": "MemberOf", "target": "HELPDESK", "note": "CHG-1"},
  {"op": "create", "type": "user", "name": "newhire"}
]}
```

### PowerShell

`--powershell script.ps1` (or any `.ps1` given to `--changes`) extracts what the script would change.
Modeled: `Add/Remove-ADGroupMember`, `Add/Remove-ADPrincipalGroupMembership`, `Set-ADComputer
-PrincipalsAllowedToDelegateToAccount` (RBCD) and `net group ... /add`. Every statement is scanned, including
those after `;`, after `|`, and inside `if`/`foreach` blocks.

Anything recognised as an AD change that cannot be modeled becomes an `UNMODELED` finding with the file and
line: uses of variables or pipeline input (who is affected cannot be known), ACL edits (`Set-Acl`, `dsacls`),
unconstrained delegation, local group changes. Express those as explicit `grant`/`revoke` lines to have them
analyzed. Set `"fail_on_unmodeled": true` in the policy to make them block.

## Baselines

```bash
pathcutter snapshot sharphound.zip -o baseline.pcsnap      # parse once
pathcutter check --baseline baseline.pcsnap ...            # seconds, not minutes
```

`--baseline` also accepts a raw SharpHound ZIP or directory. A snapshot records where it came from, when it
was collected and a content hash; reports show the baseline's age and `max_baseline_age_days` in the policy
raises a note when it is stale. A result is only as current as the baseline, so refresh it on a schedule.

> **Treat baselines as secrets.** A `.pcsnap` contains your full AD topology and every attack edge in it.
> Keep it in an access-controlled artifact store, never in a repository or a public bucket. `*.pcsnap` is
> in this project's `.gitignore` for that reason.

## Policy

`--policy policy.json`. Unknown keys are rejected so typos cannot weaken the gate silently.

```json
{
  "block_severity": "high",
  "block_kinds": ["TIER0_PROMOTION", "NEW_EXPOSURE", "COMBINED_EFFECT"],
  "review_severity": "medium",
  "max_new_exposed_actors": 0,
  "max_score_increase": 5,
  "fail_on_unmodeled": false,
  "extra_tier0": ["SQL-PROD-ADMINS", "PKI-CA01"],
  "max_baseline_age_days": 14,
  "require_waiver_expiry": true,
  "waivers": []
}
```

| Key | Meaning |
|---|---|
| `block_severity` | Lowest severity that blocks, for the kinds in `block_kinds`. Default `high`. |
| `block_kinds` | Finding kinds that can block. Default promotion, new exposure, combined effect. |
| `review_severity` | Lowest severity that asks for a human decision. Default `medium`. |
| `max_new_exposed_actors` | Hard cap on user/computer accounts gaining a route to Tier 0, counted after waivers. |
| `max_score_increase` | Hard cap on the risk-score rise. Advisory when path enumeration was capped. |
| `fail_on_unmodeled` | Treat unmodeled script lines as blocking. |
| `extra_tier0` | Your crown jewels beyond the built-in list (names or SIDs). They count as Tier 0 for the whole analysis. |
| `max_baseline_age_days` | Note (non-blocking) when the baseline is older than this. |
| `require_waiver_expiry` | Reject any waiver without an `expires` date. |

### Waivers: accepted risk with a paper trail

```json
{"waivers": [{
  "id": "CHG-20417",
  "reason": "Backup duty rota approved by the CISO; compensating alert in SIEM rule 114",
  "approver": "j.doe",
  "expires": "2026-09-30",
  "source": "jsmith", "edge": "MemberOf", "target": "BACKUP OPERATORS",
  "kinds": ["TIER0_PROMOTION"]
}]}
```

`source`, `edge` and `target` are case-insensitive globs (default `*`) matched against what was written and
the resolved object names. A finding is waived only if **every** change involved is covered, so a combined
effect needs both. Waived findings stay visible in every report with the reason, approver and expiry. An
**expired waiver stops applying** the day after `expires`, the finding blocks again, and the report says why.
Thresholds (`max_*`) cannot be waived per finding; change the policy instead.

## CI

See [`examples/github-actions/ad-change-gate.yml`](../examples/github-actions/ad-change-gate.yml): it
checks every pull request that touches `ad-changes/`, posts the Markdown summary as a PR comment,
uploads SARIF so findings annotate the exact lines of the change file, attaches the HTML review page,
and fails the job on `BLOCK`. A companion workflow
([`refresh-baseline.yml`](../examples/github-actions/refresh-baseline.yml)) rebuilds the baseline on a schedule.

Any CI works: run `pathcutter check`, look at the exit code (0, 2, or 3 with `--fail-on review`), and
publish whichever of `--markdown`, `--sarif`, `--html`, `--json` you want.

## Security model of the gate

In a CI gate the author of the change is, by definition, the party being checked. PathCutter is built so
that author cannot talk their way past it:

- **Policy and waivers must come from a protected branch, not the PR.** A waiver in the PR's own policy
  file would let it approve itself. The example workflow checks the policy out from the base commit and
  only `ad-changes/` from the PR head. Require CODEOWNERS review on the policy file so waivers are a
  deliberate, approved act.
- **Change notes (`# ...`) are display-only.** They never affect a verdict.
- **Nothing is skipped silently.** Unknown objects, ambiguous names and unmodeled script lines are errors
  or findings, not passes.
- **Every output neutralises attacker-controlled text.** Object names and notes are HTML-escaped in the
  review page, escaped in Markdown (no links, images, HTML or `@mentions` in the PR comment), and carried as
  data in JSON/SARIF.
- **Input is bounded.** Change files over 2 MB or more than 5000 changes are rejected.
- **PathCutter never executes change files.** The PowerShell extractor is a text parser; scripts are not run.
- The baseline is sensitive; protect it like the AD data it describes.

## Outputs

| Flag | Output |
|---|---|
| (default) | ASCII text report on stdout (`-q` to silence) |
| `--html FILE` | Self-contained review page: verdict, score before/after, per-change cards, path diagrams with the new edge highlighted, who is affected, fix-first commands, waivers, limitations. Works offline, prints cleanly, attachable to a ticket. |
| `--json FILE` | Full machine-readable result, schema `pathcutter.check/1` |
| `--markdown FILE` | Compact PR comment |
| `--sarif FILE` | SARIF 2.1.0 for code-scanning annotations; waived findings use native SARIF suppressions |

## How it decides (and what it does not know)

- **Exact, not sampled.** Whether an object can reach Tier 0 is computed by a reverse search from Tier 0
  that never enumerates paths, so it is unaffected by the path cap that limits path *counting* on large
  graphs. A route counts when it contains at least one attack edge (not only `MemberOf`/`Contains`).
- **Tiers are recomputed** the same way for the baseline and the modified graph, so group changes correctly
  promote and demote principals.
- **Final state wins.** Each change is also evaluated alone for attribution, but the verdict reflects the
  combined result: a risky change that another change in the set cancels is reported as cancelled, not as a
  blocker. Effects that exist only in combination are reported separately.
- **Capped enumeration is labelled.** When path counts are capped, add/remove counts are not shown and the
  score is marked approximate; exposure results stay exact.

Not modeled: deny ACEs, conditional access, PAM/JIT elevation, Kerberos delegation configured outside the
collected data, replication delay, and anything SharpHound did not collect. A path means an attacker who
controls the starting object could reach Tier 0 by abusing the listed edges; it does not prove an exploit
exists in your environment.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `target 'X' not found in the baseline` | Typo, or a new object. Use the suggestion, `create`, or `--on-unresolved assume-new`. |
| `NOOP: already present` / `not present in the baseline` | The baseline is stale, or the change was already applied. |
| `The baseline has no Tier 0 objects` | Incomplete collection; nothing can be exposed. Re-collect. |
| `Path enumeration hit the ... cap` | Large graph; exposure is still exact. Raise `--max-paths` if you need path counts. |
| Exit code 1 | The check did not run; read the `[!]` lines on stderr. |
