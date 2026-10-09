# Changelog

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
