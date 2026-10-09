# Changelog

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
