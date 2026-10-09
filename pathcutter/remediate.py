"""Remediation script generation - produces PowerShell scripts from chokepoint fixes."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .choke import ChokeReport, Fix
from .edges import get_edge_type, EdgeCategory


@dataclass
class RemediationPlan:
    """Complete remediation plan with grouped fixes and scripts."""
    fixes: list[Fix]
    total_paths: int
    paths_eliminated: int
    categories: dict[str, list[Fix]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def elimination_pct(self) -> float:
        if self.total_paths == 0:
            return 0.0
        return self.paths_eliminated / self.total_paths * 100

    def powershell_script(self, include_rollback: bool = True) -> str:
        lines = [
            "# Pathcutter Remediation Script",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"# Fixes: {len(self.fixes)} | Paths eliminated: {self.paths_eliminated}/{self.total_paths} ({self.elimination_pct:.0f}%)",
            "",
            "Import-Module ActiveDirectory",
            "",
        ]

        if self.warnings:
            lines.append("# ======================== WARNINGS ========================")
            for w in self.warnings:
                lines.append(f"# WARNING: {w}")
            lines.append("")

        for category, fixes in self.categories.items():
            lines.append(f"# ======================== {category.upper()} ========================")
            lines.append("")
            for fix in fixes:
                lines.append(f"# Fix #{fix.rank}: {fix.description}")
                # Machine-readable twin of this fix, so `pathcutter check --powershell` can verify the
                # script's effect before it is run.
                lines.append(f'# pc: revoke "{fix.source_name}" {fix.edge_type} "{fix.target_name}"')
                lines.append(f"# Impact: eliminates {fix.paths_eliminated} paths ({fix.cumulative_pct}% cumulative)")
                lines.append(f"# MITRE: {fix.mitre or 'N/A'}")
                lines.append("")
                lines.append(fix.fix_command)
                lines.append("")

        if include_rollback:
            rollback = self._rollback_section()
            if rollback:
                lines.append("")
                lines.append(rollback)

        return "\n".join(lines)

    def _rollback_section(self) -> str:
        lines = [
            "# ======================== ROLLBACK ========================",
            "# To revert changes, export ACLs BEFORE running fixes:",
            "#   $backup = @{}",
            '#   Get-ADObject -Filter * -SearchBase "DC=corp,DC=local" | ForEach-Object {',
            "#       $backup[$_.DistinguishedName] = Get-Acl \"AD:\\$($_.DistinguishedName)\"",
            "#   }",
            '#   $backup | Export-Clixml "acl_backup_$(Get-Date -Format yyyyMMdd).xml"',
            "#",
            "# To restore:",
            '#   $backup = Import-Clixml "acl_backup_YYYYMMDD.xml"',
            "#   foreach ($dn in $backup.Keys) {",
            '#       Set-Acl "AD:\\$dn" $backup[$dn]',
            "#   }",
        ]
        return "\n".join(lines)

    def markdown_summary(self) -> str:
        lines = [
            "# Remediation Plan",
            "",
            f"**Fixes:** {len(self.fixes)} | "
            f"**Paths eliminated:** {self.paths_eliminated}/{self.total_paths} ({self.elimination_pct:.0f}%)",
            "",
            "| # | Fix | Type | Paths Cut | Cumulative |",
            "|---|-----|------|-----------|------------|",
        ]
        for fix in self.fixes:
            lines.append(
                f"| {fix.rank} | {fix.source_name} -> {fix.target_name} | "
                f"{fix.edge_type} | {fix.paths_eliminated} | {fix.cumulative_pct}% |"
            )

        if self.warnings:
            lines.append("")
            lines.append("## Warnings")
            for w in self.warnings:
                lines.append(f"- {w}")

        return "\n".join(lines)


def build_plan(choke_report: ChokeReport, top_n: int | None = None) -> RemediationPlan:
    """Build a remediation plan from chokepoint analysis results."""
    fixes = choke_report.top(top_n) if top_n else choke_report.fixes
    if not fixes:
        return RemediationPlan(
            fixes=[], total_paths=choke_report.total_paths,
            paths_eliminated=0,
        )

    categories: dict[str, list[Fix]] = {}
    warnings: list[str] = []

    for fix in fixes:
        et = get_edge_type(fix.edge_type)
        if et:
            cat = _category_label(et.category)
            if not et.reversible:
                warnings.append(
                    f"Fix #{fix.rank} ({fix.description}) is NOT easily reversible"
                )
        else:
            cat = "Other"
        categories.setdefault(cat, []).append(fix)

    paths_eliminated = fixes[-1].cumulative_eliminated if fixes else 0

    return RemediationPlan(
        fixes=fixes,
        total_paths=choke_report.total_paths,
        paths_eliminated=paths_eliminated,
        categories=categories,
        warnings=warnings,
    )


def _category_label(cat: EdgeCategory) -> str:
    return {
        EdgeCategory.ACL: "ACL Cleanup",
        EdgeCategory.DELEGATION: "Delegation Fixes",
        EdgeCategory.GROUP: "Group Membership",
        EdgeCategory.SESSION: "Session / Access Control",
        EdgeCategory.DOMAIN: "Domain-Level Fixes",
        EdgeCategory.SPECIAL: "Special",
    }.get(cat, "Other")
