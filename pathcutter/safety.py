"""Fix safety analysis - identifies which remediation actions might break production.

Before blindly removing ACLs, check:
- Is the source a service account? (might need that permission to function)
- Is the source account actively used? (recent logon timestamp)
- Is the target a production server? (removing admin access could break monitoring)
- Is this a known AD functional dependency? (Exchange, SCCM, ADConnect)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .graph import AttackGraph, NodeType
from .choke import Fix


class RiskLevel(Enum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"


@dataclass
class SafetyAssessment:
    """Safety assessment for a single fix."""
    fix: Fix
    risk_level: RiskLevel
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return self.risk_level == RiskLevel.SAFE

    @property
    def summary(self) -> str:
        if self.is_safe:
            return "Safe to apply"
        return "; ".join(self.warnings)


KNOWN_SERVICE_PREFIXES = frozenset({
    "SVC_", "SA_", "SVCACCOUNT", "SERVICE",
    "MSOL_", "AZUREADSSOACC", "ADCONNECT",
    "EXCHANGE", "EXCH_", "HEALTHMAILBOX",
    "SCCM", "CM_", "SMSWRITER",
    "KRBTGT", "AZUREADSSOACC",
})

KNOWN_FUNCTIONAL_DEPENDENCIES = {
    "DCSync": {
        "patterns": ["MSOL_", "AZUREAD", "ADCONNECT"],
        "warning": "This account may be Azure AD Connect - removing DCSync rights will break hybrid identity sync",
    },
    "GenericAll": {
        "patterns": ["EXCHANGE", "EXCH_"],
        "warning": "Exchange service accounts often need broad permissions for mail flow",
    },
    "AdminTo": {
        "patterns": ["SCCM", "CM_", "SCCMADMIN"],
        "warning": "SCCM accounts need local admin for software deployment",
    },
}


def assess_fixes(graph: AttackGraph, fixes: list[Fix]) -> list[SafetyAssessment]:
    """Assess the safety of each proposed fix."""
    results = []
    for fix in fixes:
        assessment = _assess_single(graph, fix)
        results.append(assessment)
    return results


def _assess_single(graph: AttackGraph, fix: Fix) -> SafetyAssessment:
    warnings = []
    recommendations = []
    risk = RiskLevel.SAFE

    source_node = graph.get_node(fix.source_id)
    target_node = graph.get_node(fix.target_id)

    if source_node:
        # Check if source is a service account
        if _is_service_account(source_node.name):
            warnings.append(f"Source '{source_node.display_name}' appears to be a service account")
            recommendations.append("Verify this account's functional requirements before removing permissions")
            risk = RiskLevel.CAUTION

        # Check for known functional dependencies
        dep = KNOWN_FUNCTIONAL_DEPENDENCIES.get(fix.edge_type)
        if dep:
            for pattern in dep["patterns"]:
                if pattern.upper() in source_node.name.upper():
                    warnings.append(dep["warning"])
                    risk = RiskLevel.DANGEROUS
                    break

        # Check if source is enabled and actively used
        if not source_node.enabled:
            recommendations.append("Source account is DISABLED - safe to remove permissions")
            if risk == RiskLevel.CAUTION:
                risk = RiskLevel.SAFE

        # Check if source has admin_count flag
        if source_node.admin_count:
            warnings.append(f"Source has adminCount=1 (protected by AdminSDHolder)")
            recommendations.append("Check if this is an intentional administrative delegation")

    if target_node:
        # Check if target is a domain controller
        if target_node.node_type == NodeType.COMPUTER and target_node.tier == 0:
            warnings.append(f"Target '{target_node.display_name}' is a Tier 0 system")
            recommendations.append("Test in a lab environment first")
            if risk == RiskLevel.SAFE:
                risk = RiskLevel.CAUTION

        # Check if target is a critical group
        if target_node.name.upper().split("@")[0] in (
            "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
            "ADMINISTRATORS", "DOMAIN CONTROLLERS"
        ):
            recommendations.append("Changes to Tier 0 group ACLs require change management approval")

    # Specific edge type warnings
    if fix.edge_type == "MemberOf":
        warnings.append("Removing group membership may affect application access and GPO assignments")
        risk = max(risk, RiskLevel.CAUTION, key=lambda r: {"safe": 0, "caution": 1, "dangerous": 2}[r.value])

    if fix.edge_type in ("HasSession", "CanRDP", "CanPSRemote"):
        recommendations.append("Consider implementing Administrative Tier Model instead of per-machine fixes")

    return SafetyAssessment(
        fix=fix,
        risk_level=risk,
        warnings=warnings,
        recommendations=recommendations,
    )


def _is_service_account(name: str) -> bool:
    upper = name.upper().split("@")[0]
    for prefix in KNOWN_SERVICE_PREFIXES:
        if upper.startswith(prefix):
            return True
    if "$" in name:
        return True
    return False


def summarize_safety(assessments: list[SafetyAssessment]) -> dict:
    """Summary statistics for a batch of safety assessments."""
    safe = sum(1 for a in assessments if a.risk_level == RiskLevel.SAFE)
    caution = sum(1 for a in assessments if a.risk_level == RiskLevel.CAUTION)
    dangerous = sum(1 for a in assessments if a.risk_level == RiskLevel.DANGEROUS)
    return {
        "total": len(assessments),
        "safe": safe,
        "caution": caution,
        "dangerous": dangerous,
        "safe_pct": round(safe / len(assessments) * 100, 1) if assessments else 0,
    }
