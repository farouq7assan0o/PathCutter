"""How much to trust each step of a path: where an edge came from and what it assumes.

A path is only as strong as its weakest step. Some edges are read straight from the directory (a group membership, an ACE),
some are computed by PathCutter from collected settings (an AD CS escalation, DCSync from two rights), and some rest on an
assumption nobody verified (a host trusted for unconstrained delegation can capture a DC ticket *if* the DC can be coerced
to authenticate). Reporting all of them with the same certainty over-states the second kind and the third.

Levels:
  high    observed: the relationship is in the collected data as it is
  medium  derived: computed from collected data; sound as long as the data is complete and current
  low     assumed or thin: relies on an unverified condition, or was seen only once

This is a property of the edge type plus the few facts stored on the edge, so it works on any graph, snapshot or change set.
It never changes whether an edge exists: it labels, it does not hide.
"""
from __future__ import annotations

LEVELS = ("low", "medium", "high")
_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# edge type -> (level, source, reason). Edge types not listed fall back to the collector default below.
_TABLE: dict[str, tuple[str, str, str]] = {
    # derived from template / CA / registry data
    "ADCSESC1": ("medium", "derived:adcs", "computed from template, CA and enrollment rights"),
    "ADCSESC3": ("medium", "derived:adcs", "computed from agent and target templates and enrollment rights"),
    "ADCSESC4": ("medium", "derived:adcs", "computed from control of a published template"),
    "ADCSESC5": ("medium", "derived:adcs", "computed from control of the NTAuth store or a CA object"),
    "ADCSESC6": ("medium", "derived:adcs", "computed from the CA's SAN flag, which was collected"),
    "ADCSESC7": ("medium", "derived:adcs", "computed from ManageCA / ManageCertificates"),
    "ADCSESC9": ("medium", "derived:adcs", "needs domain controller registry data (certificate binding)"),
    "ADCSESC10": ("medium", "derived:adcs", "needs domain controller registry data (certificate mapping)"),
    "ADCSESC13": ("medium", "derived:adcs", "computed from an issuance policy linked to a group"),
    "ADCSESC15": ("low", "assumption:unpatched-ca", "assumes the CA has not been patched for CVE-2024-49019"),
    "ADCSESC8": ("medium", "sidecar:adcsrelay", "from the web enrollment settings collected by Export-AdCsRelay.ps1; a DC must be coercible"),
    "ADCSESC11": ("medium", "sidecar:adcsrelay", "from the RPC settings collected by Export-AdCsRelay.ps1; a DC must be coercible"),
    "ADCSESC16": ("medium", "sidecar:adcsrelay", "from the CA policy module settings collected by Export-AdCsRelay.ps1"),
    "GoldenCert": ("medium", "derived:adcs", "administering the CA host exposes the CA key"),
    "DCSync": ("medium", "derived:replication-rights", "both replication rights are held (possibly through different groups)"),
    # cloud
    "SyncedTo": ("medium", "derived:entra-sync", "matched through the on-premises security identifier"),
    "AZResetPassword": ("medium", "derived:entra-role", "from the role's capability and its scope; Conditional Access is not evaluated"),
    "AZAddSecret": ("medium", "derived:entra-role", "from the role's capability and its scope"),
    "AZMGGrantRole": ("high", "collector:graph-permission", "an application permission that was granted"),
    "AZMGAddSecret": ("high", "collector:graph-permission", "an application permission that was granted"),
    "AZMGAddMember": ("high", "collector:graph-permission", "an application permission that was granted"),
    "AZMGResetPassword": ("high", "collector:graph-permission", "an application permission that was granted"),
    "AZEligibleRole": ("low", "assumption:pim-policy", "eligibility only: activation may need approval or MFA, and that policy was not collected"),
    "AZAuthenticatesTo": ("medium", "derived:federation", "holds only if the external issuer's token can be obtained for that subject"),
    "AZRunsAs": ("high", "collector:application", "an application and its service principal share an app id"),
    # on-premises derived or approximate
    "GPOUserRight": ("medium", "sidecar:gporights", "security filtering, WMI filters and enforcement are not evaluated: may over-report"),
    "GPOControlsObject": ("medium", "collector:gplink", "the link exists; security filtering and blocked inheritance are not evaluated"),
    "CoerceAndRelayNTLMToSMB": ("low", "assumption:coercion", "experimental derivation that over-reports against BloodHound's own harnesses"),
    "CoerceAndRelayNTLMToLDAP": ("low", "assumption:coercion", "experimental derivation that over-reports against BloodHound's own harnesses"),
    # key vault data plane is reported, never walked
    "AZGetSecrets": ("medium", "collector:keyvault", "an access policy entry; the vault's contents are unknown"),
    "AZGetKeys": ("medium", "collector:keyvault", "an access policy entry; the vault's contents are unknown"),
    "AZGetCertificates": ("medium", "collector:keyvault", "an access policy entry; the vault's contents are unknown"),
}

# a basis marker written onto an edge by the code that synthesised it (see ingest._link_unconstrained_delegation)
_BASIS: dict[str, tuple[str, str, str]] = {
    "unconstrained-delegation": ("low", "assumption:coercion",
                                 "a host trusted for unconstrained delegation captures a DC ticket only if the DC can be coerced to authenticate to it"),
}

_SESSION_TYPES = {"HasSession"}


def edge_confidence(edge_type: str, props: dict | None = None) -> tuple[str, str, str]:
    """(level, source, reason) for one edge."""
    props = props or {}
    basis = props.get("basis")
    if basis in _BASIS:
        return _BASIS[basis]
    if props.get("proposed"):
        return ("high", "proposed:change", "added by a proposed change")
    if edge_type in _SESSION_TYPES:
        seen = int(props.get("seen", 1) or 1)
        if seen >= 3:
            return ("high", "collector:sessions", f"seen in {seen} collections")
        if seen == 2:
            return ("medium", "collector:sessions", "seen in 2 collections")
        return ("low", "collector:sessions", "a session seen in one collection only: sessions are transient")
    if edge_type == "AZEligibleRole" and props.get("pim_collected"):
        # the PIM activation policy was collected (AzureHound AZRoleManagementPolicyAssignment): say what it enforces
        if props.get("pim_approval"):
            return ("low", "assumption:pim-approval", "activation requires approval, which may be denied")
        if props.get("pim_mfa"):
            return ("medium", "derived:pim-policy", "the eligible holder can activate after MFA (no approval)")
        return ("high", "derived:pim-policy", "activation requires neither MFA nor approval: effectively a standing assignment")
    if edge_type in _TABLE:
        return _TABLE[edge_type]
    return ("high", "collector:directory", "read directly from the collected directory data")


def weakest(steps: list[tuple[str, str, str]]) -> tuple[str, str, str, int] | None:
    """Weakest of a list of (edge_type, level, reason); returns (edge_type, level, reason, index) or None."""
    best = None
    for i, (et, lvl, why) in enumerate(steps):
        if best is None or _RANK[lvl] < _RANK[best[1]]:
            best = (et, lvl, why, i)
    return best


def path_confidence(edges: list[dict]) -> dict:
    """Confidence of a path given its edge data dicts (each with at least edge_type)."""
    steps = []
    for e in edges:
        et = e.get("edge_type") or e.get("edge") or "?"
        if et in ("MemberOf", "Contains", "AZContains"):
            continue                       # structure is not an attack step: it neither adds nor removes doubt
        lvl, src, why = edge_confidence(et, e)
        steps.append((et, lvl, why, src))
    if not steps:
        return {"level": "high", "edge": None, "reason": "", "sources": []}
    w = weakest([(s[0], s[1], s[2]) for s in steps])
    return {"level": w[1], "edge": w[0], "reason": w[2], "sources": sorted({s[3] for s in steps})}


def finding_confidence(paths: list[list[dict]]) -> dict:
    """Confidence of a finding: an attacker takes the most certain route, so the strongest path counts.

    `paths` are lists of step dicts as `impact._path_dicts` builds them (each step may carry `conf`)."""
    best = None
    for p in paths:
        steps = [(s.get("edge"), s["conf"]) for s in p if s.get("edge") and isinstance(s.get("conf"), dict)
                 and s.get("edge") not in ("MemberOf", "Contains", "AZContains")]
        if not steps:
            continue
        w = min(steps, key=lambda s: _RANK[s[1]["level"]])
        cand = {"level": w[1]["level"], "edge": w[0], "reason": w[1]["reason"], "sources": sorted({s[1]["source"] for s in steps})}
        if best is None or _RANK[cand["level"]] > _RANK[best["level"]]:
            best = cand
    return best or {"level": "high", "edge": None, "reason": "", "sources": []}


def label(c: dict) -> str:
    if c["level"] == "high" or not c.get("edge"):
        return c["level"]
    return f"{c['level']} (weakest: {c['edge']} - {c['reason']})"
