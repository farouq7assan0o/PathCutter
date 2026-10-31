"""Map each audit finding to the compliance controls it bears on, so regulated orgs (government, defence, healthcare,
universities) can read PathCutter in the language their auditors use.

Findings already carry a MITRE ATT&CK technique (the attacker view); this adds the defender/auditor view: which control
each finding fails against, across four widely-required frameworks. Identifiers are chosen to be stable: precise NIST
SP 800-53 Rev5 control IDs, CIS Controls v8 top-level controls (safeguard sub-numbers change between revisions, the
control numbers do not), ASD Essential Eight mitigation-strategy names, and a DISA STIG requirement THEME rather than a
version-specific V-ID (those move every quarterly release). Nothing here is a compliance attestation - it points an
auditor at the relevant control; the finding itself is the evidence.
"""
from __future__ import annotations

FRAMEWORK_NAMES = {
    "nist": "NIST SP 800-53 Rev5",
    "cis": "CIS Controls v8",
    "e8": "ASD Essential Eight",
    "stig": "DISA Windows/AD STIG (theme)",
}

# Essential Eight mitigation-strategy names (stable)
_ADMIN = "Restrict administrative privileges"
_MFA = "Multi-factor authentication"
_PATCH_OS = "Patch operating systems"
_UAH = "User application hardening"

# CIS Controls v8 top-level controls (stable numbers)
_CIS_SECCFG = "CIS v8 4: Secure Configuration"
_CIS_ACCT = "CIS v8 5: Account Management"
_CIS_ACCESS = "CIS v8 6: Access Control Management"
_CIS_DATA = "CIS v8 3: Data Protection"
_CIS_AUDIT = "CIS v8 8: Audit Log Management"

# finding rule-id -> {nist:[...], cis:[...], e8:[...], stig: "theme"}
MAP: dict[str, dict] = {
    "kerberoast": {"nist": ["IA-5", "IA-5(1)"], "cis": [_CIS_ACCT], "e8": [], "stig": "service accounts: long random password, AES only"},
    "kerberoast-privileged": {"nist": ["IA-5", "IA-5(1)", "AC-6(5)"], "cis": [_CIS_ACCT, _CIS_ACCESS], "e8": [_ADMIN], "stig": "privileged service accounts: gMSA / AES only"},
    "asrep": {"nist": ["IA-2", "IA-5"], "cis": [_CIS_ACCT], "e8": [], "stig": "Kerberos pre-authentication required"},
    "asrep-privileged": {"nist": ["IA-2", "IA-5", "AC-6(5)"], "cis": [_CIS_ACCT], "e8": [_ADMIN], "stig": "Kerberos pre-authentication required"},
    "passwd-notreqd": {"nist": ["IA-5", "IA-5(1)"], "cis": [_CIS_ACCT], "e8": [], "stig": "password required on all accounts"},
    "priv-pwd-never-expires": {"nist": ["IA-5", "IA-5(1)", "AC-6(5)"], "cis": [_CIS_ACCT], "e8": [_ADMIN], "stig": "privileged password rotation"},
    "pwd-in-description": {"nist": ["IA-5", "SC-28"], "cis": [_CIS_DATA], "e8": [], "stig": "no clear-text credentials in attributes"},
    "pwd-attributes": {"nist": ["IA-5", "SC-28"], "cis": [_CIS_DATA], "e8": [], "stig": "no credential material in directory attributes"},
    "stale-privileged": {"nist": ["AC-2", "AC-2(3)"], "cis": [_CIS_ACCT], "e8": [_ADMIN], "stig": "disable inactive privileged accounts"},
    "stale-computers": {"nist": ["AC-2", "AC-2(3)"], "cis": [_CIS_ACCT], "e8": [], "stig": "remove inactive computer accounts"},
    "krbtgt-old": {"nist": ["IA-5"], "cis": [_CIS_ACCT], "e8": [], "stig": "krbtgt password reset cadence"},
    "machine-account-quota": {"nist": ["AC-6", "CM-6"], "cis": [_CIS_SECCFG, _CIS_ACCESS], "e8": [_ADMIN], "stig": "ms-DS-MachineAccountQuota = 0"},
    "weak-kerberos-enc": {"nist": ["SC-13", "IA-7"], "cis": [_CIS_SECCFG], "e8": [], "stig": "enforce AES Kerberos encryption"},
    "weak-kerberos-enc-spn": {"nist": ["SC-13", "IA-7"], "cis": [_CIS_SECCFG], "e8": [], "stig": "enforce AES Kerberos encryption"},
    "weak-kerberos-enc-privileged": {"nist": ["SC-13", "IA-7", "AC-6(5)"], "cis": [_CIS_SECCFG], "e8": [_ADMIN], "stig": "enforce AES on krbtgt and Tier 0"},
    "tier0-exposed-on-lower-tier": {"nist": ["AC-6", "AC-6(5)", "AC-5", "AC-17"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "tiered administration: deny Tier 0 logon to lower tiers"},
    "recent-privileged-object": {"nist": ["AC-2", "SI-4"], "cis": [_CIS_ACCT], "e8": [_ADMIN], "stig": "review privileged account creation"},
    "priv-not-protected": {"nist": ["AC-6(5)", "IA-5"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "Protected Users / sensitive, cannot be delegated"},
    "sid-history": {"nist": ["AC-6", "AC-4"], "cis": [_CIS_ACCESS], "e8": [], "stig": "review and remove SID history"},
    "admincount-orphan": {"nist": ["AC-6", "AC-6(7)"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "re-enable inheritance on orphaned adminCount objects"},
    "adminsdholder-nonpriv": {"nist": ["AC-6", "AC-6(5)"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "restrict AdminSDHolder ACL"},
    "unconstrained-delegation": {"nist": ["AC-6", "IA-5"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "no unconstrained delegation"},
    "protocol-transition": {"nist": ["AC-6", "IA-5"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "restrict protocol-transition delegation"},
    "old-os": {"nist": ["SI-2", "CM-6"], "cis": [_CIS_SECCFG], "e8": [_PATCH_OS], "stig": "supported operating system"},
    "no-laps": {"nist": ["IA-5", "AC-6"], "cis": [_CIS_SECCFG, _CIS_ACCT], "e8": [_ADMIN], "stig": "LAPS-managed unique local admin passwords"},
    "old-functional-level": {"nist": ["CM-6"], "cis": [_CIS_SECCFG], "e8": [], "stig": "current domain/forest functional level"},
    "trust-no-sid-filtering": {"nist": ["AC-4", "AC-6"], "cis": [_CIS_ACCESS], "e8": [], "stig": "SID filtering / quarantine on external trusts"},
    "broad-rights": {"nist": ["AC-3", "AC-6"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "least-privilege object ACLs"},
    "adcs-everyone": {"nist": ["AC-3", "AC-6"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "restrict AD CS enrollment / template rights"},
    "dcsync-nonpriv": {"nist": ["AC-6(5)", "AC-3"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "restrict directory replication rights"},
    "domain-control-nonpriv": {"nist": ["AC-6(5)", "AC-3"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "restrict control of the domain object"},
    "ea-sa-populated": {"nist": ["AC-5", "AC-6(5)"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "keep Schema/Enterprise Admins empty except during use"},
    "many-domain-admins": {"nist": ["AC-5", "AC-6(5)"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "minimise Domain Admins membership"},
    "dnsadmins": {"nist": ["AC-6(5)", "AC-3"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "restrict DNSAdmins; monitor ServerLevelPluginDll"},
    "svc-privileged": {"nist": ["AC-5", "AC-6(5)"], "cis": [_CIS_ACCT, _CIS_ACCESS], "e8": [_ADMIN], "stig": "service accounts not in privileged groups"},
    "guest-enabled": {"nist": ["AC-2"], "cis": [_CIS_ACCT], "e8": [], "stig": "built-in Guest disabled"},
    "smb-signing": {"nist": ["SC-8", "SC-13"], "cis": [_CIS_SECCFG], "e8": [], "stig": "require SMB signing"},
    "smb-signing-dc": {"nist": ["SC-8", "SC-13"], "cis": [_CIS_SECCFG], "e8": [], "stig": "require SMB signing on domain controllers"},
    "ldap-signing": {"nist": ["SC-8", "SC-13"], "cis": [_CIS_SECCFG], "e8": [], "stig": "require LDAP signing and channel binding"},
    "webclient": {"nist": ["CM-7", "SC-8"], "cis": [_CIS_SECCFG], "e8": [_UAH], "stig": "disable WebClient where not needed"},
    "ca-no-admin-mfa": {"nist": ["IA-2", "IA-2(1)"], "cis": [_CIS_ACCESS], "e8": [_MFA], "stig": "enforce MFA for administrators"},
    "ca-report-only": {"nist": ["IA-2", "IA-2(1)"], "cis": [_CIS_ACCESS], "e8": [_MFA], "stig": "enforce (not report-only) MFA policies"},
    "ca-admin-uncovered": {"nist": ["IA-2", "IA-2(1)"], "cis": [_CIS_ACCESS], "e8": [_MFA], "stig": "all admins covered by enforced MFA"},
    "ca-admin-excluded": {"nist": ["IA-2", "IA-2(1)"], "cis": [_CIS_ACCESS], "e8": [_MFA], "stig": "no admins excluded from MFA"},
    "ca-legacy-auth": {"nist": ["IA-2", "AC-17"], "cis": [_CIS_ACCESS], "e8": [_MFA], "stig": "block legacy authentication"},
    "pim-activation-no-mfa": {"nist": ["IA-2(1)", "AC-6(5)", "AC-5"], "cis": [_CIS_ACCESS], "e8": [_MFA, _ADMIN], "stig": "PIM: require MFA on role activation"},
    "pim-activation-no-approval": {"nist": ["AC-6(5)", "AC-5"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "PIM: require approval on role activation"},
    "fic-wildcard-subject": {"nist": ["IA-5", "AC-3"], "cis": [_CIS_ACCESS], "e8": [], "stig": "scope workload-identity federation subjects"},
    "fic-pull-request-trigger": {"nist": ["IA-5", "AC-3"], "cis": [_CIS_ACCESS], "e8": [], "stig": "pin federation to protected branch/environment"},
    "fic-no-ref-pin": {"nist": ["IA-5", "AC-3"], "cis": [_CIS_ACCESS], "e8": [], "stig": "pin federation subject to a branch/environment"},
    "shadow-tier0-derived": {"nist": ["AC-6", "AC-6(5)"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "tier management-plane admins as Tier 0"},
    "shadow-tier0-by-name": {"nist": ["AC-6", "AC-6(5)"], "cis": [_CIS_ACCESS], "e8": [_ADMIN], "stig": "tier management-plane admins as Tier 0"},
    "keyvault-secret-readers": {"nist": ["AC-6", "SC-28"], "cis": [_CIS_ACCESS, _CIS_DATA], "e8": [], "stig": "least-privilege key vault access"},
}


def tag(findings) -> list:
    """Attach f.compliance = the control map for each finding whose rule is known. Returns findings."""
    for f in findings:
        m = MAP.get(f.rule)
        if m:
            f.compliance = m
    return findings


def rollup(findings) -> dict:
    """Per framework, which controls are implicated and by how many findings. {framework: [{control, findings, count}]}."""
    out: dict[str, dict[str, list[str]]] = {fw: {} for fw in FRAMEWORK_NAMES}
    for f in findings:
        m = MAP.get(f.rule)
        if not m:
            continue
        for fw in ("nist", "cis", "e8"):
            for ref in m.get(fw, []):
                out[fw].setdefault(ref, []).append(f.rule)
    result = {}
    for fw, controls in out.items():
        rows = [{"control": c, "findings": sorted(set(rs)), "count": len(set(rs))} for c, rs in controls.items()]
        rows.sort(key=lambda r: (-r["count"], r["control"]))
        result[fw] = rows
    return result


def render(findings) -> str:
    r = rollup(findings)
    out = ["", "  compliance mapping", "  " + "-" * 60]
    any_rows = False
    for fw in ("nist", "cis", "e8"):
        rows = r[fw]
        if not rows:
            continue
        any_rows = True
        out.append(f"  {FRAMEWORK_NAMES[fw]}")
        for row in rows:
            out.append(f"    {row['control']:<28} {row['count']} finding(s): {', '.join(row['findings'][:6])}"
                       + (" ..." if len(row["findings"]) > 6 else ""))
        out.append("")
    if not any_rows:
        out.append("  (no findings mapped to a framework control)")
    out.append("  Each finding also carries a DISA STIG requirement theme (see --json); V-IDs vary by STIG release.")
    return "\n".join(out) + "\n"
