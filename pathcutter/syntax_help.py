"""`pathcutter syntax`: the complete reference, generated from the live registries so it cannot drift."""
from __future__ import annotations

from .changes import VERB_HELP
from .edges import EDGE_REGISTRY
from .graph import NodeType
from .policy import ALL_KINDS, POLICY_SCHEMA
from . import ps_rules

TOPICS = ("changes", "powershell", "edges", "policy", "model", "exit-codes")


def _heading(title: str) -> str:
    return f"\n{title}\n{'=' * len(title)}\n"


def changes() -> str:
    return _heading("CHANGE LANGUAGE") + f"""\
A change set is a list of proposed AD changes. Write them in a .changes file (one per line, '#' starts a
note such as a ticket id), pass them with --change, use a JSON file, or point --powershell at a script.

{VERB_HELP}

NAMES
  An object can be written as: a SID, NAME@DOMAIN, the short name, DOMAIN\\name, or (computers) the host
  name, HOST$ or FQDN. Matching is case-insensitive and type-aware: `add-member alice HELPDESK` picks the
  GROUP even if a user is also called HELPDESK. Quote names with spaces: "DOMAIN ADMINS".
  An unknown name is an error with suggestions (a change that cannot be resolved cannot be judged);
  an ambiguous name lists the candidates. `--on-unresolved assume-new` treats unknown names as new objects.

SELECTORS (expanded against the baseline)
  @members(GROUP)      every direct member of GROUP
  @members*(GROUP)     every nested member (users and computers only)
  @dcs                 every domain controller
  e.g.  add-member "@members(HELPDESK)" "DB ADMINS"       grants all current HELPDESK members

EXAMPLES
  add-member alice "DOMAIN ADMINS"           # CHG-20417 weekend duty
  grant SUPPORT GenericWrite SVC_SCOM        # any edge name; see `pathcutter syntax edges`
  revoke bob WriteDacl "SERVER ADMINS"
  revoke-all stannis kingslanding            # every ACL right the principal holds on the object
  local-admin DEVOPS SRV01
  unconstrained SRV02                        # trusted for unconstrained delegation
  create user newhire
  add-member newhire HELPDESK
  move alice "Admins"                        # re-parent under an OU
  delete olduser
  add-member alice HELPDESK ttl=4h           # a time-bound (JIT/PAM) grant: the window is still reported
  deny interns GenericAll svc_backup         # a Deny ACE: blocks interns' token only, others keep the allow
  undeny interns GenericAll svc_backup       # lifting a deny is treated as a grant

JSON
  {{"changes": [{{"op": "add", "source": "alice", "edge": "MemberOf", "target": "HELPDESK", "note": "CHG-1"}},
               {{"op": "create", "type": "user", "name": "newhire"}}, "remove-member bob HELPDESK"]}}
  ops: add, remove, create, move, delete. A string entry is a DSL line.
"""


def powershell() -> str:
    rows = []
    for name, (_, _, desc) in sorted(ps_rules.SUPPORTED.items()):
        rows.append(f"  {name:<34} {desc}")
    notes = "\n".join(f"  {n:<34} {t}" for n, t in sorted(ps_rules.NOTES.items()))
    return _heading("POWERSHELL EXTRACTION") + f"""\
`pathcutter check --powershell script.ps1` reads the script (it never runs it) and works out which AD
changes it would make. It follows real automation, not just one-liners:

  variables         $g = "HelpDesk"; $users = 'a','b'; "$prefix-admins"; $x = Get-ADGroup "X"
  loops/pipelines   foreach ($u in 'a','b') {{ ... }};  'a','b' | ForEach-Object {{ ... $_ }};  Get-ADUser bob | Add-...
  baseline lookups  Get-ADGroupMember HelpDesk | ...   (members come from your baseline)
  structure         if/else, try/catch, functions, Invoke-Command -ComputerName HOST {{ ... }}, splatting (@params)
  parameters        any unambiguous prefix (-Ident), aliases (-Member), positional and -Name:value forms
  directives        # pc: add-member alice "Domain Admins"   states the effect of a line the parser cannot read

MODELED CMDLETS
{chr(10).join(rows)}

RECOGNISED, NO GRAPH EFFECT (reported as notes)
{notes}

NEVER SILENT
  Any other cmdlet named Set/New/Add/Remove/Move/Rename/Enable/Disable/Grant/Revoke/Install/Reset/... on AD,
  Domain*, GP*, or local groups is reported as "not modeled". Values that cannot be resolved (Import-Csv,
  parameters, -Filter queries, other variables) are reported with the variable name. That is a finding for
  a human, never an assumption. Use `# pc:` directives to describe those lines yourself.
"""


def edges() -> str:
    out = [_heading("EDGE TYPES (the rights you can grant or revoke)")]
    seen = set()
    for key, et in sorted(EDGE_REGISTRY.items(), key=lambda kv: (kv[1].category.value, kv[1].name)):
        if et.name in seen or key != et.name:
            continue
        seen.add(et.name)
        expl = f"{et.exploitability}/10" if et.exploitability else "structural"
        out.append(f"  {et.name:<24} {et.category.value:<11} {expl:<11} {et.mitre or '-':<10} {et.abuse[:70]}")
    out.append("\n  Node types: " + ", ".join(t.value for t in NodeType if t != NodeType.UNKNOWN))
    out.append("  Columns: edge, category, exploitability, MITRE technique, what it allows.")
    return "\n".join(out) + "\n"


def policy() -> str:
    return _heading("POLICY FILE (--policy policy.json)") + f"""\
Unknown keys are rejected so a typo cannot weaken the gate silently.

  {{
    "schema": "{POLICY_SCHEMA}",
    "block_severity": "high",          critical | high | medium | low | info
    "block_kinds": ["TIER0_PROMOTION", "NEW_EXPOSURE", "COMBINED_EFFECT"],
    "review_severity": "medium",
    "max_new_exposed_actors": 0,       hard cap on accounts gaining a route to Tier 0 (after waivers)
    "max_score_increase": 5,           advisory when path counts are capped
    "fail_on_unmodeled": false,        make unmodeled script lines block
    "extra_tier0": ["SQL-PROD-ADMINS", "PKI-CA01"],     your crown jewels, beyond the built-in list
    "max_baseline_age_days": 14,
    "require_waiver_expiry": true,
    "jit_max_minutes": 480,            grants with ttl= up to this long are lowered one severity step (never hidden)
    "controls": [{{"id": "CA-7", "type": "conditional-access", "owner": "iam-team", "evidence": "CA policy 'Admins need compliant device'",
                  "target": "HELPDESK", "edge": "MemberOf", "steps": 1, "expires": "2026-12-31"}}],
    "waivers": [{{"id": "CHG-1", "reason": "approved by CISO", "approver": "j.doe", "expires": "2026-12-31",
                 "source": "jsmith", "edge": "MemberOf", "target": "BACKUP OPERATORS", "kinds": ["TIER0_PROMOTION"]}}]
  }}

  controls: DECLARED compensating controls (types: conditional-access, mfa, pim, vault, tiering, network, monitoring,
  other). PathCutter cannot verify them. A control needs an owner and evidence, lowers matching findings by 1-2
  severity steps (never below low; never below medium for a Tier 0 promotion or a combined effect), never removes
  a finding, and every report says "declared, not verified". Expired controls stop applying and are flagged.

  Finding kinds: {", ".join(ALL_KINDS)}
  Waivers match by glob, apply only if EVERY change in a finding is covered, always show in the report, and
  stop applying the day after `expires`. Read policy and waivers from a protected branch in CI, never from the PR.
"""


def model() -> str:
    return _heading("WHAT IS MODELED, AND WHAT IS NOT") + """\
MODELED (exposure is computed exactly for these)
  Allow ACLs, group nesting and primary group, local admin/RDP/PSRemote/DCOM, sessions (computer -> user),
  GPO links and GPO-granted local rights, delegation (unconstrained, constrained, RBCD), SID history, AD CS
  rights, DCSync, gMSA/LAPS reads, containment, trusts, implicit membership of Everyone and Authenticated Users.
  AD CS escalation, derived from collected template and CA data, on CAs trusted via NTAuth: ESC1 (enrollee-supplied
  subject), ESC3 (enrollment agents), ESC4 (template control), ESC5 (NTAuth / CA object control), ESC6 (CA accepts a
  requester SAN), ESC7 (ManageCA/ManageCertificates), ESC9 and ESC10 (need domain controller registry data), ESC8, ESC11 and ESC16 (need tools/Export-AdCsRelay.ps1), ESC2 (an Any Purpose template counts as an
  enrollment-agent template and feeds ESC3), golden certificate.
  Microsoft Entra ID and hybrid identity from AzureHound output: users, groups, applications, service principals,
  directory roles, ownership, active and PIM-eligible role assignments, password-reset and add-secret roles (also scoped to an administrative unit or one object), and the
  on-premises -> cloud sync link, so one search follows a path across the boundary. Azure resource RBAC: subscriptions,
  resource groups, VMs and key vaults with Owner / Contributor / User Access Administrator / VM login assignments, the
  scope hierarchy, and VM managed identities (name a subscription in policy extra_tier0 to make it a target). Tier 0 roles: Global Administrator,
  Privileged Role Administrator, Privileged Authentication Administrator, Partner Tier2 Support.
  Deny ACEs, identity-sensitive: a deny binds the denied principal's token (members of a denied group included)
  and only at the hop where that identity acts. Collect them with tools/Export-AdDenyAces.ps1 (SharpHound does
  not), or state them with `deny` / `undeny`, `dsacls /D` and Deny access rules in scripts.

GPO USER RIGHTS (needs tools/Export-AdGpoRights.ps1)
  SeBackup / SeRestore / SeTakeOwnership / SeDebug / SeLoadDriver / SeTcb / SeCreateToken / SeSyncAgent granted by a GPO's
  security template become edges to the computers the GPO is linked to (GPOUserRight). Security filtering, WMI filters,
  enforcement and blocked inheritance are not evaluated, so this can only over-report.

NTLM RELAY (experimental, not applied)
  pathcutter/relay.py can derive CoerceAndRelayNTLMToSMB / ...ToLDAP from SMB signing, LDAP signing and WebClient properties, but it
  over-reports against BloodHound's own harnesses (it ignores Protected Users and RestrictOutboundNTLM), so it is NOT run when a
  collection is loaded and no edges of these types appear in results.

RESTRICTIONS (applied when the graph is built; always reported, never silent)
  Protected Users / 'sensitive and cannot be delegated': constrained and resource-based delegation edges into a host
  are removed when EVERY administrator of that host is protected. Listed by `audit`; `check` does not re-evaluate it
  and says so when a change touches memberships or administrators.

MODELED AS REPORTING, NOT AS A GRAPH CHANGE
  Conditional Access: policies are evaluated against the collected Entra identities (users, groups, roles, nested; MFA,
  authentication strength, block; enabled / report-only / disabled) and reported by `pathcutter audit`. Locations,
  platforms, risk levels, device filters and session controls are not evaluated, so coverage is never over-stated.
  Several collections: `--also` merges them; sessions record how many collections saw them.
  Time-bound grants (`ttl=`, -MemberTimeToLive): flagged "temporary"; the exposure window is still a finding.
  Declared compensating controls (Conditional Access, PIM approval, vaulting, tiering): lower severity only.
  SDProp: ACL edits on adminCount=1 objects are noted as likely to be reverted (or to return) within ~60 min.
  Revocation lag: removals are noted as not ending live sessions or already-issued Kerberos tickets.
  Trusts: direction, transitivity and SID filtering are recorded and `doctor` reports unfiltered external trusts,
  but every trust is treated as traversable (conservative: it can over-report, not under-report).

NOT MODELED (stated so nobody assumes otherwise)
  ESC14 (weak altSecurityIdentities mapping): the attacker needs a write right on the victim, and GenericWrite / GenericAll over a user
  or computer is already a followed edge that gives the same takeover, so a separate edge would add no path.
  Key vault data plane: access-policy entries are shown as AZGetSecrets / AZGetKeys / AZGetCertificates and listed by `audit`, but a
  vault's contents are unknown, so they are never followed as a step to another identity.
  AD CS ESC14 (and ESC8/ESC11/ESC16 unless the relay sidecar was collected); AD CS paths are only as
  good as the template, CA and NTAuth data collected. Graph application
  permissions other than the role, secret, group-member and user-password ones, custom Azure roles, deny assignments and key vault data-plane access policies.
  Whether MFA / PIM approval is really enforced at sign-in (Conditional Access is evaluated and reported, not turned
  into graph edges), authentication silos as graph restrictions, smart-card
  required flags, fine-grained password policy, network reachability and firewalls, SMB/LDAP signing and NTLM relay (see above),
  EDR, GPO content other than local-group membership and the user rights above, Kerberos ticket and token contents.
  Sessions are snapshots of one moment: merge several collections with --also.
  Exposure is a floor for anything the collection missed: run `pathcutter doctor` on the export first.
"""


def exit_codes() -> str:
    return _heading("EXIT CODES") + """\
  0   pass (or REVIEW/BLOCK with a looser --fail-on); analyze/score/fix/diff finished
  1   could not run: bad syntax, unknown object, unreadable baseline or policy, missing input
  2   blocked by policy (check) / threshold exceeded (export)
  3   needs a human decision (check --fail-on review only)
"""


def render(topic: str | None = None) -> str:
    topic = (topic or "").lower()
    if topic in ("", "all"):
        return (changes() + powershell() + edges() + policy() + model() + exit_codes())
    table = {"changes": changes, "powershell": powershell, "ps": powershell, "edges": edges, "policy": policy,
             "model": model, "exit-codes": exit_codes, "exit": exit_codes}
    if topic not in table:
        return f"Unknown topic '{topic}'. Topics: {', '.join(TOPICS)}, all\n"
    return table[topic]()
