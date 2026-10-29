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

AD EXPLORER SNAPSHOTS (LDAP-only, for EDR-blocked domains)
  A Sysinternals AD Explorer snapshot (signed, not flagged by EDR) exported to NDJSON by `ADExplorerSnapshot.py -m Objects`
  is read natively: objects, memberships, GPO links, and ACL edges parsed from the security descriptors. It has no sessions,
  local-group or AD CS data, so exposure is a floor and `doctor` says so.

SHADOW TIER 0 (objects that can push code or credentials to real Tier 0)
  A software-deployment server (SCCM/MECM, WSUS, Tanium ...), a backup admin (Veeam, Commvault ...), a hypervisor admin
  (VMware, Hyper-V ...), an EDR console admin, a PAM vault admin, or the directory-sync account (Entra Connect / MSOL_) can
  take over domain controllers through their own product, not through an AD ACL. Their AD groups and service accounts are
  marked Tier 0 so a path TO them is a path to Domain Admin. DERIVED matches (DCSync or control of the domain object) are
  certain; BY-NAME matches are listed by `audit` and can be turned off with `analyze --no-shadow-tier0`.

CONFIDENCE AND COVERAGE
  Every step has a confidence: high = read from the directory, medium = computed by PathCutter from collected settings, low = rests on an
  unverified assumption or was seen once (a session in one collection, the unconstrained-delegation link, ESC15, PIM eligibility without
  its policy). A path is as strong as its weakest step; a finding takes the strongest of its paths. It labels, it never hides an edge.
  `pathcutter coverage --telemetry FILE` marks each path detected / visible / blind from the log sources and rules you declare.

ATTACKER COST (cheapest and stealthiest route, not just fewest hops)
  Every attack edge carries an effort (from its exploitability: higher effort = more work/privilege/tooling) and a noise
  level (from its detection difficulty: higher noise = easier to catch). A path sums both over its attack steps (structural
  MemberOf / Contains hops are free), and is flagged fragile if a step rests on an unverified precondition (coercion, PIM
  activation) and cross-plane if it crosses between on-premises AD and the cloud (Entra / Azure / Graph). The report's path
  explorer shows "effort N . noise N" per path, so a short but loud or fragile route is no longer mistaken for the easy one.

FIX AS CODE (open the remediation as a pull request)
  `fix --pr -o DIR` writes a branch-ready bundle instead of a bare script: remediation.ps1, a PR.md description with the
  per-fix safety table, fixes.changes (the fixes as change lines so `pathcutter check --changes fixes.changes` confirms
  they REMOVE exposure, not add it), and apply.sh / apply.ps1 that create the branch and open the PR with your own `gh`
  (GitHub) or `glab` (GitLab; --pr-platform gitlab). PathCutter stays offline and never touches your remote - the apply
  script does, with your credentials, and a human reviews and merges. A fix the change DSL cannot express (e.g. an ADCS
  escalation fixed on the template) is written as a comment and confirmed by re-collection instead.

CROWN JEWELS (business value, not just hop count)
  `analyze --crown-jewels FILE` names the assets whose compromise is a crisis even when it is not domain takeover: the
  student-records system, the finance ERP, research servers. Each entry is {"match": name-or-id, "value":
  critical|high|medium, "label": "..."} or {"ou": "OU=...,DC=...", ...} to value everything under an OU. A crown jewel
  becomes a target (the exposure search measures who can reach it) and the HTML report adds an executive summary, a Crown
  Jewels card (reachable / by how many / cheapest route) and a per-OU breakdown, and prints cleanly to PDF. PathCutter
  never invents value: an asset counts only because you declared it.

ASSUME BREACH (work outward from one compromised object)
  `pathcutter breach INPUT --from OBJECT` starts from a single object you name - a laptop, a service account, a contractor -
  and reports its blast radius, which Tier 0 objects it can reach, and for each the cheapest (least effort) and stealthiest
  (least noise) route. --profile opportunist|stealth|balanced sets how routes are ranked. Tier 0 reachable only past another
  Tier 0 is listed separately. Exit code 2 means this object can reach Tier 0 (useful for gating). --from takes an exact name,
  a short name, or an object id; an ambiguous name lists the matches.

PIM ACTIVATION POLICY (Entra Privileged Identity Management)
  A PIM-eligible role (AZEligibleRole) is only a real standing risk if the holder can actually activate it. When
  AzureHound collected the role-management-policy assignments (AZRoleManagementPolicyAssignment, needs
  RoleManagement.Read.Directory), PathCutter reads what end-user activation requires and upgrades the edge from an
  assumption to a verdict: approval required -> low confidence and FRAGILE (an approver may say no); MFA but no approval
  -> medium (the holder activates on their own after MFA); neither -> HIGH, because the eligibility is effectively a
  standing assignment. `audit` flags roles activatable with no MFA/approval (high) or no approval (medium). Without the
  policy data the edge stays the old low-confidence assumption, and `doctor`-style honesty applies.

WORKLOAD IDENTITY FEDERATION (CI/CD to cloud)
  A federated credential (GitHub, Azure DevOps, another tenant) becomes a node with an AZAuthenticatesTo edge to its application: whoever can
  mint the trusted token acts as the app. PathCutter parses the credential's SUBJECT to show exactly which pipeline is trusted and how wide
  the trust is: a single protected branch is tight; `audit` flags a wildcard (high), a `pull_request` subject (high: any contributor via a PR)
  and a repo with no branch/environment pin (medium), as well as outside issuers. An optional `*_cicd.json` sidecar (one entry per repository,
  optionally who can push; see tools/Export-GitHubActions.ps1) adds a CI/CD source node with an edge to the application each repo can authenticate
  as, so the attack path reaches from the pipeline into the cloud. GitHub/ADO logins only connect to a pusher when their id maps to a collected
  object; unmapped logins are counted, never invented.

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
  Trusts: direction, transitivity and SID filtering are recorded and `doctor` reports unfiltered external trusts. The
  legacy TrustedBy edge is treated as traversable (conservative). SharpHound v7.4+ splits trusts into SameForestTrust
  (traversable), CrossForestTrust (the trust fact, NOT traversable on its own) and the attack edges SpoofSIDHistory
  (weak SID filtering) and AbuseTGTDelegation (TGT delegation) which ARE traversable: those are ingested as such.

MODERN BLOODHOUND CE EDGES
  SharpHound v6/v7 emit edges older collections did not. PathCutter ingests them so current collections are not
  under-reported: CoerceToTGT (unconstrained delegation: coerce a privileged computer or DC and capture its TGT),
  WriteOwnerLimitedRights / OwnsLimitedRights (owner control limited by an OWNER RIGHTS ACE), and the v7.4 trust edges
  above. Edges that are only a precondition (CrossForestTrust) are recorded but never walked.

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
