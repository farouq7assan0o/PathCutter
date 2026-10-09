# Detections for the paths you cannot fix: `pathcutter detect`

Fixing every attack path is rarely possible. The business needs the helpdesk group to reset passwords, the
backup account to have its rights, the service to delegate. Generic advice ("monitor Domain Admins") is what
most teams get for the rest. PathCutter instead turns each **residual choke point** into a detection scoped
to the exact objects on the path.

```bash
# I will fix the top 5 things; watch what remains
pathcutter detect baseline.pcsnap --assume-fixed 5 --top 15 -o detections/

# or: a change set I am accepting ships with the detections that watch it
pathcutter check --baseline baseline.pcsnap --changes ad-changes/ --policy policy.json --detections detections/
```

## What you get

```
detections/
  sigma/*.yml          one Sigma rule per detection (valid YAML, deterministic ids)
  splunk/*.spl         Splunk SPL (Windows TA, XmlWinEventLog:Security)
  sentinel/*.kql       Microsoft Sentinel / Defender KQL over SecurityEvent
  elastic/*.kql        Elastic / Kibana KQL over winlog.*
  coverage.md          what each rule watches, who can abuse it, how to test it, what to do when it fires
  coverage.json        the same, machine-readable
  prerequisites.md     the Advanced Audit Policy you must enable (with auditpol commands)
```

All four languages are compiled from one intermediate representation, so they always agree. Every value that
ends up in a rule comes from AD and is therefore attacker-controllable; the compilers quote strictly and
neutralise control characters.

## How the monitor points are chosen

1. Apply the top N fixes **virtually** (`--assume-fixed N`). Nothing is changed in your environment.
2. Re-enumerate the paths that remain, then pick the edges that cover the most of them (the same greedy
   set cover that ranks fixes), up to `--top K`. The report says what percentage of residual paths they cover.
3. Add two always-on watches that PathCutter's exposure engine makes possible:
   * **Tier 0 group membership**: any member added to a Tier 0 group.
   * **Exposed group membership**: any member added to *any group that can reach Tier 0*. This is the runtime
     twin of `pathcutter check`: the same question, asked of live events.

## Detection kinds

| Rule | Watches | Events |
|---|---|---|
| `T0_GROUP_MEMBERSHIP` | members added to Tier 0 groups | 4728, 4732, 4756 |
| `EXPOSED_GROUP_MEMBERSHIP` | members added to groups that reach Tier 0 | 4728, 4732, 4756 |
| `ADD_MEMBER_ABUSE` | groups someone holds AddMember/GenericAll over | 4728, 4732, 4756 |
| `ACL_CHANGE` | DACL/owner changes on objects on a residual path | 5136 (`nTSecurityDescriptor`) |
| `SENSITIVE_ATTRIBUTE_WRITE` | SPN, RBCD, shadow-credential, delegation, script, UAC writes | 5136 |
| `PASSWORD_RESET` | resets of accounts on a residual path by someone else | 4724 |
| `DCSYNC` | replication GUIDs used by a non-DC | 4662 |
| `MANAGED_PASSWORD_READ` | gMSA / LAPS password reads | 4662 |
| `ADMIN_LOGON`, `RDP_LOGON`, `PSREMOTE_LOGON` | logons to hosts on a residual path | 4624, 4672 |
| `DELEGATION_USE` | S4U2Proxy toward a delegation target | 4769 |
| `GPO_CHANGE` | edits to GPOs on a residual path | 5136 |
| `ADCS_ISSUANCE` | issuance from templates/CAs on a residual path | 4886, 4887 |

Each rule lists the **principals who can abuse the covered edges** (a ready-made watchlist for tuning), a lab
command that should trigger it (`test_command`), the expected event, and response steps. Test your detections
in a lab before you trust them.

## Audit policy comes first

A rule fires only if the log exists. `prerequisites.md` lists the audit subcategories used by the pack with the
exact `auditpol` command, plus the caveat people miss: events 5136 and 4662 are only written for objects whose
**SACL** audits the access, so configure SACLs on the domain root or the OUs that matter.

## Limits

* Rules describe the *abuse of an edge* (a membership change, an ACL write, a logon), not the attacker; expect to
  tune with allowlists of your change-management accounts and legitimate admins.
* Elastic keyword fields are case-sensitive; Windows writes names in their original case while BloodHound data is
  upper-case. SPL and KQL comparisons are case-insensitive; for Elastic use a case-insensitive mapping.
* Sentinel's `SecurityEvent` exposes some fields as columns and the rest only in `EventData`; the generated KQL
  parses `EventData` where needed.
* The pack reflects the baseline. Re-generate it when the baseline changes.
