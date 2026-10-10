# Getting real data into PathCutter's tests

PathCutter can only model what a collector has gathered, and it can only be trusted where it has run on real collector output.
This page says what is still missing, how to produce it in a lab you own, and how to hand it over safely.

**Only collect from environments you own or are authorised to assess.** Everything below is read-only enumeration of your own
directory, tenant or subscription.

## What is missing, and what it unlocks

| Missing | Why it matters | Real data exists today? |
|---|---|---|
| Computers carrying SMB signing, LDAP signing and WebClient properties | NTLM-relay edges. `pathcutter/relay.py` exists but is **not applied**: it over-reports against BloodHound's own harnesses and has never seen a real collection | No. None of the 13 public collections checked carries these properties |
| Entra PIM policy settings (approval, MFA, justification, duration) | Whether an eligible role is a real path or needs a second human | No. The only public Entra export has no PIM data |
| Azure custom role definitions and deny assignments | Custom roles that can write role assignments or run commands on VMs are invisible today | No. Not in AzureHound output |
| A tenant with Conditional Access policies | `audit` evaluates them, but only synthetic policies have been tested | No |
| An Entra tenant with administrative units | Scoped roles are modelled from the AzureHound shape; the public sample has none | No |
| A production-shaped AD (thousands of objects, real nesting) | Scale numbers come from a synthetic generator | No |

## Lab 1: Active Directory (covers relay properties, ACLs, AD CS, GPO rights)

The cheapest route is a public lab definition such as [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (about 5 VMs,
runs under VirtualBox or VMware) or any Windows Server 2019/2022 evaluation forest with two or three domain controllers.

1. Build the lab and make it slightly realistic: a few dozen users, nested groups, one AD CS enterprise CA with the default
   templates plus a couple of custom ones, a GPO or two.
2. Collect with the **current SharpHound CE** release from a domain-joined host. Run `SharpHound.exe --help` and use the collection
   methods that gather SMB information, WebClient service state and LDAP service information (SpecterOps' flags page calls them
   `SmbInfo`, `WebClientService` and `LdapServices`), in addition to `Default`, `ACL`, `Container`, `GPOLocalGroup`, `CertServices`
   and `Session`. Run the session collection more than once on different days.
3. Run the PathCutter collectors that fill SharpHound's gaps: `tools/Export-AdDenyAces.ps1`, `tools/Export-AdGpoRights.ps1`,
   `tools/Export-AdCsRelay.ps1`.
4. Put every output file (the SharpHound ZIP and the three `*_denies.json`, `*_gporights.json`, `*_adcsrelay.json`) in one folder.

## Lab 2: Microsoft Entra ID and Azure

A free tenant is enough. This is where an Azure portal login, a subscription and a few VMs help the most.

1. **Tenant.** Use the Microsoft 365 Developer Program sandbox, or a free Azure account. Add 20 or so users and 5 groups.
2. **Make it interesting** (this is what the tests need, not realism):
   - assign Helpdesk Administrator to one user **scoped to an administrative unit** that holds two other users;
   - assign Application Administrator to a user and Cloud Application Administrator to another;
   - register 3 applications and grant one of them `RoleManagement.ReadWrite.Directory` or `Group.ReadWrite.All`;
   - make a user **eligible** (not active) for a privileged role in PIM, with approval required on one role and MFA only on another
     (Microsoft Entra ID P2 trial is needed for PIM);
   - create one **Conditional Access** policy requiring MFA for admins, one in report-only mode.
3. **Azure.** Create a subscription, two resource groups, two small VMs (one with a system-assigned managed identity), a Function
   App, an Automation Account and a Key Vault. Give a user Contributor on one resource group, and a **custom role** that includes
   `Microsoft.Authorization/roleAssignments/write`. Add a deny assignment (a blueprint or a managed-app deny) if you can.
4. **Collect.**
   - [AzureHound](https://github.com/SpecterOps/AzureHound): `azurehound list -o azure.json` with an account that has Global
     Reader and Reader on the subscription.
   - Everything that is not in AzureHound's output, in one read-only run: `tools/Export-EntraSidecars.ps1` (Conditional Access, PIM
     policies and eligibility, role assignments with their scope, custom role definitions, administrative units with members).
   - PIM policies: `Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -ExpandProperty policy`
     and `Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance`.
   - Custom roles: `az role definition list --custom-role-only true`; deny assignments:
     `az rest --method get --url "https://management.azure.com/subscriptions/<id>/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01"`.

## Hybrid (best of all)

Joining the AD lab to the Entra tenant with Entra Connect (or Cloud Sync) produces the on-premises to cloud links that a hybrid
test needs, with real `onPremisesSecurityIdentifier` values on both sides.

## Before you share anything

```bash
pathcutter anonymize collection.zip -o shareable.zip --salt <random>
pathcutter doctor shareable.zip        # still readable? same verdict as the original?
```

`anonymize` pseudonymises names, domains, SIDs and GUIDs, drops free text and password-like attributes, keeps built-in groups,
built-in role ids and Graph permission ids, and is tested to give identical attack paths. Review the output before sending; free-text
fields not on its drop list could still hold identifying text. Never share the `--map` file.

## What I do with it

1. `pathcutter doctor` and `audit` on the raw data, to see what the parsers miss or misread (this is how the real Entra sample
   found five bugs).
2. Fix the parsers, add the file as a fixture with its licence, pin facts about it in a test.
3. Only then turn on derivations that depend on the new properties (NTLM relay, PIM enforcement, custom roles), validated
   against the BloodHound harnesses in `tests/data/harnesses/` first.
