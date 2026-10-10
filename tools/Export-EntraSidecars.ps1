<#
.SYNOPSIS
  Read-only export of the Entra settings AzureHound does not collect: Conditional Access, PIM policies and eligibility,
  administrative units (with members), and custom directory role definitions.

.DESCRIPTION
  Signs in with Microsoft Graph PowerShell (interactive, so MFA and passkeys work) and writes one JSON file per area into
  -OutDir. Nothing is changed in the tenant. The scopes requested are read-only; an administrator must consent once.
  A call that fails (licence, permission) is recorded in <OutDir>\export-log.txt and the rest still runs.
  Run `pathcutter anonymize` on the AzureHound ZIP before sharing; these files hold display names and ids, so review them too.

.EXAMPLE
  Install-Module Microsoft.Graph -Scope CurrentUser
  .\Export-EntraSidecars.ps1 -OutDir C:\collect\entra
#>
[CmdletBinding()]
param([string]$OutDir = (Join-Path (Get-Location).Path 'entra-export'))
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir 'export-log.txt'

$scopes = 'Policy.Read.All', 'RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.Directory',
          'AdministrativeUnit.Read.All', 'Directory.Read.All', 'User.Read.All', 'Group.Read.All'
Connect-MgGraph -Scopes $scopes -NoWelcome

function Save-Json([string]$Name, [scriptblock]$Fetch) {
    try {
        $data = & $Fetch
        $path = Join-Path $OutDir $Name
        ConvertTo-Json -InputObject @($data) -Depth 20 | Set-Content -Path $path -Encoding UTF8
        $msg = "ok   $Name ($(@($data).Count) items)"
    } catch { $msg = "FAIL $Name : $($_.Exception.Message)" }
    Write-Host $msg
    Add-Content -Path $log -Value $msg
}

# Conditional Access: the format `pathcutter audit` reads
Save-Json 'conditional_access.json' { Get-MgIdentityConditionalAccessPolicy -All }

# PIM: what activating an eligible role requires (approval, MFA, justification, maximum duration)
Save-Json 'pim_policy_assignments.json' {
    Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -ExpandProperty 'policy($expand=rules)' -All
}
Save-Json 'pim_eligibility.json' { Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All }
Save-Json 'pim_active_assignments.json' { Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All }

# Role assignments with their directory scope, and custom role definitions with their permissions
Save-Json 'role_assignments.json' { Get-MgRoleManagementDirectoryRoleAssignment -All }
Save-Json 'custom_role_definitions.json' { Get-MgRoleManagementDirectoryRoleDefinition -Filter 'isBuiltIn eq false' -All }

# Administrative units and their members (scoped roles reach only these)
Save-Json 'administrative_units.json' {
    foreach ($au in Get-MgDirectoryAdministrativeUnit -All) {
        $members = @(Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All | ForEach-Object { @{ id = $_.Id } })
        [pscustomobject]@{ id = $au.Id; displayName = $au.DisplayName; members = $members }
    }
}

# Sign-in context: which authentication methods are enabled (passkeys, SMS, ...)
Save-Json 'authentication_methods_policy.json' { Get-MgPolicyAuthenticationMethodPolicy }

Disconnect-MgGraph | Out-Null
Write-Host "Done. Files and export-log.txt are in $OutDir"
