<#
.SYNOPSIS
  Read-only export of the Entra settings AzureHound does not collect: Conditional Access, PIM policies and eligibility,
  role assignments with their scope, custom role definitions, administrative units (with members), authentication methods.

.DESCRIPTION
  Signs in with Microsoft Graph PowerShell (interactive, so MFA and passkeys work) and calls the Graph REST API directly, so the
  files keep Graph's own camelCase shape. Nothing is changed in the tenant; only read scopes are requested.
  A call that fails (licence, permission) is written to export-log.txt and the rest still runs.
  Works in Windows PowerShell 5.1 and PowerShell 7.

  Output (in -OutDir):
    conditional_access.json        read by `pathcutter audit` (put it next to the AzureHound file)
    administrative_units_azure.json  AzureHound-shaped, read by PathCutter to scope Entra roles
    pim_*.json, role_*.json, custom_role_definitions.json, authentication_methods_policy.json   kept for the next parsers

.EXAMPLE
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  .\Export-EntraSidecars.ps1 -OutDir D:\collect\entra
#>
[CmdletBinding()]
param([string]$OutDir = (Join-Path (Get-Location).Path 'entra-export'))
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir 'export-log.txt'
Set-Content -Path $log -Value "Export-EntraSidecars $(Get-Date -Format s)"

$scopes = 'Policy.Read.All', 'RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.Directory',
          'AdministrativeUnit.Read.All', 'Directory.Read.All'
Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
$ctx = Get-MgContext
Add-Content $log "tenant $($ctx.TenantId) account $($ctx.Account)"

function Get-GraphPages([string]$Uri) {
    $all = @()
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri
        if ($r.ContainsKey('value')) { $all += @($r.value) } else { $all += $r }
        $Uri = $r['@odata.nextLink']
    }
    return $all
}

function Write-Json([string]$Name, $Object) {
    $path = Join-Path $OutDir $Name
    $json = ConvertTo-Json -InputObject $Object -Depth 30
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))    # UTF-8 without BOM
}

function Export-List([string]$Name, [string]$Uri) {
    try {
        $items = Get-GraphPages $Uri
        Write-Json $Name @{ value = @($items) }
        $msg = "ok   $Name ($(@($items).Count) items)"
    } catch { $msg = "FAIL $Name : $($_.Exception.Message)" }
    Write-Host $msg; Add-Content $log $msg
}

$g = 'https://graph.microsoft.com/v1.0'
try {   # Conditional Access: the shape `pathcutter audit` evaluates
    $ca = Get-GraphPages "$g/identity/conditionalAccess/policies"
    Write-Json 'conditional_access.json' @{ meta = @{ type = 'conditional_access'; version = 1 }; data = @($ca) }
    $m = "ok   conditional_access.json ($(@($ca).Count) policies)"
} catch { $m = "FAIL conditional_access.json : $($_.Exception.Message)" }
Write-Host $m; Add-Content $log $m

Export-List 'pim_policy_assignments.json' "$g/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=policy(`$expand=rules)"
Export-List 'pim_eligibility.json' "$g/roleManagement/directory/roleEligibilityScheduleInstances"
Export-List 'pim_active_assignments.json' "$g/roleManagement/directory/roleAssignmentScheduleInstances"
Export-List 'role_assignments.json' "$g/roleManagement/directory/roleAssignments"
Export-List 'custom_role_definitions.json' "$g/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false"
Export-List 'authentication_methods_policy.json' "$g/policies/authenticationMethodsPolicy"

try {   # administrative units with their members, in AzureHound's shape so the existing parser scopes roles by them
    $units = @()
    foreach ($au in (Get-GraphPages "$g/directory/administrativeUnits")) {
        $members = @(Get-GraphPages "$g/directory/administrativeUnits/$($au.id)/members?`$select=id" | ForEach-Object { @{ id = $_.id } })
        $units += @{ kind = 'AZAdministrativeUnit'; data = @{ id = $au.id; displayName = $au.displayName; members = $members } }
    }
    Write-Json 'administrative_units_azure.json' @{ meta = @{ type = 'azure'; version = 5; count = $units.Count }; data = @($units) }
    $m = "ok   administrative_units_azure.json ($($units.Count) units)"
} catch { $m = "FAIL administrative_units_azure.json : $($_.Exception.Message)" }
Write-Host $m; Add-Content $log $m

Disconnect-MgGraph | Out-Null
Write-Host "Done. Files and export-log.txt are in $OutDir"
