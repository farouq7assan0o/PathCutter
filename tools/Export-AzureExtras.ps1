<#
.SYNOPSIS
  Read-only posture checks through the signed-in Azure CLI (`az login` first): network exposure, storage, Defender plans,
  tenant-wide Entra settings, credential expiry, OAuth consent grants.

.DESCRIPTION
  Every call is a GET / list. Nothing is changed. A call that is not permitted for your account is logged and skipped.
  Output: one JSON file per check in -OutDir, a summary table on screen and findings.txt with what looks risky.
  Works in Windows PowerShell 5.1 and PowerShell 7. Needs only Azure CLI.

.EXAMPLE
  az login --tenant <tenant-id> --use-device-code
  .\Export-AzureExtras.ps1 -OutDir D:\collect\extra
#>
[CmdletBinding()]
param([string]$OutDir = (Join-Path (Get-Location).Path 'azure-extras'))
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir 'export-log.txt'
Set-Content $log "Export-AzureExtras $(Get-Date -Format s)"
$findings = New-Object System.Collections.ArrayList
function Add-Finding([string]$Sev, [string]$Text) { [void]$findings.Add("[$Sev] $Text") }

function Save-Az([string]$Name, [string[]]$AzArgs) {
    $raw = & az @AzArgs 2>&1
    $text = ($raw | Out-String)
    if ($LASTEXITCODE -ne 0 -or $text -match '^\s*(ERROR|WARNING: .*ERROR)') {
        $msg = "FAIL $Name : " + (($text -split "`n" | Select-Object -First 2) -join ' ').Trim()
        Write-Host $msg; Add-Content $log $msg; return $null
    }
    [System.IO.File]::WriteAllText((Join-Path $OutDir "$Name.json"), $text, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "ok   $Name"; Add-Content $log "ok   $Name"
    try { return ($text | ConvertFrom-Json) } catch { return $null }
}

function Get-Rest([string]$Name, [string]$Url, [string[]]$Extra = @()) {
    return Save-Az $Name (@('rest', '--method', 'get', '--url', $Url) + $Extra)
}

$null = & az account show 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Run `az login` first.' }
$g = 'https://graph.microsoft.com/v1.0'

# ---- Azure resources -------------------------------------------------------------------------------------------------
$vms = Save-Az 'vms' @('vm', 'list', '-d', '-o', 'json')
$nsgs = Save-Az 'nsgs' @('network', 'nsg', 'list', '-o', 'json')
$pips = Save-Az 'public_ips' @('network', 'public-ip', 'list', '-o', 'json')
$stor = Save-Az 'storage_accounts' @('storage', 'account', 'list', '-o', 'json')
$null = Save-Az 'keyvaults' @('keyvault', 'list', '-o', 'json')
$null = Save-Az 'role_assignments_all' @('role', 'assignment', 'list', '--all', '--include-inherited', '-o', 'json')
$null = Save-Az 'role_definitions_custom' @('role', 'definition', 'list', '--custom-role-only', 'true', '-o', 'json')
$defender = Save-Az 'defender_plans' @('security', 'pricing', 'list', '-o', 'json')
$null = Save-Az 'resources' @('resource', 'list', '-o', 'json')
$null = Save-Az 'policy_assignments' @('policy', 'assignment', 'list', '-o', 'json')

foreach ($v in @($vms)) {
    if ($v -and $v.publicIps) { Add-Finding 'high' "VM $($v.name) has a public IP ($($v.publicIps))" }
    if ($v -and $v.identity -and $v.identity.type) { Add-Finding 'info' "VM $($v.name) has a managed identity ($($v.identity.type)): whoever controls the VM acts as it" }
}
foreach ($n in @($nsgs)) {
    foreach ($r in @($n.securityRules)) {
        if ($r.access -eq 'Allow' -and $r.direction -eq 'Inbound' -and $r.sourceAddressPrefix -in '*', 'Internet', '0.0.0.0/0') {
            $port = "$($r.destinationPortRange) $($r.destinationPortRanges -join ',')"
            $sev = if ($port -match '(^|\D)(22|3389|5985|5986|445)(\D|$)|\*') { 'high' } else { 'medium' }
            Add-Finding $sev "NSG $($n.name) rule $($r.name) allows $port from any source"
        }
    }
}
foreach ($s in @($stor)) {
    if ($s.allowBlobPublicAccess) { Add-Finding 'medium' "Storage account $($s.name) allows public blob access" }
    if ($s.minimumTlsVersion -and $s.minimumTlsVersion -ne 'TLS1_2') { Add-Finding 'low' "Storage account $($s.name) minimum TLS is $($s.minimumTlsVersion)" }
}
foreach ($p in @($defender)) {
    if ($p.pricingTier -eq 'Free' -and $p.name -in 'VirtualMachines', 'KeyVaults', 'StorageAccounts', 'AppServices', 'Arm') {
        Add-Finding 'low' "Defender for Cloud plan $($p.name) is on the Free tier (no protection)"
    }
}

# ---- Entra: tenant-wide settings (Directory.AccessAsUser covers these for an administrator) -----------------------------
$sec = Get-Rest 'security_defaults' "$g/policies/identitySecurityDefaultsEnforcementPolicy"
if ($sec -and $sec.isEnabled -eq $false) { Add-Finding 'info' 'Security defaults are off (expected when Conditional Access is used)' }
$auth = Get-Rest 'authorization_policy' "$g/policies/authorizationPolicy"
if ($auth) {
    if ($auth.allowInvitesFrom -eq 'everyone') { Add-Finding 'medium' 'Anyone, including guests, can invite external users (allowInvitesFrom = everyone)' }
    if ($auth.defaultUserRolePermissions.allowedToCreateApps) { Add-Finding 'low' 'Every user can register applications' }
    if ($auth.defaultUserRolePermissions.allowedToCreateSecurityGroups) { Add-Finding 'info' 'Every user can create security groups' }
    if ($auth.allowUserConsentForRiskyApps) { Add-Finding 'high' 'Users can consent to risky applications' }
}
$null = Get-Rest 'named_locations' "$g/identity/conditionalAccess/namedLocations"
$guests = Get-Rest 'guest_users' "$g/users?`$filter=userType eq 'Guest'&`$select=displayName,userPrincipalName,createdDateTime,accountEnabled&`$top=999" @('--headers', 'ConsistencyLevel=eventual')
if ($guests -and @($guests.value).Count -gt 0) { Add-Finding 'info' "$(@($guests.value).Count) guest account(s) in the tenant" }

$apps = Get-Rest 'application_credentials' "$g/applications?`$select=displayName,appId,passwordCredentials,keyCredentials,signInAudience&`$top=999"
foreach ($a in @($apps.value)) {
    foreach ($c in @($a.passwordCredentials)) {
        if ($c.endDateTime) {
            $end = [datetime]$c.endDateTime
            if ($end -lt (Get-Date)) { Add-Finding 'low' "App $($a.displayName): client secret expired $($end.ToString('yyyy-MM-dd'))" }
            elseif ($end -gt (Get-Date).AddYears(2)) { Add-Finding 'medium' "App $($a.displayName): client secret valid for more than 2 years (until $($end.ToString('yyyy-MM-dd')))" }
        }
    }
    if ($a.signInAudience -in 'AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount') { Add-Finding 'info' "App $($a.displayName) accepts sign-ins from other tenants ($($a.signInAudience))" }
}
$grants = Get-Rest 'oauth2_permission_grants' "$g/oauth2PermissionGrants?`$top=999"
foreach ($gr in @($grants.value)) {
    if ($gr.consentType -eq 'AllPrincipals' -and $gr.scope -match 'ReadWrite|FullControl|Directory|Mail\.Send|Files') {
        Add-Finding 'medium' "Tenant-wide delegated consent to client $($gr.clientId): $($gr.scope.Trim())"
    }
}

# ---- Entra: things that may be refused for your account (logged, not fatal) ------------------------------------------------
$null = Get-Rest 'mfa_registration' "$g/reports/authenticationMethods/userRegistrationDetails?`$top=999"
$null = Get-Rest 'signins_recent' "$g/auditLogs/signIns?`$top=50"
$null = Get-Rest 'directory_audits_recent' "$g/auditLogs/directoryAudits?`$top=50"

$out = Join-Path $OutDir 'findings.txt'
$sorted = @($findings | Sort-Object { switch -Regex ($_) { '^\[high\]' { 0 } '^\[medium\]' { 1 } '^\[low\]' { 2 } default { 3 } } })
Set-Content $out $sorted
Write-Host ''
Write-Host "Findings ($($sorted.Count)):"
$sorted | ForEach-Object { Write-Host "  $_" }
Write-Host ''
Write-Host "Files and export-log.txt are in $OutDir"
