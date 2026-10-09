<#
.SYNOPSIS
  Collects the user-rights assignments (Privilege Rights) that Group Policy security templates grant to principals.

.DESCRIPTION
  SharpHound reads the local-group part of a GPO but not its [Privilege Rights] section. This script reads every
  GptTmpl.inf under SYSVOL (read access for any domain user is enough), keeps only the rights that let a holder become
  SYSTEM on a computer -- SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege,
  SeLoadDriverPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeSyncAgentPrivilege -- resolves each account name to a
  SID, and writes <prefix>_gporights.json. Put it next to the SharpHound export; PathCutter derives GPOUserRight edges to
  the computers each GPO applies to. Read-only. A name that cannot be resolved is skipped and listed on screen.

.EXAMPLE
  .\Export-AdGpoRights.ps1 -OutDir C:\collect
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Get-Location).Path,
    [string]$Prefix = (Get-Date -Format 'yyyyMMddHHmmss'),
    [string]$Domain = $env:USERDNSDOMAIN
)
$ErrorActionPreference = 'Stop'
$wanted = 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeDebugPrivilege',
          'SeLoadDriverPrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeSyncAgentPrivilege'

function Resolve-Principal([string]$Token) {
    $t = $Token.Trim()
    if ($t.StartsWith('*')) { return $t.Substring(1) }                       # already a SID
    try { return ([System.Security.Principal.NTAccount]$t).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { Write-Warning "cannot resolve '$t'"; return $null }
}

$root = "\\$Domain\SYSVOL\$Domain\Policies"
$out = @()
foreach ($dir in Get-ChildItem -Path $root -Directory -ErrorAction Stop) {
    $inf = Join-Path $dir.FullName 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (-not (Test-Path $inf)) { continue }
    $section = ''
    $rights = [ordered]@{}
    foreach ($line in Get-Content -Path $inf -Encoding Unicode) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1]; continue }
        if ($section -ne 'Privilege Rights') { continue }
        if ($line -match '^\s*(Se\w+)\s*=\s*(.*)$' -and $wanted -contains $Matches[1]) {
            $sids = @($Matches[2].Split(',') | Where-Object { $_.Trim() } | ForEach-Object { Resolve-Principal $_ } | Where-Object { $_ })
            if ($sids.Count) { $rights[$Matches[1]] = $sids }
        }
    }
    if ($rights.Count) { $out += [ordered]@{ GPO = $dir.Name.Trim('{}'); Rights = $rights } }
}
$doc = [ordered]@{ meta = [ordered]@{ type = 'gporights'; version = 1; count = $out.Count }; data = $out }
$path = Join-Path $OutDir "${Prefix}_gporights.json"
$doc | ConvertTo-Json -Depth 6 | Set-Content -Path $path -Encoding UTF8
Write-Host "Wrote $path ($($out.Count) GPOs grant a dangerous privilege)"
