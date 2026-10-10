<#
.SYNOPSIS
  Collects the host-side data an LDAP snapshot cannot: local-group membership (admins / RDP / DCOM / PSRemote) and
  logged-on users. Plain built-in cmdlets only, so endpoint protection does not flag it (unlike SharpHound).

.DESCRIPTION
  Run it LOCALLY on each domain computer you can reach (RDP in and run), or let it try the domain computers remotely
  (needs admin + WinRM/remote access). Each host appends one record to <OutDir>\<prefix>_localsessions.json. Give that
  file to PathCutter alongside the AD Explorer NDJSON folder; it adds AdminTo / CanRDP / ExecuteDCOM / CanPSRemote /
  HasSession edges. Read-only.

.PARAMETER Computers
  Optional list of hostnames to collect from remotely. Omit to collect from THIS machine only.

.EXAMPLE
  .\Export-AdLocalSessions.ps1 -OutDir C:\collect\ad                      # this host
  .\Export-AdLocalSessions.ps1 -OutDir C:\collect\ad -Computers dc01,nurse-pc
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Get-Location).Path,
    [string]$Prefix = (Get-Date -Format 'yyyyMMddHHmmss'),
    [string[]]$Computers
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$path = Join-Path $OutDir "${Prefix}_localsessions.json"

function Get-HostRecord {
    $groups = @{ 'Administrators' = 'LocalAdmins'; 'Remote Desktop Users' = 'RemoteDesktopUsers';
                 'Distributed COM Users' = 'DcomUsers'; 'Remote Management Users' = 'PSRemoteUsers' }
    $rec = [ordered]@{ Computer = $env:COMPUTERNAME; FQDN = ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName;
                       LocalAdmins = @(); RemoteDesktopUsers = @(); DcomUsers = @(); PSRemoteUsers = @(); Sessions = @() }
    foreach ($g in $groups.Keys) {
        try {
            $rec[$groups[$g]] = @(Get-LocalGroupMember -Group $g -ErrorAction Stop |
                ForEach-Object { if ($_.SID) { $_.SID.Value } } | Where-Object { $_ -like 'S-1-5-21-*' })
        } catch {}
    }
    # logged-on users: interactive + remote sessions mapped to SIDs
    try {
        $sids = @()
        foreach ($s in (Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop)) {
            $acct = $s.Antecedent
            if ($acct.Domain -and $acct.Name -and $acct.Name -notmatch '\$$') {
                try { $sids += (New-Object System.Security.Principal.NTAccount($acct.Domain, $acct.Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
            }
        }
        $rec.Sessions = @($sids | Where-Object { $_ -like 'S-1-5-21-*' } | Select-Object -Unique)
    } catch {}
    return $rec
}

$records = @()
if ($Computers) {
    foreach ($c in $Computers) {
        try { $records += Invoke-Command -ComputerName $c -ScriptBlock ${function:Get-HostRecord} -ErrorAction Stop }
        catch { Write-Warning "remote $c failed (need admin + WinRM): $($_.Exception.Message)" }
    }
} else {
    $records += Get-HostRecord
}

# merge into an existing file so running on several hosts accumulates
$existing = @()
if (Test-Path $path) { try { $existing = @(Get-Content $path -Raw | ConvertFrom-Json).data } catch {} }
$byname = @{}
foreach ($r in @($existing) + @($records)) { if ($r.Computer) { $byname[$r.Computer] = $r } }
$doc = [ordered]@{ meta = [ordered]@{ type = 'localsessions'; version = 1; count = $byname.Count }; data = @($byname.Values) }
$doc | ConvertTo-Json -Depth 6 | Set-Content -Path $path -Encoding UTF8
Write-Host "Wrote $path ($($byname.Count) host(s))"
