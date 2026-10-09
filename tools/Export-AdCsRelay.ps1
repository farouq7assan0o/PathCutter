<#
.SYNOPSIS
  Collects the two AD CS NTLM-relay facts that SharpHound does not: web enrollment (ESC8) and RPC encryption (ESC11).

.DESCRIPTION
  For every Enterprise CA published in Active Directory it records
    * WebEnrollment : is the /certsrv endpoint reachable over HTTP and/or HTTPS with NTLM/Negotiate, and (HTTPS) the IIS
                      Extended Protection setting (Off / Allowed / Required, or Unknown when it could not be read)
    * RpcEncryptionEnforced : the IF_ENFORCEENCRYPTICERTREQUEST (0x200) bit of the CA's InterfaceFlags registry value
  and (ESC16) whether the CA's policy module lists the security extension in DisableExtensionList,
  and writes <prefix>_adcsrelay.json. Put that file in the same folder or ZIP as the SharpHound export; PathCutter reads it
  and derives ADCSESC8 / ADCSESC11 edges. Read-only: it makes unauthenticated HTTP requests and reads remote registry / IIS
  configuration. A value it could not read is written as null / "Unknown" and is never guessed.

.EXAMPLE
  .\Export-AdCsRelay.ps1 -OutDir C:\collect
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Get-Location).Path,
    [string]$Prefix = (Get-Date -Format 'yyyyMMddHHmmss'),
    [int]$TimeoutSec = 8
)
$ErrorActionPreference = 'Stop'

function Get-Challenge([string]$Url) {
    # an unauthenticated request: a 401 that offers NTLM or Negotiate means the endpoint accepts relayed authentication
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Timeout = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $false
        $req.ServerCertificateValidationCallback = { $true }
        $resp = $req.GetResponse(); $resp.Close(); return $false
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($null -eq $r) { return $false }
        $auth = [string]$r.Headers['WWW-Authenticate']
        return ($r.StatusCode -eq 401 -and $auth -match 'NTLM|Negotiate')
    } catch { return $false }
}

function Get-Epa([string]$HostName) {
    try {
        $v = Invoke-Command -ComputerName $HostName -ErrorAction Stop -ScriptBlock {
            Import-Module WebAdministration
            (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/CertSrv' `
                -Filter 'system.webServer/security/authentication/windowsAuthentication/extendedProtection' -Name tokenChecking).ToString()
        }
        switch -Regex ($v) { 'Require' { return 'Required' } 'Allow' { return 'Allowed' } 'None' { return 'Off' } default { return 'Unknown' } }
    } catch { return 'Unknown' }
}

function Get-InterfaceFlags([string]$HostName, [string]$CaName) {
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $HostName)
        $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName")
        $val = $key.GetValue('InterfaceFlags')
        if ($null -eq $val) { return $null }
        return [int]$val
    } catch { return $null }
}

function Get-SecurityExtensionDisabled([string]$HostName, [string]$CaName) {
    # ESC16: the CA policy module lists 1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT) among the extensions it does not add
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $HostName)
        $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
        $list = $key.GetValue('DisableExtensionList')
        if ($null -eq $list) { return $false }
        return [bool]($list -contains '1.3.6.1.4.1.311.25.2')
    } catch { return $null }
}

$config = ([ADSI]'LDAP://RootDSE').configurationNamingContext
$searcher = [adsisearcher]"(objectClass=pKIEnrollmentService)"
$searcher.SearchRoot = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$config"
$out = @()
foreach ($ca in $searcher.FindAll()) {
    $name = [string]$ca.Properties['cn'][0]
    $hostName = [string]$ca.Properties['dnshostname'][0]
    Write-Host "CA $name on $hostName"
    $http = Get-Challenge "http://$hostName/certsrv/"
    $https = Get-Challenge "https://$hostName/certsrv/"
    $epa = if ($https) { Get-Epa $hostName } else { 'Unknown' }
    $flags = Get-InterfaceFlags $hostName $name
    $out += [ordered]@{
        CA = $name
        Host = $hostName
        WebEnrollment = [ordered]@{ Collected = $true; Http = $http; Https = $https; ExtendedProtection = $epa }
        RpcEncryptionEnforced = $(if ($null -eq $flags) { $null } else { [bool]($flags -band 0x200) })
        InterfaceFlags = $flags
        SecurityExtensionDisabled = Get-SecurityExtensionDisabled $hostName $name
    }
}
$doc = [ordered]@{ meta = [ordered]@{ type = 'adcsrelay'; version = 1; count = $out.Count }; data = $out }
$path = Join-Path $OutDir "${Prefix}_adcsrelay.json"
$doc | ConvertTo-Json -Depth 6 | Set-Content -Path $path -Encoding UTF8
Write-Host "Wrote $path"
