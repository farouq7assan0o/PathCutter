<#
.SYNOPSIS
    Collects Deny ACEs from Active Directory for PathCutter. READ-ONLY: it changes nothing.

.DESCRIPTION
    SharpHound/BloodHound collect Allow ACEs only. A Deny ACE can quietly cancel an Allow for the denied
    principal's token, so PathCutter can model it only if you collect it. This script reads the DACL of every
    user, group, computer, OU, container, GPO and domain object and writes the Deny entries that matter for
    attack paths to <timestamp>_denies.json. Put that file in the SharpHound ZIP or folder you give to PathCutter.

    Needs only normal authenticated-user read access to the directory (the same access SharpHound uses).

.PARAMETER SearchBase
    Distinguished name to start from. Default: the domain root of the current user's domain.

.PARAMETER Server
    A domain controller to query. Default: the nearest one.

.PARAMETER OutFile
    Output path. Default: .\<timestamp>_denies.json

.PARAMETER SelfTest
    Run the built-in offline checks of the right mapping (no directory needed) and exit.

.EXAMPLE
    .\Export-AdDenyAces.ps1
    pathcutter doctor export.zip   # after adding the *_denies.json next to the SharpHound files
#>
[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$Server,
    [string]$OutFile = (Join-Path (Get-Location) ((Get-Date).ToString('yyyyMMddHHmmss') + '_denies.json')),
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# schema / extended-right GUIDs that map to PathCutter edges
# BEGIN GENERATED (tools/gen_collector_table.py from pathcutter/data/rights.json)
$Ids = @{
    Member             = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    Spn                = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    Rbcd               = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    KeyCredentialLink  = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    ForceChangePwd     = '00299570-246d-11d0-a768-00aa006e0529'
    GetChanges         = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    GetChangesAll      = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    GetChangesFiltered = '89e95b76-444d-4c62-991a-0facbeda640c'
}
# END GENERATED

function Convert-DenyRule {
    <# Maps one ActiveDirectoryAccessRule (Deny) to the PathCutter right names it blocks. #>
    param([Parameter(Mandatory)]$Rule)
    $rights = $Rule.ActiveDirectoryRights.ToString()
    $type = if ($Rule.ObjectType -and $Rule.ObjectType -ne [Guid]::Empty) { $Rule.ObjectType.ToString().ToLowerInvariant() } else { '' }
    $out = New-Object System.Collections.Generic.List[string]
    if ($rights -match 'GenericAll')   { $out.Add('GenericAll') }
    if ($rights -match 'GenericWrite') { $out.Add('GenericWrite') }
    if ($rights -match 'WriteDacl')    { $out.Add('WriteDacl') }
    if ($rights -match 'WriteOwner')   { $out.Add('WriteOwner') }
    if ($rights -match 'ExtendedRight') {
        switch ($type) {
            ''                          { $out.Add('AllExtendedRights') }
            ($Ids.ForceChangePwd)        { $out.Add('ForceChangePassword') }
            ($Ids.GetChanges)            { $out.Add('GetChanges') }
            ($Ids.GetChangesAll)         { $out.Add('GetChangesAll') }
            ($Ids.GetChangesFiltered)    { $out.Add('GetChangesInFilteredSet') }
        }
    }
    if ($rights -match 'WriteProperty') {
        switch ($type) {
            ''                          { $out.Add('GenericWrite') }
            ($Ids.Member)                { $out.Add('AddMember') }
            ($Ids.Spn)                   { $out.Add('WriteSPN') }
            ($Ids.Rbcd)                  { $out.Add('AddAllowedToAct') }
            ($Ids.KeyCredentialLink)     { $out.Add('AddKeyCredentialLink') }
        }
    }
    if ($rights -match 'Self' -and $type -eq $Ids.Member) { $out.Add('AddSelf') }
    return ,($out | Select-Object -Unique)
}

function Get-DenyRecords {
    param([string]$ObjectId, [byte[]]$SecurityDescriptor)
    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm($SecurityDescriptor)
    foreach ($rule in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Deny') { continue }
        foreach ($right in (Convert-DenyRule $rule)) {
            [ordered]@{
                PrincipalSID     = $rule.IdentityReference.Value
                RightName        = $right
                ObjectIdentifier = $ObjectId
                IsInherited      = [bool]$rule.IsInherited
            }
        }
    }
}

if ($SelfTest) {
    $fail = 0
    function Assert-Rights($rights, $guid, $expected) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-21-1-2-3-1001')
        $g = if ($guid) { [Guid]$guid } else { [Guid]::Empty }
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, 'Deny', $g)
        $got = (Convert-DenyRule $rule) -join ','
        if ($got -ne $expected) { Write-Host "FAIL $rights/$guid -> '$got' (expected '$expected')"; $script:fail++ }
    }
    Assert-Rights 'GenericAll' $null 'GenericAll'
    Assert-Rights 'WriteDacl' $null 'WriteDacl'
    Assert-Rights 'ExtendedRight' $null 'AllExtendedRights'
    Assert-Rights 'ExtendedRight' $Ids.ForceChangePwd 'ForceChangePassword'
    Assert-Rights 'ExtendedRight' $Ids.GetChangesAll 'GetChangesAll'
    Assert-Rights 'WriteProperty' $Ids.Member 'AddMember'
    Assert-Rights 'WriteProperty' $Ids.KeyCredentialLink 'AddKeyCredentialLink'
    Assert-Rights 'WriteProperty' $null 'GenericWrite'
    Assert-Rights 'Self' $Ids.Member 'AddSelf'
    Assert-Rights 'ReadProperty' $null ''
    # end to end on a real security descriptor: one Allow (ignored) and one Deny on the member property
    $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-21-1-2-3-1001')
    $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'GenericAll', 'Allow')))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'WriteProperty', 'Deny', [Guid]$Ids.Member)))
    $recs = @(Get-DenyRecords -ObjectId 'S-1-5-21-1-2-3-1002' -SecurityDescriptor $acl.GetSecurityDescriptorBinaryForm())
    if ($recs.Count -ne 1 -or $recs[0].RightName -ne 'AddMember' -or $recs[0].PrincipalSID -ne 'S-1-5-21-1-2-3-1001' -or $recs[0].ObjectIdentifier -ne 'S-1-5-21-1-2-3-1002') {
        Write-Host 'FAIL end-to-end descriptor test'; $fail++
    }
    if ($fail) { Write-Host "SELFTEST FAILED ($fail)"; exit 1 }
    Write-Host 'SELFTEST OK'
    return
}

if (-not $SearchBase) { $SearchBase = ([adsi]'LDAP://RootDSE').defaultNamingContext.ToString() }
$prefix = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }
$root = New-Object System.DirectoryServices.DirectoryEntry($prefix + $SearchBase)
$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
$searcher.Filter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)' +
                   '(objectClass=domainDNS)(objectClass=container)(objectClass=groupPolicyContainer))'
$searcher.PageSize = 1000
$searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
[void]$searcher.PropertiesToLoad.AddRange(@('objectsid', 'objectguid', 'ntsecuritydescriptor'))

$records = New-Object System.Collections.Generic.List[object]
$scanned = 0
foreach ($r in $searcher.FindAll()) {
    $scanned++
    $p = $r.Properties
    if (-not $p['ntsecuritydescriptor'] -or $p['ntsecuritydescriptor'].Count -eq 0) { continue }
    $id = if ($p['objectsid'] -and $p['objectsid'].Count) {
        (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$p['objectsid'][0], 0)).Value
    } else {
        ([Guid][byte[]]$p['objectguid'][0]).ToString().ToUpperInvariant()
    }
    foreach ($rec in (Get-DenyRecords -ObjectId $id -SecurityDescriptor ([byte[]]$p['ntsecuritydescriptor'][0]))) { $records.Add($rec) }
    if ($scanned % 5000 -eq 0) { Write-Progress -Activity 'Reading ACLs' -Status "$scanned objects, $($records.Count) deny entries" }
}

$doc = [ordered]@{
    meta = [ordered]@{ type = 'denies'; version = 1; count = $records.Count; collector = 'Export-AdDenyAces.ps1'; searchbase = $SearchBase }
    data = $records
}
$doc | ConvertTo-Json -Depth 5 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Scanned $scanned objects; $($records.Count) Deny entries written to $OutFile"
Write-Host 'Add that file to your SharpHound ZIP/folder; PathCutter reads it automatically.'
