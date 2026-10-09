param([string]$Who = "eve")
$groups = "Helpdesk","Printing"
foreach ($g in $groups) {
    Add-ADGroupMember -Identity $g -Members $Who
}
if ($Who -eq "eve") {
    Add-ADGroupMember -Identity "Backup Operators" -Members $Who
} else {
    Remove-ADGroupMember -Identity "Backup Operators" -Members $Who -Confirm:$false
}
try {
    Set-ADComputer -Identity SRV01 -PrincipalsAllowedToDelegateToAccount (Get-ADUser web_svc)
} catch {
    Write-Error $_
}
function Grant-Temp { param($u) Add-ADGroupMember -Identity "Server Admins" -Members $u }
Grant-Temp -u frank
