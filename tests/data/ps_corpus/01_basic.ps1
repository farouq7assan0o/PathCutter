# Add-ADGroupMember -Identity "Domain Admins" -Members mallory   (commented out: must NOT be analyzed)
Import-Module ActiveDirectory
Add-ADGroupMember -Identity "Helpdesk" -Members "alice","bob"
Remove-ADGroupMember -Identity "Helpdesk" -Members carol -Confirm:$false
Add-ADPrincipalGroupMembership -Identity dave -MemberOf "IT Admins"
Set-ADUser -Identity svc_sql -ServicePrincipalNames @{Add="MSSQLSvc/db01:1433"}
$text = @"
Add-ADGroupMember -Identity "Enterprise Admins" -Members mallory
"@
Write-Host "Add-ADGroupMember -Identity x -Members y"
