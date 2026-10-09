Get-ADGroupMember -Identity "Contractors" | ForEach-Object {
    Add-ADGroupMember -Identity "VPN Users" -Members $_
}
$p = @{
    Identity = "Helpdesk"
    Members  = "gina", "hank"
}
Add-ADGroupMember @p
Get-ADUser -Filter 'Department -eq "IT"' | Add-ADPrincipalGroupMembership -MemberOf "IT Admins"
Add-ADGroupMember -Identity `
    "Account Operators" `
    -Members ivan
