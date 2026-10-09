$cred = Get-Credential
Invoke-Command -ComputerName DC01 -ScriptBlock { Add-ADGroupMember -Identity "Domain Admins" -Members kim }
Add-ADGroupMember -Identity "Helpdesk" -Members $env:TARGETUSER
Add-ADGroupMember -Identity (Get-Content groups.txt) -Members leo
net group "Domain Admins" mike /add /domain
Add-ADGroupMember -Identity "Helpdesk" -Members nina -WhatIf
