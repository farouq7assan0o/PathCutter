dsacls "CN=Svc Backup,OU=Svc,DC=corp,DC=local" /G "CORP\helpdesk:GA"
dsacls "CN=Svc Backup,OU=Svc,DC=corp,DC=local" /D "CORP\interns:WP;member"
$acl = Get-Acl "AD:\CN=Svc Backup,OU=Svc,DC=corp,DC=local"
$id = New-Object System.Security.Principal.NTAccount("CORP","jane")
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($id, "WriteDacl", "Allow")
$acl.AddAccessRule($rule)
Set-Acl "AD:\CN=Svc Backup,OU=Svc,DC=corp,DC=local" $acl
