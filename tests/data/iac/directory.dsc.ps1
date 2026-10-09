Configuration DirectoryState {
    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName PSDscResources

    Node 'DC01' {
        ADGroup 'Helpdesk' {
            GroupName        = 'Helpdesk'
            MembersToInclude = @('alice', 'bob')
            MembersToExclude = 'eve'
            Ensure           = 'Present'
        }

        ADUser 'NewHire' {
            UserName = 'newhire'
            Ensure   = 'Present'
        }

        ADGroup 'Gone' {
            GroupName = 'Legacy'
            Ensure    = 'Absent'
        }

        ADGroup 'Exact' {
            GroupName = 'Auditors'
            Members   = @('hank')
        }

        ADGroup 'Computed' {
            GroupName        = 'Printers'
            MembersToInclude = $Config.Printers
        }

        ADObjectPermissionEntry 'HelpdeskOnSvc' {
            Path                  = 'CN=Svc Backup,OU=Svc,DC=corp,DC=local'
            IdentityReference     = 'CORP\helpdesk'
            ActiveDirectoryRights = 'GenericAll'
            AccessControlType     = 'Allow'
            Ensure                = 'Present'
        }

        ADObjectPermissionEntry 'DenyInterns' {
            Path                  = 'CN=Svc Backup,OU=Svc,DC=corp,DC=local'
            IdentityReference     = 'CORP\interns'
            ActiveDirectoryRights = 'GenericAll'
            AccessControlType     = 'Deny'
            Ensure                = 'Present'
        }

        WindowsFeature 'AD' { Name = 'AD-Domain-Services' }
    }

    Node @('SRV01', 'SRV02') {
        Group 'LocalAdmins' {
            GroupName        = 'Administrators'
            MembersToInclude = @('CORP\helpdesk')
            Ensure           = 'Present'
        }
    }

    Node $AllNodes.NodeName {
        Group 'Everywhere' {
            GroupName        = 'Administrators'
            MembersToInclude = 'CORP\ops'
        }
    }
}
