"""Edge type registry - every AD attack relationship with abuse info, MITRE mapping, and fix templates."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EdgeCategory(Enum):
    ACL = "acl"
    DELEGATION = "delegation"
    GROUP = "group"
    SESSION = "session"
    DOMAIN = "domain"
    SPECIAL = "special"


@dataclass(frozen=True, slots=True)
class EdgeType:
    name: str
    category: EdgeCategory
    abuse: str
    mitre: str
    exploitability: int  # 1-10, higher = easier to exploit
    fix_template: str
    detection_difficulty: str  # low, medium, high (how hard to detect the abuse)
    reversible: bool  # can the fix be safely rolled back?
    description: str = ""


# ACL-based edges
GenericAll = EdgeType(
    name="GenericAll",
    category=EdgeCategory.ACL,
    abuse="Full control over object - change password, write any attribute, modify DACL",
    mitre="T1222.001",
    exploitability=9,
    fix_template='$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
    description="Grants all permissions including password reset, attribute writes, and DACL modification",
)

GenericWrite = EdgeType(
    name="GenericWrite",
    category=EdgeCategory.ACL,
    abuse="Write any attribute - set SPN for kerberoasting, write scriptPath for code execution",
    mitre="T1222.001",
    exploitability=8,
    fix_template='$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ActiveDirectoryRights -match "WriteProperty"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

WriteOwner = EdgeType(
    name="WriteOwner",
    category=EdgeCategory.ACL,
    abuse="Take ownership of object, then WriteDACL to grant yourself GenericAll",
    mitre="T1222.001",
    exploitability=8,
    fix_template='$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ActiveDirectoryRights -match "WriteOwner"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="high",
    reversible=True,
)

WriteDacl = EdgeType(
    name="WriteDacl",
    category=EdgeCategory.ACL,
    abuse="Modify the DACL to grant yourself any permission including GenericAll",
    mitre="T1222.001",
    exploitability=8,
    fix_template='$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ActiveDirectoryRights -match "WriteDacl"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

ForceChangePassword = EdgeType(
    name="ForceChangePassword",
    category=EdgeCategory.ACL,
    abuse="Reset target user's password without knowing the current password",
    mitre="T1098",
    exploitability=7,
    fix_template='# Remove Extended Right "User-Force-Change-Password" (GUID: 00299570-246d-11d0-a768-00aa006e0529)\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "00299570-246d-11d0-a768-00aa006e0529"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="low",
    reversible=True,
)

AddMember = EdgeType(
    name="AddMember",
    category=EdgeCategory.ACL,
    abuse="Add attacker-controlled principal to a group, inheriting all group permissions",
    mitre="T1098",
    exploitability=8,
    fix_template='# Remove WriteProperty on member attribute\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "bf9679c0-0de6-11d0-a285-00aa003049e2"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="low",
    reversible=True,
)

Owns = EdgeType(
    name="Owns",
    category=EdgeCategory.ACL,
    abuse="Object owner implicitly has WriteDACL - can grant any permission to self",
    mitre="T1222.001",
    exploitability=7,
    fix_template='# Change owner to Domain Admins\n$acl = Get-Acl "AD:\\{target_dn}"\n$owner = New-Object System.Security.Principal.NTAccount("{{domain}}","Domain Admins")\n$acl.SetOwner($owner)\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="high",
    reversible=True,
)

WriteSPN = EdgeType(
    name="WriteSPN",
    category=EdgeCategory.ACL,
    abuse="Set a Service Principal Name on a user account to enable Kerberoasting",
    mitre="T1558.003",
    exploitability=7,
    fix_template='# Remove WriteProperty on servicePrincipalName attribute\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "f3a64788-5306-11d1-a9c5-0000f80367c1"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

AddAllowedToAct = EdgeType(
    name="AddAllowedToAct",
    category=EdgeCategory.ACL,
    abuse="Configure Resource-Based Constrained Delegation to impersonate any user to target",
    mitre="T1134.001",
    exploitability=7,
    fix_template='# Remove WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

WriteKeyCredentialLink = EdgeType(
    name="WriteKeyCredentialLink",
    category=EdgeCategory.ACL,
    abuse="Shadow Credentials - add key credential to authenticate as target via PKINIT",
    mitre="T1556",
    exploitability=7,
    fix_template='# Remove WriteProperty on msDS-KeyCredentialLink\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "5b47d60f-6090-40b2-9f37-2a4de88f3063"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

# Kerberos delegation edges
UnconstrainedDelegation = EdgeType(
    name="AllowedToDelegate",
    category=EdgeCategory.DELEGATION,
    abuse="Unconstrained delegation - capture and reuse any TGT that authenticates to this host",
    mitre="T1558",
    exploitability=10,
    fix_template='Set-ADComputer -Identity "{target_name}" -TrustedForDelegation $false',
    detection_difficulty="low",
    reversible=True,
    description="Host stores TGTs of all users who authenticate - compromising it yields all their credentials",
)

ConstrainedDelegation = EdgeType(
    name="AllowedToDelegate",
    category=EdgeCategory.DELEGATION,
    abuse="Constrained delegation with protocol transition - S4U2Self + S4U2Proxy to impersonate users to target SPNs",
    mitre="T1134.001",
    exploitability=6,
    fix_template='# Remove constrained delegation SPNs\nSet-ADComputer -Identity "{source_name}" -Clear msDS-AllowedToDelegateTo\n# Or for specific SPN removal:\n# Set-ADComputer -Identity "{source_name}" -Remove @{{\'msDS-AllowedToDelegateTo\'=\'{target_spn}\'}}',
    detection_difficulty="medium",
    reversible=True,
)

RBCD = EdgeType(
    name="AllowedToAct",
    category=EdgeCategory.DELEGATION,
    abuse="Resource-Based Constrained Delegation - impersonate any user to the target service",
    mitre="T1134.001",
    exploitability=7,
    fix_template='# Clear RBCD configuration on target\nSet-ADComputer -Identity "{target_name}" -Clear msDS-AllowedToActOnBehalfOfOtherIdentity',
    detection_difficulty="medium",
    reversible=True,
)

# Group/session edges
MemberOf = EdgeType(
    name="MemberOf",
    category=EdgeCategory.GROUP,
    abuse="Inherits all permissions of the group (transitive through nested groups)",
    mitre="",
    exploitability=0,  # not directly exploitable, just inheritance
    fix_template='Remove-ADGroupMember -Identity "{target_name}" -Members "{source_name}" -Confirm:$false',
    detection_difficulty="low",
    reversible=True,
)

AdminTo = EdgeType(
    name="AdminTo",
    category=EdgeCategory.SESSION,
    abuse="Local administrator on target - full control, credential dumping, lateral movement",
    mitre="T1078",
    exploitability=8,
    fix_template='# Remove from local Administrators group (via GPO is preferred)\n# Restricted Groups or Local Users and Groups GPO:\n# Computer Config > Policies > Windows Settings > Security Settings > Restricted Groups\n# Or directly:\nInvoke-Command -ComputerName "{target_name}" -ScriptBlock {{\n    Remove-LocalGroupMember -Group "Administrators" -Member "{source_name}" -ErrorAction SilentlyContinue\n}}',
    detection_difficulty="low",
    reversible=True,
)

HasSession = EdgeType(
    name="HasSession",
    category=EdgeCategory.SESSION,
    abuse="Computer holds an active session of this user - whoever controls the machine can harvest the user's credentials from memory (edge runs computer -> user)",
    mitre="T1003",
    exploitability=6,
    fix_template='# Implement Administrative Tier Model:\n# Tier 0 accounts only log on to Tier 0 systems (DCs)\n# Tier 1 accounts only log on to Tier 1 systems (servers)\n# Tier 2 accounts only log on to Tier 2 systems (workstations)\n# GPO: Computer Config > Policies > User Rights Assignment > Deny log on locally/through RDP',
    detection_difficulty="low",
    reversible=True,
)

CanRDP = EdgeType(
    name="CanRDP",
    category=EdgeCategory.SESSION,
    abuse="Remote Desktop access to target machine",
    mitre="T1021.001",
    exploitability=5,
    fix_template='Invoke-Command -ComputerName "{target_name}" -ScriptBlock {{\n    Remove-LocalGroupMember -Group "Remote Desktop Users" -Member "{source_name}" -ErrorAction SilentlyContinue\n}}',
    detection_difficulty="low",
    reversible=True,
)

CanPSRemote = EdgeType(
    name="CanPSRemote",
    category=EdgeCategory.SESSION,
    abuse="PowerShell Remoting / WinRM access to target machine",
    mitre="T1021.006",
    exploitability=5,
    fix_template='Invoke-Command -ComputerName "{target_name}" -ScriptBlock {{\n    Remove-LocalGroupMember -Group "Remote Management Users" -Member "{source_name}" -ErrorAction SilentlyContinue\n}}',
    detection_difficulty="low",
    reversible=True,
)

ExecuteDCOM = EdgeType(
    name="ExecuteDCOM",
    category=EdgeCategory.SESSION,
    abuse="DCOM execution rights - lateral movement via MMC20, ShellWindows, ShellBrowserWindow",
    mitre="T1021.003",
    exploitability=5,
    fix_template='Invoke-Command -ComputerName "{target_name}" -ScriptBlock {{\n    Remove-LocalGroupMember -Group "Distributed COM Users" -Member "{source_name}" -ErrorAction SilentlyContinue\n}}',
    detection_difficulty="medium",
    reversible=True,
)

SQLAdmin = EdgeType(
    name="SQLAdmin",
    category=EdgeCategory.SESSION,
    abuse="SQL Server sysadmin role - xp_cmdshell for OS command execution, credential access",
    mitre="T1505",
    exploitability=7,
    fix_template='# Remove sysadmin role in SQL Server:\n# ALTER SERVER ROLE sysadmin DROP MEMBER [{source_name}]',
    detection_difficulty="medium",
    reversible=True,
)

# Domain-level edges
DCSync = EdgeType(
    name="DCSync",
    category=EdgeCategory.DOMAIN,
    abuse="Replicating Directory Changes + Replicating Directory Changes All = dump all domain password hashes",
    mitre="T1003.006",
    exploitability=10,
    fix_template='# Remove Replicating Directory Changes and Replicating Directory Changes All\n$acl = Get-Acl "AD:\\{target_dn}"\n# DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\n# DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and ($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="low",
    reversible=True,
    description="Most critical AD attack - dumps NTDS.dit equivalent remotely. Only DCs should have this right.",
)

GPOControlsObject = EdgeType(
    name="GPOControlsObject",
    category=EdgeCategory.DOMAIN,
    abuse="GPO linked to OU containing target - push scheduled tasks, startup scripts, software installs",
    mitre="T1484.001",
    exploitability=7,
    fix_template='# Restrict GPO edit permissions:\n$gpoAcl = Get-Acl "AD:\\{gpo_dn}"\n$gpoAcl.Access | Where-Object {{$_.IdentityReference -match "{source_name}"}} | ForEach-Object {{$gpoAcl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{gpo_dn}" $gpoAcl',
    detection_difficulty="medium",
    reversible=True,
)

Contains = EdgeType(
    name="Contains",
    category=EdgeCategory.DOMAIN,
    abuse="OU/Container contains objects - used for GPO inheritance mapping",
    mitre="",
    exploitability=0,
    fix_template="",
    detection_difficulty="low",
    reversible=False,
    description="Structural relationship, not directly exploitable",
)

ReadLAPSPassword = EdgeType(
    name="ReadLAPSPassword",
    category=EdgeCategory.DOMAIN,
    abuse="Read the LAPS-managed local administrator password for a computer",
    mitre="T1003",
    exploitability=7,
    fix_template='# Remove ReadProperty on ms-Mcs-AdmPwd (LAPS password attribute)\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "e6a34e1c-14b3-4359-8e30-26b3ee395c7e"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="low",
    reversible=True,
)

ReadGMSAPassword = EdgeType(
    name="ReadGMSAPassword",
    category=EdgeCategory.DOMAIN,
    abuse="Read the Group Managed Service Account password blob",
    mitre="T1003",
    exploitability=7,
    fix_template='# Review msDS-GroupMSAMembership on the gMSA and remove unauthorized readers\nSet-ADServiceAccount -Identity "{target_name}" -PrincipalsAllowedToRetrieveManagedPassword @{{Remove="{source_name}"}}',
    detection_difficulty="medium",
    reversible=True,
)

# ADCS edges (AD Certificate Services - ESC1-ESC8)
Enroll = EdgeType(
    name="Enroll",
    category=EdgeCategory.ACL,
    abuse="Enroll in certificate template - request certs that may allow authentication as another user (ESC1/ESC2)",
    mitre="T1649",
    exploitability=7,
    fix_template='# Remove Enroll permission on the certificate template\n# Review template settings: msPKI-Certificate-Name-Flag should NOT include ENROLLEE_SUPPLIES_SUBJECT\n# certutil -dstemplate "{target_name}" msPKI-Certificate-Name-Flag',
    detection_difficulty="medium",
    reversible=True,
)

AutoEnroll = EdgeType(
    name="AutoEnroll",
    category=EdgeCategory.ACL,
    abuse="Auto-enroll in certificate template - automatically issued vulnerable certificates",
    mitre="T1649",
    exploitability=6,
    fix_template='# Remove AutoEnroll permission on the certificate template\n# Review: certutil -dstemplate "{target_name}"',
    detection_difficulty="high",
    reversible=True,
)

ManageCA = EdgeType(
    name="ManageCA",
    category=EdgeCategory.ACL,
    abuse="Manage CA server - can approve pending requests, enable SAN, issue arbitrary certs (ESC7)",
    mitre="T1649",
    exploitability=9,
    fix_template='# Remove ManageCA permission\ncertutil -config "{target_name}" -setreg ca\\security\\',
    detection_difficulty="medium",
    reversible=True,
)

ManageCertificates = EdgeType(
    name="ManageCertificates",
    category=EdgeCategory.ACL,
    abuse="Approve/deny certificate requests - can approve attacker's pending enrollment (ESC7)",
    mitre="T1649",
    exploitability=8,
    fix_template='# Remove ManageCertificates (Officer) permission from the CA',
    detection_difficulty="medium",
    reversible=True,
)

WritePKIEnrollmentFlag = EdgeType(
    name="WritePKIEnrollmentFlag",
    category=EdgeCategory.ACL,
    abuse="Modify certificate template enrollment flags to enable vulnerable configurations (ESC4)",
    mitre="T1649",
    exploitability=8,
    fix_template='# Remove WriteProperty on msPKI-Enrollment-Flag\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "d15ef7d8-f226-46db-ae79-b34e560bd12c"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

WritePKINameFlag = EdgeType(
    name="WritePKINameFlag",
    category=EdgeCategory.ACL,
    abuse="Modify certificate template name flags to enable ENROLLEE_SUPPLIES_SUBJECT (ESC4)",
    mitre="T1649",
    exploitability=8,
    fix_template='# Remove WriteProperty on msPKI-Certificate-Name-Flag\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "ea1dddc4-60ff-416e-8cc0-17cee534bce7"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

# Trust edges
TrustedBy = EdgeType(
    name="TrustedBy",
    category=EdgeCategory.DOMAIN,
    abuse="Domain trust - can authenticate to the trusting domain, potentially escalate via SID history",
    mitre="T1134.005",
    exploitability=5,
    fix_template="# Domain trusts require careful review before modification\n# Consider: SID Filtering, Selective Authentication, or trust removal",
    detection_difficulty="medium",
    reversible=False,
    description="Modifying trust relationships is high-risk and requires change management",
)

HasSIDHistory = EdgeType(
    name="HasSIDHistory",
    category=EdgeCategory.SPECIAL,
    abuse="Principal carries another principal's SID in its SID history, so access checks treat it as that principal (including Tier 0 ones)",
    mitre="T1134.005",
    exploitability=9,
    fix_template='# Remove the foreign SID from sIDHistory (needs elevated tooling; verify migration is complete first)\nSet-ADUser "{source_name}" -Remove @{{SIDHistory=@("<foreign SID>")}}',
    detection_difficulty="medium",
    reversible=False,
)

WriteGPLink = EdgeType(
    name="WriteGPLink",
    category=EdgeCategory.ACL,
    abuse="Link an attacker-controlled GPO to the OU or domain, applying its settings (scripts, local admins, scheduled tasks) to everything beneath it",
    mitre="T1484.001",
    exploitability=7,
    fix_template='# Remove WriteProperty on gPLink\n$acl = Get-Acl "AD:\\{target_dn}"\n$acl.Access | Where-Object {{$_.IdentityReference -match "{source_name}" -and $_.ObjectType -eq "f30e3bbe-9ff0-11d1-b603-0000f80367c1"}} | ForEach-Object {{$acl.RemoveAccessRule($_)}}\nSet-Acl "AD:\\{target_dn}" $acl',
    detection_difficulty="medium",
    reversible=True,
)

ADCSAbuse = EdgeType(
    name="ADCSAbuse",
    category=EdgeCategory.SPECIAL,
    abuse="Certificate Services misconfiguration (ESC1-ESC13 class) lets the principal obtain a certificate that authenticates as a privileged identity",
    mitre="T1649",
    exploitability=9,
    fix_template="# Review the certificate template / CA configuration for the ESC technique that produced this edge\n# (e.g. disable ENROLLEE_SUPPLIES_SUBJECT, require manager approval, restrict enrollment rights)",
    detection_difficulty="medium",
    reversible=True,
)

ADCSESC1 = EdgeType(
    name="ADCSESC1",
    category=EdgeCategory.SPECIAL,
    abuse="Enroll in a template that lets the requester name any subject and allows client authentication, then authenticate as any domain principal, including Domain Admins (ESC1)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate template / CA configuration that produces this edge (disable ENROLLEE_SUPPLIES_SUBJECT, require manager approval or authorized signatures, or restrict who can enroll). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template and CA data, not collected directly",
)

ADCSESC4 = EdgeType(
    name="ADCSESC4",
    category=EdgeCategory.SPECIAL,
    abuse="Control a published certificate template, turn it into an ESC1 template, enroll, and authenticate as any domain principal (ESC4)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate template / CA configuration that produces this edge (remove write/owner rights on the template from non-admin principals). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template and CA data, not collected directly",
)

ADCSESC6 = EdgeType(
    name="ADCSESC6",
    category=EdgeCategory.SPECIAL,
    abuse="Enroll in any client-authentication template on a CA that accepts a requester-supplied subject alternative name (EDITF_ATTRIBUTESUBJECTALTNAME2), and authenticate as any domain principal (ESC6)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate template / CA configuration that produces this edge (clear EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template and CA data, not collected directly",
)

ADCSESC7 = EdgeType(
    name="ADCSESC7",
    category=EdgeCategory.SPECIAL,
    abuse="Hold ManageCA or ManageCertificates on a trusted CA: enable the SAN flag or approve pending requests, then obtain a certificate for any domain principal (ESC7)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate template / CA configuration that produces this edge (remove ManageCA / ManageCertificates from non-admin principals). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template and CA data, not collected directly",
)

ADCSESC3 = EdgeType(
    name="ADCSESC3",
    category=EdgeCategory.SPECIAL,
    abuse="Use an enrollment-agent certificate to request a client-authentication certificate on behalf of any user, then authenticate as them (ESC3)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate configuration that produces this edge (restrict the agent template and set enrollment agent restrictions on the CA). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template, CA and domain controller data, not collected directly",
)

ADCSESC5 = EdgeType(
    name="ADCSESC5",
    category=EdgeCategory.SPECIAL,
    abuse="Control a PKI object (NTAuth store or enterprise CA object): trust a rogue CA or publish a vulnerable template, then obtain certificates for any principal (ESC5)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate configuration that produces this edge (remove write/owner rights on PKI objects from non-admin principals). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template, CA and domain controller data, not collected directly",
)

GoldenCert = EdgeType(
    name="GoldenCert",
    category=EdgeCategory.SPECIAL,
    abuse="Administer the host of a trusted CA: extract the CA private key and forge a certificate for any principal (golden certificate)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate configuration that produces this edge (treat the CA host as Tier 0 and remove non-admin local administrators). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template, CA and domain controller data, not collected directly",
)

ADCSESC9 = EdgeType(
    name="ADCSESC9",
    category=EdgeCategory.SPECIAL,
    abuse="Change a victim account's UPN and enroll in a template without the security extension while certificate binding is not enforced, then authenticate as any principal (ESC9)",
    mitre="T1649",
    exploitability=9,
    fix_template="# Fix the certificate configuration that produces this edge (enforce StrongCertificateBindingEnforcement=2 on domain controllers). Re-collect and re-run PathCutter to confirm the path is gone.",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template, CA and domain controller data, not collected directly",
)

AZOwns = EdgeType(
    name="AZOwns",
    category=EdgeCategory.SPECIAL,
    abuse="Owner of an Entra group, application or service principal: add members or add a credential and authenticate as it",
    mitre="T1098.001",
    exploitability=8,
    fix_template="# Remove the owner (Entra admin center > Owners) or replace with a managed, reviewed owner group",
    detection_difficulty="medium",
    reversible=True,
    description="Microsoft Entra ID / hybrid identity edge",
)

AZRunsAs = EdgeType(
    name="AZRunsAs",
    category=EdgeCategory.SPECIAL,
    abuse="Authenticating as the application's service principal grants every permission and role the service principal holds",
    mitre="T1078.004",
    exploitability=7,
    fix_template="# Remove unneeded roles and permissions from the service principal",
    detection_difficulty="medium",
    reversible=True,
    description="Microsoft Entra ID / hybrid identity edge",
)

AZEligibleRole = EdgeType(
    name="AZEligibleRole",
    category=EdgeCategory.SPECIAL,
    abuse="PIM-eligible for a directory role: the holder can activate it (subject to MFA / approval) and gain its permissions",
    mitre="T1078.004",
    exploitability=6,
    fix_template="# Require approval and MFA for activation, shorten the activation window, or remove the eligibility",
    detection_difficulty="medium",
    reversible=True,
    description="Microsoft Entra ID / hybrid identity edge",
)

AZResetPassword = EdgeType(
    name="AZResetPassword",
    category=EdgeCategory.SPECIAL,
    abuse="Reset the password of a non-privileged Entra user and sign in as them",
    mitre="T1098",
    exploitability=8,
    fix_template="# Scope the administrator role with administrative units or remove it from broad groups",
    detection_difficulty="medium",
    reversible=True,
    description="Microsoft Entra ID / hybrid identity edge",
)

AZAddSecret = EdgeType(
    name="AZAddSecret",
    category=EdgeCategory.SPECIAL,
    abuse="Add a client secret or certificate to an application or service principal and authenticate as it",
    mitre="T1098.001",
    exploitability=8,
    fix_template="# Remove Application / Cloud Application Administrator from non-admin principals",
    detection_difficulty="medium",
    reversible=True,
    description="Microsoft Entra ID / hybrid identity edge",
)

SyncedTo = EdgeType(
    name="SyncedTo",
    category=EdgeCategory.SPECIAL,
    abuse="The on-premises account is synchronized to this Entra user: whoever controls the on-premises object controls the cloud identity (password hash sync / writeback)",
    mitre="T1098",
    exploitability=8,
    fix_template="# Do not synchronize privileged cloud accounts; keep Entra admins cloud-only",
    detection_difficulty="medium",
    reversible=True,
    description="Microsoft Entra ID / hybrid identity edge",
)

ADCSESC15 = EdgeType(
    name="ADCSESC15",
    category=EdgeCategory.SPECIAL,
    abuse="Enroll in a schema-version-1 template that lets the requester name the subject and inject a client-authentication application policy, then authenticate as any principal (ESC15 / EKUwu, CVE-2024-49019); fixed on patched CAs, patch level is not collected",
    mitre="T1649",
    exploitability=8,
    fix_template="# Patch the CA (November 2024 or later), replace schema-version-1 templates with version 2+, and disable ENROLLEE_SUPPLIES_SUBJECT",
    detection_difficulty="medium",
    reversible=True,
    description="Derived from certificate template data; assumes the CA is unpatched because the patch level is not collected",
)

AZOwner = EdgeType(
    name="AZOwner",
    category=EdgeCategory.SPECIAL,
    abuse="Owner of an Azure scope: full control of everything beneath it, including granting access to anyone",
    mitre="T1078.004",
    exploitability=9,
    fix_template="# Remove the Owner assignment or make it eligible through PIM with approval",
    detection_difficulty="medium",
    reversible=True,
    description="Azure resource RBAC edge",
)

AZContributor = EdgeType(
    name="AZContributor",
    category=EdgeCategory.SPECIAL,
    abuse="Contributor on an Azure scope: create and change everything beneath it (run commands on VMs, read secrets, change networking)",
    mitre="T1078.004",
    exploitability=8,
    fix_template="# Replace Contributor with the narrowest role that fits the task",
    detection_difficulty="medium",
    reversible=True,
    description="Azure resource RBAC edge",
)

AZUserAccessAdmin = EdgeType(
    name="AZUserAccessAdmin",
    category=EdgeCategory.SPECIAL,
    abuse="User Access Administrator on an Azure scope: grant yourself or anyone Owner there",
    mitre="T1098",
    exploitability=9,
    fix_template="# Remove the assignment; use PIM for the rare cases it is needed",
    detection_difficulty="medium",
    reversible=True,
    description="Azure resource RBAC edge",
)

AZVMAdminLogin = EdgeType(
    name="AZVMAdminLogin",
    category=EdgeCategory.SPECIAL,
    abuse="Sign in to the virtual machine as a local administrator with an Entra identity",
    mitre="T1021",
    exploitability=7,
    fix_template="# Use Virtual Machine User Login unless administration is required",
    detection_difficulty="medium",
    reversible=True,
    description="Azure resource RBAC edge",
)

AZContains = EdgeType(
    name="AZContains",
    category=EdgeCategory.DOMAIN,
    abuse="Azure hierarchy: rights on the parent scope apply to this child resource",
    mitre="",
    exploitability=0,
    fix_template="# Structural: reduce rights on the parent scope instead",
    detection_difficulty="medium",
    reversible=True,
    description="Azure resource RBAC edge",
)

AZManagedIdentity = EdgeType(
    name="AZManagedIdentity",
    category=EdgeCategory.SPECIAL,
    abuse="Code running on the resource can request tokens as its managed identity and use every role that identity holds",
    mitre="T1552.005",
    exploitability=8,
    fix_template="# Remove roles from the managed identity or stop using it on this resource",
    detection_difficulty="medium",
    reversible=True,
    description="Azure resource RBAC edge",
)

# -------------------------------------------------------------------
# Registry: name -> EdgeType lookup
# -------------------------------------------------------------------

EDGE_REGISTRY: dict[str, EdgeType] = {}

def _register():
    import sys
    module = sys.modules[__name__]
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, EdgeType):
            # Use the EdgeType.name as the registry key (not the Python variable name)
            # Some edge types share a name (e.g. constrained vs unconstrained delegation)
            # so we register by variable name as well for disambiguation
            EDGE_REGISTRY[obj.name] = obj
            EDGE_REGISTRY[name] = obj

_register()


def get_edge_type(name: str) -> EdgeType | None:
    """Look up an edge type by SharpHound relationship name or Python variable name."""
    return EDGE_REGISTRY.get(name)


def exploitability_weight(edge_name: str) -> float:
    """Return inverse exploitability as path weight (lower = more exploitable = preferred path)."""
    et = get_edge_type(edge_name)
    if et is None or et.exploitability == 0:
        return 100.0  # non-exploitable edges (MemberOf, Contains) get high weight
    return 10.0 / et.exploitability


TIER0_GROUPS = frozenset({
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "DOMAIN CONTROLLERS",
    "SCHEMA ADMINS",
    "ACCOUNT OPERATORS",
    "BACKUP OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "CERT PUBLISHERS",
    "KEY ADMINS",
    "ENTERPRISE KEY ADMINS",
    "ADMINSDHOLDER",
    "ENTERPRISE DOMAIN CONTROLLERS",
    "READ-ONLY DOMAIN CONTROLLERS",
    "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
})

TIER0_SIDS_SUFFIXES = frozenset({
    "-500",   # Built-in Administrator
    "-502",   # KRBTGT
    "-512",   # Domain Admins
    "-516",   # Domain Controllers
    "-518",   # Schema Admins
    "-519",   # Enterprise Admins
    "-521",   # Read-only Domain Controllers
})


TIER0_AZ_ROLE_IDS = frozenset({"62E90394-69F5-4237-9190-012177145E10", "E8611AB8-C189-46E8-94E1-60213AB1F814",
                               "7BE44C8A-ADAF-4E2A-84D6-AB2649E08A13", "E00E864A-17C5-4A4B-9C06-F5B95A8D5BD8"})


def is_tier0(node_name: str, node_sid: str = "", node_type: str = "") -> bool:
    """Determine if a node is Tier 0 (high-value target)."""
    if node_type == "AZRole" and node_sid.upper() in TIER0_AZ_ROLE_IDS:
        return True
    if node_type.lower() == "domain":
        return True                       # the domain object is the crown jewel: DCSync, WriteDacl or GPO control on it is a takeover
    upper = node_name.upper()
    # Check name against known Tier 0 groups
    # Strip domain prefix if present (DOMAIN\\Group -> Group)
    short = upper.split("@")[0] if "@" in upper else upper
    if short in TIER0_GROUPS:
        return True
    # Check SID suffix
    if node_sid:
        for suffix in TIER0_SIDS_SUFFIXES:
            if node_sid.endswith(suffix):
                return True
    # Domain Controllers are always Tier 0
    if node_type.lower() == "computer" and "DC" in upper:
        return False  # heuristic is unreliable, rely on group membership
    return False
