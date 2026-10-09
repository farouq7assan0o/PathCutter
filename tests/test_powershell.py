"""PowerShell change extraction: parsing, variables, pipelines, ACLs, delegation, GPO, local groups, coverage."""
import pytest

from pathcutter.changes import from_powershell, resolve_changes
from pathcutter.impact import analyze_impact
from pathcutter.policy import Policy, evaluate


def ps(text):
    return from_powershell(text, "s.ps1")


def trip(text):
    specs, _ = ps(text)
    return [(s.op, s.source, s.edge_type, s.target) for s in specs]


def levels(text):
    return [(w.origin, w.level) for w in ps(text)[1]]


# ------------------------------------------------------------ statements and strings

def test_here_strings_block_comments_and_backticks_do_not_confuse_the_parser():
    text = '''<# Add-ADGroupMember -Identity Hidden -Members nobody #>
$note = @"
Add-ADGroupMember -Identity InString -Members nobody
"@
Add-ADGroupMember -Identity G `
    -Members alice
Write-Host "Add-ADGroupMember -Identity AlsoText -Members nobody"
'''
    assert trip(text) == [("add", "alice", "MemberOf", "G")]


def test_allman_braces_else_try_catch_and_functions_are_all_analyzed():
    text = '''
if ($true)
{
    Add-ADGroupMember -Identity A -Members a1
}
else
{
    Add-ADGroupMember -Identity B -Members b1
}
try { Add-ADGroupMember -Identity C -Members c1 } catch { Add-ADGroupMember -Identity D -Members d1 } finally { }
function Do-It { param($who) Add-ADGroupMember -Identity E -Members e1 }
'''
    assert {t[3] for t in trip(text)} == {"A", "B", "C", "D", "E"}


def test_semicolons_pipes_and_nested_blocks():
    text = "Write-Host hi; if ($x) { foreach ($u in 'a','b') { Add-ADGroupMember -Identity G -Members $u } }"
    assert trip(text) == [("add", "a", "MemberOf", "G"), ("add", "b", "MemberOf", "G")]


def test_origin_line_numbers_survive_blocks_and_strings():
    text = "# one\n$x = 1\nif ($x) {\n  Add-ADGroupMember -Identity G -Members a\n}\n"
    specs, _ = ps(text)
    assert specs[0].origin == "s.ps1:4"


# ---------------------------------------------------------------------- variables

def test_variables_arrays_and_interpolation():
    text = '''$g = "HelpDesk"
$names = @('a','b')
$prefix = 'svc'
Add-ADGroupMember -Identity $g -Members $names
Add-ADGroupMember -Identity "$g-Admins" -Members "$prefix-x"
'''
    assert trip(text) == [("add", "a", "MemberOf", "HelpDesk"), ("add", "b", "MemberOf", "HelpDesk"),
                          ("add", "svc-x", "MemberOf", "HelpDesk-Admins")]


def test_variable_bound_from_a_getter_and_property_access():
    text = '''$grp = Get-ADGroup "Exchange Admins"
$u = (Get-ADUser tharris).SamAccountName
Add-ADGroupMember -Identity $grp -Members $u
'''
    assert trip(text) == [("add", "tharris", "MemberOf", "Exchange Admins")]


def test_append_assignment_and_unknown_variable_is_flagged_not_guessed():
    text = '''$m = 'a'
$m += 'b'
Add-ADGroupMember -Identity G -Members $m
Add-ADGroupMember -Identity G -Members $nope
'''
    specs, warns = ps(text)
    assert [(s.source) for s in specs] == ["a", "b"]
    assert len(warns) == 1 and "$nope" in warns[0].message


def test_splatting():
    text = "$p = @{Identity='Domain Admins'; Members='mallory'}\nAdd-ADGroupMember @p\n"
    assert trip(text) == [("add", "mallory", "MemberOf", "Domain Admins")]


def test_parameter_prefixes_and_positional_forms():
    assert trip("Add-ADGroupMember -Ident G -Members a") == [("add", "a", "MemberOf", "G")]
    assert trip("Add-ADGroupMember -Ident G -Memb a") == []     # ambiguous with -MemberTimeToLive: PowerShell itself rejects it
    assert trip('Add-ADGroupMember "G" "a","b"') == [("add", "a", "MemberOf", "G"), ("add", "b", "MemberOf", "G")]
    assert trip("Add-ADGroupMember -Identity:G -Members:a") == [("add", "a", "MemberOf", "G")]


def test_whatif_does_not_change_anything():
    assert trip("Add-ADGroupMember -Identity G -Members a -WhatIf") == []


# ----------------------------------------------------------------------- pipelines

def test_foreach_object_over_a_literal_list_and_aliases():
    for loop in ("ForEach-Object", "%", "foreach"):
        assert trip(f"'a','b' | {loop} {{ Add-ADGroupMember -Identity G -Members $_ }}") == [
            ("add", "a", "MemberOf", "G"), ("add", "b", "MemberOf", "G")]


def test_getter_piped_into_membership_cmdlet():
    assert trip('Get-ADUser bob | Add-ADPrincipalGroupMembership -MemberOf "G1","G2"') == [
        ("add", "bob", "MemberOf", "G1"), ("add", "bob", "MemberOf", "G2")]


def test_group_expansion_is_deferred_to_the_baseline():
    text = 'Get-ADGroupMember "HelpDesk" | ForEach-Object { Add-ADGroupMember -Identity "DB Admins" -Members $_ }'
    assert trip(text) == [("add", "@members(HelpDesk)", "MemberOf", "DB Admins")]
    assert trip('Add-ADGroupMember -Identity G -Members (Get-ADGroupMember X -Recursive)') == [
        ("add", "@members*(X)", "MemberOf", "G")]


def test_unfilterable_sources_are_flagged():
    _, warns = ps('Get-ADUser -Filter {Department -eq "IT"} | Add-ADPrincipalGroupMembership -MemberOf G')
    assert len(warns) == 1 and warns[0].level == "review"
    _, warns = ps("Import-Csv users.csv | ForEach-Object { Add-ADGroupMember -Identity G -Members $_.sam }")
    assert warns


# ------------------------------------------------------ membership / object lifecycle

def test_set_adgroup_member_hashtable_forms():
    text = """Set-ADGroup -Identity G -Add @{member='CN=alice,CN=Users,DC=corp,DC=local'}
Set-ADObject -Identity G -Remove @{member='CN=bob,CN=Users,DC=corp,DC=local'}
"""
    assert trip(text) == [("add", "alice", "MemberOf", "G"), ("remove", "bob", "MemberOf", "G")]


def test_replace_member_models_additions_and_warns_about_the_rest():
    specs, warns = ps("Set-ADGroup G -Replace @{member='alice'}")
    assert [(s.op, s.source) for s in specs] == [("add", "alice")] and warns


def test_create_and_delete_and_move():
    text = '''New-ADUser -Name "newhire" -SamAccountName newhire
New-ADGroup -Name Ops -GroupScope Global
New-ADComputer -Name WS99
Remove-ADUser -Identity olduser
Move-ADObject -Identity "CN=alice,CN=Users,DC=corp,DC=local" -TargetPath "OU=Admins,DC=corp,DC=local"
'''
    got = [(s.op, s.source, s.new_type, s.target) for s in ps(text)[0]]
    assert got == [("create", "newhire", "user", ""), ("create", "Ops", "group", ""), ("create", "WS99", "computer", ""),
                   ("delete", "olduser", "", ""), ("move", "alice", "", "Admins")]


def test_gmsa_readers_and_creation():
    text = "New-ADServiceAccount -Name gmsa1 -PrincipalsAllowedToRetrieveManagedPassword 'Web Servers','alice'"
    got = trip(text)
    assert ("add", "Web Servers", "ReadGMSAPassword", "gmsa1") in got and ("add", "alice", "ReadGMSAPassword", "gmsa1") in got
    assert trip("Set-ADServiceAccount gmsa1 -PrincipalsAllowedToRetrieveManagedPassword bob") == [
        ("add", "bob", "ReadGMSAPassword", "gmsa1")]


# --------------------------------------------------------------------- delegation

def test_rbcd_unconstrained_and_constrained():
    assert trip("Set-ADComputer SRV01 -PrincipalsAllowedToDelegateToAccount 'WEB01$','alice'") == [
        ("add", "WEB01$", "AllowedToAct", "SRV01"), ("add", "alice", "AllowedToAct", "SRV01")]
    assert trip("Set-ADAccountControl -Identity SRV02 -TrustedForDelegation $true") == [
        ("add", "SRV02", "AllowedToDelegate", "@dcs")]
    assert trip("Set-ADComputer SRV02 -TrustedForDelegation $false") == [("remove", "SRV02", "AllowedToDelegate", "@dcs")]
    assert trip("Set-ADUser svc -Add @{'msDS-AllowedToDelegateTo'='cifs/dc01.corp.local','HTTP/web01:8080'}") == [
        ("add", "svc", "AllowedToDelegate", "dc01"), ("add", "svc", "AllowedToDelegate", "web01")]


def test_uac_delegation_bit_is_read():
    assert trip("Set-ADUser svc -Replace @{userAccountControl=524800}") == [("add", "svc", "AllowedToDelegate", "@dcs")]


def test_raw_security_attribute_writes_are_flagged():
    for text in ("Set-ADUser x -Replace @{SIDHistory='S-1-5-21-1'}", "Set-ADObject x -Replace @{ntSecurityDescriptor=$sd}",
                 "Set-ADObject x -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$d}"):
        specs, warns = ps(text)
        assert not specs and warns and warns[0].level == "review", text


# ------------------------------------------------------------------------- ACLs

def test_dsacls_grants_map_rights_and_properties():
    text = r'''dsacls "CN=SVC,OU=x,DC=corp,DC=local" /G "CORP\bob:GA"
dsacls "CN=GRP,DC=corp,DC=local" /G "CORP\carol:WP;member"
dsacls "CN=U,DC=corp,DC=local" /G "CORP\dave:CA;User-Force-Change-Password"
dsacls "DC=corp,DC=local" /G "CORP\eve:CA;DS-Replication-Get-Changes-All"
dsacls "CN=U,DC=corp,DC=local" /G "CORP\fay:WD" "CORP\gus:WO"
'''
    assert trip(text) == [("add", "bob", "GenericAll", "SVC"), ("add", "carol", "AddMember", "GRP"),
                          ("add", "dave", "ForceChangePassword", "U"), ("add", "eve", "DCSync", "corp.local"),
                          ("add", "fay", "WriteDacl", "U"), ("add", "gus", "WriteOwner", "U")]


def test_dsacls_deny_becomes_a_deny_change_not_a_grant():
    specs, warns = ps(r'dsacls "CN=U,DC=corp,DC=local" /D "CORP\bob:GA"')
    assert [(s.op, s.deny, s.source, s.edge_type) for s in specs] == [("add", True, "bob", "GenericAll")]


def test_set_acl_with_access_rule_objects():
    text = r'''$acl = Get-Acl "AD:\CN=Svc Backup,OU=Svc,DC=corp,DC=local"
$id = New-Object System.Security.Principal.NTAccount("CORP","helpdesk")
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($id, "GenericAll", "Allow")
$acl.AddAccessRule($rule)
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.NTAccount("CORP","carol")), "WriteProperty", "Allow",
    [guid]"bf9679c0-0de6-11d0-a285-00aa003049e2")))
Set-Acl -Path "AD:\CN=Svc Backup,OU=Svc,DC=corp,DC=local" -AclObject $acl
'''
    assert trip(text) == [("add", "helpdesk", "GenericAll", "Svc Backup"), ("add", "carol", "AddMember", "Svc Backup")]


def test_acl_edits_never_committed_have_no_effect():
    text = r'''$acl = Get-Acl "AD:\CN=X,DC=corp,DC=local"
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule((New-Object System.Security.Principal.NTAccount("C","bob")), "GenericAll", "Allow")))
'''
    assert trip(text) == []


def test_remove_access_rule_pattern_used_by_pathcutter_templates():
    text = r'''$acl = Get-Acl "AD:\SVC_BACKUP@CORP.LOCAL"
$acl.Access | Where-Object {$_.IdentityReference -match "HELPDESK@CORP.LOCAL" -and $_.ActiveDirectoryRights -match "WriteDacl"} | ForEach-Object {$acl.RemoveAccessRule($_)}
Set-Acl "AD:\SVC_BACKUP@CORP.LOCAL" $acl
'''
    assert trip(text) == [("remove", "HELPDESK@CORP.LOCAL", "WriteDacl", "SVC_BACKUP@CORP.LOCAL")]
    text2 = text.replace('-match "WriteDacl"', '-eq "x" -and $_.ObjectType -eq "f3a64788-5306-11d1-a9c5-0000f80367c1"')
    assert trip(text2) == [("remove", "HELPDESK@CORP.LOCAL", "WriteSPN", "SVC_BACKUP@CORP.LOCAL")]


def test_set_owner():
    text = r'''$acl = Get-Acl "AD:\CN=X,DC=corp,DC=local"
$acl.SetOwner((New-Object System.Security.Principal.NTAccount("CORP","mallory")))
Set-Acl "AD:\CN=X,DC=corp,DC=local" $acl'''
    assert trip(text) == [("add", "mallory", "Owns", "X")]


def test_powerview_and_exchange_permissions():
    text = '''Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity bob -Rights All
Add-DomainObjectAcl -TargetIdentity victim -PrincipalIdentity bob -Rights ResetPassword,WriteMembers
Set-DomainObjectOwner -Identity target -OwnerIdentity mallory
Add-ADPermission -Identity "CN=Mailbox,DC=corp,DC=local" -User carol -AccessRights GenericAll
'''
    assert trip(text) == [("add", "bob", "GenericAll", "Domain Admins"), ("add", "bob", "ForceChangePassword", "victim"),
                          ("add", "bob", "AddMember", "victim"), ("add", "mallory", "Owns", "target"),
                          ("add", "carol", "GenericAll", "Mailbox")]


# ------------------------------------------------------------------ GPO, local groups

def test_gpo_permissions_and_links():
    text = '''Set-GPPermission -Name "Workstation Baseline" -TargetName helpdesk -TargetType Group -PermissionLevel GpoEdit
Set-GPPermission -Name "Workstation Baseline" -TargetName ops -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity
Set-GPPermission -Name "Workstation Baseline" -TargetName bob -TargetType User -PermissionLevel GpoRead
New-GPLink -Name "Workstation Baseline" -Target "OU=Workstations,DC=corp,DC=local"
'''
    assert trip(text) == [("add", "helpdesk", "GenericWrite", "Workstation Baseline"),
                          ("add", "ops", "GenericAll", "Workstation Baseline"),
                          ("add", "Workstation Baseline", "GPOControlsObject", "Workstations")]


def test_local_groups_need_a_named_host():
    specs, warns = ps("Add-LocalGroupMember -Group Administrators -Member 'CORP\\bob'")
    assert not specs and warns and warns[0].level == "review"
    text = '''Invoke-Command -ComputerName SRV01 -ScriptBlock { Add-LocalGroupMember -Group "Administrators" -Member 'CORP\\bob' }
Invoke-Command -ComputerName 'SRV02' { net localgroup "Remote Desktop Users" carol /add }
'''
    assert trip(text) == [("add", "bob", "AdminTo", "SRV01"), ("add", "carol", "CanRDP", "SRV02")]


def test_net_and_dsmod_legacy_commands():
    text = '''net group "Domain Admins" mallory /add /domain
net group "Helpdesk" carol /delete /domain
net user newbie /add /domain
dsmod group "CN=Backup Operators,CN=Builtin,DC=corp,DC=local" -addmbr "CN=eve,CN=Users,DC=corp,DC=local"
'''
    assert trip(text) == [("add", "mallory", "MemberOf", "Domain Admins"), ("remove", "carol", "MemberOf", "Helpdesk"),
                          ("create", "newbie", "if-missing", ""), ("add", "eve", "MemberOf", "Backup Operators")]


# ------------------------------------------------------- directives, notes, coverage

def test_pc_directives_let_authors_state_what_a_line_does():
    text = '''# pc: add-member alice "Domain Admins"   # CHG-9
Invoke-SomethingCustom -Do It   #pathcutter: grant bob GenericAll svc
'''
    assert trip(text) == [("add", "alice", "MemberOf", "Domain Admins"), ("add", "bob", "GenericAll", "svc")]
    _, warns = ps("#pc: nonsense verb here")
    assert warns and "invalid #pc directive" in warns[0].message


def test_duplicates_collapse():
    text = "Add-ADGroupMember -Identity G -Members a\n# pc: add-member a G\n"
    assert trip(text) == [("add", "a", "MemberOf", "G")]


def test_harmless_cmdlets_are_notes_not_blockers():
    assert levels("Enable-ADAccount -Identity bob\nSet-ADAccountPassword bob -Reset\nsetspn -S http/x svc") == [
        ("s.ps1:1", "note"), ("s.ps1:2", "note"), ("s.ps1:3", "note")]


MODIFYING = [
    "Set-ADFooBar -Identity x", "Grant-ADAuthenticationPolicySiloAccess -Identity s -Account a",
    "Install-ADServiceAccount -Identity g", "Set-ADDomainMode -Identity corp -DomainMode Windows2016Domain",
    "Add-ADCentralAccessPolicyMember -Identity p -Member r", "Remove-GPLink -Name x -Target y",
    "Set-ADObject -Identity x -Replace @{foo=1}", "Restore-ADObject -Identity x",
    "Add-ADComputerServiceAccount -Identity c -ServiceAccount s", "Set-ADForest -Identity corp",
    "Remove-ADGroupMember -Identity $g -Members $m", "Add-ADGroupMember $x $y", "Move-ADObject -Identity $o -TargetPath $p",
    "New-ADUser -Name $n", "Set-ADComputer -Identity $c -PrincipalsAllowedToDelegateToAccount $a",
    "Set-ADUser -Identity $u -Add @{member=$x}", "dsacls $dn /G $spec", "Set-Acl -Path $p -AclObject $a",
    "Add-LocalGroupMember -Group Administrators -Member $m", "net localgroup administrators bob /add",
]


@pytest.mark.parametrize("stmt", MODIFYING)
def test_no_recognised_ad_change_is_ever_silently_ignored(stmt):
    specs, warns = ps(stmt)
    assert specs or warns, f"silently ignored: {stmt}"


def test_read_only_commands_produce_nothing():
    assert ps("Get-ADUser bob\nGet-ADGroup G -Properties *\nGet-Acl 'AD:\\CN=x'\nWrite-Host hi\n$x = 1\n") == ([], [])


def test_alias_and_module_qualified_names():
    assert trip("ActiveDirectory\\Add-ADGroupMember -Identity G -Members a") == [("add", "a", "MemberOf", "G")]
    assert trip("& Add-ADGroupMember -Identity G -Members a") == [("add", "a", "MemberOf", "G")]
    assert trip("add-adgroupmember -identity G -members a") == [("add", "a", "MemberOf", "G")]


# ------------------------------------------------- through resolution and the gate

def gate(graph, text, **kw):
    specs, warns = from_powershell(text, "s.ps1")
    resolved, errors = resolve_changes(graph, specs)
    assert not errors, errors
    report = analyze_impact(graph, resolved, unmodeled=warns, **kw)
    evaluate(report, Policy(), resolved)
    return report, resolved


def test_group_expansion_uses_the_baseline_membership(corp):
    r, resolved = gate(corp, 'Get-ADGroupMember "IT ADMINS" | ForEach-Object { Add-ADGroupMember -Identity HELPDESK -Members $_ }')
    assert resolved[0].pairs == [("u-bob", "g-help")]
    assert r.verdict == "block" and r.totals["newly_exposed_actors"] == 1


def test_empty_group_expansion_is_a_noop_not_a_pass_by_accident(corp):
    r, resolved = gate(corp, "Add-ADGroupMember -Identity HELPDESK -Members (Get-ADGroupMember TEAM)")
    assert resolved[0].noop and "matched no objects" in resolved[0].noop_reason and r.verdict == "pass"


def test_nested_expansion_returns_leaf_members(corp):
    from pathcutter.graph import ADEdge
    corp.add_edge(ADEdge("g-team", "g-it", "MemberOf"))
    corp.add_edge(ADEdge("u-dave", "g-team", "MemberOf"))
    _, direct = gate(corp, "Add-ADGroupMember -Identity HELPDESK -Members (Get-ADGroupMember 'IT ADMINS')")
    _, nested = gate(corp, "Add-ADGroupMember -Identity HELPDESK -Members (Get-ADGroupMember 'IT ADMINS' -Recursive)")
    assert {s for s, _ in direct[0].pairs} == {"u-bob", "g-team"}      # direct members include the nested group
    assert {s for s, _ in nested[0].pairs} == {"u-bob", "u-dave"}      # recursive: leaf accounts only


def test_unconstrained_delegation_through_the_gate(corp):
    from pathcutter.graph import ADEdge
    corp.add_edge(ADEdge("c-dc01", "g-da", "MemberOf"))               # DC01 is a domain controller (Tier 0)
    corp.add_node(__import__("pathcutter.graph", fromlist=["ADNode"]).ADNode("g-dcs", "DOMAIN CONTROLLERS@CORP.LOCAL",
                  __import__("pathcutter.graph", fromlist=["NodeType"]).NodeType.GROUP, "corp.local"))
    corp.add_edge(ADEdge("c-dc01", "g-dcs", "MemberOf"))
    corp.retier()
    r, resolved = gate(corp, "Set-ADAccountControl -Identity SRV01 -TrustedForDelegation $true")
    assert ("c-srv01", "c-dc01") in resolved[0].pairs
    assert r.verdict == "block" and any(f.kind == "NEW_EXPOSURE" for f in r.findings)


def test_delete_move_and_create_through_the_gate(corp):
    r, _ = gate(corp, 'Remove-ADUser -Identity svc_backup\nNew-ADUser -Name "newhire"\nAdd-ADGroupMember -Identity HELPDESK -Members newhire')
    kinds = {f.kind for f in r.findings}
    assert "RISK_REDUCTION" in kinds                                    # deleting the Tier 0 service account secures HELPDESK
    assert r.verdict in ("pass", "review")


def test_create_if_missing_is_idempotent(corp):
    r, resolved = gate(corp, 'New-ADUser -Name "alice"')
    assert resolved[0].noop and r.verdict == "pass"


def test_waiver_for_a_fan_out_requires_every_member_to_match(corp):
    from pathcutter.graph import ADEdge
    corp.add_edge(ADEdge("u-dave", "g-it", "MemberOf"))
    from pathcutter.policy import parse_policy
    text = 'Add-ADGroupMember -Identity HELPDESK -Members (Get-ADGroupMember "IT ADMINS")'
    specs, warns = from_powershell(text, "s.ps1")
    resolved, _ = resolve_changes(corp, specs)
    one = parse_policy({"waivers": [{"id": "W", "reason": "r", "source": "bob"}]})
    report = analyze_impact(corp, resolved)
    evaluate(report, one, resolved)
    assert report.verdict == "block"                                    # bob alone does not cover dave
    both = parse_policy({"waivers": [{"id": "W", "reason": "r", "source": "@members(IT ADMINS)"}]})
    report = analyze_impact(corp, resolved)
    evaluate(report, both, resolved)
    assert report.verdict == "pass"
