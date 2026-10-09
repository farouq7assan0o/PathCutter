# Example AD automation script. `pathcutter check --powershell` extracts the changes it would make.
# Lines it can model are analyzed; lines it cannot (variables, ACL edits, delegation flags) are
# reported as "Not analyzed" instead of being skipped.

Add-ADGroupMember -Identity "DB ADMINS" -Members "mchen","djones"

# Unconstrained delegation: not modeled by the graph, flagged for manual review
Set-ADAccountControl -Identity SRV02$ -TrustedForDelegation $true

# Members come from a variable, so who is affected cannot be known: flagged, never skipped
$g = Get-ADGroup "Exchange Admins"; Add-ADGroupMember -Identity $g -Members tharris
