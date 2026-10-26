# Collecting with AD Explorer (when EDR blocks SharpHound)

SharpHound is frequently quarantined by endpoint protection (for example Microsoft Defender flags
`HackTool:MSIL/SharpHound`, and newer builds can fail to load `SharpHoundRPC`). Sysinternals **AD Explorer** is
Microsoft-signed and is not flagged, so it is a reliable way to take a full LDAP snapshot of a domain. PathCutter reads
that snapshot natively: it parses the binary security descriptors itself, with no impacket, no certipy and no external
converter.

This path is LDAP-only. It does **not** include sessions or local-group membership (those are not in the directory), so
exposure is a floor. Pair it with `tools/Export-AdLocalSessions.ps1` (plain read-only PowerShell) for the real
lateral-movement edges.

## 1. Take the snapshot

In AD Explorer: **File > Connect** to a domain controller, then **File > Create Snapshot**.

**Snapshot from the directory root (or at least include the Configuration partition), not only the domain.**
AD CS objects - certificate templates, enterprise CAs, the NTAuth store, issuance policies - and the schema (needed to
resolve LAPS attribute GUIDs) live under `CN=Configuration,<forest root>`, not under the domain naming context. If you
connect and snapshot at the directory root, everything is captured in one `.dat`. If you snapshot only the domain NC you
still get users, groups, computers, GPOs, OUs and all ACLs, but no ADCS, no trusts resolved from the forest, and no LAPS
GUID resolution.

```
# GUI: File > Create Snapshot, save as C:\collect\meditrust.dat
# (or non-interactively)
ADExplorer.exe -accepteula -snapshot "" C:\collect\meditrust.dat
```

## 2. Export the snapshot to NDJSON

Use ADExplorerSnapshot.py in **Objects** mode (one JSON object per line, every attribute):

```
py -m adexpsnapshot C:\collect\meditrust.dat -o C:\collect\ad\obj -m Objects
```

This writes one or more `*.ndjson` files into `C:\collect\ad\obj`.

## 3. (Optional) collect the read-only sidecars next to it

These are plain PowerShell, not flagged, and `analyze` / `snapshot` pick them up automatically when they sit in (or
beside) the NDJSON folder:

| Sidecar script | File it writes | What it adds |
|---|---|---|
| `tools/Export-AdLocalSessions.ps1` | `*_localsessions.json` | `HasSession`, `AdminTo`, `CanRDP`, `CanPSRemote` edges (real lateral movement) |
| `tools/Export-AdDenyAces.ps1` | `*_denies.json` | Deny ACEs (identity-sensitive; SharpHound does not collect them) |
| `tools/Export-AdGpoRights.ps1` | `*_gporights.json` | GPO user-rights assignments (SeBackup, SeDebug, ...) as `GPOUserRight` edges |
| `tools/Export-AdCsRelay.ps1` | `*_adcsrelay.json` | CA web-enrollment / RPC settings for ESC8 / ESC11 / ESC16 |

## 4. Analyze

```
python -m pathcutter doctor  C:\collect\ad\obj
python -m pathcutter analyze C:\collect\ad\obj --html -o C:\collect\report
# hybrid, joined to a cloud tenant export:
python -m pathcutter analyze C:\collect\ad\obj --also C:\collect\entra --html -o C:\collect\report-hybrid
python -m pathcutter breach  C:\collect\ad\obj --also C:\collect\entra --from "SOME.USER@DOMAIN"
```

## What derives from the snapshot, and what needs a sidecar

| From the snapshot alone (if the Configuration partition was included) | Needs a sidecar or SharpHound |
|---|---|
| ACL edges (GenericAll, WriteDacl, WriteOwner, AddMember, WriteSPN, ForceChangePassword, RBCD, shadow credentials, Owns) | Sessions, local admins, RDP/PSRemote/DCOM (`Export-AdLocalSessions.ps1`) |
| DCSync (both replication rights, including via two groups) | Deny ACEs (`Export-AdDenyAces.ps1`) |
| AD CS: ESC1, ESC4, ESC5, ESC15, ESC13, golden certificate | ESC6 / ESC7 / ESC3 / ESC9 / ESC10 / ESC16 (CA and DC registry: `Export-AdCsRelay.ps1`) |
| Trusts (direction, transitivity, SID filtering) from `trustedDomain` | GPO user rights (`Export-AdGpoRights.ps1`) |
| ReadGMSAPassword (from `msDS-GroupMSAMembership`) | - |
| ReadLAPSPassword (targeted read of the LAPS attribute; GUID from the schema partition) | - |

PathCutter never fakes the data it cannot see from LDAP. `pathcutter doctor` lists exactly what is missing and the
collector flag or sidecar that fills each gap, and `pathcutter syntax model` states what is modelled versus only
reported.
