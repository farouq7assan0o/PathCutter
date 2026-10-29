<#
.SYNOPSIS
  Export a PathCutter CI/CD sidecar (*_cicd.json) for a GitHub organisation, using the GitHub CLI (`gh`).

.DESCRIPTION
  PathCutter models the cloud side of workload-identity federation from the Entra federated credential's subject (which
  GitHub repo/branch is trusted). This sidecar adds the repository side: which repositories exist and who can push to
  them. For every repo that a collected federated credential trusts, PathCutter then draws a CI/CD source node with an
  edge to the application it can authenticate as, and connects any pusher you provide.

  Only repositories that a federated credential actually trusts are used, so listing the whole org is fine.

  Principal correlation: GitHub logins are a separate identity plane from Entra. PathCutter only connects a pusher when
  its "id" is an EXISTING object id in the collection (e.g. the Entra object id of the user, if your org maps GitHub
  logins to Entra via SSO/SCIM). Logins that do not map are counted, not invented. The repo -> app edge does not need
  any principals - it holds because whoever controls that repo's workflow can mint the token.

.PARAMETER Org
  The GitHub organisation login.

.PARAMETER OutFile
  Output path (default .\github_cicd.json). Place it next to your AzureHound export (or pass it with --also).

.PARAMETER WithCollaborators
  Also list direct collaborators with push/admin access per repo (slower; needs admin:org or repo admin).

.EXAMPLE
  gh auth login
  .\Export-GitHubActions.ps1 -Org acme -OutFile D:\collect\entra\github_cicd.json -WithCollaborators
  python -m pathcutter analyze D:\collect\ad\obj --also D:\collect\entra
#>
param(
    [Parameter(Mandatory = $true)][string]$Org,
    [string]$OutFile = ".\github_cicd.json",
    [switch]$WithCollaborators
)
$ErrorActionPreference = "Stop"

$repos = gh api --paginate "orgs/$Org/repos?per_page=100" --jq '.[].full_name'
$data = @()
foreach ($repo in $repos) {
    $entry = [ordered]@{ repo = $repo }
    if ($WithCollaborators) {
        # direct collaborators with push or admin can modify or run workflows -> can drive OIDC
        $pushers = gh api --paginate "repos/$repo/collaborators?affiliation=direct&per_page=100" `
            --jq '.[] | select(.permissions.push==true or .permissions.admin==true) | {id: .login, name: .login, access: (if .permissions.admin then "admin" else "write" end)}' 2>$null |
            ForEach-Object { $_ | ConvertFrom-Json }
        # NOTE: id is the GitHub login. Replace it with the Entra object id if you map GitHub->Entra, so PathCutter can
        # connect the pusher to the pipeline; unmapped logins are still counted as unresolved.
        $entry.principals = @($pushers)
    }
    $data += $entry
}
$doc = [ordered]@{ meta = [ordered]@{ type = "cicd"; provider = "github" }; data = $data }
$doc | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "[+] Wrote $OutFile ($($data.Count) repositories)"
