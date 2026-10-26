<#
.SYNOPSIS
  Nightly PathCutter run: snapshot today's collection, diff it against the previous snapshot, write dated reports.

.DESCRIPTION
  Point this at the collection your collector (SharpHound / AzureHound / AD Explorer export) produced today. It keeps a
  dated history of .pcsnap snapshots, writes a dated analyze report, and - from the second run on - a diff report that
  shows what changed since the last run (paths opened or closed). Schedule it with Task Scheduler.

  Snapshots and reports contain your full AD topology: store the -Home folder like the sensitive data it is.

.PARAMETER Collection
  Path to today's collection: a SharpHound ZIP/directory, an AzureHound export, or an AD Explorer NDJSON folder.

.PARAMETER Home
  Base folder for history and output (default C:\PathCutter). Creates snapshots\ and reports\ under it.

.PARAMETER CrownJewels
  Optional crown-jewels JSON passed to analyze (see docs/collect-with-adexplorer.md / `pathcutter syntax`).

.PARAMETER Telemetry
  Optional telemetry JSON passed to analyze for a detection-coverage card.

.EXAMPLE
  .\nightly.ps1 -Collection D:\collect\today -Home C:\PathCutter -CrownJewels C:\PathCutter\crown.json

  Schedule (run as a least-privilege service account that can read the collection):
    schtasks /Create /TN PathCutter-Nightly /SC DAILY /ST 02:30 /RU DOMAIN\svc-pathcutter ^
      /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\PathCutter\tools\nightly.ps1 -Collection D:\collect\today"
#>
param(
    [Parameter(Mandatory = $true)][string]$Collection,
    [string]$Home = "C:\PathCutter",
    [string]$CrownJewels,
    [string]$Telemetry
)
$ErrorActionPreference = "Stop"

# `pathcutter` if installed (pip install pathcutter), else `python -m pathcutter`
$pc = (Get-Command pathcutter -ErrorAction SilentlyContinue)
$run = if ($pc) { @($pc.Source) } else { @("python", "-m", "pathcutter") }

$snapDir = Join-Path $Home "snapshots"
$repDir = Join-Path $Home "reports"
New-Item -ItemType Directory -Force -Path $snapDir, $repDir | Out-Null
$date = Get-Date -Format "yyyy-MM-dd"
$snap = Join-Path $snapDir "$date.pcsnap"

# previous snapshot = newest .pcsnap that is not today's
$prev = Get-ChildItem $snapDir -Filter *.pcsnap -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $snap } | Sort-Object LastWriteTime -Descending | Select-Object -First 1

Write-Host "[*] Snapshot -> $snap"
& $run[0] $run[1..($run.Length - 1)] snapshot $Collection -o $snap --collected $date

$analyze = @($run[1..($run.Length - 1)]) + @("analyze", $snap, "--html", "-o", (Join-Path $repDir $date))
if ($CrownJewels) { $analyze += @("--crown-jewels", $CrownJewels) }
if ($Telemetry) { $analyze += @("--telemetry", $Telemetry) }
Write-Host "[*] Analyze -> $(Join-Path $repDir $date)"
& $run[0] $analyze

if ($prev) {
    Write-Host "[*] Diff $($prev.Name) -> $date"
    & $run[0] $run[1..($run.Length - 1)] diff $prev.FullName $snap --html -o (Join-Path $repDir "$date-diff")
} else {
    Write-Host "[i] No previous snapshot yet; diff starts from the next run."
}
Write-Host "[+] Done. Reports in $repDir"
