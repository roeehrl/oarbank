# Fleet updates of the Windows MSI through the update runner (PLAN D57; docs/design/fleet-updates.md, "Packages in CI"),
# on a throwaway runner (.github/workflows/msi.yml):
#   1. -First installed by hand (unattended, no properties: the node waits unjoined), and root's update trust set to
#      `unsigned` (update-trust --unsigned: no owner key in a test fleet);
#   2. a request for -First again, confirmed: the runner now keeps that package (msiexec /i of the installed product is
#      a reinstall of it);
#   3. a request for -Second that no agent confirms: probation (5 s here) fails and the runner installs the MSI it kept
#      over the newer one (a downgrade: MajorUpgrade AllowDowngrades), result rolled_back, -First installed again;
#   4. -Second again, confirmed: a major upgrade, result done, -Second installed.
# The installed version is read from the product's uninstall entry (and Get-Package). The runner runs from a copy of
# the launcher outside Program Files, as the elevated helper starts it (the MSI replaces the installed launcher), on a
# spool and state of its own in the runner's temp directory: the helper watches the system spool, and this test must be
# the one running the runner. The msiexec and runner logs, and the runner's own, go to -Logs. The test plays the agent: it writes the spool's package, request.json (from fleet-manifest.py's
# manifest) and the confirmation. It changes the machine for good: never run it anywhere else.
#
#   scripts\ci-fleet-update-windows.ps1 -First dist\a.msi -Second dist\b.msi -Logs dist\fleet-logs
param([Parameter(Mandatory)][string]$First, [Parameter(Mandatory)][string]$Second, [Parameter(Mandatory)][string]$Logs)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force $Logs | Out-Null
$First, $Second, $Logs = (Resolve-Path $First).Path, (Resolve-Path $Second).Path, (Resolve-Path $Logs).Path
$Dist = Split-Path -Parent $First
$Product = "Oarbank agent"
$Work = Join-Path ($env:RUNNER_TEMP ?? [IO.Path]::GetTempPath()) "oarbank-fleet-ci"
$AgentHome = Join-Path $Work "agent"
$Spool = Join-Path $AgentHome "updates"
$State = Join-Path $Work "update"
$Runner = Join-Path $Work "runner\oarbank-launcher.exe"
$script:failed = 0

function Check([bool]$ok, [string]$what) {
  if ($ok) { Write-Host "ok   $what" } else { Write-Host "FAIL $what"; $script:failed++ }
}

# the MSI's version (numeric: package-windows.ps1 gives 1.0.0-alpha.1 the MSI version 1.0.0) from its file name
function MsiVersion([string]$msi) {
  if ((Split-Path -Leaf $msi) -notmatch '^oarbank-agent-(\d+\.\d+\.\d+)') { throw "not an agent MSI: $msi" }
  $Matches[1]
}

function Installed {
  $keys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  $entries = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object DisplayName -eq $Product)
  $package = @(Get-Package -Name $Product -ProviderName msi -ErrorAction SilentlyContinue)
  if ($entries.Count -ne 1) { return "($($entries.Count) uninstall entries)" }
  if ($package.Count -eq 1 -and $package[0].Version -ne $entries[0].DisplayVersion) {
    return "(uninstall entry $($entries[0].DisplayVersion), Get-Package $($package[0].Version))"
  }
  $entries[0].DisplayVersion
}

$v1, $v2 = (MsiVersion $First), (MsiVersion $Second)
# each version's manifest, as CI writes it for a release (seq 1 and 2: any two versions in order)
$Manifests = @{}
foreach ($v in @(@($v1, 1), @($v2, 2))) {
  $out = Join-Path $Logs "oarbank-fleet-$($v[0]).json"
  & python "$Repo\scripts\fleet-manifest.py" $v[0] $Dist --seq $v[1] --released-at 0 --out $out
  if ($LASTEXITCODE) { throw "fleet-manifest.py $($v[0]) failed" }
  $Manifests[$v[0]] = @{ seq = $v[1]; text = [IO.File]::ReadAllText($out) }
}

# 1. the first version by hand
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @("/i", "`"$First`"", "/qn", "/norestart", "/l*v", "`"$Logs\install-first.log`"")
if ($p.ExitCode -notin 0, 3010) { throw "msiexec /i $First failed: $($p.ExitCode)" }
Check ((Installed) -eq $v1) "the first install: $(Installed)"
New-Item -ItemType Directory -Force (Split-Path -Parent $Runner), $Spool, $State | Out-Null
Copy-Item "$env:ProgramFiles\Oarbank\oarbank-launcher.exe" $Runner
& $Runner update-trust --unsigned --agent-home $AgentHome --state $State
if ($LASTEXITCODE) { throw "update-trust --unsigned failed: $LASTEXITCODE" }

function Step([string]$name, [string]$msi, [bool]$confirm, [string]$want, [string]$version) {
  $release = MsiVersion $msi
  $m = $Manifests[$release]
  $bytes = [IO.File]::ReadAllBytes($msi)
  $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant()
  $id = "ci-msi-$name-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
  Write-Host "== $name`: $release, $(if ($confirm) { 'confirmed' } else { 'never confirmed' })"
  Remove-Item -Force -ErrorAction SilentlyContinue "$Spool\confirmed", "$Spool\result.json"
  Copy-Item -LiteralPath $msi "$Spool\package"
  $request = [ordered]@{ id = $id; release = $release; seq = $m.seq; format = "msi"; sha256 = $sha; size = $bytes.Length
                         manifest = $m.text; signature = $null; owner_anchors = $null; rollback = $false
                         requested_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
  # written last, through a rename, as the agent does
  [IO.File]::WriteAllText("$Spool\.request.json.tmp", ($request | ConvertTo-Json -Compress -Depth 4))
  Move-Item -Force "$Spool\.request.json.tmp" "$Spool\request.json"
  $log = Join-Path $Logs "runner-$name.log"
  $run = Start-Process $Runner -PassThru -NoNewWindow -RedirectStandardOutput $log -RedirectStandardError "$log.err" `
    -ArgumentList @("update-run", "--once", "--probation-s", "5", "--agent-home", "`"$AgentHome`"", "--state", "`"$State`"")
  if ($confirm) {
    $deadline = (Get-Date).AddMinutes(30)                # an MSI's 1618 retries wait minutes
    $state = $null
    while ((Get-Date) -lt $deadline -and -not $run.HasExited) {
      $r = Get-Content -Raw -ErrorAction SilentlyContinue "$Spool\result.json" | ConvertFrom-Json -ErrorAction SilentlyContinue
      $state = if ($r -and $r.id -eq $id) { $r.state } else { $null }
      if ($state -ne $null -and $state -ne "installing") { break }
      Start-Sleep -Milliseconds 200
    }
    Check ($state -eq "installed") "$name`: the runner installed $release ($state)"
    # the new agent's confirmation
    $c = [ordered]@{ id = $id; release = $release; agent_version = $release; at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
    [IO.File]::WriteAllText("$Spool\.confirmed.tmp", ($c | ConvertTo-Json -Compress))
    Move-Item -Force "$Spool\.confirmed.tmp" "$Spool\confirmed"
  }
  if (-not $run.WaitForExit(45 * 60 * 1000)) { $run.Kill(); throw "$name`: the runner did not finish within 45 min" }
  Get-Content -ErrorAction SilentlyContinue $log, "$log.err" | Write-Host
  $r = Get-Content -Raw "$Spool\result.json" | ConvertFrom-Json
  Check ($r.id -eq $id -and $r.state -eq $want) "$name`: the result is $want ($($r.state): $($r.error); exit $($run.ExitCode))"
  Check (-not (Test-Path "$Spool\request.json")) "$name`: the runner took the request"
  Check ((Installed) -eq $version) "$name`: $version installed ($(Installed))"
  Check ((& $Runner --home $AgentHome current) -like "versions/$version-*") "$name`: the agent of $version is current"
}

try {
  Step "reinstall" $First $true "done" $v1
  Step "unconfirmed" $Second $false "rolled_back" $v1
  Step "update" $Second $true "done" $v2
} finally {
  # the runner's journal, result and own logs beside the msiexec logs (msi.yml uploads them on failure)
  Copy-Item -Recurse -Force -ErrorAction SilentlyContinue "$State\logs", "$State\journal.json", "$Spool\result.json" $Logs
}

# the node itself is uninstalled with the product
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @("/x", "`"$Second`"", "/qn", "/norestart", "/l*v", "`"$Logs\uninstall.log`"")
Check ($p.ExitCode -in 0, 3010) "uninstall: exit $($p.ExitCode)"
Check ((Installed) -eq "(0 uninstall entries)") "nothing installed after the uninstall"
if ($script:failed) { throw "$script:failed check(s) failed" }
Write-Host "ok   fleet updates of the MSI through the runner"
