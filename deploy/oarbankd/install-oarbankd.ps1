# Install the Oarbank coordinator on Windows from a coordinator build: oarbankd and the console as services of the
# service control manager, each run by its own virtual account (NT SERVICE\dev.codonic.oarbank.oarbankd and
# NT SERVICE\dev.codonic.oarbank.console), started at boot (delayed) and restarted after a crash or a failed exit, with
# the coordinator's home in %ProgramData%\Oarbank\coordinator (docs/design/windows-coordinator.md). Run it from an
# elevated PowerShell; running it again with a newer build upgrades in place. `-Help` lists the options. A move to a
# Windows machine that is not an enrolled node installs the standby with -Pair (coordinator-move.md, runbook).
param(
  [string]$Build = "",            # oarbank-coordinator-<v>-windows-<arch>.tar.gz (scripts\build-coordinator.ps1)
  [string]$AgentBind = "",        # the address agents reach: a LAN or tailnet address (127.0.0.1 only for a trial)
  [int]$AgentPort = 7443,
  [string]$Url = "",              # the agent URL as agents reach it when that is not https://<AgentBind>:<AgentPort> (a NAT)
  [string]$Pair = "",             # a standby for a move: the pairing code coordinator.prepare printed,
  [string]$From = "",             #   the old coordinator's agent URL,
  [string]$FromCa = "",           #   and its TLS CA pin
  [switch]$ArchiveHome,           # with -Pair: move an existing home aside first (a move back to this machine)
  [switch]$Uninstall,             # remove the services, the firewall rule and the programs; the home stays
  [switch]$DryRun,                # print what would be done instead of doing it
  [switch]$Help
)
$ErrorActionPreference = "Stop"
$Services = @{oarbankd = "dev.codonic.oarbank.oarbankd"; console = "dev.codonic.oarbank.console"}
$App = "$env:ProgramFiles\Oarbank\Coordinator"
$Home_ = "$env:ProgramData\Oarbank\coordinator"
$Rule = "Oarbank coordinator (agents)"

if ($Help) {
  @"
usage: install-oarbankd.ps1 -Build <archive> -AgentBind <address> [-AgentPort 7443] [-Url <url>] [-DryRun]
       install-oarbankd.ps1 -Build <archive> -AgentBind <address> -Pair <code> -From <url> -FromCa <pin> [-ArchiveHome]
       install-oarbankd.ps1 -Uninstall [-DryRun]

Installs the coordinator build under $App (each version beside the others, `current` a junction to the
running one) and the services $($Services.oarbankd) and $($Services.console). The home is
$Home_, private to SYSTEM, Administrators and the two services' accounts. An inbound firewall rule lets agents reach
oarbankd's agent port. Environment: OARBANK_RELEASE_SIGNING=0 installs developer mode (signing is on by default).
"@
  exit 0
}
function Fail($m) { [Console]::Error.WriteLine("install-oarbankd.ps1: $m (try -Help)"); exit 2 }
function Run([string]$exe, [string[]]$a) {
  if ($DryRun) { "$exe $($a -join ' ')"; return }
  & $exe @a
  if ($LASTEXITCODE) { throw "$exe $($a -join ' ') failed ($LASTEXITCODE)" }
}
function Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not $DryRun -and -not (Admin)) { Fail "run it from an elevated PowerShell" }

function Remove-Services {
  foreach ($s in $Services.Values) {
    if (Get-Service $s -ErrorAction SilentlyContinue) {
      Run "sc.exe" @("stop", $s) 2>$null; if (-not $DryRun) { (Get-Service $s).WaitForStatus("Stopped", "00:01:00") }
      Run "sc.exe" @("delete", $s)
    }
  }
}

if ($Uninstall) {
  Remove-Services
  if (Get-NetFirewallRule -DisplayName $Rule -ErrorAction SilentlyContinue) {
    if ($DryRun) { "Remove-NetFirewallRule -DisplayName '$Rule'" } else { Remove-NetFirewallRule -DisplayName $Rule }
  }
  if (Test-Path $App) { if ($DryRun) { "remove $App" } else { Remove-Item -Recurse -Force $App } }
  "Oarbank coordinator removed. Its home stays in $Home_ until you delete it."
  exit 0
}
if (-not $Build) { Fail "give -Build <archive>" }
if (-not $AgentBind) { Fail "give -AgentBind <address agents reach>" }
if ($Pair -and -not ($From -and $FromCa)) { Fail "a standby (-Pair) also needs -From and -FromCa" }

# the build: its manifest names this machine's platform
$manifest = (tar -xzOf $Build oarbank-coordinator.json) | ConvertFrom-Json
if ($LASTEXITCODE -or $manifest.format -ne 1) { Fail "$Build is not a coordinator build" }
$want = "windows-$(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' })"
if ($manifest.platform -ne $want) { Fail "the build is for $($manifest.platform), this machine is $want" }
$sha = (Get-FileHash -Algorithm SHA256 $Build).Hash.ToLower().Substring(0, 12)
$dir = "$App\$($manifest.version)-$sha"

Remove-Services                                   # an upgrade: the services stop before `current` moves
if (-not (Test-Path $dir)) {
  if ($DryRun) { "unpack $Build into $dir" } else {
    New-Item -ItemType Directory -Force $dir | Out-Null
    tar -xzf $Build -C $dir
    if ($LASTEXITCODE) { Remove-Item -Recurse -Force $dir; throw "unpacking $Build failed" }
  }
}
if ($DryRun) { "junction $App\current -> $dir" } else {
  if (Test-Path "$App\current") { cmd /c rmdir "$App\current" | Out-Null }
  New-Item -ItemType Junction -Path "$App\current" -Target $dir | Out-Null
}

# the home: created before the services so its entries name their accounts by SID (they exist once the services do,
# but a SID needs no lookup); nothing inherited from ProgramData, which lets every user read and create files
$sid = @{}
foreach ($k in $Services.Keys) {
  $sha1 = [Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes($Services[$k].ToUpper()))
  $sid[$k] = "S-1-5-80-" + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($sha1, $_ * 4) }) -join "-")
}
if (-not $DryRun) { New-Item -ItemType Directory -Force $Home_ | Out-Null }
Run "icacls.exe" @($Home_, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                   "/grant:r", "*$($sid.oarbankd):(OI)(CI)F", "/grant:r", "*$($sid.console):(OI)(CI)F")

$py = "$App\current\python\python.exe"
$signing = if ($env:OARBANK_RELEASE_SIGNING) { $env:OARBANK_RELEASE_SIGNING } else { "1" }
$env_ = @("OARBANKD_HOME=$Home_", "OARBANK_RELEASE_SIGNING=$signing",
          "PATH=$App\current\bin;$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem")
if (-not $Url) { $Url = "https://${AgentBind}:$AgentPort" }
$args_ = @{
  oarbankd = @("-I", "-m", "oarbank.coordinator", "--service", "--agent-bind", $AgentBind, "--agent-port", "$AgentPort", "--url", $Url)
  console = @("-I", "-m", "oarbank.console", "--service")
}
if ($Pair) {
  $args_.oarbankd += @("--standby", "--pair", $Pair, "--from", $From, "--from-ca", $FromCa)
  if ($ArchiveHome) { $args_.oarbankd += "--archive-home" }
}
$display = @{oarbankd = "Oarbank coordinator"; console = "Oarbank console"}
$about = @{oarbankd = "Runs this fleet's coordinator: the agent API, the admin API and module processes";
           console = "Serves the Oarbank console on this machine's loopback"}
foreach ($k in "oarbankd", "console") {
  $name = $Services[$k]
  $bin = "`"$py`" " + (($args_[$k] | ForEach-Object { if ($_ -match '[\s"]') { "`"$($_ -replace '"', '\"')`"" } else { $_ } }) -join " ")
  Run "sc.exe" @("create", $name, "binPath=", $bin, "start=", "delayed-auto", "obj=", "NT SERVICE\$name", "DisplayName=", $display[$k])
  Run "sc.exe" @("description", $name, $about[$k])
  # restarted 10 s after a crash or a failed exit (a standby exits 75 to start again on the copy a move installed), as
  # launchd and systemd do; exit 0 (a finalized old coordinator) leaves it stopped
  Run "sc.exe" @("failure", $name, "reset=", "86400", "actions=", "restart/10000/restart/10000/restart/60000")
  Run "sc.exe" @("failureflag", $name, "1")
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
  if ($DryRun) { "set $key\Environment = $($env_ -join '; ')" } else {
    New-ItemProperty -Path $key -Name Environment -PropertyType MultiString -Value $env_ -Force | Out-Null
  }
}
# agents connect in; nothing else does (the admin API and the console answer on loopback only)
if ($DryRun) { "firewall rule '$Rule': inbound TCP $AgentPort for $($Services.oarbankd)" } else {
  Get-NetFirewallRule -DisplayName $Rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName $Rule -Direction Inbound -Action Allow -Protocol TCP -LocalPort $AgentPort `
    -Service $Services.oarbankd | Out-Null
}
foreach ($k in "oarbankd", "console") { Run "sc.exe" @("start", $Services[$k]) }
@"
Oarbank coordinator installed ($($manifest.version), $($manifest.platform)).
  agents:  $Url (client certificates; give nodes a join code)
  console: http://127.0.0.1:7400   admin API: http://127.0.0.1:7401
Next, in an elevated prompt on this machine:
  & "$App\current\bin\oarbank.cmd" account create <you> --role admin --password
  & "$App\current\bin\oarbank.cmd" join-code --label <node>
"@
