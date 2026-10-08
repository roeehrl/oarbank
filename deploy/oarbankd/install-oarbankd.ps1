# Install the Oarbank coordinator on Windows from a coordinator build: oarbankd and the console as services of the
# service control manager, each run by its own virtual account (NT SERVICE\dev.codonic.oarbank.oarbankd and
# NT SERVICE\dev.codonic.oarbank.console), started at boot (delayed) and restarted after a crash or a failed exit, with
# the coordinator's home in %ProgramData%\Oarbank\coordinator (docs/design/windows-coordinator.md). Run it from an
# elevated PowerShell; running it again with a newer build upgrades in place. `-Help` lists the options. A move to a
# Windows machine that is not an enrolled node installs the standby with -Pair (coordinator-move.md, runbook).
param(
  [string]$Build = "",            # oarbank-coordinator-<v>-windows-<arch>.tar.gz (scripts\build-coordinator.ps1)
  [string]$Installed = "",        # an already installed build directory (the coordinator MSI's package directory)
  [string]$AgentBind = "",        # the address agents reach: a LAN or tailnet address (127.0.0.1 only for a trial)
  [int]$AgentPort = 7443,
  [string]$Url = "",              # the agent URL as agents reach it when that is not https://<AgentBind>:<AgentPort> (a NAT)
  [string]$Pair = "",             # a standby for a move: the pairing code coordinator.prepare printed,
  [string]$From = "",             #   the old coordinator's agent URL,
  [string]$FromCa = "",           #   and its TLS CA pin
  [switch]$ArchiveHome,           # with -Pair: move an existing home aside first (a move back to this machine)
  [switch]$Uninstall,             # remove the services, the firewall rule and the programs; the home stays
  [switch]$KeepPrograms,          # with -Uninstall: leave the payload for its owner (MSI) to remove
  [string]$SaveConfiguration = "", # MSI uninstall: save service definitions, firewall and junction for rollback
  [string]$RestoreConfiguration = "", # MSI rollback: restore that snapshot (no coordinator data is touched)
  [switch]$DryRun,                # print what would be done instead of doing it
  [switch]$Help
)
$ErrorActionPreference = "Stop"
$Services = @{oarbankd = "dev.codonic.oarbank.oarbankd"; console = "dev.codonic.oarbank.console"}
$ProgramRoot = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$App = "$ProgramRoot\Oarbank\Coordinator"
$Home_ = "$env:ProgramData\Oarbank\coordinator"
$Rule = "Oarbank coordinator (agents)"

if ($Help) {
  @"
usage: install-oarbankd.ps1 -Build <archive> -AgentBind <address> [-AgentPort 7443] [-Url <url>] [-DryRun]
       install-oarbankd.ps1 -Installed <directory> -AgentBind <address> [-AgentPort 7443] [-Url <url>] [-DryRun]
       install-oarbankd.ps1 -Build <archive> -AgentBind <address> -Pair <code> -From <url> -FromCa <pin> [-ArchiveHome]
       install-oarbankd.ps1 -Uninstall [-KeepPrograms] [-SaveConfiguration <file>] [-DryRun]
       install-oarbankd.ps1 -RestoreConfiguration <file> [-DryRun]

Installs the coordinator build under $App (each version beside the others, `current` a junction to the
running one) and the services $($Services.oarbankd) and $($Services.console). The home is
$Home_, private to SYSTEM, Administrators and the two services' accounts. An inbound firewall rule lets agents reach
oarbankd's agent port. Environment: OARBANK_RELEASE_SIGNING=0 installs developer mode (signing is on by default).
-Installed uses the validated directory directly; it never unpacks, copies or deletes that payload. -Build and
-Installed are mutually exclusive. Standby options also apply to -Installed. -KeepPrograms removes only the services,
firewall rule and current junction, preserving the MSI-owned package and all coordinator data.
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
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc) {
      if ($svc.Status -ne "Stopped") {
        Run "sc.exe" @("stop", $s)
        if (-not $DryRun) { $svc.WaitForStatus("Stopped", "00:01:00") }
      }
      Run "sc.exe" @("delete", $s)
      $svc.Dispose()
      if (-not $DryRun) {
        $deadline = (Get-Date).AddSeconds(30)
        do {
          $remaining = Get-Service $s -ErrorAction SilentlyContinue
          if (-not $remaining) { break }
          $remaining.Dispose()
          if ((Get-Date) -ge $deadline) { throw "$s is still marked for deletion; close other service management tools and retry" }
          Start-Sleep -Milliseconds 100
        } while ($true)
      }
    }
  }
}

# Remove the junction itself, never recurse through it into an MSI-owned build. Refuse an unexpected real directory.
function Remove-Current {
  $link = Get-Item -LiteralPath "$App\current" -Force -ErrorAction SilentlyContinue
  if ($link) {
    if (-not ($link.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Fail "$App\current is not a junction" }
    if ($DryRun) { "remove junction $App\current" } else { [IO.Directory]::Delete($link.FullName) }
  }
}

# MSI restores removed payload files before this rollback action runs. Capture only installation state, never the
# database, accounts or keys. Program Files protects the snapshot from writes by non-administrators.
function Save-Configuration {
  if ($DryRun) { "save service/firewall/junction configuration to $SaveConfiguration"; return }
  $saved = @()
  foreach ($name in $Services.Values) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if (-not $svc) { continue }
    if ($svc.StartName -ne "NT SERVICE\$name") { throw "cannot snapshot $name with an unexpected service account" }
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$name")
    try {
      $values = @($key.GetValueNames() | ForEach-Object {
        @{Name = $_; Kind = $key.GetValueKind($_).ToString(); Value = $key.GetValue($_, $null, 'DoNotExpandEnvironmentNames')}
      })
    } finally { $key.Dispose() }
    $saved += @{Name = $name; Command = $svc.PathName; Display = $svc.DisplayName; Values = $values}
  }
  $rules = @(Get-NetFirewallRule -DisplayName $Rule -ErrorAction SilentlyContinue | ForEach-Object {
    $port = $_ | Get-NetFirewallPortFilter
    @{Name = $_.Name; Ports = $port.LocalPort; Profile = $_.Profile.ToString(); Enabled = $_.Enabled.ToString()}
  })
  $link = Get-Item -LiteralPath "$App\current" -Force -ErrorAction SilentlyContinue
  $target = if ($link -and ($link.Attributes -band [IO.FileAttributes]::ReparsePoint)) { @($link.Target)[0] } else { $null }
  @{Services = $saved; Rules = $rules; Current = $target} | Export-Clixml -LiteralPath $SaveConfiguration
}

if ($RestoreConfiguration) {
  if ($DryRun) { "restore service/firewall/junction configuration from $RestoreConfiguration"; exit 0 }
  if (-not (Test-Path -LiteralPath $RestoreConfiguration -PathType Leaf)) { exit 0 } # failed before snapshot creation
  $state = Import-Clixml -LiteralPath $RestoreConfiguration
  foreach ($svc in $state.Services) {
    if (-not (Get-Service $svc.Name -ErrorAction SilentlyContinue)) {
      New-Service -Name $svc.Name -DisplayName $svc.Display -BinaryPathName $svc.Command -StartupType Automatic | Out-Null
    }
    Run 'sc.exe' @('config', $svc.Name, 'obj=', "NT SERVICE\$($svc.Name)")
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$($svc.Name)", $true)
    try {
      foreach ($value in $svc.Values) {
        $typed = switch ($value.Kind) {
          'Binary' { ,([byte[]]$value.Value) }
          'MultiString' { ,([string[]]$value.Value) }
          'DWord' { [int]$value.Value }
          'QWord' { [long]$value.Value }
          default { [string]$value.Value }
        }
        $key.SetValue($value.Name, $typed, [Microsoft.Win32.RegistryValueKind]$value.Kind)
      }
    } finally { $key.Dispose() }
    # Restore the SCM's cached configuration as well as its persisted values. These are the virtual-account
    # services configured below; MSI's StopServices rollback restarts services that were running before uninstall.
    $start = ($svc.Values | Where-Object Name -eq 'Start').Value
    $delayed = ($svc.Values | Where-Object Name -eq 'DelayedAutostart').Value
    $mode = switch ($start) { 2 { if ($delayed) { 'delayed-auto' } else { 'auto' } } 3 { 'demand' } 4 { 'disabled' } }
    Run 'sc.exe' @('config', $svc.Name, 'start=', $mode)
    Run 'sc.exe' @('failure', $svc.Name, 'reset=', '86400', 'actions=', 'restart/10000/restart/10000/restart/60000')
    Run 'sc.exe' @('failureflag', $svc.Name, '1')
  }
  foreach ($rule_ in $state.Rules) {
    if (-not (Get-NetFirewallRule -Name $rule_.Name -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -Name $rule_.Name -DisplayName $Rule -Direction Inbound -Action Allow -Protocol TCP `
        -LocalPort $rule_.Ports -Service $Services.oarbankd -Profile ($rule_.Profile -split ',\s*') -Enabled $rule_.Enabled | Out-Null
    }
  }
  if ($state.Current -and -not (Get-Item -LiteralPath "$App\current" -Force -ErrorAction SilentlyContinue)) {
    New-Item -ItemType Junction -Path "$App\current" -Target $state.Current | Out-Null
  }
  Remove-Item -LiteralPath $RestoreConfiguration -Force
  exit 0
}

if ($Uninstall) {
  if ($SaveConfiguration) { Save-Configuration }
  Remove-Services
  if (Get-NetFirewallRule -DisplayName $Rule -ErrorAction SilentlyContinue) {
    if ($DryRun) { "Remove-NetFirewallRule -DisplayName '$Rule'" } else { Remove-NetFirewallRule -DisplayName $Rule }
  }
  if ($KeepPrograms) {
    Remove-Current
    "Keeping programs in $App for their package owner."
  } elseif (Test-Path $App) { if ($DryRun) { "remove $App" } else { Remove-Item -Recurse -Force $App } }
  "Oarbank coordinator removed. Its home stays in $Home_ until you delete it."
  exit 0
}
if ($SaveConfiguration) { Fail "-SaveConfiguration requires -Uninstall" }
if ($KeepPrograms) { Fail "-KeepPrograms requires -Uninstall" }
if ($Build -and $Installed) { Fail "give either -Build <archive> or -Installed <directory>, not both" }
if (-not ($Build -or $Installed)) { Fail "give -Build <archive> or -Installed <directory>" }
if (-not $AgentBind) { Fail "give -AgentBind <address agents reach>" }
if ($AgentPort -lt 1 -or $AgentPort -gt 65535) { Fail "-AgentPort must be between 1 and 65535" }
if ($Pair -and -not ($From -and $FromCa)) { Fail "a standby (-Pair) also needs -From and -FromCa" }

# Check the manifest before changing any existing services or files.
if ($Installed) {
  try {
    $item = Get-Item -LiteralPath $Installed -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      Fail "-Installed must name a real build directory, not a link"
    }
    $dir = $item.FullName.TrimEnd('\')
    if ($dir -eq $App -or $dir -eq "$App\current" -or $dir.StartsWith("$App\current\", [StringComparison]::OrdinalIgnoreCase)) {
      Fail "-Installed cannot be the application directory or its current junction"
    }
    $manifest = Get-Content -LiteralPath "$dir\oarbank-coordinator.json" -Raw | ConvertFrom-Json
  } catch { Fail "cannot read the installed build manifest: $($_.Exception.Message)" }
  if ((@($manifest.exec) -join '|') -ne 'python/python.exe|-I|bin/oarbankd.py' -or
      (@($manifest.console) -join '|') -ne 'python/python.exe|-I|bin/oarbank-console.py') {
    Fail "the installed build manifest does not name the Windows coordinator launchers"
  }
  foreach ($file in @('python\python.exe', 'bin\oarbankd.py', 'bin\oarbank-console.py')) {
    if (-not (Test-Path -LiteralPath "$dir\$file" -PathType Leaf)) { Fail "the installed build is missing $file" }
  }
} else {
  try { $manifest = (tar -xzOf $Build oarbank-coordinator.json) | ConvertFrom-Json }
  catch { Fail "$Build is not a coordinator build" }
  if ($LASTEXITCODE) { Fail "$Build is not a coordinator build" }
}
if ($manifest.format -ne 1 -or $manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$') {
  Fail "invalid coordinator build format or version"
}
# the machine's architecture, not this PowerShell's (an x64 one runs under emulation on Windows on Arm, and then
# PROCESSOR_ARCHITECTURE and .NET both say AMD64): the system's own environment says
$native = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").PROCESSOR_ARCHITECTURE
$want = "windows-$(if ($native -eq 'ARM64') { 'arm64' } else { 'amd64' })"
if ($manifest.platform -ne $want) { Fail "the build is for $($manifest.platform), this machine is $want" }
if ($Installed -and (Get-Item -LiteralPath "$App\current" -Force -ErrorAction SilentlyContinue) -and
    -not ((Get-Item -LiteralPath "$App\current" -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  Fail "$App\current is not a junction"
}
if (-not $Installed) {
  $sha = (Get-FileHash -Algorithm SHA256 $Build).Hash.ToLower().Substring(0, 12)
  $dir = "$App\$($manifest.version)-$sha"
}

Remove-Services                                   # an upgrade: the services stop before `current` moves
if (-not $Installed -and -not (Test-Path $dir)) {
  if ($DryRun) { "unpack $Build into $dir" } else {
    New-Item -ItemType Directory -Force $dir | Out-Null
    tar -xzf $Build -C $dir
    if ($LASTEXITCODE) { Remove-Item -Recurse -Force $dir; throw "unpacking $Build failed" }
  }
}
if ($DryRun) { "junction $App\current -> $dir" } else {
  Remove-Current
  New-Item -ItemType Directory -Force $App | Out-Null
  New-Item -ItemType Junction -Path "$App\current" -Target $dir | Out-Null
}

$py = "$App\current\python\python.exe"
$signing = if ($env:OARBANK_RELEASE_SIGNING) { $env:OARBANK_RELEASE_SIGNING } else { "1" }
$env_ = @("OARBANKD_HOME=$Home_", "OARBANK_RELEASE_SIGNING=$signing",
          "PATH=$App\current\bin;$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem")
if (-not $Url) { $Url = "https://${AgentBind}:$AgentPort" }
$args_ = @{
  oarbankd = @("-I", "$App\current\bin\oarbankd.py", "--service", "--agent-bind", $AgentBind, "--agent-port", "$AgentPort", "--url", $Url)
  console = @("-I", "$App\current\bin\oarbank-console.py", "--service")
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
  # New-Service takes the command line as it is (sc.exe's own quoting of embedded quotes is unreliable from PowerShell)
  if ($DryRun) { "New-Service $name -BinaryPathName $bin" } else {
    New-Service -Name $name -BinaryPathName $bin -DisplayName $display[$k] -StartupType Automatic | Out-Null
  }
  Run "sc.exe" @("config", $name, "start=", "delayed-auto", "obj=", "NT SERVICE\$name")
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
# the home, once the services (and with them their virtual accounts, which icacls looks up) exist and before they
# start: nothing inherited from ProgramData, which lets every user read and create files
$sid = @{}
foreach ($k in $Services.Keys) {
  $sha1 = [Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes($Services[$k].ToUpper()))
  $sid[$k] = "S-1-5-80-" + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($sha1, $_ * 4) }) -join "-")
}
if (-not $DryRun) { New-Item -ItemType Directory -Force $Home_ | Out-Null }
Run "icacls.exe" @($Home_, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                   "/grant:r", "*$($sid.oarbankd):(OI)(CI)F", "/grant:r", "*$($sid.console):(OI)(CI)F")

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
