# CI on a throwaway Windows runner (.github/workflows/msi.yml): the agent's MSI installed, upgraded and removed for real.
# Install -First unattended with no properties: both services run, the node waits unjoined (its status document says
# so), oarbank-node is on the machine PATH and answers `status --json`, the oarbank:// handler, the join window and the
# Oarbank Node tray app (with its self-test) are in place; uninstall it and check that PATH and the handler are clean.
# Install it with CONTAINERS=1: the MSI exits 0 or 3010 (never 1603: the WSL package, itself an MSI, is never installed
# inside it), registers the container support task, which starts by itself once the installer has ended, runs
# `oarbank-agent containers install` as LocalSystem and records the outcome (whatever the runner's WSL makes of it);
# any WSL installation starts after the agent's installation ended; uninstalling removes the task and its record.
# Install it again for an unreachable coordinator (COORDINATOR=, the node then tries to enroll), check both services,
# open loopback for a test AppContainer through the elevated helper and see it close when its owner ends; open one again
# and keep its owner running through a major upgrade to -Second, which keeps it (helper_windows.rs: a restarted helper
# keeps the openings of owners that still run); then uninstall with an owner still running and check that the
# services, the helper's filters, provider and exemptions, its state file, PATH, the handler and Program Files\Oarbank
# are gone. Every msiexec log is written to -Logs. It changes the machine for good: never run it anywhere else.
#
#   scripts\ci-windows-msi.ps1 -First dist\a.msi -Second dist\b.msi -Logs dist\msi-logs
param([Parameter(Mandatory)][string]$First, [Parameter(Mandatory)][string]$Second, [Parameter(Mandatory)][string]$Logs)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Logs | Out-Null
# msiexec opens a package only by its full path (1619 otherwise)
$First, $Second, $Logs = (Resolve-Path $First).Path, (Resolve-Path $Second).Path, (Resolve-Path $Logs).Path
$Agent = "dev.codonic.oarbank.agent"
$Helper = "OarbankHelper"
$Provider = "{6f617262-616e-6b00-9a41-2f6c6f6f7062}"          # helper_windows.rs PROVIDER
$Container = "Oarbank.ci-msi"
$Pipe = "oarbank-helper"
$script:failed = 0

function Check([bool]$ok, [string]$what) {
  if ($ok) { Write-Host "ok   $what" } else { Write-Host "FAIL $what"; $script:failed++ }
}

function Msi([string]$verb, [string]$msi, [string]$log, [string[]]$props = @()) {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList (@($verb, "`"$msi`"", "/qn", "/norestart", "/l*v", "`"$Logs\$log`"") + $props)
  Check ($p.ExitCode -in 0, 3010) "msiexec $verb $(Split-Path -Leaf $msi): exit $($p.ExitCode)"
  if ($p.ExitCode -notin 0, 3010) { throw "msiexec $verb failed (its log: $Logs\$log)" }
}

function Service([string]$name) {
  Get-CimInstance Win32_Service -Filter "Name='$name'"
}

function Delayed([string]$name) {
  (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction SilentlyContinue).DelayedAutostart -eq 1
}

function WaitRunning([string]$name) {
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    $s = Service $name
    if ($s -and $s.State -eq "Running") { return $s }
    Start-Sleep -Milliseconds 500
  }
  Service $name
}

function CheckServices([string]$when) {
  $a, $h = (WaitRunning $Agent), (WaitRunning $Helper)
  Check ($a -and $a.State -eq "Running" -and $a.StartName -eq "NT SERVICE\$Agent" -and $a.StartMode -eq "Auto" -and (Delayed $Agent)) `
    "$when`: the agent's service runs as its virtual account, started at boot, delayed ($($a.State), $($a.StartName), $($a.StartMode))"
  Check ($h -and $h.State -eq "Running" -and $h.StartName -eq "LocalSystem" -and $h.StartMode -eq "Auto" -and (Delayed $Helper)) `
    "$when`: the helper's service runs as LocalSystem, started at boot, delayed ($($h.State), $($h.StartName), $($h.StartMode))"
}

Add-Type -Namespace Oarbank -Name Ac -MemberDefinition @'
[DllImport("userenv.dll", CharSet = CharSet.Unicode)]
public static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
public static extern bool ConvertSidToStringSid(IntPtr sid, out string text);
'@
$sidPtr = [IntPtr]::Zero
if ([Oarbank.Ac]::DeriveAppContainerSidFromAppContainerName($Container, [ref]$sidPtr) -ne 0) { throw "no SID for $Container" }
$Sid = ""
[void][Oarbank.Ac]::ConvertSidToStringSid($sidPtr, [ref]$Sid)

# the helper's filters for the test container's port (block filters name no port), from the filtering engine's own list
function Openings([int]$port) {
  $f = "$env:RUNNER_TEMP\wfp-filters.xml"
  netsh wfp show filters file="$f" | Out-Null
  [xml]$x = Get-Content $f
  @($x.wfpdiag.filters.item | Where-Object { $_.providerKey -eq $Provider -and
    ($_.filterCondition.item | Where-Object { $_.conditionValue.uint16 -eq "$port" }) }).Count
}

function HelperFilters {
  $f = "$env:RUNNER_TEMP\wfp-filters.xml"
  netsh wfp show filters file="$f" | Out-Null
  [xml]$x = Get-Content $f
  @($x.wfpdiag.filters.item | Where-Object { $_.providerKey -eq $Provider }).Count
}

function ProviderPresent {
  $f = "$env:RUNNER_TEMP\wfp-state.xml"
  netsh wfp show state file="$f" | Out-Null
  (Get-Content -Raw $f).Contains($Provider)
}

function Exempt { [bool]((CheckNetIsolation.exe LoopbackExempt -s) -match [regex]::Escape($Sid)) }

# a process that asks the helper for an opening, as a job's shim does, and waits to be ended
function Owner([int]$port) {
  $script = "`$p = New-Object IO.Pipes.NamedPipeClientStream('.', '$Pipe', 'InOut'); `$p.Connect(60000); " +
            "`$w = New-Object IO.StreamWriter(`$p); `$w.WriteLine('{`"op`": `"allow`", `"container`": `"$Container`", `"port`": $port}'); " +
            "`$w.Flush(); [IO.File]::WriteAllText('$env:RUNNER_TEMP\owner-$port.txt', (New-Object IO.StreamReader(`$p)).ReadLine()); " +
            "Start-Sleep 1800"
  # encoded: Start-Process passes its arguments as one command line, whose quotes the JSON's would break
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
  $o = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList "-NoProfile", "-EncodedCommand", $encoded `
    -RedirectStandardError "$Logs\owner-$port.err"
  $deadline = (Get-Date).AddSeconds(60)
  while (-not (Test-Path "$env:RUNNER_TEMP\owner-$port.txt") -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
  $reply = Get-Content "$env:RUNNER_TEMP\owner-$port.txt" -ErrorAction SilentlyContinue
  Check ($reply -match '"ok":\s*true') "the helper opens loopback on port $port for $Container ($reply)"
  if ($reply -notmatch '"ok":\s*true') {
    Write-Host "the owner's errors: $(Get-Content "$Logs\owner-$port.err" -Raw -ErrorAction SilentlyContinue)"
    Write-Host "the helper's filters: $(HelperFilters); exemptions: $((CheckNetIsolation.exe LoopbackExempt -s) -join ' | ')"
  }
  return $o
}

$Installed = "$env:ProgramFiles\Oarbank"
$SupportTask = "OarbankContainerSupport"                       # container_support.rs TASK
$SupportKey = "HKLM:\SOFTWARE\Codonic\Oarbank\ContainerSupport"  # container_support.rs KEY
$StatusFile = "$env:ProgramData\Oarbank\status\node.json"
$Protocol = "Registry::HKEY_CLASSES_ROOT\oarbank"
$Shortcut = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Oarbank Node.lnk"

# the node's status document (docs/design/node-enrollment.md), once it says what $want accepts, or the last one read
function NodeStatus([scriptblock]$want, [int]$seconds = 90) {
  $deadline = (Get-Date).AddSeconds($seconds)
  do {
    $doc = $null
    try { $doc = Get-Content -Raw -LiteralPath $StatusFile -ErrorAction Stop | ConvertFrom-Json } catch { }
    if ($doc -and (& $want $doc)) { return $doc }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  $doc
}

# the machine PATH as a new process gets it: from the registry, not this process's environment
function MachinePathHasOarbank {
  $entries = [Environment]::GetEnvironmentVariable("Path", "Machine").Split(";") | ForEach-Object { $_.TrimEnd("\") }
  $entries -contains $Installed
}

function CheckNodeParts([string]$when) {
  Check (Test-Path "$Installed\oarbank-node.exe") "$when`: Program Files\Oarbank holds oarbank-node.exe"
  Check (MachinePathHasOarbank) "$when`: Program Files\Oarbank is on the machine PATH"
  $command = (Get-ItemProperty -LiteralPath "$Protocol\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
  $urlProtocol = (Get-ItemProperty -LiteralPath $Protocol -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains "URL Protocol"
  Check ($command -eq "`"$Installed\Oarbank Node.exe`" --link `"%1`"" -and $urlProtocol) "$when`: oarbank:// opens Oarbank Node ($command)"
  Check ((Test-Path "$Installed\Oarbank Node.exe") -and (Test-Path $Shortcut)) "$when`: the Oarbank Node tray app and its Start menu shortcut"
  Check ((Test-Path "$Installed\join\join-window.py") -and (Test-Path "$Installed\join\join-window.html") -and
         (Test-Path "$Installed\runtime\pythonw.exe")) "$when`: the join window and the runtime's pythonw.exe"
}

function CheckNodePartsGone([string]$when) {
  Check (-not (MachinePathHasOarbank)) "$when`: Program Files\Oarbank is off the machine PATH"
  Check (-not (Test-Path -LiteralPath $Protocol)) "$when`: the oarbank:// handler is gone"
  Check (-not (Test-Path $Shortcut)) "$when`: the Start menu shortcut is gone"
}

function TaskPresent { & schtasks.exe /query /tn $SupportTask 2>$null | Out-Null; $LASTEXITCODE -eq 0 }

function Support { Get-ItemProperty -Path $SupportKey -ErrorAction SilentlyContinue }

function Until([scriptblock]$cond, [int]$seconds = 30) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while (-not (& $cond) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
  & $cond
}

# 1. install with nothing: the package installs, the node's service starts and waits for a code
Msi "/i" $First "install-unjoined.log"
CheckServices "installed without a code"
$st = NodeStatus { param($d) $d.state -eq "unjoined" }
Check ($st -and $st.state -eq "unjoined" -and $st.format -eq 1) "the node waits unjoined ($($st | ConvertTo-Json -Compress))"
CheckNodeParts "installed without a code"
# oarbank-node as a new prompt finds it: on the PATH the registry gives a new process
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
$cli = (Get-Command oarbank-node.exe -ErrorAction SilentlyContinue).Source
Check ($cli -eq "$Installed\oarbank-node.exe") "oarbank-node resolves from the machine PATH ($cli)"
# exit 1 means "not joined" here; the JSON on stdout is what counts
$out = (& oarbank-node.exe status --json) | Out-String
$reply = $null
try { $reply = $out | ConvertFrom-Json } catch { }
Check ($reply -and $reply.scope -eq "system" -and $reply.status.state -eq "unjoined") "oarbank-node status --json reads the waiting node ($($out.Trim()))"
$tray = Start-Process -FilePath "$Installed\Oarbank Node.exe" -ArgumentList "--self-test" -Wait -PassThru `
  -RedirectStandardOutput "$Logs\node-tray.log" -RedirectStandardError "$Logs\node-tray-error.log"
Check ($tray.ExitCode -eq 0) "the Oarbank Node tray app's self-test: $((Get-Content "$Logs\node-tray.log" -Raw -ErrorAction SilentlyContinue) -replace '\s+$', '') $(Get-Content "$Logs\node-tray-error.log" -Raw -ErrorAction SilentlyContinue)"
Msi "/x" $First "uninstall-unjoined.log"
Check (-not (Service $Agent) -and -not (Service $Helper)) "the uninstall removes both services"
CheckNodePartsGone "uninstalled"

# 1b. container support: registered by the MSI, run after it
$since = Get-Date
Msi "/i" $First "install-containers.log" @("CONTAINERS=1", "COORDINATOR=https://127.0.0.1:9")
$log = Get-Content -Raw "$Logs\install-containers.log"
Check ($log -match "(Doing action|Action start [0-9:]+): ScheduleContainers" -and $log -notmatch "oarbank-agent\.exe`"? containers install") `
  "the MSI schedules container support and runs no containers install inside itself"
$rec = Support
Check ($rec -and $rec.State -in @("scheduled", "installing", "waiting", "restart", "done", "failed") -and $rec.Detail -notmatch "could not register") `
  "the MSI recorded container support ($($rec.State): $($rec.Detail))"
$defined = & schtasks.exe /query /tn $SupportTask /xml 2>$null | Out-String
Check (($defined -match "<UserId>S-1-5-18</UserId>" -and $defined -match "<EventTrigger>" -and $defined -match "<BootTrigger>") -or
       ($rec -and $rec.State -in @("done", "failed"))) "the container support task runs as LocalSystem after the installer and at boot (or already ran)"
# the installer's end (MsiInstaller 1033 for this product) starts it: nobody runs it here
$started = Until { (Support).State -ne "scheduled" } 180
Check $started "the container support task started by itself once the installer had ended ($((Support).State))"
if (-not $started) { & schtasks.exe /run /tn $SupportTask | Out-Null }
$ended = Until { (Support).State -in @("done", "failed", "restart", "waiting") } 1500
$rec = Support
Check $ended "container support reached an outcome: $($rec.State) ($($rec.Detail)), attempt $($rec.Attempts)"
if ($rec.State -in @("done", "failed")) {
  Check (Until { -not (TaskPresent) } 30) "the task deleted itself after its outcome ($($rec.State))"
} else {
  Check (TaskPresent) "the task stays for the next start of Windows ($($rec.State))"
}
# never nested: any WSL installation began after this product's installation had ended
$ours = Get-WinEvent -FilterHashtable @{LogName = "Application"; ProviderName = "MsiInstaller"; Id = 1033; StartTime = $since} -ErrorAction SilentlyContinue |
  Where-Object { $_.Properties[0].Value -eq "Oarbank agent" } | Sort-Object TimeCreated | Select-Object -First 1
$wsl = @(Get-WinEvent -FilterHashtable @{LogName = "Application"; ProviderName = "MsiInstaller"; Id = 1040; StartTime = $since} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match "wsl" })
Check ($ours -and @($wsl | Where-Object { $_.TimeCreated -lt $ours.TimeCreated }).Count -eq 0) `
  "no WSL installation began inside the agent's ($($wsl.Count) WSL installation(s), the agent's ended $($ours.TimeCreated))"
Msi "/x" $First "uninstall-containers.log"
Check (-not (TaskPresent) -and -not (Support)) "the uninstall removes the container support task and its record"
Check (-not (Service $Agent) -and -not (Service $Helper)) "the uninstall removes both services (CONTAINERS=1)"

# 2. install for a coordinator that never answers: the node tries to enroll (and retries), the install still succeeds
Msi "/i" $First "install.log" @("COORDINATOR=https://127.0.0.1:9")
CheckServices "installed"
Check (Test-Path "$env:ProgramFiles\Oarbank\oarbank-launcher.exe") "Program Files\Oarbank holds the launcher"
$st = NodeStatus { param($d) $d.state -eq "joining" -or $d.error.code -eq "E_TCP" }
Check ($st -and $st.coordinator -eq "https://127.0.0.1:9" -and ($st.state -eq "joining" -or $st.error.code -eq "E_TCP")) `
  "the node enrolls by address and retries the unreachable coordinator ($($st | ConvertTo-Json -Compress))"
CheckNodeParts "installed"

# 3. an opening ends with its owner
$o = Owner 45901
$n, $e = (Openings 45901), (Exempt)
Check ($n -eq 2 -and $e) "the opening's permit filters (IPv4, IPv6) and the exemption are in place ($n of the helper's $(HelperFilters) filters, exempt: $e)"
Stop-Process -Id $o.Id -Force
Check ($n -eq 2 -and $e -and (Until { (Openings 45901) -eq 0 -and -not (Exempt) })) "the opening and the exemption go when its owner is killed"

# 4. a major upgrade keeps a running owner's opening, and the node's PATH entry, handler and tray app
$o = Owner 45902
Msi "/i" $Second "upgrade.log"
CheckServices "upgraded"
CheckNodeParts "upgraded"
$n, $e = (Openings 45902), (Exempt)
Check ($n -eq 2 -and $e) "the upgraded helper kept the opening of an owner that still runs ($n of the helper's $(HelperFilters) filters, exempt: $e)"
Stop-Process -Id $o.Id -Force
Check ($n -eq 2 -and $e -and (Until { (Openings 45902) -eq 0 -and -not (Exempt) })) "the upgraded helper ends that opening with its owner"

# 5. uninstall, with an owner still running
$o = Owner 45903
Check ((Openings 45903) -eq 2 -and (Exempt)) "an opening is in place before the uninstall"
Msi "/x" $Second "uninstall.log"
Check (-not (Service $Agent) -and -not (Service $Helper)) "the agent's and the helper's services are gone"
Check ((HelperFilters) -eq 0 -and -not (ProviderPresent)) "the helper's filters and provider are gone"
Check (-not (Exempt)) "the exemption is gone though its owner still runs"
Check (-not (Test-Path "$env:ProgramData\Oarbank\helper-exemptions.json")) "the helper's state file is gone"
Check (-not (Test-Path "$env:ProgramFiles\Oarbank")) "Program Files\Oarbank is gone"
CheckNodePartsGone "uninstalled after the upgrade"
Stop-Process -Id $o.Id -Force -ErrorAction SilentlyContinue

if ($script:failed) { throw "$($script:failed) check(s) failed (msiexec logs in $Logs)" }
