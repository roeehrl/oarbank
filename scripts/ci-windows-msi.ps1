# CI on a throwaway Windows runner (.github/workflows/msi.yml): the agent's MSI installed, upgraded and removed for real.
# Install -First unattended (the agent's service set up for an unreachable coordinator), check both services, open
# loopback for a test AppContainer through the elevated helper and see it close when its owner ends; open one again
# and keep its owner running through a major upgrade to -Second, which keeps it (helper_windows.rs: a restarted helper
# keeps the openings of owners that still run); then uninstall with an owner still running and check that the
# services, the helper's filters, provider and exemptions, its state file and Program Files\Oarbank are gone. Every
# msiexec log is written to -Logs. It changes the machine for good: never run it anywhere else.
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

function Until([scriptblock]$cond, [int]$seconds = 30) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while (-not (& $cond) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
  & $cond
}

# 1. install
Msi "/i" $First "install.log" @("COORDINATOR=https://127.0.0.1:9")
CheckServices "installed"
Check (Test-Path "$env:ProgramFiles\Oarbank\oarbank-launcher.exe") "Program Files\Oarbank holds the launcher"

# 2. an opening ends with its owner
$o = Owner 45901
$n, $e = (Openings 45901), (Exempt)
Check ($n -eq 2 -and $e) "the opening's permit filters (IPv4, IPv6) and the exemption are in place ($n of the helper's $(HelperFilters) filters, exempt: $e)"
Stop-Process -Id $o.Id -Force
Check ($n -eq 2 -and $e -and (Until { (Openings 45901) -eq 0 -and -not (Exempt) })) "the opening and the exemption go when its owner is killed"

# 3. a major upgrade keeps a running owner's opening
$o = Owner 45902
Msi "/i" $Second "upgrade.log"
CheckServices "upgraded"
$n, $e = (Openings 45902), (Exempt)
Check ($n -eq 2 -and $e) "the upgraded helper kept the opening of an owner that still runs ($n of the helper's $(HelperFilters) filters, exempt: $e)"
Stop-Process -Id $o.Id -Force
Check ($n -eq 2 -and $e -and (Until { (Openings 45902) -eq 0 -and -not (Exempt) })) "the upgraded helper ends that opening with its owner"

# 4. uninstall, with an owner still running
$o = Owner 45903
Check ((Openings 45903) -eq 2 -and (Exempt)) "an opening is in place before the uninstall"
Msi "/x" $Second "uninstall.log"
Check (-not (Service $Agent) -and -not (Service $Helper)) "the agent's and the helper's services are gone"
Check ((HelperFilters) -eq 0 -and -not (ProviderPresent)) "the helper's filters and provider are gone"
Check (-not (Exempt)) "the exemption is gone though its owner still runs"
Check (-not (Test-Path "$env:ProgramData\Oarbank\helper-exemptions.json")) "the helper's state file is gone"
Check (-not (Test-Path "$env:ProgramFiles\Oarbank")) "Program Files\Oarbank is gone"
Stop-Process -Id $o.Id -Force -ErrorAction SilentlyContinue

if ($script:failed) { throw "$($script:failed) check(s) failed (msiexec logs in $Logs)" }
