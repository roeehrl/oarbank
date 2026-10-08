# Native MSI lifecycle regression on disposable runners; no Oarbank programs are executed.
param([Parameter(Mandatory=$true)][string]$First, [Parameter(Mandatory=$true)][string]$Second)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Disposable GitHub Actions runners only.' }
$First = (Resolve-Path $First).Path
$Second = (Resolve-Path $Second).Path
$services = @('dev.codonic.oarbank.oarbankd', 'dev.codonic.oarbank.console')
$root = Join-Path $env:ProgramW6432 'Oarbank\Coordinator\package'
$fixture = Join-Path $env:ProgramData 'Oarbank\ci-service-fixture'
$state = Join-Path $env:ProgramData 'Oarbank\coordinator'
New-Item -ItemType Directory -Force $fixture, $state | Out-Null
Set-Content "$state/ci-retained-data.txt" 'retain across upgrade and removal'
function Installer([string]$action, [string]$msi, [string]$phase) {
    $log = Join-Path $env:RUNNER_TEMP "coordinator-fixture-$phase.log"
    $result = Start-Process msiexec.exe -ArgumentList "$action `"$msi`" /qn /norestart /l*v `"$log`"" -Wait -PassThru
    if ($result.ExitCode -notin @(0,3010)) {
        Get-Content $log | Select-String -Pattern 'Error [0-9]+|Return value 3' -Context 3,3 | Select-Object -Last 35 | ForEach-Object { Write-Host $_ }
        throw "$phase failed: $($result.ExitCode)"
    }
}
function ServiceState {
    $result = @{}
    foreach ($name in $services) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if (-not $svc -or $svc.State -ne 'Running' -or $svc.StartName -ne "NT SERVICE\$name") { throw "unexpected service state for $name : $($svc | Out-String)" }
        $result[$name] = $svc.ProcessId
    }
    return $result
}
foreach ($name in $services) {
    if (Get-Service $name -ErrorAction SilentlyContinue) { throw "unexpected existing service $name" }
}
try {
    Installer '/i' $First 'install'
    foreach ($name in $services) {
        if (Get-Service $name -ErrorAction SilentlyContinue) { throw "initial package install created $name" }
    }
    # A tiny no-op Windows service simulates services created later by the wizard. It performs no fleet work.
    @'
using System.ServiceProcess;
public sealed class Fixture : ServiceBase {
    Fixture(string name) { ServiceName = name; }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { }
    public static void Main(string[] args) { ServiceBase.Run(new Fixture(args[0])); }
}
'@ | Set-Content "$fixture/Fixture.cs"
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /target:exe /reference:System.ServiceProcess.dll "/out:$fixture/Fixture.exe" "$fixture/Fixture.cs"
    if ($LASTEXITCODE) { throw 'service fixture compilation failed' }
    foreach ($name in $services) {
        New-Service -Name $name -BinaryPathName "`"$fixture\Fixture.exe`" $name" -StartupType Manual | Out-Null
        & sc.exe config $name obj= "NT SERVICE\$name"
        if ($LASTEXITCODE) { throw 'virtual account configuration failed' }
        Start-Service $name
    }
    $before = ServiceState
    Installer '/fvomus' $First 'repair'
    $after = ServiceState
    foreach ($name in $services) { if ($after[$name] -eq $before[$name]) { throw "repair did not restart $name" } }
    Installer '/i' $Second 'upgrade'
    $upgraded = ServiceState
    foreach ($name in $services) { if ($upgraded[$name] -eq $after[$name]) { throw "upgrade did not restart $name" } }
    Installer '/x' $Second 'uninstall'
    foreach ($name in $services) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw "uninstall retained $name" } }
    if (Test-Path $root) { throw 'uninstall retained package files' }
    if (-not (Test-Path "$state/ci-retained-data.txt")) { throw 'uninstall removed fleet data' }
    'Software-only install, later-service repair, major upgrade and retained-data uninstall all passed.'
} finally {
    foreach ($name in $services) {
        if (Get-Service $name -ErrorAction SilentlyContinue) {
            Stop-Service $name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $name
        }
    }
    Remove-Item $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
