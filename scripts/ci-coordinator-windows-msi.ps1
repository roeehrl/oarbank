# Software-only MSI smoke on disposable GitHub runners. Never run on a user's machine.
param([Parameter(Mandatory=$true)][string]$Msi)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This smoke test is only for disposable GitHub Actions runners.' }
$Msi = (Resolve-Path -LiteralPath $Msi).Path
$root = Join-Path $env:ProgramW6432 'Oarbank\Coordinator\package'
$state = Join-Path $env:ProgramData 'Oarbank\coordinator'
$services = @('dev.codonic.oarbank.oarbankd', 'dev.codonic.oarbank.console')
foreach ($name in $services) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw "unexpected existing service $name" } }
New-Item -ItemType Directory -Force $state | Out-Null
$sentinel = Join-Path $state 'ci-retained-data.txt'
Set-Content -LiteralPath $sentinel -Value 'retain across package removal'
function Installer([string]$action, [string]$log) {
    $process = Start-Process msiexec.exe -ArgumentList "$action `"$Msi`" /qn /norestart /l*v `"$log`"" -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "Windows Installer $action failed: $($process.ExitCode); see $log" }
}
Installer '/i' (Join-Path $env:RUNNER_TEMP 'coordinator-install.log')
try {
    foreach ($name in $services) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw "package installation created service $name" } }
    & "$root\python\python.exe" -I -B "$root\bin\oarbank-setup.py" --help
    if ($LASTEXITCODE) { throw 'installed setup launcher cannot run' }
    if (-not (Test-Path "$root\oarbank-setup.ps1")) { throw 'Start menu elevation broker missing' }
    $shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Oarbank coordinator setup.lnk'
    if (-not (Test-Path $shortcut)) { throw 'Start menu shortcut missing' }
} finally {
    Installer '/x' (Join-Path $env:RUNNER_TEMP 'coordinator-uninstall.log')
}
if (Test-Path $root) { throw 'MSI payload remains after uninstall' }
if (-not (Test-Path $sentinel)) { throw 'uninstall deleted coordinator data' }
foreach ($name in $services) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw "service remains: $name" } }
'Coordinator MSI install/uninstall passed; no services created, existing data retained.'
