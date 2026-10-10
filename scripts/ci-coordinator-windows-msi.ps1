# Software-only MSI smoke on disposable GitHub runners. Never run on a user's machine.
param([Parameter(Mandatory=$true)][string]$Msi)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This smoke test is only for disposable GitHub Actions runners.' }
$Msi = (Resolve-Path -LiteralPath $Msi).Path
$root = Join-Path $env:ProgramW6432 'Oarbank\Coordinator\package'
$state = Join-Path $env:ProgramData 'Oarbank\coordinator'
$services = @('dev.codonic.oarbank.oarbankd', 'dev.codonic.oarbank.console')
$cliDir = Join-Path $root 'cli'
# the PATH a new prompt gets: from the registry, not this process's environment
function NewPromptPath {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}
function MachinePathHasCli {
    @([Environment]::GetEnvironmentVariable('Path', 'Machine').Split(';') | ForEach-Object { $_.TrimEnd('\') }) -contains $cliDir
}
foreach ($name in $services) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw "unexpected existing service $name" } }
New-Item -ItemType Directory -Force $state | Out-Null
$sentinel = Join-Path $state 'ci-retained-data.txt'
Set-Content -LiteralPath $sentinel -Value 'retain across package removal'
function Installer([string]$action, [string]$log) {
    $process = Start-Process msiexec.exe -ArgumentList "$action `"$Msi`" /qn /norestart /l*v `"$log`"" -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        Get-Content -LiteralPath $log | Select-String -Pattern 'Error [0-9]+|Return value 3|MainEngineThread is returning' -Context 3,3 | Select-Object -Last 35 | ForEach-Object { Write-Host $_ }
        throw "Windows Installer $action failed: $($process.ExitCode); see $log"
    }
}
Installer '/i' (Join-Path $env:RUNNER_TEMP 'coordinator-install.log')
try {
    foreach ($name in $services) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw "package installation created service $name" } }
    & "$root\python\python.exe" -I -B "$root\bin\oarbank-setup.py" --help
    if ($LASTEXITCODE) { throw 'installed setup launcher cannot run' }
    if (-not (Test-Path "$root\oarbank-setup.ps1")) { throw 'Start menu elevation broker missing' }
    $shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Oarbank Coordinator.lnk'
    if (-not (Test-Path $shortcut)) { throw 'Start menu shortcut missing' }
    # `oarbank` resolves from the PATH a new prompt gets, before setup through the package's own CLI
    if (-not (MachinePathHasCli)) { throw "$cliDir is not on the machine PATH" }
    NewPromptPath
    $cli = (Get-Command oarbank -ErrorAction SilentlyContinue).Source
    if ($cli -ne (Join-Path $cliDir 'oarbank.cmd')) { throw "oarbank resolves to '$cli', not the package's cli\oarbank.cmd" }
    $help = (& oarbank --help) | Out-String
    if ($LASTEXITCODE -or $help -notmatch 'usage: oarbank') { throw "oarbank --help from the PATH failed ($LASTEXITCODE): $help" }
    $ErrorActionPreference = 'Continue'   # argparse's usage message on stderr is expected here
    & oarbank --no-such-option 2>$null
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 2) { throw "oarbank on the PATH does not pass the CLI's exit code back ($code)" }
    # once setup has pointed Coordinator\current at a build, the PATH runs that build's CLI, arguments and exit code intact
    $current = Join-Path $env:ProgramW6432 'Oarbank\Coordinator\current'
    $fake = Join-Path $env:RUNNER_TEMP 'coordinator-current-fixture'
    New-Item -ItemType Directory -Force (Join-Path $fake 'bin') | Out-Null
    Set-Content -Encoding ascii (Join-Path $fake 'bin\oarbank.cmd') '@echo current build: %*& exit /b 7'
    New-Item -ItemType Junction -Path $current -Target $fake | Out-Null
    try {
        $out = (& oarbank join-code --label "a b") | Out-String
        if ($LASTEXITCODE -ne 7 -or $out.Trim() -ne 'current build: join-code --label "a b"') {
            throw "oarbank on the PATH did not forward to Coordinator\current ($LASTEXITCODE): $out"
        }
    } finally {
        [IO.Directory]::Delete($current)
    }
    $tray = Start-Process -FilePath "$root\Oarbank Coordinator.exe" -ArgumentList '--self-test' -Wait -PassThru -RedirectStandardOutput "$env:RUNNER_TEMP\coordinator-tray.log" -RedirectStandardError "$env:RUNNER_TEMP\coordinator-tray-error.log"
    if ($tray.ExitCode) { Get-Content "$env:RUNNER_TEMP\coordinator-tray-error.log"; throw 'native tray self-test failed' }
} finally {
    Installer '/x' (Join-Path $env:RUNNER_TEMP 'coordinator-uninstall.log')
}
if (Test-Path $root) { throw 'MSI payload remains after uninstall' }
if (MachinePathHasCli) { throw "$cliDir remains on the machine PATH after uninstall" }
NewPromptPath
if (Get-Command oarbank -ErrorAction SilentlyContinue) { throw 'oarbank still resolves from the PATH after uninstall' }
if (-not (Test-Path $sentinel)) { throw 'uninstall deleted coordinator data' }
foreach ($name in $services) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw "service remains: $name" } }
'Coordinator MSI install/uninstall passed; oarbank on the PATH and off it again, no services created, existing data retained.'
