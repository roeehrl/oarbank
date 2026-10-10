# Install an Oarbank node on Windows, then join it (docs/design/node-enrollment.md, "Channels", one-liner). From an
# elevated PowerShell (Windows PowerShell 5.1 or PowerShell 7):
#
#   irm https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.ps1 | iex
#   & ([scriptblock]::Create((irm https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.ps1))) -Containers -Name build-07
#   irm .../oarbank-install.ps1 | iex     with $env:OARBANK_JOIN_CODE set from a secret store (scripts: no prompt)
#
# It downloads this release's MSI for the machine's architecture (x64 or arm64, the machine's own even from an emulated
# PowerShell) and its SHA256SUMS file, refuses an MSI whose SHA-256 does not match (Get-FileHash), installs it quietly
# (msiexec /qn; exit 3010, restart needed, is success), and runs `oarbank-node join`. The join code never goes on a
# command line, msiexec's included: it comes from $env:OARBANK_JOIN_CODE or a hidden prompt (Read-Host -AsSecureString)
# and reaches oarbank-node on standard input.
#
#   -Containers   container jobs on this node: the MSI installs their Windows components (CONTAINERS=1)
#   -Name NAME    the node's name when the code has no label
#   -NoJoin       install only; join later from an elevated prompt with: oarbank-node join
#
# Environment: OARBANK_JOIN_CODE, OARBANK_JOIN_CODE_FILE, OARBANK_COORDINATOR (join by URL: device code).
# OARBANK_INSTALL_BASE_URL replaces the release's download URL, for mirrors and tests (a directory path works too).
#
# scripts/package-install-scripts.sh fills in the version. The body is one function called at the end, so a download
# cut short runs nothing, and it returns instead of exiting: `exit` would close the window of a person who ran it with
# iex. Run as a file, the exit code is oarbank-node's.
param([switch]$Containers, [string]$Name = "", [switch]$NoJoin)

function Install-OarbankNode {
    param([switch]$Containers, [string]$Name = "", [switch]$NoJoin)
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"            # Windows PowerShell 5.1 downloads many times slower with it
    $Version = '@OARBANK_VERSION@'
    if ($Version.Contains('@')) {
        Write-Host "oarbank-install: this is the unreleased source; use the release's oarbank-install.ps1" -ForegroundColor Red
        return 2
    }
    $Base = if ($env:OARBANK_INSTALL_BASE_URL) { $env:OARBANK_INSTALL_BASE_URL.TrimEnd('/') } else { "https://github.com/roeehrl/oarbank/releases/download/v$Version" }

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Write-Host "oarbank-install.ps1 is for Windows; on macOS and Linux use oarbank-install.sh" -ForegroundColor Red
        return 2
    }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "oarbank-install: installing a node needs an administrator. Open PowerShell with 'Run as administrator' and run:" -ForegroundColor Red
        Write-Host "  irm https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.ps1 | iex"
        return 8
    }
    if ($Name.Contains('"')) {
        Write-Host "oarbank-install: a node name cannot hold a double quote" -ForegroundColor Red
        return 2
    }

    # the machine's architecture: IsWow64Process2 names it whatever this PowerShell runs as (scripts/windows-arch.ps1);
    # PROCESSOR_ARCHITEW6432 where that is unavailable
    $Arch = $null
    try {
        if (-not ("OarbankInstall.Machine" -as [type])) {
            Add-Type -Namespace OarbankInstall -Name Machine -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
'@
        }
        $process, $native = [uint16]0, [uint16]0
        if ([OarbankInstall.Machine]::IsWow64Process2([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$process, [ref]$native)) {
            $Arch = @{ 0xAA64 = "arm64"; 0x8664 = "x64" }[[int]$native]
        }
    } catch { }
    if (-not $Arch) {
        $a = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
        $Arch = @{ "ARM64" = "arm64"; "AMD64" = "x64" }[$a]
    }
    if (-not $Arch) {
        Write-Host "oarbank-install: no Oarbank package for this machine's architecture (x64 or arm64)" -ForegroundColor Red
        return 2
    }

    # GitHub needs TLS 1.2, which Windows PowerShell 5.1 does not always offer by default
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    function Get-OarbankFile([string]$File, [string]$To) {
        if ($Base -match '^https?://') {
            Invoke-WebRequest -UseBasicParsing -Uri "$Base/$File" -OutFile $To
        } else {
            Copy-Item -LiteralPath (Join-Path ($Base -replace '^file://', '') $File) -Destination $To
        }
    }

    $Msi = "oarbank-agent-$Version-windows-$Arch.msi"
    $Sums = "SHA256SUMS-agent-$Version-windows-$Arch"
    $Tmp = Join-Path ([IO.Path]::GetTempPath()) ("oarbank-install-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $Tmp | Out-Null
    try {
        Write-Host "Downloading Oarbank $Version for windows-$Arch"
        try {
            Get-OarbankFile $Sums (Join-Path $Tmp $Sums)
            Get-OarbankFile $Msi (Join-Path $Tmp $Msi)
        } catch {
            Write-Host "oarbank-install: could not download from ${Base}: $($_.Exception.Message)" -ForegroundColor Red
            return 1
        }
        $want = $null
        foreach ($line in [IO.File]::ReadAllLines((Join-Path $Tmp $Sums))) {
            $h, $f = ($line.Trim() -split '\s+', 2)
            if ($f -and ($f.TrimStart('*') -replace '^\./', '') -eq $Msi) { $want = $h }
        }
        if (-not $want) {
            Write-Host "oarbank-install: $Sums names no $Msi" -ForegroundColor Red
            return 1
        }
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Tmp $Msi)).Hash
        if ($got -ine $want) {
            Write-Host "oarbank-install: $Msi does not match its SHA-256 in $Sums; nothing was installed" -ForegroundColor Red
            return 1
        }
        Write-Host "Verified $Msi (SHA-256 $($got.ToLower()))"

        # The MSI installs only: the join below is this script's, so no code goes to msiexec. NOLAUNCH: the tray app
        # does not open the join window this script replaces.
        $log = Join-Path $Tmp "msiexec.log"
        $msiArgs = @("/i", "`"$(Join-Path $Tmp $Msi)`"", "/qn", "/norestart", "/l*", "`"$log`"", "NOLAUNCH=1")
        if ($Containers) { $msiArgs += "CONTAINERS=1" }
        if ($Name) { $msiArgs += "NAME=`"$Name`"" }
        Write-Host "Installing $Msi"
        $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
        $restart = $false
        switch ($p.ExitCode) {
            0 { }
            3010 { $restart = $true }                     # ERROR_SUCCESS_REBOOT_REQUIRED
            1641 { $restart = $true }                     # ERROR_SUCCESS_REBOOT_INITIATED
            default {
                $keep = Join-Path ([IO.Path]::GetTempPath()) "oarbank-install-msiexec.log"
                Copy-Item -LiteralPath $log -Destination $keep -ErrorAction SilentlyContinue
                Write-Host "oarbank-install: msiexec failed with exit code $($p.ExitCode); its log: $keep" -ForegroundColor Red
                return 1
            }
        }
        if ($restart) { Write-Host "Installed. Windows needs a restart to finish (container components); joining works now." -ForegroundColor Yellow }
    } finally {
        Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($NoJoin) {
        Write-Host "Installed. Join this machine from an elevated prompt with: oarbank-node join"
        return 0
    }
    $dir = Join-Path $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }) "Oarbank"
    $node = @("oarbank-node.exe", "oarbank-launcher.exe") | ForEach-Object { Join-Path $dir $_ } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $node) {
        Write-Host "oarbank-install: installed, but $dir holds no oarbank-node.exe" -ForegroundColor Red
        return 1
    }
    $joinArgs = @("join")                              # -Containers: the MSI installed the components (CONTAINERS=1)
    if ($Name) { $joinArgs += @("--name", $Name) }

    $code = $env:OARBANK_JOIN_CODE
    Remove-Item Env:OARBANK_JOIN_CODE -ErrorAction SilentlyContinue
    if (-not $code -and -not $env:OARBANK_JOIN_CODE_FILE -and -not $env:OARBANK_COORDINATOR) {
        if (-not [Environment]::UserInteractive) {
            Write-Host "Installed. Join this machine from an elevated prompt with: oarbank-node join"
            return 0
        }
        $secure = Read-Host -AsSecureString "Join code from the console (input hidden; Enter alone to join later)"
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $code = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if (-not $code.Trim()) {
            Write-Host "Installed. Join this machine from an elevated prompt with: oarbank-node join"
            return 0
        }
    }
    if ($code) {
        # the only path with piped input; --no-input, so nothing waits on the console
        $code | & $node @joinArgs --code-stdin --no-input | Out-Host
        $code = $null
        return [int]$LASTEXITCODE
    }
    # on the console itself: a device-code join asks to confirm the coordinator's fingerprint there
    if ($env:OARBANK_JOIN_CODE_FILE) { $joinArgs += @("--code-file", $env:OARBANK_JOIN_CODE_FILE, "--no-input") }
    else { $joinArgs += @("--coordinator", $env:OARBANK_COORDINATOR) }
    $argLine = ($joinArgs | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $p = Start-Process -FilePath $node -ArgumentList $argLine -NoNewWindow -Wait -PassThru
    return [int]$p.ExitCode
}

# the function's last output is its exit code (anything a command let slip into the pipeline comes before it)
$OarbankInstallExit = [int]@(Install-OarbankNode -Containers:$Containers -Name $Name -NoJoin:$NoJoin)[-1]
if ($PSCommandPath) { exit $OarbankInstallExit }
$global:LASTEXITCODE = $OarbankInstallExit
