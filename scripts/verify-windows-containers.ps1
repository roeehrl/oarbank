# Verify the Windows container runtime on real hardware (docs/design/windows-containers.md, "Testing"): the agent's own
# WSL containers session, a signed image through the broker, and with -Gpu a GPU container. Run from a checkout on a
# Windows x64 or arm64 machine with virtualization (WSL 2), Rust and uv; CI runs it on GitHub's windows-2025 runners.
#
#   scripts\verify-windows-containers.ps1 [-Gpu] [-InstallWsl]
#
# It downloads the pinned WSL containers SDK library, sets `session: hostLoopback: none` in your account's
# %LOCALAPPDATA%\wslc\settings.yaml (the agent's containers must not reach this machine's loopback services; it is the
# only change to your settings and removes the host.wslc.internal name from your own wslc containers), runs the live
# tests and the doctor's probe, and writes everything to dist\verify-windows-containers.log: attach that file to the
# issue if anything fails. -InstallWsl first installs WSL 3.0.1 from its release (an administrator shell).
param([switch]$Gpu, [switch]$InstallWsl)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
New-Item -ItemType Directory -Force "$Repo\dist" | Out-Null
$Log = "$Repo\dist\verify-windows-containers.log"
Start-Transcript -Path $Log -Force | Out-Null
try {
  if ($InstallWsl) {
    $WslSha256 = @{ x64 = "28B1A0D013640A2AC95898EA705FA186E5B4FF767A1C1B49257161BC106599C6"; arm64 = "857DDBB335EC7D05FFA71D0FD2203750C0E8FC29BB164F8A95DB92BD7BBA4263" }
    $msi = "$env:TEMP\wsl.3.0.1.0.$Arch.msi"
    Invoke-WebRequest -UseBasicParsing "https://github.com/microsoft/WSL/releases/download/3.0.1/wsl.3.0.1.0.$Arch.msi" -OutFile $msi
    if ((Get-FileHash -Algorithm SHA256 $msi).Hash -ne $WslSha256[$Arch]) { throw "wsl.msi does not match its pin" }
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
    if ($p.ExitCode -notin 0, 3010) { throw "msiexec $($p.ExitCode)" }
  }
  & "$env:ProgramFiles\WSL\wsl.exe" --version
  Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion | Format-Table -AutoSize | Out-String | Write-Output
  # the SDK library, as scripts\package-windows.ps1 pins it
  $WslcSha256 = @{ x64 = "f3528a5b69b777d2bf606edc1629d13ca549f1b87c9f57380dd2f2c611b30b4f"; arm64 = "7afecfc4fc5d3133172e8c0fba763ff8266473d4f78b4cfb20386eb2865b1ab4" }
  $Sdk = "$env:TEMP\oarbank-wslc-3.0.1"
  New-Item -ItemType Directory -Force $Sdk | Out-Null
  Invoke-WebRequest -UseBasicParsing "https://api.nuget.org/v3-flatcontainer/microsoft.wsl.containers/3.0.1/microsoft.wsl.containers.3.0.1.nupkg" -OutFile "$Sdk\sdk.nupkg"
  tar -xf "$Sdk\sdk.nupkg" -C $Sdk "runtimes/win-$Arch/native/wslcsdk.dll"
  $env:OARBANK_WSLC_SDK = "$Sdk\runtimes\win-$Arch\native\wslcsdk.dll"
  if ((Get-FileHash -Algorithm SHA256 $env:OARBANK_WSLC_SDK).Hash.ToLower() -ne $WslcSha256[$Arch]) { throw "wslcsdk.dll does not match its pin" }
  $settings = "$env:LOCALAPPDATA\wslc\settings.yaml"
  $text = if (Test-Path $settings) { Get-Content -Raw $settings } else { "" }
  if ($text -notmatch "(?m)^session:\s*$[\s\S]*?^\s+hostLoopback:\s*none") {
    New-Item -ItemType Directory -Force (Split-Path $settings) | Out-Null
    if ($text -match "(?m)^session:\s*$") { $text = $text -replace "(?m)^session:\s*$", "session:`n  hostLoopback: none" }
    else { $text = $text.TrimEnd() + "`nsession:`n  hostLoopback: none`n" }
    Set-Content -NoNewline $settings $text.TrimStart()
    Write-Output "set session.hostLoopback: none in $settings"
  }
  $env:OARBANK_LIVE_WSLC = "1"
  if ($Gpu) { $env:OARBANK_LIVE_WSLC_GPU = "1" }
  Push-Location "$Repo\rust"
  try {
    cargo test --locked -p oarbank-agent --bin oarbank-agent live_ -- --ignored --nocapture --test-threads 1
    if ($LASTEXITCODE) { throw "the live tests failed" }
    cargo build --locked -p oarbank-agent
    if ($LASTEXITCODE) { throw "cargo build failed" }
    Copy-Item $env:OARBANK_WSLC_SDK target\debug\
    $env:OARBANK_AGENT_HOME = "$env:TEMP\oarbank-verify-agent"
    $probe = @("containers", "doctor", "--probe")
    if ($Gpu) { $probe += "--gpu" }
    target\debug\oarbank-agent.exe @probe
    if ($LASTEXITCODE) { throw "containers doctor --probe failed ($LASTEXITCODE)" }
    target\debug\oarbank-agent.exe containers remove
  } finally {
    Pop-Location
  }
  Write-Output "OK: the Windows container runtime works here$(if ($Gpu) { ', GPU included' })"
} finally {
  Stop-Transcript | Out-Null
}
