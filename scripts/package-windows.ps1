# Build the Windows agent package on a Windows host: dist\oarbank-agent-<version>-windows-<arch>.msi and the agent
# binary for the coordinator's update channel, for the host's architecture (x64 or arm64). Needs Rust, uv and WiX 5
# (dotnet tool install --global wix, then wix extension add WixToolset.Util.wixext); on arm64 also clang, which
# scripts\windows-clang.ps1 finds (Visual Studio's C++ Clang component or LLVM).
#
#   scripts\package-windows.ps1 [-Version 1.0.0]
#
# Signing is the owner's: OARBANK_SIGNTOOL_ARGS (for example "/fd SHA256 /tr http://timestamp.acs.microsoft.com /td
# SHA256 /dlib ... /dmdf ...", Azure Artifact Signing) signs the binaries and the MSI with signtool; without it they
# stay unsigned (Smart App Control blocks unsigned programs on machines that enforce it).
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Version) { $Version = (Select-String -Path "$Repo\rust\Cargo.toml" -Pattern '^version = "(.*)"').Matches[0].Groups[1].Value }
$MsiVersion = ($Version -split '[-+]')[0]                         # MSI versions are numeric only
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
$env:OARBANK_AGENT_VERSION = $Version
if ($Arch -eq "arm64") { $env:PATH = "$(& "$PSScriptRoot\windows-clang.ps1");$env:PATH" }   # ring needs clang here
Push-Location "$Repo\rust"
cargo build -q --release --locked -p oarbank-agent -p oarbank-launcher
$built = $LASTEXITCODE
Pop-Location
if ($built) { throw "cargo build failed" }        # never package the binaries an earlier build left behind
$Bin = "$Repo\rust\target\release"
# a clean Windows machine has no Visual C++ runtime: the binaries must not import it (static CRT, rust/.cargo/config.toml)
uv run --no-project --python 3.12 python "$Repo\scripts\check-pe-imports.py" "$Bin\oarbank-agent.exe" "$Bin\oarbank-launcher.exe"
if ($LASTEXITCODE) { throw "the binaries import a DLL a clean Windows install does not have" }
$Out = "$Repo\dist"
New-Item -ItemType Directory -Force $Out | Out-Null
function Sign($path) {
  if ($env:OARBANK_SIGNTOOL_ARGS) { & signtool sign $env:OARBANK_SIGNTOOL_ARGS.Split(' ') $path; if ($LASTEXITCODE) { throw "signtool $path" } }
}
Sign "$Bin\oarbank-agent.exe"; Sign "$Bin\oarbank-launcher.exe"
$Runtime = "$env:TEMP\oarbank-runtime"
& "$Repo\scripts\build-node-runtime.ps1" -Out $Runtime -Arch $Arch
$Msi = "$Out\oarbank-agent-$Version-windows-$Arch.msi"
wix build "$Repo\deploy\windows\oarbank-agent.wxs" -arch $Arch -ext WixToolset.Util.wixext -d "Version=$MsiVersion" -d "BinDir=$Bin" -d "RuntimeDir=$Runtime" -o $Msi
if ($LASTEXITCODE) { throw "wix build failed" }
Sign $Msi
Copy-Item "$Bin\oarbank-agent.exe" "$Out\oarbank-agent-$Version-windows-$Arch.exe"
# collect the hashes before writing: the sums file matches the same pattern
$Sums = Get-ChildItem "$Out\oarbank-agent-$Version-windows-$Arch*" | Where-Object Extension -ne ".wixpdb" | Get-FileHash -Algorithm SHA256 |
  ForEach-Object { "$($_.Hash.ToLower())  $(Split-Path -Leaf $_.Path)" }
Set-Content "$Out\SHA256SUMS-agent-$Version-windows-$Arch" $Sums
Get-ChildItem $Out
