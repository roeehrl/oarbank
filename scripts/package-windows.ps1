# Build the Windows agent package on a Windows host: dist\oarbank-agent-<version>-windows-<arch>.msi, the agent
# binary for the coordinator's update channel and the Group Policy template (oarbank-agent-<version>-windows-admx.zip),
# for -Arch (x64 or arm64; the machine's architecture by default, never the architecture this PowerShell happens to run
# as). Needs Rust with the target's standard library (rustup target add aarch64-pc-windows-msvc or
# x86_64-pc-windows-msvc), uv and WiX 5 (dotnet tool install --global wix, then wix extension add --global
# WixToolset.Util.wixext/5.0.2 and WixToolset.UI.wixext/5.0.2); for arm64 also clang, which scripts\windows-clang.ps1
# finds (Visual Studio's C++ Clang component or LLVM). The Oarbank Node tray app is compiled with the .NET Framework 4
# compiler every Windows has, and the MSI ships the join window from deploy\node.
#
#   scripts\package-windows.ps1 [-Version 1.0.0] [-Arch x64|arm64]
#
# Signing is the owner's: OARBANK_SIGNTOOL_ARGS (for example "/fd SHA256 /tr http://timestamp.acs.microsoft.com /td
# SHA256 /dlib ... /dmdf ...", Azure Artifact Signing) signs the binaries and the MSI with signtool; without it they
# stay unsigned (Smart App Control blocks unsigned programs on machines that enforce it).
param([string]$Version = "", [string]$Arch = "")
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Version) { $Version = (Select-String -Path "$Repo\rust\Cargo.toml" -Pattern '^version = "(.*)"').Matches[0].Groups[1].Value }
$MsiVersion = ($Version -split '[-+]')[0]                         # MSI versions are numeric only
$Arch = & "$PSScriptRoot\windows-arch.ps1" -Arch $Arch
$env:OARBANK_AGENT_VERSION = $Version
if ($Arch -eq "arm64") { $env:PATH = "$(& "$PSScriptRoot\windows-clang.ps1");$env:PATH" }   # ring needs clang here
# the target named, so the binaries are for $Arch whatever the toolchain's own host is (an x64 toolchain on Windows on
# Arm builds x64 by default)
$Target = @{ x64 = "x86_64-pc-windows-msvc"; arm64 = "aarch64-pc-windows-msvc" }[$Arch]
# the crates' source paths the binaries embed name CARGO_HOME as /cargo, not this machine's
$CargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$HOME\.cargo" }
Set-Item "env:CARGO_TARGET_$($Target.ToUpper().Replace('-', '_'))_RUSTFLAGS" "--remap-path-prefix=$CargoHome=/cargo"
Push-Location "$Repo\rust"
cargo build -q --release --locked --target $Target -p oarbank-agent -p oarbank-launcher
$built = $LASTEXITCODE
Pop-Location
if ($built) { throw "cargo build failed" }        # never package the binaries an earlier build left behind
$Bin = "$Repo\rust\target\$Target\release"
# the WSL containers SDK library the agent loads at run time for its Windows container runtime (Microsoft.WSL.Containers,
# MIT, docs/design/windows-containers.md); pinned by the library's own SHA-256 per architecture
$WslcVersion = "3.0.1"
$WslcSha256 = @{ x64 = "f3528a5b69b777d2bf606edc1629d13ca549f1b87c9f57380dd2f2c611b30b4f"; arm64 = "7afecfc4fc5d3133172e8c0fba763ff8266473d4f78b4cfb20386eb2865b1ab4" }
$Wslc = "$env:TEMP\oarbank-wslc-$WslcVersion"
New-Item -ItemType Directory -Force $Wslc | Out-Null
Invoke-WebRequest -UseBasicParsing "https://api.nuget.org/v3-flatcontainer/microsoft.wsl.containers/$WslcVersion/microsoft.wsl.containers.$WslcVersion.nupkg" -OutFile "$Wslc\sdk.nupkg"
tar -xf "$Wslc\sdk.nupkg" -C $Wslc "runtimes/win-$Arch/native/wslcsdk.dll"
if ($LASTEXITCODE) { throw "the WSL containers SDK package has no win-$Arch library" }
$WslcDll = "$Wslc\runtimes\win-$Arch\native\wslcsdk.dll"
if ((Get-FileHash -Algorithm SHA256 $WslcDll).Hash.ToLower() -ne $WslcSha256[$Arch]) { throw "wslcsdk.dll does not match its pin" }
Copy-Item $WslcDll "$Bin\wslcsdk.dll"
# a clean Windows machine has no Visual C++ runtime: the binaries must not import it (static CRT, rust/.cargo/config.toml);
# wslcsdk.dll is loaded at run time, never imported
uv run --no-project --python 3.12 python "$Repo\scripts\check-pe-imports.py" "$Bin\oarbank-agent.exe" "$Bin\oarbank-launcher.exe"
if ($LASTEXITCODE) { throw "the binaries import a DLL a clean Windows install does not have" }
$Out = "$Repo\dist"
New-Item -ItemType Directory -Force $Out | Out-Null
function Sign($path) {
  if ($env:OARBANK_SIGNTOOL_ARGS) { & signtool sign $env:OARBANK_SIGNTOOL_ARGS.Split(' ') $path; if ($LASTEXITCODE) { throw "signtool $path" } }
}
Sign "$Bin\oarbank-agent.exe"; Sign "$Bin\oarbank-launcher.exe"
# oarbank-node, the node's command line, is the launcher under a second name (docs/design/node-enrollment.md,
# "oarbank-node"): a copy on Windows, made after signing so it carries the signature
Copy-Item "$Bin\oarbank-launcher.exe" "$Bin\oarbank-node.exe"
# Oarbank Node, the tray app (deploy/windows/NodeTray.cs), built as the coordinator's tray app is
# (scripts/package-coordinator-windows.ps1): any CPU, so it runs natively on x64 and Arm; its icon is installed beside it
Copy-Item "$Repo\deploy\icons\oarbank.ico" "$Bin\oarbank.ico"
$Tray = "$Bin\Oarbank Node.exe"
$Csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path -LiteralPath $Csc)) { $Csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
& $Csc /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.ServiceProcess.dll "/win32icon:$Repo\deploy\icons\oarbank.ico" "/win32manifest:$Repo\deploy\windows\node-tray.manifest" "/out:$Tray" "$Repo\deploy\windows\NodeTray.cs"
if ($LASTEXITCODE) { throw "compiling the Oarbank Node tray app failed" }
Sign $Tray
# the join window (deploy/node, standard library only), which the node runtime's pythonw.exe runs from [INSTALLFOLDER]join
$JoinDir = "$env:TEMP\oarbank-join-window"
Remove-Item -LiteralPath $JoinDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $JoinDir | Out-Null
foreach ($file in @("join-window.py", "join-window.html")) {
  if (-not (Test-Path -LiteralPath "$Repo\deploy\node\$file" -PathType Leaf)) { throw "deploy\node\$file is missing: the MSI ships the join window" }
  Copy-Item -LiteralPath "$Repo\deploy\node\$file" -Destination "$JoinDir\$file"
}
$Runtime = "$env:TEMP\oarbank-runtime"
& "$Repo\scripts\build-node-runtime.ps1" -Out $Runtime -Arch $Arch
# what the MSI copies holds no link, no path of this machine and no native file for another architecture, and the
# runtime runs from wherever it is installed
uv run --no-project --python 3.12 python "$Repo\scripts\check-package.py" --build-path (uv python dir).Trim() `
  --platform "windows-$(if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' })" --run "$Runtime=python.exe" `
  $Runtime "$Bin\oarbank-agent.exe" "$Bin\oarbank-launcher.exe" "$Bin\wslcsdk.dll"
if ($LASTEXITCODE) { throw "the package is not fit to ship" }
$Msi = "$Out\oarbank-agent-$Version-windows-$Arch.msi"
# the UI extension draws the attended install's pages (the join page, the last page's "Open Oarbank Node")
wix build "$Repo\deploy\windows\oarbank-agent.wxs" -arch $Arch -ext WixToolset.Util.wixext -ext WixToolset.UI.wixext -culture en-US -d "Version=$MsiVersion" -d "BinDir=$Bin" -d "RuntimeDir=$Runtime" -d "JoinDir=$JoinDir" -o $Msi
if ($LASTEXITCODE) { throw "wix build failed" }
Sign $Msi
Copy-Item "$Bin\oarbank-agent.exe" "$Out\oarbank-agent-$Version-windows-$Arch.exe"
# the Group Policy template (deploy/windows/admx: oarbank.admx, en-US\oarbank.adml) for PolicyDefinitions or the Central
# Store; the same for every architecture. Windows' own tar (bsdtar, not a Git for Windows tar earlier on PATH) writes the
# zip, with forward slashes in its entry names (Windows PowerShell's Compress-Archive wrote backslashes). Both
# architectures publish this one file, so it must be byte-identical: the entries get a fixed time, not the checkout's.
$Admx = "$Out\oarbank-agent-$Version-windows-admx.zip"
Remove-Item -LiteralPath $Admx -Force -ErrorAction SilentlyContinue
$AdmxSrc = Join-Path ([IO.Path]::GetTempPath()) "oarbank-admx-$PID"
Remove-Item -LiteralPath $AdmxSrc -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Recurse "$Repo\deploy\windows\admx" $AdmxSrc
Get-ChildItem -LiteralPath $AdmxSrc -Recurse | ForEach-Object { $_.LastWriteTimeUtc = [DateTime]::new(2000, 1, 1, 0, 0, 0, 'Utc') }
& "$env:SystemRoot\System32\tar.exe" -a -c -f $Admx -C $AdmxSrc oarbank.admx en-US/oarbank.adml
$AdmxExit = $LASTEXITCODE
Remove-Item -LiteralPath $AdmxSrc -Recurse -Force -ErrorAction SilentlyContinue
if ($AdmxExit) { throw "zipping the Group Policy template failed" }
# collect the hashes before writing: the sums file matches the same pattern
$Sums = @(Get-ChildItem "$Out\oarbank-agent-$Version-windows-$Arch*" | Where-Object Extension -ne ".wixpdb") + @(Get-Item -LiteralPath $Admx) |
  Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLower())  $(Split-Path -Leaf $_.Path)" }
# LF, as sha256sum -c reads it on any OS (Set-Content ends lines with CRLF, which it takes as part of the name)
[IO.File]::WriteAllText("$Out\SHA256SUMS-agent-$Version-windows-$Arch", (($Sums -join "`n") + "`n"))
Get-ChildItem $Out
