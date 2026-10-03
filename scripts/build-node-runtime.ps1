# Build the node runtime for Windows (see build-node-runtime.sh): OUT\python.exe with the module SDK, and OUT\uv.exe.
#   scripts\build-node-runtime.ps1 -Out dist\runtime
param([Parameter(Mandatory)][string]$Out, [string]$Python = "3.12",
      [string]$Arch = $(if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }))
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
# named in full: on Windows on Arm uv picks an x86_64 CPython by default, which would run emulated
$Request = "cpython-$Python-windows-$(if ($Arch -eq 'arm64') { 'aarch64' } else { 'x86_64' })-none"
uv python install -q $Request
if ($LASTEXITCODE) { throw "uv python install $Request failed" }
$exe = (uv python find --managed-python $Request).Trim()
$home_ = Split-Path -Parent $exe
if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
Copy-Item -Recurse $home_ $Out
Get-ChildItem $Out -Recurse -Filter EXTERNALLY-MANAGED | Remove-Item -Force
uv pip install -q --python "$Out\python.exe" --break-system-packages "$Repo\vendor\oarbank-sdk"
if ($LASTEXITCODE) { throw "installing the SDK failed" }
Copy-Item (Get-Command uv).Source "$Out\uv.exe"
# uv's launchers (Scripts\oarbank-sdk.exe, ...) name this build path as their interpreter: point them at ..\python.exe,
# then check every launcher the runtime ships
& "$Out\python.exe" -I "$Repo\scripts\relocate_shebangs.py" "$Out\Scripts" $Out
if ($LASTEXITCODE) { throw "a launcher in the node runtime names an interpreter by absolute path" }
& "$Out\python.exe" -I -c "import oarbank_sdk, platform, pydantic; print('node runtime:', platform.python_compiler(), pydantic.VERSION)"
if ($LASTEXITCODE) { throw "the node runtime does not import the SDK" }
