# Build the node runtime for Windows (see build-node-runtime.sh): OUT\python.exe with the module SDK, and OUT\uv.exe.
#   scripts\build-node-runtime.ps1 -Out dist\runtime [-Arch x64|arm64]     # the machine's architecture by default
param([Parameter(Mandatory)][string]$Out, [string]$Python = "3.12", [string]$Arch = "")
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Arch = & "$PSScriptRoot\windows-arch.ps1" -Arch $Arch
# named in full: on Windows on Arm uv picks an x86_64 CPython by default, which would run emulated
$Request = "cpython-$Python-windows-$(if ($Arch -eq 'arm64') { 'aarch64' } else { 'x86_64' })-none"
uv python install -q $Request
if ($LASTEXITCODE) { throw "uv python install $Request failed" }
$exe = (uv python find --managed-python $Request).Trim()
# the interpreter's real files: uv names a managed Python through a junction (cpython-3.12-... points at
# cpython-3.12.<patch>-...), and what a copy through a link holds depends on the copying tool
$PyHome = (& $exe -I -c "import os, sys; print(os.path.realpath(sys.base_prefix))").Trim()
if ((Get-Item $PyHome).LinkType) { throw "$PyHome is still a link" }
if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
Copy-Item -Recurse $PyHome $Out
Get-ChildItem $Out -Recurse -Filter EXTERNALLY-MANAGED | Remove-Item -Force
uv pip install -q --python "$Out\python.exe" --break-system-packages "$Repo\vendor\oarbank-sdk"
if ($LASTEXITCODE) { throw "installing the SDK failed" }
# a plain install, as from an index: uv records the checkout it installed from (direct_url.json), a path on this build
# machine that the runtime has no use for
$Info = (Get-Item "$Out\Lib\site-packages\oarbank_sdk-*.dist-info").FullName
Remove-Item "$Info\direct_url.json"
[IO.File]::WriteAllLines("$Info\RECORD", [string[]](Get-Content "$Info\RECORD" | Where-Object { $_ -notmatch '/direct_url\.json,' }),
                         (New-Object Text.UTF8Encoding $false))
Copy-Item (Get-Command uv).Source "$Out\uv.exe"
# uv's launchers (Scripts\oarbank-sdk.exe, ...) name this build path as their interpreter: point them at ..\python.exe,
# then check every launcher the runtime ships
& "$Out\python.exe" -I "$Repo\scripts\relocate_shebangs.py" "$Out\Scripts" $Out
if ($LASTEXITCODE) { throw "a launcher in the node runtime names an interpreter by absolute path" }
& "$Out\python.exe" -I -c "import oarbank_sdk, platform, pydantic; print('node runtime:', platform.python_compiler(), pydantic.VERSION)"
if ($LASTEXITCODE) { throw "the node runtime does not import the SDK" }
