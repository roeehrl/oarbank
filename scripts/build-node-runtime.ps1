# Build the node runtime for Windows (see build-node-runtime.sh): OUT\python.exe with the module SDK, and OUT\uv.exe,
# every native file for -Arch: the interpreter's build for it, the wheels it asks for, uv's release for it
# (scripts\fetch-uv.py).
#   scripts\build-node-runtime.ps1 -Out dist\runtime [-Arch x64|arm64]     # the machine's architecture by default
param([Parameter(Mandatory)][string]$Out, [string]$Python = "3.12", [string]$Arch = "")
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Arch = & "$PSScriptRoot\windows-arch.ps1" -Arch $Arch
# named in full: on Windows on Arm uv picks an x86_64 CPython by default, which would run emulated
$Request = "cpython-$Python-windows-$(if ($Arch -eq 'arm64') { 'aarch64' } else { 'x86_64' })-none"
& "$PSScriptRoot\bundle-python.ps1" -Dest $Out -Request $Request
# the runtime's own uv installs into it: uv writes console-script launchers (Scripts\*.exe) for its own architecture
& "$Out\python.exe" -I -B "$Repo\scripts\fetch-uv.py" "windows-$(if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' })" "$Out\uv.exe"
if ($LASTEXITCODE) { throw "fetching uv failed" }
& "$Out\uv.exe" pip install -q --python "$Out\python.exe" --break-system-packages "$Repo\vendor\oarbank-sdk"
if ($LASTEXITCODE) { throw "installing the SDK failed" }
# a plain install, as from an index: uv records the checkout it installed from (direct_url.json), a path on this build
# machine that the runtime has no use for
$Info = (Get-Item "$Out\Lib\site-packages\oarbank_sdk-*.dist-info").FullName
Remove-Item "$Info\direct_url.json"
[IO.File]::WriteAllLines("$Info\RECORD", [string[]](Get-Content "$Info\RECORD" | Where-Object { $_ -notmatch '/direct_url\.json,' }),
                         (New-Object Text.UTF8Encoding $false))
# uv's launchers (Scripts\oarbank-sdk.exe, ...) name this build path as their interpreter: point them at ..\python.exe,
# then check every launcher the runtime ships (-B wherever the build runs it: bytecode written now would name this
# build's directory)
& "$Out\python.exe" -I -B "$Repo\scripts\relocate_shebangs.py" "$Out\Scripts" $Out
if ($LASTEXITCODE) { throw "a launcher in the node runtime names an interpreter by absolute path" }
# bytecode for everything, recording paths relative to the runtime and checked against the sources' hashes (the MSI's
# file times are not the build's), so a runtime installed read-only never compiles on start
& "$Out\python.exe" -I -B -m compileall -q -f -j 0 -s $Out --invalidation-mode checked-hash "$Out\Lib"
if ($LASTEXITCODE) { throw "compiling the runtime's bytecode failed" }
& "$Out\python.exe" -I -B -c "import oarbank_sdk, platform, pydantic; print('node runtime:', platform.python_compiler(), pydantic.VERSION)"
if ($LASTEXITCODE) { throw "the node runtime does not import the SDK" }
