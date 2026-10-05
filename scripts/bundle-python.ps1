# Copy uv's managed CPython (python-build-standalone, relocatable) to -Dest for a Windows build to ship, as files of its
# own (see bundle-python.sh): never a virtual environment (uv finds the checkout's .venv first unless told --system) nor
# the junction uv names a managed Python by (what a copy through a link holds depends on the copying tool), and no
# bytecode this machine wrote into uv's store (it names the store's path). scripts\build-node-runtime.ps1 and
# scripts\build-coordinator.ps1 use it; scripts\check-package.py checks what they build.
#
#   scripts\bundle-python.ps1 -Dest DIR -Request cpython-3.12-windows-aarch64-none
param([Parameter(Mandatory)][string]$Dest, [Parameter(Mandatory)][string]$Request)
$ErrorActionPreference = "Stop"
uv python install -q $Request
if ($LASTEXITCODE) { throw "uv python install $Request failed" }
$exe = (uv python find --managed-python --system $Request).Trim()
if ($LASTEXITCODE) { throw "uv python find $Request failed" }
$PyHome = (& $exe -I -B -c "import os, sys; print(os.path.realpath(sys.base_prefix))").Trim()
if ((Get-Item $PyHome).LinkType) { throw "$PyHome is still a link" }
$UvPython = (Get-Item (uv python dir).Trim()).FullName
if (-not $PyHome.StartsWith("$UvPython\", [StringComparison]::OrdinalIgnoreCase)) { throw "refusing to bundle ${PyHome}: not a uv-managed Python" }
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
Copy-Item -Recurse $PyHome $Dest
Get-ChildItem $Dest -Recurse -Filter EXTERNALLY-MANAGED | Remove-Item -Force
Get-ChildItem $Dest -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
