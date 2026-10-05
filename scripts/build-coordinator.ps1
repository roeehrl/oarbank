# Build a coordinator build for this Windows machine's platform: dist\oarbank-coordinator-<version>-windows-<arch>.tar.gz,
# the archive deploy\oarbankd\install-oarbankd.ps1 installs, `oarbank coordinator-build upload` registers and moves
# install (coordinator-builds format 1; scripts/build-coordinator.sh builds it on macOS and Linux).
#
#   scripts\build-coordinator.ps1 [-Version 1.0.0]
#
# Layout: oarbank-coordinator.json, python\ (a relocatable CPython with the coordinator's dependencies and the SDK;
# modules run on this interpreter), bin\oarbank-sandbox.exe (the agent's module launcher: AppContainers), bin\uv.exe
# (module environments), and per program a launcher (bin\oarbankd.py, …) and a .cmd for people. The services run
# python\python.exe with the launcher (the manifest's exec): a service needs a program, not a script. The core is compiled with
# Nuitka into one native extension module (D7: its source is not shipped); its templates, static files and schemas sit
# beside it. Needs Rust, uv and the MSVC build tools for x64 (Nuitka compiles for the interpreter); on arm64 also clang
# (scripts\windows-clang.ps1). OARBANK_SIGNTOOL_ARGS signs the executables, as for the agent's package.
#
# The interpreter is x64 on both architectures: the coordinator's cryptography dependency publishes no Windows on Arm
# wheels, and Windows on Arm runs x64 programs under emulation. The build is still for the machine's platform
# (windows-arm64), which is what oarbankd reports (oarbank_sdk.portable.host_platform).
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Version) { $Version = (Select-String -Path "$Repo\pyproject.toml" -Pattern '^version = "(.*)"').Matches[0].Groups[1].Value }
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$') { throw "bad version $Version" }
# the machine's architecture (scripts\windows-arch.ps1: never the one this PowerShell runs as under emulation)
$Arch = if ((& "$PSScriptRoot\windows-arch.ps1") -eq "arm64") { "arm64" } else { "amd64" }
$Platform = "windows-$Arch"
$Out = "$Repo\dist"
$Work = Join-Path $env:TEMP "oarbank-coord-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$Root = "$Work\oarbank-coordinator"
New-Item -ItemType Directory -Force $Out, "$Root\bin" | Out-Null
function Check($what) { if ($LASTEXITCODE) { throw "$what failed ($LASTEXITCODE)" } }
function Sign($path) {
  if ($env:OARBANK_SIGNTOOL_ARGS) { & signtool sign $env:OARBANK_SIGNTOOL_ARGS.Split(' ') $path; Check "signtool $path" }
}
try {
  # 1. the interpreter: uv's managed CPython (python-build-standalone) is relocatable; named in full, x64 (see above)
  #    (scripts\bundle-python.ps1: its real files, never a virtual environment or the junction uv names it by)
  $Request = "cpython-$(if ($env:OARBANK_PYTHON) { $env:OARBANK_PYTHON } else { '3.12' })-windows-x86_64-none"
  & "$PSScriptRoot\bundle-python.ps1" -Dest "$Root\python" -Request $Request
  $Py = "$Root\python\python.exe"
  # nothing the build runs writes bytecode (-B where -I ignores the environment): a .pyc written now would name this
  # build's directory
  $env:PYTHONDONTWRITEBYTECODE = "1"

  # 2. the dependencies (locked) and the SDK, never the core's source
  Push-Location $Repo
  $req = uv export --frozen --no-dev --no-emit-project --no-editable --no-hashes -q | Where-Object { $_ -notmatch '^\./vendor/oarbank-sdk$' }
  Check "uv export"
  Pop-Location
  Set-Content -Encoding utf8 "$Work\requirements.txt" $req
  uv pip install -q --python $Py --break-system-packages -r "$Work\requirements.txt"; Check "installing the dependencies"
  uv pip install -q --python $Py --break-system-packages --no-deps "$Repo\vendor\oarbank-sdk"; Check "installing the SDK"
  # a plain install, as from an index: uv records the checkout it installed from (direct_url.json)
  $Info = (Get-Item "$Root\python\Lib\site-packages\oarbank_sdk-*.dist-info").FullName
  Remove-Item "$Info\direct_url.json"
  [IO.File]::WriteAllLines("$Info\RECORD", [string[]](Get-Content "$Info\RECORD" | Where-Object { $_ -notmatch '/direct_url\.json,' }),
                           (New-Object Text.UTF8Encoding $false))

  # 3. the core, compiled, with its other files beside it
  $Site = (& $Py -I -B -c "import sysconfig; print(sysconfig.get_paths()['purelib'])").Trim()
  Push-Location $Repo
  uv run --no-project --python $Py --with "nuitka>=2.7" python -m nuitka --module src\oarbank --include-package=oarbank `
    --nofollow-imports --output-dir="$Work\nuitka" --remove-output --quiet --assume-yes-for-downloads
  Check "nuitka"
  Pop-Location
  Copy-Item "$Work\nuitka\oarbank.*.pyd" $Site
  Get-ChildItem "$Repo\src\oarbank" -Recurse -File | Where-Object { $_.Extension -notin ".py", ".pyc" -and $_.FullName -notmatch '__pycache__' } |
    ForEach-Object {
      $rel = $_.FullName.Substring("$Repo\src\".Length)
      New-Item -ItemType Directory -Force (Split-Path -Parent "$Site\$rel") | Out-Null
      Copy-Item $_.FullName "$Site\$rel"
    }
  & $Py -I -B -c "import oarbank, oarbank.coordinator.app, oarbank.console.app; assert hasattr(oarbank, '__compiled__'), oarbank.__file__"
  Check "the compiled core does not import"

  # 3b. the agent's launcher confines module processes (AppContainers); uv makes module environments
  if ($Arch -eq "arm64") { $env:PATH = "$(& "$PSScriptRoot\windows-clang.ps1");$env:PATH" }   # ring needs clang here
  # for the platform's architecture, whatever the toolchain's own host is
  $Target = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
  # the crates' source paths it embeds name CARGO_HOME as /cargo, not this machine's
  $CargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$HOME\.cargo" }
  Set-Item "env:CARGO_TARGET_$($Target.ToUpper().Replace('-', '_'))_RUSTFLAGS" "--remap-path-prefix=$CargoHome=/cargo"
  Push-Location "$Repo\rust"
  cargo build -q --release --locked --target $Target -p oarbank-agent
  $built = $LASTEXITCODE
  Pop-Location
  if ($built) { throw "cargo build failed" }
  Copy-Item "$Repo\rust\target\$Target\release\oarbank-agent.exe" "$Root\bin\oarbank-sandbox.exe"
  Copy-Item (Get-Command uv).Source "$Root\bin\uv.exe"

  # 4. entry points, relative to the build so it runs from wherever it is unpacked: a two-line launcher per program
  #    (the compiled core cannot run as `python -m`: its loader has no code objects), and a .cmd for people
  foreach ($e in @(@("oarbankd", "oarbank.coordinator.__main__"), @("oarbank", "oarbank.cli.main"),
                   @("oarbank-console", "oarbank.console.__main__"))) {
    Set-Content -Encoding ascii "$Root\bin\$($e[0]).py" "import sys`nfrom $($e[1]) import main`nsys.argv[0] = `"$($e[0])`"`nsys.exit(main())"
    Set-Content -Encoding ascii "$Root\bin\$($e[0]).cmd" "@`"%~dp0..\python\python.exe`" -I `"%~dp0$($e[0]).py`" %*"
  }
  # uv's launchers (python\Scripts\*.exe) name the build path as their interpreter: point them at ..\python.exe, then
  # check every launcher the build ships
  & $Py -I -B "$Repo\scripts\relocate_shebangs.py" "$Root\python\Scripts" $Root; Check "relocating the launchers"
  # bytecode for everything, recording paths relative to the build and checked against the sources' hashes
  & $Py -I -B -m compileall -q -f -j 0 -s "$Root\python" --invalidation-mode checked-hash "$Root\python\Lib"; Check "compiling bytecode"
  $Manifest = [ordered]@{format = 1; version = $Version; platform = $Platform
                         exec = @("python/python.exe", "-I", "bin/oarbankd.py")
                         console = @("python/python.exe", "-I", "bin/oarbank-console.py")}
  Set-Content -Encoding ascii "$Root\oarbank-coordinator.json" ($Manifest | ConvertTo-Json -Compress)

  # 5. signatures, then the archive
  Get-ChildItem $Root -Recurse -Include *.exe, *.dll, *.pyd | ForEach-Object { Sign $_.FullName }
  # it runs from wherever it is unpacked (a copy, so the run writes no bytecode into the build), and it ships no link and
  # no path of this build machine
  Copy-Item -Recurse $Root "$Work\moved"
  & "$Work\moved\bin\oarbankd.cmd" --help | Out-Null; Check "oarbankd --help"
  uv run --no-project --python 3.12 python "$Repo\scripts\check-package.py" --build-path $Work --build-path (uv python dir).Trim() `
    --run "$Root=python\python.exe" --imports oarbank,oarbank_sdk $Root (Get-Item "$Site\oarbank.*.pyd").FullName "$Root\bin\oarbank-sandbox.exe"
  Check "the coordinator build is not fit to ship"
  $Tgz = "$Out\oarbank-coordinator-$Version-$Platform.tar.gz"
  & $Py -I -B "$Repo\scripts\pack-tar.py" $Tgz $Root oarbank-coordinator.json bin python; Check "the archive"
  $h = (Get-FileHash -Algorithm SHA256 $Tgz).Hash.ToLower()
  Set-Content -Encoding ascii "$Out\SHA256SUMS-coordinator-$Version-$Platform" "$h  $(Split-Path -Leaf $Tgz)"
  $Tgz
} finally {
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}
