# Wrap a coordinator archive in a native Windows MSI, without rebuilding or running its programs.
# Requires Windows tar, WiX 5 and WixToolset.Util.wixext. The archive must include bin\oarbank-setup.py and pythonw.exe.
#
#   scripts\package-coordinator-windows.ps1 [-Build dist\oarbank-coordinator-<v>-windows-<arch>.tar.gz] [-Out dist] [-DryRun]
#
# Without -Build, select the repository version and native host architecture's archive in dist. With -Build,
# version/platform come from the archive manifest; optional -Version/-Arch must agree with it. -DryRun validates and
# stages the archive, then prints the packaging command without invoking WiX or signing. OARBANK_SIGNTOOL_ARGS signs
# the MSI when set; the existing build already signs its executable payload. No installation or service operations.
param(
  [string]$Build = "",
  [string]$Version = "",
  [ValidateSet("x64", "arm64")][string]$Arch = "",
  [string]$Out = "",
  [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = "$Repo\dist" }
if (-not $Build) {
  if (-not $Version) { $Version = (Select-String -Path "$Repo\pyproject.toml" -Pattern '^version = "(.*)"').Matches[0].Groups[1].Value }
  $Arch = & "$PSScriptRoot\windows-arch.ps1" -Arch $Arch
  $Platform = if ($Arch -eq 'arm64') { 'windows-arm64' } else { 'windows-amd64' }
  $Build = "$Repo\dist\oarbank-coordinator-$Version-$Platform.tar.gz"
}
$Build = (Resolve-Path -LiteralPath $Build).Path
$Out = [IO.Path]::GetFullPath($Out)
$Work = Join-Path $env:TEMP "oarbank-coordinator-msi-$([guid]::NewGuid().ToString('N'))"
$Root = "$Work\package"
function Check($what) { if ($LASTEXITCODE) { throw "$what failed ($LASTEXITCODE)" } }
try {
  # Refuse traversal and links before extraction, not after tar has had a chance to write outside the staging tree.
  $names = @(& tar -tzf $Build); Check "listing the archive"
  if (-not $names.Count) { throw "the coordinator archive is empty" }
  foreach ($name in $names) {
    $normal = $name.Replace('\', '/')
    if ($normal.StartsWith('/') -or $normal.Contains(':') -or ($normal.Split('/') -contains '..')) {
      throw "unsafe coordinator archive path: $name"
    }
  }
  $entries = @(& tar -tvzf $Build); Check "checking archive entry types"
  foreach ($entry in $entries) {
    if ($entry -notmatch '^[-d]') { throw "the coordinator archive must contain only regular files and directories: $entry" }
  }
  New-Item -ItemType Directory -Force $Root | Out-Null
  & tar -xzf $Build -C $Root; Check "extracting the coordinator archive"
  if (Get-ChildItem -LiteralPath $Root -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
    throw "the coordinator payload contains a reparse point"
  }
  $manifest = Get-Content -LiteralPath "$Root\oarbank-coordinator.json" -Raw | ConvertFrom-Json
  if ($manifest.format -ne 1 -or $manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$') {
    throw "invalid coordinator build format or version"
  }
  $BuildArch = switch ($manifest.platform) {
    'windows-amd64' { 'x64' }
    'windows-arm64' { 'arm64' }
    default { throw "not a Windows coordinator build: $($manifest.platform)" }
  }
  if ($Arch -and $Arch -ne $BuildArch) { throw "-Arch $Arch does not match $($manifest.platform)" }
  if ($Version -and $Version -ne $manifest.version) { throw "-Version $Version does not match $($manifest.version)" }
  $Arch = $BuildArch
  $Version = $manifest.version
  if ((@($manifest.exec) -join '|') -ne 'python/python.exe|-I|bin/oarbankd.py' -or
      (@($manifest.console) -join '|') -ne 'python/python.exe|-I|bin/oarbank-console.py') {
    throw "the build manifest does not name the Windows coordinator launchers"
  }
  foreach ($file in @('python\python.exe', 'python\pythonw.exe', 'bin\oarbankd.py', 'bin\oarbank-console.py',
                      'bin\oarbank-setup.py', 'bin\oarbank-setup.cmd', 'bin\oarbank.cmd', 'bin\oarbank-sandbox.exe', 'bin\uv.exe')) {
    if (-not (Test-Path -LiteralPath "$Root\$file" -PathType Leaf)) { throw "the coordinator build is missing $file" }
  }
  # Always ship the installer that implements -Installed and -KeepPrograms, including when wrapping an older archive.
  Copy-Item -LiteralPath "$Repo\deploy\oarbankd\install-oarbankd.ps1" -Destination "$Root\install-oarbankd.ps1"
  # A hidden elevation broker keeps the shortcut independent of the user's Python installation. Waiting also lets
  # it display a startup error if pythonw exits before the wizard can show its own diagnostics. No services are
  # installed here; that is the portable wizard's explicit configuration step.
  $setupBroker = @'
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
try {
  $python = Join-Path $PSScriptRoot 'python\pythonw.exe'
  $launcher = Join-Path $PSScriptRoot 'bin\oarbank-setup.py'
  if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or -not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    throw 'The bundled setup launcher is missing. Repair the Oarbank coordinator installation.'
  }
  $process = Start-Process -FilePath $python -ArgumentList ('-I "' + $launcher + '" --root "' + $PSScriptRoot + '"') -WorkingDirectory $PSScriptRoot -Verb RunAs -PassThru -Wait
  if ($process.ExitCode -ne 0) {
    throw "Setup exited with error $($process.ExitCode). Run bin\oarbank-setup.cmd from an elevated prompt to see diagnostics."
  }
} catch {
  [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Oarbank coordinator setup', 'OK', 'Error')
  exit 1
}
'@
  [IO.File]::WriteAllText("$Root\oarbank-setup.ps1", $setupBroker)
  Copy-Item -LiteralPath "$Repo\deploy\icons\oarbank.ico" -Destination "$Root\oarbank.ico"
  $MsiVersion = ($Version -split '[-+]')[0]
  $parts = $MsiVersion.Split('.')
  if ([long]$parts[0] -gt 255 -or [long]$parts[1] -gt 255 -or [long]$parts[2] -gt 65535) {
    throw "version $MsiVersion exceeds Windows Installer version limits"
  }
  $Msi = "$Out\oarbank-coordinator-$Version-windows-$Arch.msi"
  $wixArgs = @('build', "$Repo\deploy\windows\oarbank-coordinator.wxs", '-arch', $Arch,
               '-ext', 'WixToolset.Util.wixext', '-d', "Version=$MsiVersion", '-d', "PackageDir=$Root", '-o', $Msi)
  if ($DryRun) {
    "Validated coordinator build ($Version, $($manifest.platform)); payload includes the setup launcher."
    'wix ' + (($wixArgs | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    if ($env:OARBANK_SIGNTOOL_ARGS) { "Would sign $Msi with signtool." }
    return
  }
  New-Item -ItemType Directory -Force $Out | Out-Null
  & wix @wixArgs; Check "building the coordinator MSI"
  if ($env:OARBANK_SIGNTOOL_ARGS) {
    & signtool sign $env:OARBANK_SIGNTOOL_ARGS.Split(' ') $Msi; Check "signing the coordinator MSI"
  }
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Msi).Hash.ToLower()
  [IO.File]::WriteAllText("$Out\SHA256SUMS-coordinator-msi-$Version-windows-$Arch", "$hash  $(Split-Path -Leaf $Msi)`n")
  $Msi
} finally {
  Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}
