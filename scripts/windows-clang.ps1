# Find clang for building the agent on Windows on Arm and print the directory that holds clang.exe: the ring crate
# needs clang for aarch64-pc-windows-msvc (MSVC alone cannot build it). Looks on PATH, then in a standalone LLVM, then
# in Visual Studio's "C++ Clang Compiler for Windows" component; -Install adds that component when none is found.
#
#   $env:PATH = "$(scripts\windows-clang.ps1);$env:PATH"
#   scripts\windows-clang.ps1 -Install | Add-Content $env:GITHUB_PATH      # CI
param([switch]$Install)
$ErrorActionPreference = "Stop"
$Component = "Microsoft.VisualStudio.Component.VC.Llvm.Clang"
$Installer = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"

function VisualStudio {
  if (Test-Path "$Installer\vswhere.exe") { & "$Installer\vswhere.exe" -latest -products * -property installationPath }
}

function Find-Clang {
  $onPath = Get-Command clang.exe -ErrorAction SilentlyContinue
  if ($onPath) { return Split-Path -Parent $onPath.Source }
  $dirs = @("$env:ProgramFiles\LLVM\bin")
  $vs = VisualStudio
  if ($vs) { $dirs += "$vs\VC\Tools\Llvm\ARM64\bin", "$vs\VC\Tools\Llvm\x64\bin" }
  $dirs | Where-Object { Test-Path "$_\clang.exe" } | Select-Object -First 1
}

$dir = Find-Clang
if (-not $dir -and $Install) {
  $vs = VisualStudio
  if (-not $vs) { throw "no Visual Studio to add $Component to: install Visual Studio 2022 (or LLVM) first" }
  Write-Host "adding $Component to $vs"
  $p = Start-Process -FilePath "$Installer\setup.exe" -Wait -PassThru -ArgumentList @(
    "modify", "--installPath", "`"$vs`"", "--add", $Component, "--quiet", "--norestart", "--nocache")
  if ($p.ExitCode -notin 0, 3010) { throw "the Visual Studio installer failed ($($p.ExitCode))" }
  $dir = Find-Clang
}
if (-not $dir) { throw "clang not found: install Visual Studio's $Component or LLVM, or run scripts\windows-clang.ps1 -Install" }
$dir
