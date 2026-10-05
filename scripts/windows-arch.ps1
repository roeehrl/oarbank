# The architecture a Windows build is for: -Arch when the caller names one (x64 or arm64), else this machine's.
# The machine's comes from IsWow64Process2, which names the native machine whatever this PowerShell runs as: under
# emulation (an x64 or x86 PowerShell on Windows on Arm) PROCESSOR_ARCHITECTURE says AMD64 or x86, and .NET's
# RuntimeInformation.OSArchitecture says X64 too.
#
#   $Arch = & scripts\windows-arch.ps1 [-Arch x64|arm64]
param([string]$Arch = "")
$ErrorActionPreference = "Stop"
if ($Arch) {
  if ($Arch -notin "x64", "arm64") { throw "unknown architecture $Arch (x64 or arm64)" }
  return $Arch
}
if (-not ("Oarbank.Machine" -as [type])) {
  Add-Type -Namespace Oarbank -Name Machine -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
'@
}
$process, $native = [uint16]0, [uint16]0
if (-not [Oarbank.Machine]::IsWow64Process2([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$process, [ref]$native)) {
  throw "IsWow64Process2 failed"
}
switch ($native) {
  0xAA64 { "arm64" }                       # IMAGE_FILE_MACHINE_ARM64
  0x8664 { "x64" }                         # IMAGE_FILE_MACHINE_AMD64
  default { throw ("no Oarbank build for this machine (0x{0:X4})" -f $native) }
}
