# CI on Windows: install the elevated helper from the launcher cargo just built (rust\target\debug), as the agent's
# MSI installs it from Program Files: a LocalSystem service that opens loopback to a module container's egress proxy
# (enforced allowlists: oarbank-launcher's helper_windows.rs). The runner is a throwaway machine; nothing removes it.
$ErrorActionPreference = "Stop"
$launcher = (Resolve-Path "$PSScriptRoot\..\rust\target\debug\oarbank-launcher.exe").Path
sc.exe create OarbankHelper binPath= "`"$launcher`" helper-main" obj= LocalSystem start= demand depend= BFE DisplayName= "Oarbank helper"
if ($LASTEXITCODE) { throw "sc create OarbankHelper failed" }
sc.exe start OarbankHelper
if ($LASTEXITCODE) { throw "sc start OarbankHelper failed" }
