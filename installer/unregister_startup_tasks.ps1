$ErrorActionPreference = "Continue"
$TaskPath = "\SentinelClip\"
$AppRoot = Split-Path -Parent $PSScriptRoot
$Pythonw = Join-Path $AppRoot "runtime\pythonw.exe"
$StartupLink = Join-Path ([Environment]::GetFolderPath("Startup")) "SentinelClip.lnk"

Stop-ScheduledTask -TaskPath $TaskPath -TaskName "Tray" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskPath $TaskPath -TaskName "Tray" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskPath $TaskPath -TaskName "BrowserSetup" -Confirm:$false -ErrorAction SilentlyContinue

Get-CimInstance Win32_Process |
	Where-Object { $_.ExecutablePath -eq $Pythonw } |
	ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

if (Test-Path $StartupLink) {
	Remove-Item $StartupLink -Force
}