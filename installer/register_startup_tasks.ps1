$ErrorActionPreference = "Stop"
$AppRoot = Split-Path -Parent $PSScriptRoot
$Pythonw = Join-Path $AppRoot "runtime\pythonw.exe"
$PowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$Launcher = Join-Path $AppRoot "app_launcher.pyw"
$BrowserSetup = Join-Path $AppRoot "installer\configure_browser.ps1"
$UserId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$TaskPath = "\SentinelClip\"
$StartupLink = Join-Path ([Environment]::GetFolderPath("Startup")) "SentinelClip.lnk"
$TaskRunner = Join-Path $env:SystemRoot "System32\schtasks.exe"

$Principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries
$LogonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$TrayAction = New-ScheduledTaskAction `
    -Execute $Pythonw `
    -Argument ('"{0}"' -f $Launcher) `
    -WorkingDirectory $AppRoot
$BrowserAction = New-ScheduledTaskAction `
    -Execute $PowerShell `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $BrowserSetup) `
    -WorkingDirectory $AppRoot

Register-ScheduledTask `
    -TaskPath $TaskPath `
    -TaskName "Tray" `
    -Action $TrayAction `
    -Trigger $LogonTrigger `
    -Principal $Principal `
    -Settings $Settings `
    -Force | Out-Null

Register-ScheduledTask `
    -TaskPath $TaskPath `
    -TaskName "BrowserSetup" `
    -Action $BrowserAction `
    -Principal $Principal `
    -Settings $Settings `
    -Force | Out-Null

$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($StartupLink)
$Shortcut.TargetPath = $TaskRunner
$Shortcut.Arguments = '/Run /TN "\SentinelClip\Tray"'
$Shortcut.WorkingDirectory = $AppRoot
$Shortcut.Description = "Start SentinelClip DLP protection at sign-in"
$Shortcut.IconLocation = Join-Path $AppRoot "browser_extension\icons\icon48.png"
$Shortcut.Save()

Start-ScheduledTask -TaskPath $TaskPath -TaskName "Tray"