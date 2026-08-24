# SentinelClip Desktop & Start Menu Shortcut Creator

$ProjectDir = $PSScriptRoot
$TargetBat = Join-Path $ProjectDir "SentinelClip.bat"
$IconPath = Join-Path $ProjectDir "browser_extension\icons\icon48.png"

# Desktop Path
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$ShortcutPath = Join-Path $DesktopPath "SentinelClip.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetBat
$Shortcut.WorkingDirectory = $ProjectDir
$Shortcut.Description = "SentinelClip -- Local-First DLP Middleware Application"
$Shortcut.Save()

Write-Host "Created Desktop Shortcut: $ShortcutPath" -ForegroundColor Green

# Start Menu Path
$StartMenuPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Programs)
$StartShortcutPath = Join-Path $StartMenuPath "SentinelClip.lnk"
$StartShortcut = $WshShell.CreateShortcut($StartShortcutPath)
$StartShortcut.TargetPath = $TargetBat
$StartShortcut.WorkingDirectory = $ProjectDir
$StartShortcut.Description = "SentinelClip -- Local-First DLP Middleware Application"
$StartShortcut.Save()

Write-Host "Created Start Menu Shortcut: $StartShortcutPath" -ForegroundColor Green
