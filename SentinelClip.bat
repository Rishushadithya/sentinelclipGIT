@echo off
setlocal
"%SystemRoot%\System32\schtasks.exe" /Run /TN "\SentinelClip\Tray" >nul 2>&1
if errorlevel 1 (
    echo SentinelClip could not start.
    echo The elevated SentinelClip startup task is not registered or Windows denied access.
    echo Run SentinelClip-Setup-Offline.exe again and approve the administrator prompt.
    echo.
    pause
    exit /b 1
)
exit /b 0
