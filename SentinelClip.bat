@echo off
:: SentinelClip Windows Application Launcher
:: Double-click this file to launch SentinelClip as a background app.
:: Automatically requests Administrator privileges if required.

cd /d "%~dp0"

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Run app_launcher.pyw using pythonw.exe (windowless GUI executable)
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" "app_launcher.pyw"
) else (
    start "" pythonw "app_launcher.pyw"
)

exit
