@echo off
:: SentinelClip Native Messaging Host Launcher
:: This batch file is referenced by the native messaging manifest.
:: Chrome requires an executable path; this wraps the Python script.

set "APP_ROOT=%~dp0.."
cd /d "%APP_ROOT%"

if exist "%APP_ROOT%\runtime\python.exe" (
	"%APP_ROOT%\runtime\python.exe" "%APP_ROOT%\native_host\native_host.py"
) else if exist "%APP_ROOT%\.venv\Scripts\python.exe" (
	"%APP_ROOT%\.venv\Scripts\python.exe" "%APP_ROOT%\native_host\native_host.py"
) else (
	python "%APP_ROOT%\native_host\native_host.py"
)
