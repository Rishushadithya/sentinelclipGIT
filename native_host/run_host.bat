@echo off
:: SentinelClip Native Messaging Host Launcher
:: This batch file is referenced by the native messaging manifest.
:: Chrome requires an executable path; this wraps the Python script.

cd /d "%~dp0\.."
".venv\Scripts\python.exe" "native_host\native_host.py"
