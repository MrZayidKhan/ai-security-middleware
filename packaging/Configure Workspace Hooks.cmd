@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_detector.ps1" -WorkspaceHooks
set "setup_exit=%ERRORLEVEL%"
pause
exit /b %setup_exit%
