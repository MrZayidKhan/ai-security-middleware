@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_antigravity_panel.ps1"
set "panel_exit=%ERRORLEVEL%"
pause
exit /b %panel_exit%
