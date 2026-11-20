@echo off
py -3 "%~dp0uninstall_detector.py"
set "uninstall_exit=%ERRORLEVEL%"
pause
exit /b %uninstall_exit%
