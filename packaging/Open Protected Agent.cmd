@echo off
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Run Setup first.
  pause
  exit /b 1
)
"%~dp0.venv\Scripts\python.exe" -m security_middleware.protected_agent --model-dir "%~dp0model" --audit-db "%~dp0runtime_data\security_events.db"
set "agent_exit=%ERRORLEVEL%"
pause
exit /b %agent_exit%
