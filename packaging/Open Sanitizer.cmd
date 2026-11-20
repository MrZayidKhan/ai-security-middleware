@echo off
pushd "%~dp0"
if not exist ".venv\Scripts\ai-security-middleware-serve.exe" (
  echo Run Setup first.
  pause
  exit /b 1
)
".venv\Scripts\ai-security-middleware-serve.exe" --detector offline --model-dir model --audit-db runtime_data\security_events.db
set "sanitizer_exit=%ERRORLEVEL%"
popd
exit /b %sanitizer_exit%
