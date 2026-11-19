@echo off
cd /d "%~dp0"
if exist "rust-dashboard\target\release\security-dashboard.exe" (
    start "" "%~dp0rust-dashboard\target\release\security-dashboard.exe"
    exit /b 0
)
if exist "rust-dashboard\target\x86_64-pc-windows-msvc\release\security-dashboard.exe" (
    start "" "%~dp0rust-dashboard\target\x86_64-pc-windows-msvc\release\security-dashboard.exe"
    exit /b 0
)
if exist "rust-dashboard\target\debug\security-dashboard.exe" (
    start "" "%~dp0rust-dashboard\target\debug\security-dashboard.exe"
    exit /b 0
)
echo The Rust dashboard binary is missing. See docs\STANDALONE_SETUP.md for builds and downloads.
pause
exit /b 1
