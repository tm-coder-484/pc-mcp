@echo off
rem pc-mcp launcher for Windows: double-click to let Claude connect to this PC.
rem First run installs uv (Python manager), Python and dependencies automatically - about a minute.
setlocal
title pc-mcp - remote access for Claude
cd /d "%~dp0"

where uv >nul 2>nul
if errorlevel 1 set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul
if errorlevel 1 (
    echo Installing uv, the Python manager pc-mcp runs on - one time only...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://astral.sh/uv/install.ps1 | iex"
)
where uv >nul 2>nul
if errorlevel 1 (
    echo.
    echo Could not install uv automatically. Install it from https://docs.astral.sh/uv/ and run this file again.
    pause
    exit /b 1
)

set "ARGS=%*"
if not "%ARGS%"=="" goto run

echo.
echo  How much should Claude be allowed to do on this PC?
echo    [1] Full access - run commands, manage files and processes  (default)
echo    [2] Full access, but ask me here before every command or change
echo    [3] Read-only - diagnose and inspect only, change nothing
echo.
choice /c 123 /n /t 20 /d 1 /m "Press 1, 2 or 3 (defaults to 1 in 20 seconds): "
if errorlevel 3 (set "ARGS=--mode read-only" & goto run)
if errorlevel 2 (set "ARGS=--confirm" & goto run)

:run
echo.
echo Starting pc-mcp - the first start downloads Python and dependencies, please wait...
uv run --quiet pc-mcp %ARGS%
echo.
echo pc-mcp has stopped.
pause
