@echo off
setlocal
title Stop SentinelX Classroom Demo
cd /d "%~dp0"

echo ========================================================================
echo                 Stop SentinelX Classroom Demo
echo ========================================================================
echo.

if not exist "%~dp0.demo.pid" (
    echo [i] No .demo.pid file found. Demo server is not running.
    echo.
    pause
    exit /b 0
)

powershell -NoProfile -Command ^
    "$pidPath = '%~dp0.demo.pid'; " ^
    "if (-not (Test-Path -LiteralPath $pidPath)) { " ^
    "    Write-Host '[i] No .demo.pid file found. Demo server is not running.'; " ^
    "    exit 0; " ^
    "}; " ^
    "$pidText = Get-Content -LiteralPath $pidPath -ErrorAction SilentlyContinue; " ^
    "if (-not $pidText) { " ^
    "    Write-Host '[i] .demo.pid is empty. Removing file.'; " ^
    "    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue; " ^
    "    exit 0; " ^
    "}; " ^
    "$targetPid = [int]$pidText.Trim(); " ^
    "$proc = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $targetPid) -ErrorAction SilentlyContinue; " ^
    "if ($proc -and ($proc.CommandLine -match 'demo_server\.py' -or $proc.Name -match 'python')) { " ^
    "    Write-Host ('Stopping SentinelX demo server (PID ' + $targetPid + ')...'); " ^
    "    taskkill /PID $targetPid /T /F >$null 2>&1; " ^
    "    Write-Host 'SentinelX demo server stopped cleanly.'; " ^
    "} else { " ^
    "    Write-Host ('Process ' + $targetPid + ' does not match SentinelX demo server. Removing stale PID file.'); " ^
    "}; " ^
    "Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue"

echo.
pause
