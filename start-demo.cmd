@echo off
setlocal enabledelayedexpansion
title SentinelX Classroom Demo
cd /d "%~dp0"

echo ========================================================================
echo                    SentinelX Classroom Demo
echo ========================================================================
echo.

rem Step 1: Check Python availability on PATH
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python was not found on your PATH.
    echo.
    echo Please install Python 3.12 or newer and check "Add python.exe to PATH".
    echo Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python 3.12 or newer is required to run SentinelX.
    echo Please install Python 3.12 or newer and try again.
    echo.
    pause
    exit /b 1
)

rem Step 2: Check or create virtual environment
set "VENV_DIR=%~dp0.venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"

if not exist "%VENV_PY%" (
    echo [*] Creating virtual environment in .venv...
    python -m venv "%VENV_DIR%"
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create virtual environment in .venv.
        pause
        exit /b 1
    )
    echo [*] Installing dependencies from requirements.txt...
    "%VENV_PY%" -m pip install -r "%~dp0requirements.txt"
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to install dependencies from requirements.txt.
        pause
        exit /b 1
    )
) else (
    "%VENV_PY%" -c "import flask, waitress" >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo [*] Installing missing dependencies from requirements.txt...
        "%VENV_PY%" -m pip install -r "%~dp0requirements.txt"
        if %ERRORLEVEL% neq 0 (
            echo [ERROR] Failed to install dependencies from requirements.txt.
            pause
            exit /b 1
        )
    )
)

rem Step 3: Check if demo server is already running
if exist "%~dp0.demo.pid" (
    powershell -NoProfile -Command ^
        "$pidText = Get-Content -LiteralPath '%~dp0.demo.pid' -ErrorAction SilentlyContinue; " ^
        "if ($pidText) { " ^
        "    $targetPid = [int]$pidText.Trim(); " ^
        "    $proc = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $targetPid) -ErrorAction SilentlyContinue; " ^
        "    if ($proc -and ($proc.CommandLine -match 'demo_server\.py' -or $proc.Name -match 'python')) { " ^
        "        Write-Host '[*] SentinelX demo server is already running (PID: ' $targetPid ').'; " ^
        "        Write-Host '[*] Run stop-demo.cmd to stop it first.'; " ^
        "        exit 42; " ^
        "    } " ^
        "}"
    if !ERRORLEVEL! equ 42 (
        echo.
        pause
        exit /b 0
    )
    del /f /q "%~dp0.demo.pid" >nul 2>nul
)

rem Step 4: Start demo server on 127.0.0.1 (generates random password, picks free port if 5000 busy, opens browser)
echo [*] Starting SentinelX demo server...
"%VENV_PY%" "%~dp0scripts\demo_server.py" --pid-file "%~dp0.demo.pid" --open-browser
set EXIT_CODE=%ERRORLEVEL%

if exist "%~dp0.demo.pid" (
    del /f /q "%~dp0.demo.pid" >nul 2>nul
)
