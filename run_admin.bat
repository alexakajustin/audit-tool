@echo off
title NetAudit - Administrator Mode
echo Checking for Administrator privileges...

:: Test if we are administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with Administrator privileges...
    echo.
    :: Change directory to the folder where this batch script lives
    cd /d "%~dp0"
    python app.py
) else (
    echo Requesting Administrator elevation...
    :: Elevate and re-run the script to trigger UAC
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    exit /b
)

if %errorlevel% neq 0 (
    echo.
    echo An error occurred. If the window closed immediately, check if python is in your system PATH.
    pause
)
