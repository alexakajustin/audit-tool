@echo off
title NetAudit - Standard Privileges
echo Starting NetAudit in standard mode...
echo (Note: Active scans like ARP Sweep and Sniffing require Administrator mode)
echo.
python app.py
if %errorlevel% neq 0 (
    echo.
    echo An error occurred while starting the application. Please make sure Python is installed and dependencies are loaded.
    pause
)
