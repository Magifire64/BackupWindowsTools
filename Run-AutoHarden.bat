@echo off
REM CyberPatriot Auto-Hardening Script Launcher
REM This batch file launches the PowerShell hardening script with administrator privileges

echo ============================================
echo CyberPatriot Auto-Hardening Tool
echo ============================================
echo.
echo This script will:
echo - Configure password policies
echo - Enable Windows Firewall
echo - Disable vulnerable services
echo - Enable audit logging
echo - Apply security registry settings
echo - Start malware scanning
echo.
echo Administrator privileges are required!
echo.
pause

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
    echo.
) else (
    echo ERROR: This script must be run as Administrator!
    echo Right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

REM Change to script directory
cd /d "%~dp0"

REM Run the PowerShell script
echo Starting PowerShell hardening script...
echo.
powershell.exe -ExecutionPolicy Bypass -File ".\CyberPatriot-AutoHarden.ps1"

echo.
echo ============================================
echo Script execution completed!
echo Check the log file for details.
echo ============================================
echo.
pause
