@echo off
REM CyberPatriot Security Check Script Launcher
REM This batch file launches the PowerShell security check script with administrator privileges

echo ============================================
echo CyberPatriot Advanced Security Check
echo ============================================
echo.
echo This script will analyze:
echo - User account security
echo - Password settings
echo - Installed software
echo - Service configuration
echo - Firewall status
echo - Scheduled tasks
echo - Network shares
echo - Windows Defender status
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
echo Starting PowerShell security check...
echo.
powershell.exe -ExecutionPolicy Bypass -File ".\Advanced-SecurityCheck.ps1"

echo.
echo ============================================
echo Security check completed!
echo Review the findings above.
echo ============================================
echo.
pause
