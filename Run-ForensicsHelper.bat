@echo off
REM CyberPatriot Forensics Helper Launcher
REM This batch file launches the PowerShell forensics helper script

echo ============================================
echo CyberPatriot Forensics Helper
echo ============================================
echo.
echo This script will gather information for:
echo - User account history
echo - Security event logs
echo - Software installation history
echo - Recent file activity
echo - Prohibited file types
echo - Browser history locations
echo - Scheduled tasks
echo - Network connections
echo - Startup programs
echo.
echo NOTE: This script does NOT answer forensics
echo questions automatically. It provides data
echo for you to manually analyze and answer.
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

REM Ask if user wants to export report
set /p EXPORT="Export report to file? (Y/N): "
if /i "%EXPORT%"=="Y" (
    echo Starting forensics helper with report export...
    powershell.exe -ExecutionPolicy Bypass -File ".\Forensics-Helper.ps1" -ExportReport
) else (
    echo Starting forensics helper...
    powershell.exe -ExecutionPolicy Bypass -File ".\Forensics-Helper.ps1"
)

echo.
echo ============================================
echo Forensics helper completed!
echo Use the information above to answer questions.
echo ============================================
echo.
pause
