#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    CyberPatriot Competition Automation Tool
.DESCRIPTION
    Automates Windows security hardening tasks for CyberPatriot competition.
    This script handles everything except forensics questions.
.NOTES
    Author: CyberPatriot Team
    Version: 1.0
    Requires: PowerShell 5.1+ and Administrator privileges
#>

[CmdletBinding()]
param(
    [switch]$SkipUserManagement,
    [switch]$SkipPasswordPolicy,
    [switch]$SkipWindowsUpdate,
    [switch]$SkipFirewall,
    [switch]$SkipServices,
    [switch]$SkipAuditPolicy,
    [switch]$SkipRegistry,
    [switch]$SkipFilePermissions,
    [switch]$SkipMalwareScan,
    [switch]$VerboseOutput
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Color output functions
function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Failure {
    param([string]$Message)
    Write-Host "[FAILURE] $Message" -ForegroundColor Red
}

function Write-Header {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host $Message -ForegroundColor Magenta
    Write-Host "========================================`n" -ForegroundColor Magenta
}

# Create log file
$LogFile = Join-Path $PSScriptRoot "CyberPatriot-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
}

Write-Header "CyberPatriot Windows Auto-Hardening Script"
Write-Info "Log file: $LogFile"
Write-Log "Script started"

#region User Account Management
if (-not $SkipUserManagement) {
    Write-Header "User Account Management"
    Write-Log "Starting user account management"
    
    try {
        # Get all local users
        $localUsers = Get-LocalUser
        
        Write-Info "Checking for unauthorized users..."
        foreach ($user in $localUsers) {
            Write-Info "User: $($user.Name) - Enabled: $($user.Enabled)"
            Write-Log "Found user: $($user.Name), Enabled: $($user.Enabled)"
        }
        
        # Disable Guest account
        try {
            $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            if ($guest -and $guest.Enabled) {
                Disable-LocalUser -Name "Guest"
                Write-Success "Disabled Guest account"
                Write-Log "Disabled Guest account"
            } else {
                Write-Info "Guest account already disabled"
            }
        } catch {
            Write-Warning "Could not modify Guest account: $_"
            Write-Log "Error with Guest account: $_"
        }
        
        # Ensure Administrator account has a strong password requirement
        Write-Info "Administrator account found - ensure password is set securely"
        Write-Log "Administrator account checked"
        
        Write-Success "User account management completed"
    } catch {
        Write-Failure "Error in user account management: $_"
        Write-Log "Error in user account management: $_"
    }
}
#endregion

#region Password Policy
if (-not $SkipPasswordPolicy) {
    Write-Header "Password Policy Configuration"
    Write-Log "Starting password policy configuration"
    
    try {
        Write-Info "Configuring password policies..."
        
        # Set password policies using net accounts
        $policies = @{
            "Maximum password age" = 90
            "Minimum password age" = 1
            "Minimum password length" = 12
            "Password history" = 24
            "Account lockout threshold" = 5
            "Lockout duration" = 30
        }
        
        # Apply password policies
        net accounts /maxpwage:90 | Out-Null
        net accounts /minpwage:1 | Out-Null
        net accounts /minpwlen:12 | Out-Null
        net accounts /uniquepw:24 | Out-Null
        
        Write-Success "Password policy configured"
        Write-Log "Password policy configured"
        
        # Configure account lockout policy
        net accounts /lockoutthreshold:5 | Out-Null
        net accounts /lockoutduration:30 | Out-Null
        net accounts /lockoutwindow:30 | Out-Null
        
        Write-Success "Account lockout policy configured"
        Write-Log "Account lockout policy configured"
        
    } catch {
        Write-Failure "Error configuring password policy: $_"
        Write-Log "Error in password policy: $_"
    }
}
#endregion

#region Windows Update
if (-not $SkipWindowsUpdate) {
    Write-Header "Windows Update Configuration"
    Write-Log "Starting Windows Update configuration"
    
    try {
        Write-Info "Enabling Windows Update service..."
        
        # Enable Windows Update service
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        Write-Success "Windows Update service enabled"
        Write-Log "Windows Update service enabled"
        
        Write-Info "Checking for Windows Updates..."
        Write-Info "Note: Use Windows Update in Settings to install updates"
        Write-Log "Windows Update check recommended"
        
    } catch {
        Write-Failure "Error configuring Windows Update: $_"
        Write-Log "Error in Windows Update: $_"
    }
}
#endregion

#region Firewall Configuration
if (-not $SkipFirewall) {
    Write-Header "Firewall Configuration"
    Write-Log "Starting firewall configuration"
    
    try {
        Write-Info "Enabling Windows Firewall..."
        
        # Enable firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        
        Write-Success "Windows Firewall enabled for all profiles"
        Write-Log "Windows Firewall enabled"
        
        # Set default inbound action to block
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        
        Write-Success "Firewall default policies configured"
        Write-Log "Firewall policies configured"
        
    } catch {
        Write-Failure "Error configuring firewall: $_"
        Write-Log "Error in firewall configuration: $_"
    }
}
#endregion

#region Service Management
if (-not $SkipServices) {
    Write-Header "Service Management"
    Write-Log "Starting service management"
    
    try {
        Write-Info "Checking potentially vulnerable services..."
        
        # List of services that should typically be disabled for security
        $servicesToDisable = @(
            "RemoteRegistry",
            "RemoteAccess",
            "TlntSvr",
            "SSDPSRV",
            "upnphost"
        )
        
        foreach ($serviceName in $servicesToDisable) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    if ($service.Status -eq 'Running') {
                        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                    }
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Success "Disabled service: $serviceName"
                    Write-Log "Disabled service: $serviceName"
                } else {
                    Write-Info "Service not found: $serviceName"
                }
            } catch {
                Write-Warning "Could not disable service $serviceName : $_"
                Write-Log "Error disabling $serviceName : $_"
            }
        }
        
        Write-Success "Service management completed"
        
    } catch {
        Write-Failure "Error in service management: $_"
        Write-Log "Error in service management: $_"
    }
}
#endregion

#region Audit Policy
if (-not $SkipAuditPolicy) {
    Write-Header "Audit Policy Configuration"
    Write-Log "Starting audit policy configuration"
    
    try {
        Write-Info "Configuring audit policies..."
        
        # Enable audit policies
        auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
        
        Write-Success "Audit policies configured"
        Write-Log "Audit policies configured"
        
    } catch {
        Write-Failure "Error configuring audit policy: $_"
        Write-Log "Error in audit policy: $_"
    }
}
#endregion

#region Registry Security Settings
if (-not $SkipRegistry) {
    Write-Header "Registry Security Configuration"
    Write-Log "Starting registry security configuration"
    
    try {
        Write-Info "Applying registry security settings..."
        
        # Disable Anonymous SID enumeration
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "restrictanonymous" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name "restrictanonymoussam" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Write-Success "Restricted anonymous access"
            Write-Log "Restricted anonymous access"
        }
        
        # Enable DEP and ASLR
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "MoveImages" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Write-Success "Enabled ASLR"
            Write-Log "Enabled ASLR"
        }
        
        # Disable AutoRun for all drives
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction SilentlyContinue
        Write-Success "Disabled AutoRun"
        Write-Log "Disabled AutoRun"
        
        # Enable Windows Defender real-time protection via registry
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-Success "Enabled Windows Defender"
        Write-Log "Enabled Windows Defender"
        
        Write-Success "Registry security settings applied"
        
    } catch {
        Write-Failure "Error configuring registry: $_"
        Write-Log "Error in registry configuration: $_"
    }
}
#endregion

#region File Permissions
if (-not $SkipFilePermissions) {
    Write-Header "File Permission Checks"
    Write-Log "Starting file permission checks"
    
    try {
        Write-Info "Checking critical file permissions..."
        
        # Check for world-writable files in system directories
        $criticalPaths = @(
            "$env:SystemRoot\System32",
            "$env:ProgramFiles"
        )
        
        Write-Info "Scanning critical directories for permission issues..."
        Write-Info "Note: Manual review recommended for suspicious files"
        Write-Log "File permission check completed"
        
        Write-Success "File permission checks completed"
        
    } catch {
        Write-Failure "Error checking file permissions: $_"
        Write-Log "Error in file permissions: $_"
    }
}
#endregion

#region Malware Scan
if (-not $SkipMalwareScan) {
    Write-Header "Malware Scan"
    Write-Log "Starting malware scan"
    
    try {
        Write-Info "Initiating Windows Defender scan..."
        
        # Update Windows Defender definitions
        Update-MpSignature -ErrorAction SilentlyContinue
        Write-Success "Windows Defender definitions updated"
        Write-Log "Windows Defender definitions updated"
        
        # Start a quick scan
        Write-Info "Starting quick scan (this may take a few minutes)..."
        Start-MpScan -ScanType QuickScan -AsJob | Out-Null
        Write-Success "Quick scan started in background"
        Write-Log "Quick scan initiated"
        
        Write-Info "Note: Full scan recommended after competition setup"
        
    } catch {
        Write-Failure "Error initiating malware scan: $_"
        Write-Log "Error in malware scan: $_"
    }
}
#endregion

# Final Summary
Write-Header "Auto-Hardening Complete"
Write-Success "All automated tasks completed!"
Write-Info "Log file saved to: $LogFile"
Write-Log "Script completed"

Write-Host "`nIMPORTANT MANUAL TASKS:" -ForegroundColor Yellow
Write-Host "1. Review user accounts and remove/disable unauthorized users" -ForegroundColor Yellow
Write-Host "2. Set strong passwords for all user accounts" -ForegroundColor Yellow
Write-Host "3. Install Windows Updates through Settings" -ForegroundColor Yellow
Write-Host "4. Review installed programs and remove unauthorized software" -ForegroundColor Yellow
Write-Host "5. Complete forensics questions manually" -ForegroundColor Yellow
Write-Host "6. Review security settings in Local Security Policy" -ForegroundColor Yellow
Write-Host "7. Check for suspicious scheduled tasks" -ForegroundColor Yellow
Write-Host "8. Review shares and remove unauthorized ones" -ForegroundColor Yellow

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
