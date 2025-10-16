#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Advanced Security Check Script for CyberPatriot
.DESCRIPTION
    Performs detailed security audits and provides actionable recommendations.
    Use this script to identify additional security issues after running the main auto-hardening script.
.NOTES
    Author: CyberPatriot Team
    Version: 1.0
#>

[CmdletBinding()]
param(
    [switch]$GenerateReport
)

$ErrorActionPreference = "Continue"

# Color output functions
function Write-Finding {
    param(
        [string]$Severity,
        [string]$Message
    )
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Yellow" }
        "MEDIUM" { "Cyan" }
        "LOW" { "Gray" }
        default { "White" }
    }
    Write-Host "[$Severity] $Message" -ForegroundColor $color
}

function Write-Header {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host $Message -ForegroundColor Magenta
    Write-Host "========================================`n" -ForegroundColor Magenta
}

$findings = @()

Write-Header "Advanced Security Check - CyberPatriot"

#region User Account Analysis
Write-Header "User Account Security Analysis"

try {
    $localUsers = Get-LocalUser
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    
    Write-Host "Local User Accounts:" -ForegroundColor Cyan
    foreach ($user in $localUsers) {
        $isAdmin = $adminGroup.Name -contains $user.Name -or $adminGroup.Name -contains "$env:COMPUTERNAME\$($user.Name)"
        $status = if ($user.Enabled) { "ENABLED" } else { "DISABLED" }
        $adminStatus = if ($isAdmin) { "[ADMIN]" } else { "" }
        
        Write-Host "  - $($user.Name): $status $adminStatus" -ForegroundColor $(if ($user.Enabled) { "Yellow" } else { "Green" })
        
        if ($user.Enabled -and $user.Name -match "^(Guest|DefaultAccount)$") {
            $finding = "CRITICAL: $($user.Name) account is enabled"
            Write-Finding "CRITICAL" $finding
            $findings += $finding
        }
    }
    
    Write-Host "`nAdministrators Group Members:" -ForegroundColor Cyan
    foreach ($admin in $adminGroup) {
        Write-Host "  - $($admin.Name)" -ForegroundColor Yellow
    }
    
    if ($adminGroup.Count -gt 2) {
        $finding = "HIGH: Multiple administrators detected ($($adminGroup.Count)). Verify all are authorized."
        Write-Finding "HIGH" $finding
        $findings += $finding
    }
    
} catch {
    Write-Host "Error analyzing users: $_" -ForegroundColor Red
}
#endregion

#region Password Settings Check
Write-Header "Password Settings Analysis"

try {
    Write-Host "Current Password Policy:" -ForegroundColor Cyan
    $output = net accounts
    Write-Host $output
    
    # Check for weak password settings
    if ($output -match "Minimum password length:\s*(\d+)") {
        $minLength = [int]$matches[1]
        if ($minLength -lt 8) {
            $finding = "HIGH: Minimum password length is $minLength (should be at least 12)"
            Write-Finding "HIGH" $finding
            $findings += $finding
        }
    }
    
} catch {
    Write-Host "Error checking password policy: $_" -ForegroundColor Red
}
#endregion

#region Installed Software Check
Write-Header "Installed Software Analysis"

try {
    Write-Host "Scanning for potentially unauthorized software..." -ForegroundColor Cyan
    
    # Check for common unauthorized software
    $suspiciousSoftware = @(
        "*torrent*",
        "*limewire*",
        "*frostwire*",
        "*wireshark*",
        "*nmap*",
        "*metasploit*",
        "*burp*",
        "*vnc*",
        "*teamviewer*",
        "*anydesk*"
    )
    
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                     Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                     Where-Object { $_.DisplayName -ne $null }
    
    $installedApps += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                      Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                      Where-Object { $_.DisplayName -ne $null }
    
    foreach ($pattern in $suspiciousSoftware) {
        $matches = $installedApps | Where-Object { $_.DisplayName -like $pattern }
        foreach ($match in $matches) {
            $finding = "MEDIUM: Potentially unauthorized software found: $($match.DisplayName)"
            Write-Finding "MEDIUM" $finding
            $findings += $finding
        }
    }
    
    Write-Host "`nTotal installed applications: $($installedApps.Count)" -ForegroundColor Cyan
    
} catch {
    Write-Host "Error scanning software: $_" -ForegroundColor Red
}
#endregion

#region Service Analysis
Write-Header "Service Security Analysis"

try {
    Write-Host "Checking for vulnerable services..." -ForegroundColor Cyan
    
    $vulnerableServices = @(
        "RemoteRegistry",
        "TlntSvr",
        "SSDPSRV",
        "upnphost",
        "RemoteAccess",
        "RpcSs",
        "Browser"
    )
    
    foreach ($serviceName in $vulnerableServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq 'Running') {
                $finding = "HIGH: Vulnerable service running: $serviceName"
                Write-Finding "HIGH" $finding
                $findings += $finding
            } elseif ($service.StartType -ne 'Disabled') {
                $finding = "MEDIUM: Vulnerable service not disabled: $serviceName (Status: $($service.Status))"
                Write-Finding "MEDIUM" $finding
                $findings += $finding
            } else {
                Write-Host "  ✓ $serviceName is disabled" -ForegroundColor Green
            }
        }
    }
    
} catch {
    Write-Host "Error analyzing services: $_" -ForegroundColor Red
}
#endregion

#region Firewall Check
Write-Header "Firewall Configuration Analysis"

try {
    $profiles = Get-NetFirewallProfile
    
    foreach ($profile in $profiles) {
        $status = if ($profile.Enabled) { "ENABLED ✓" } else { "DISABLED ✗" }
        $color = if ($profile.Enabled) { "Green" } else { "Red" }
        Write-Host "  $($profile.Name) Profile: $status" -ForegroundColor $color
        
        if (-not $profile.Enabled) {
            $finding = "CRITICAL: Firewall disabled for $($profile.Name) profile"
            Write-Finding "CRITICAL" $finding
            $findings += $finding
        }
    }
    
} catch {
    Write-Host "Error checking firewall: $_" -ForegroundColor Red
}
#endregion

#region Scheduled Tasks
Write-Header "Scheduled Tasks Analysis"

try {
    Write-Host "Scanning for suspicious scheduled tasks..." -ForegroundColor Cyan
    
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    $suspiciousTasks = $tasks | Where-Object {
        $_.TaskPath -notmatch "^\\Microsoft\\" -and
        $_.Author -notmatch "^Microsoft"
    }
    
    if ($suspiciousTasks) {
        foreach ($task in $suspiciousTasks) {
            $finding = "MEDIUM: Non-Microsoft scheduled task: $($task.TaskName) in $($task.TaskPath)"
            Write-Finding "MEDIUM" $finding
            $findings += $finding
        }
    } else {
        Write-Host "  ✓ No obviously suspicious scheduled tasks found" -ForegroundColor Green
    }
    
} catch {
    Write-Host "Error scanning scheduled tasks: $_" -ForegroundColor Red
}
#endregion

#region Network Shares
Write-Header "Network Shares Analysis"

try {
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch "^(ADMIN\$|C\$|IPC\$)$" }
    
    if ($shares) {
        Write-Host "Custom network shares found:" -ForegroundColor Yellow
        foreach ($share in $shares) {
            Write-Host "  - $($share.Name): $($share.Path)" -ForegroundColor Yellow
            $finding = "MEDIUM: Custom network share exists: $($share.Name) ($($share.Path))"
            Write-Finding "MEDIUM" $finding
            $findings += $finding
        }
    } else {
        Write-Host "  ✓ No custom network shares found" -ForegroundColor Green
    }
    
} catch {
    Write-Host "Error checking network shares: $_" -ForegroundColor Red
}
#endregion

#region Windows Defender Status
Write-Header "Windows Defender Status"

try {
    $mpStatus = Get-MpComputerStatus
    
    Write-Host "Real-time Protection: $(if ($mpStatus.RealTimeProtectionEnabled) { 'ENABLED ✓' } else { 'DISABLED ✗' })" -ForegroundColor $(if ($mpStatus.RealTimeProtectionEnabled) { "Green" } else { "Red" })
    Write-Host "Antivirus Signature Age: $($mpStatus.AntivirusSignatureAge) days" -ForegroundColor $(if ($mpStatus.AntivirusSignatureAge -gt 7) { "Yellow" } else { "Green" })
    
    if (-not $mpStatus.RealTimeProtectionEnabled) {
        $finding = "CRITICAL: Windows Defender real-time protection is disabled"
        Write-Finding "CRITICAL" $finding
        $findings += $finding
    }
    
    if ($mpStatus.AntivirusSignatureAge -gt 7) {
        $finding = "HIGH: Windows Defender signatures are outdated ($($mpStatus.AntivirusSignatureAge) days old)"
        Write-Finding "HIGH" $finding
        $findings += $finding
    }
    
} catch {
    Write-Host "Error checking Windows Defender: $_" -ForegroundColor Red
}
#endregion

#region Security Updates
Write-Header "Windows Update Status"

try {
    Write-Host "Checking Windows Update service..." -ForegroundColor Cyan
    $wuService = Get-Service -Name wuauserv
    
    Write-Host "Windows Update Service: $($wuService.Status) ($($wuService.StartType))" -ForegroundColor $(if ($wuService.Status -eq 'Running') { "Green" } else { "Yellow" })
    
    if ($wuService.Status -ne 'Running' -or $wuService.StartType -ne 'Automatic') {
        $finding = "HIGH: Windows Update service is not properly configured"
        Write-Finding "HIGH" $finding
        $findings += $finding
    }
    
} catch {
    Write-Host "Error checking Windows Update: $_" -ForegroundColor Red
}
#endregion

#region Summary
Write-Header "Security Check Summary"

if ($findings.Count -eq 0) {
    Write-Host "✓ No significant security issues found!" -ForegroundColor Green
    Write-Host "Review the detailed output above for system status." -ForegroundColor Cyan
} else {
    Write-Host "Found $($findings.Count) security issue(s) that need attention:" -ForegroundColor Yellow
    Write-Host ""
    foreach ($finding in $findings) {
        Write-Host "  • $finding" -ForegroundColor Yellow
    }
}

Write-Host "`nRecommended Actions:" -ForegroundColor Cyan
Write-Host "1. Review all findings above" -ForegroundColor White
Write-Host "2. Disable/remove unauthorized users and software" -ForegroundColor White
Write-Host "3. Ensure all security services are running" -ForegroundColor White
Write-Host "4. Install all available Windows updates" -ForegroundColor White
Write-Host "5. Review and complete forensics questions" -ForegroundColor White

if ($GenerateReport) {
    $reportFile = Join-Path $PSScriptRoot "SecurityCheck-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $findings | Out-File -FilePath $reportFile
    Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green
}

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
#endregion
