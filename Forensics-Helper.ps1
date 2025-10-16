#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Forensics Helper for CyberPatriot Competition
.DESCRIPTION
    Helps gather information for answering forensics questions.
    This script DOES NOT answer questions automatically - it provides data for manual analysis.
.NOTES
    Author: CyberPatriot Team
    Version: 1.0
#>

[CmdletBinding()]
param(
    [switch]$ExportReport
)

$ErrorActionPreference = "Continue"

function Write-Header {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host $Message -ForegroundColor Magenta
    Write-Host "========================================`n" -ForegroundColor Magenta
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

$reportContent = @()

Write-Header "CyberPatriot Forensics Helper"
Write-Info "Gathering forensics information..."

#region System Information
Write-Header "System Information"

try {
    $computerInfo = Get-ComputerInfo -Property CsName,OsName,OsVersion,OsInstallDate,OsLastBootUpTime -ErrorAction SilentlyContinue | Format-List | Out-String
    Write-Host $computerInfo
    $reportContent += "=== SYSTEM INFORMATION ===`n$computerInfo"
} catch {
    Write-Host "Error retrieving system information: $_" -ForegroundColor Red
}

#endregion

#region User Activity Timeline
Write-Header "User Account History"

try {
    $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires | Format-Table -AutoSize | Out-String
    Write-Host $users
    $reportContent += "`n=== USER ACCOUNTS ===`n$users"
} catch {
    Write-Host "Error retrieving user information: $_" -ForegroundColor Red
}

#endregion

#region Recent Security Events
Write-Header "Recent Security Events (Last 50)"

try {
    Write-Info "Checking for security events..."
    
    # User logon events
    Write-Host "`nSuccessful Logons (Event ID 4624):" -ForegroundColor Yellow
    $logons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 20 -ErrorAction SilentlyContinue |
              Select-Object TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}} |
              Format-Table -AutoSize | Out-String
    Write-Host $logons
    $reportContent += "`n=== RECENT SUCCESSFUL LOGONS ===`n$logons"
    
    # Failed logon events
    Write-Host "`nFailed Logons (Event ID 4625):" -ForegroundColor Yellow
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue |
                    Select-Object TimeCreated, Message |
                    Format-Table -AutoSize | Out-String
    Write-Host $failedLogons
    $reportContent += "`n=== FAILED LOGON ATTEMPTS ===`n$failedLogons"
    
    # User account changes
    Write-Host "`nUser Account Changes (Event ID 4720, 4722, 4724, 4726):" -ForegroundColor Yellow
    $accountChanges = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720,4722,4724,4726} -MaxEvents 20 -ErrorAction SilentlyContinue |
                      Select-Object TimeCreated, ID, Message |
                      Format-Table -AutoSize | Out-String
    Write-Host $accountChanges
    $reportContent += "`n=== USER ACCOUNT CHANGES ===`n$accountChanges"
    
} catch {
    Write-Host "Error retrieving security events: $_" -ForegroundColor Red
    Write-Host "Note: Security events may require specific audit policies to be enabled." -ForegroundColor Yellow
}

#endregion

#region Software Installation History
Write-Header "Software Installation History"

try {
    Write-Info "Checking installed programs..."
    
    $softwareList = @()
    $softwareList += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                     Where-Object { $_.DisplayName -ne $null } |
                     Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    
    $softwareList += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -ne $null } |
                     Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    
    $installedSoftware = $softwareList | Sort-Object InstallDate -Descending | Format-Table -AutoSize | Out-String
    Write-Host $installedSoftware
    $reportContent += "`n=== INSTALLED SOFTWARE ===`n$installedSoftware"
    
} catch {
    Write-Host "Error retrieving software information: $_" -ForegroundColor Red
}

#endregion

#region Recent Files
Write-Header "Recent Files by User"

try {
    Write-Info "Scanning user directories for recent files..."
    
    $userProfiles = Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue
    
    foreach ($profile in $userProfiles) {
        if ($profile.Name -notin @('Public', 'Default', 'Default User', 'All Users')) {
            Write-Host "`nRecent files for user: $($profile.Name)" -ForegroundColor Yellow
            
            # Search in common accessible directories only to avoid permission issues
            $searchPaths = @('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music')
            $recentFiles = @()
            
            foreach ($searchPath in $searchPaths) {
                $fullPath = Join-Path $profile.FullName $searchPath
                if (Test-Path $fullPath) {
                    $recentFiles += Get-ChildItem -Path $fullPath -Recurse -File -ErrorAction SilentlyContinue |
                                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Extension -in @('.txt','.doc','.docx','.pdf','.exe','.zip','.mp3','.mp4') }
                }
            }
            
            $filesList = $recentFiles | Select-Object FullName, LastWriteTime, Length |
                         Sort-Object LastWriteTime -Descending |
                         Select-Object -First 20 |
                         Format-Table -AutoSize | Out-String
            
            Write-Host $filesList
            $reportContent += "`n=== RECENT FILES FOR $($profile.Name) ===`n$filesList"
        }
    }
    
} catch {
    Write-Host "Error scanning user files: $_" -ForegroundColor Red
}

#endregion

#region Suspicious File Types
Write-Header "Searching for Prohibited File Types"

try {
    Write-Info "Searching for media files (MP3, MP4, AVI, etc.)..."
    
    $mediaExtensions = @('*.mp3', '*.mp4', '*.avi', '*.mkv', '*.mov', '*.wmv', '*.flv', '*.wav', '*.flac')
    
    $mediaFiles = Get-ChildItem C:\Users -Recurse -Include $mediaExtensions -File -ErrorAction SilentlyContinue |
                  Select-Object FullName, Length, LastWriteTime
    
    if ($mediaFiles.Count -gt 0) {
        Write-Host "Found $($mediaFiles.Count) media files:" -ForegroundColor Yellow
        $mediaList = $mediaFiles | Format-Table -AutoSize | Out-String
        Write-Host $mediaList
        $reportContent += "`n=== MEDIA FILES FOUND ===`n$mediaList"
    } else {
        Write-Host "No media files found" -ForegroundColor Green
        $reportContent += "`n=== MEDIA FILES FOUND ===`nNo media files found"
    }
    
} catch {
    Write-Host "Error searching for media files: $_" -ForegroundColor Red
}

#endregion

#region Browser History Locations
Write-Header "Browser History Information"

Write-Info "Browser history locations (manual review required):"
Write-Host "`nChrome History:"
Write-Host "  %LOCALAPPDATA%\Google\Chrome\User Data\Default\History" -ForegroundColor Cyan
Write-Host "`nFirefox History:"
Write-Host "  %APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite" -ForegroundColor Cyan
Write-Host "`nEdge History:"
Write-Host "  %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History" -ForegroundColor Cyan
Write-Host "`nInternet Explorer History:"
Write-Host "  %LOCALAPPDATA%\Microsoft\Windows\History" -ForegroundColor Cyan

$browserInfo = @"

=== BROWSER HISTORY LOCATIONS ===
Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
Firefox: %APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite
Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History
Internet Explorer: %LOCALAPPDATA%\Microsoft\Windows\History
"@

$reportContent += $browserInfo

#endregion

#region Scheduled Tasks Analysis
Write-Header "Scheduled Tasks"

try {
    Write-Info "Listing scheduled tasks..."
    
    $tasks = Get-ScheduledTask | 
            Where-Object { $_.TaskPath -notmatch "^\\Microsoft\\" } |
            Select-Object TaskName, TaskPath, State, @{Name='LastRunTime';Expression={$_.LastRunTime}}, @{Name='NextRunTime';Expression={$_.NextRunTime}} |
            Format-Table -AutoSize | Out-String
    
    Write-Host $tasks
    $reportContent += "`n=== NON-MICROSOFT SCHEDULED TASKS ===`n$tasks"
    
} catch {
    Write-Host "Error retrieving scheduled tasks: $_" -ForegroundColor Red
}

#endregion

#region Network Connections
Write-Header "Active Network Connections"

try {
    Write-Info "Checking active connections..."
    
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
                  Format-Table -AutoSize | Out-String
    
    Write-Host $connections
    $reportContent += "`n=== ACTIVE NETWORK CONNECTIONS ===`n$connections"
    
} catch {
    Write-Host "Error retrieving network connections: $_" -ForegroundColor Red
}

#endregion

#region Startup Programs
Write-Header "Startup Programs"

try {
    Write-Info "Checking startup programs..."
    
    # Registry startup locations
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Write-Host "`n$path :" -ForegroundColor Yellow
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
            ForEach-Object { Write-Host "  $($_.Name): $($_.Value)" }
            
            $startupItems = $items.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
                           Select-Object Name, Value | Format-List | Out-String
            $reportContent += "`n=== STARTUP ITEMS: $path ===`n$startupItems"
        }
    }
    
    # Startup folder
    $startupFolder = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    if (Test-Path $startupFolder) {
        Write-Host "`nStartup Folder Items:" -ForegroundColor Yellow
        $folderItems = Get-ChildItem $startupFolder | Select-Object Name, FullName | Format-Table -AutoSize | Out-String
        Write-Host $folderItems
        $reportContent += "`n=== STARTUP FOLDER ITEMS ===`n$folderItems"
    }
    
} catch {
    Write-Host "Error retrieving startup programs: $_" -ForegroundColor Red
}

#endregion

#region Useful Commands for Manual Investigation
Write-Header "Useful Commands for Further Investigation"

$commands = @"

Event Viewer Commands:
  eventvwr.msc                                    - Open Event Viewer GUI
  Get-WinEvent -ListLog *                         - List all event logs
  Get-WinEvent -LogName Security -MaxEvents 100   - View security events

User and Group Commands:
  net user                                        - List all local users
  net user [username]                             - View user details
  net localgroup administrators                   - List administrators
  whoami /priv                                    - View current privileges

File Search Commands:
  Get-ChildItem C:\ -Recurse -Include *.exe -ErrorAction SilentlyContinue
  Get-ChildItem C:\Users -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }

Registry Investigation:
  regedit                                         - Open Registry Editor
  reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

Network Investigation:
  netstat -ano                                    - View all connections with process IDs
  Get-NetTCPConnection                            - View TCP connections
  arp -a                                          - View ARP cache

Service Investigation:
  Get-Service                                     - List all services
  Get-Service | Where-Object {$_.Status -eq 'Running'}

Process Investigation:
  Get-Process                                     - List running processes
  tasklist                                        - Alternative to list processes
  
"@

Write-Host $commands -ForegroundColor Cyan
$reportContent += "`n=== USEFUL COMMANDS ===`n$commands"

#endregion

#region Export Report
if ($ExportReport) {
    $reportFile = Join-Path $PSScriptRoot "Forensics-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $reportContent -join "`n" | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[SUCCESS] Forensics report exported to: $reportFile" -ForegroundColor Green
}
#endregion

Write-Header "Forensics Helper Complete"
Write-Host "Use the information above to answer forensics questions." -ForegroundColor Cyan
Write-Host "Remember: You must manually analyze the data and answer questions." -ForegroundColor Yellow
Write-Host "`nTip: Run with -ExportReport to save this information to a file" -ForegroundColor Cyan

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
