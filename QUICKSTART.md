# CyberPatriot Quick Start Guide

## Before You Begin

1. **Read the Competition README** - Located on the Desktop, contains specific requirements
2. **Take a Snapshot** - Create a VM snapshot before making changes (if using virtual machine)
3. **Note Authorized Users** - Document which users should exist on the system

## Step 1: Run the Auto-Hardening Script (5 minutes)

```powershell
# Open PowerShell as Administrator
# Navigate to the script directory
cd C:\path\to\BackupWindowsTools

# Run the main hardening script
.\CyberPatriot-AutoHarden.ps1
```

This will automatically:
- Configure password policies
- Enable Windows Firewall
- Disable vulnerable services
- Enable audit logging
- Apply security registry settings
- Start malware scanning

## Step 2: Run Advanced Security Check (3 minutes)

```powershell
# Still in PowerShell as Administrator
.\Advanced-SecurityCheck.ps1
```

This will identify:
- Unauthorized users
- Suspicious software
- Running vulnerable services
- Network shares
- Scheduled tasks
- Security misconfigurations

## Step 3: Manual Security Tasks (30-60 minutes)

### User Account Management
```powershell
# View all users
Get-LocalUser

# Disable unauthorized user
Disable-LocalUser -Name "username"

# Remove user from Administrators group
Remove-LocalGroupMember -Group "Administrators" -Member "username"

# Change user password
Set-LocalUser -Name "username" -Password (Read-Host -AsSecureString "Enter Password")
```

### Update Windows
1. Open **Settings** → **Update & Security** → **Windows Update**
2. Click **Check for updates**
3. Install all available updates

### Remove Unauthorized Software
```powershell
# List installed programs
Get-WmiObject -Class Win32_Product | Select-Object Name, Version

# OR open Settings → Apps → Apps & features
```

### Check for Media Files (Common Violation)
```powershell
# Search for common media files
Get-ChildItem C:\Users -Recurse -Include *.mp3,*.mp4,*.avi,*.mkv,*.mov -ErrorAction SilentlyContinue
```

### Disable Unnecessary Features
```powershell
# Open "Turn Windows features on or off"
optionalfeatures.exe

# Disable:
# - Telnet Client
# - Telnet Server
# - TFTP Client
# - Simple TCPIP Services
```

### Check Remote Desktop
```powershell
# Disable Remote Desktop (unless specifically authorized)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
```

### Review Group Policy
```powershell
# Open Local Security Policy
secpol.msc

# Check:
# - Password Policy
# - Account Lockout Policy
# - Audit Policy
# - User Rights Assignment
```

## Step 4: Answer Forensics Questions (10-20 minutes)

Forensics questions typically ask:
- What unauthorized software was installed?
- Which user performed a specific action?
- What suspicious files exist?
- When was a specific change made?

**Tools for Forensics:**
- Event Viewer (`eventvwr.msc`)
- Recent files in user directories
- Browser history
- Registry Editor (`regedit`)
- Task Scheduler (`taskschd.msc`)

## Step 5: Verification (5 minutes)

### Check Scoring Report
- Open the Scoring Report (usually on Desktop)
- Verify points are being awarded
- Note which items still need attention

### Run Security Check Again
```powershell
.\Advanced-SecurityCheck.ps1
```

### Review Event Viewer for Issues
```powershell
eventvwr.msc
# Check Windows Logs → Security
# Look for failed login attempts, policy changes
```

## Common Point Getters

### Quick Wins (Do These First!)
- ✅ Disable Guest account
- ✅ Enable Windows Firewall
- ✅ Set strong password policy
- ✅ Enable Windows Defender
- ✅ Disable unnecessary services
- ✅ Remove unauthorized users
- ✅ Update Windows

### Medium Difficulty
- ✅ Configure audit policies
- ✅ Remove unauthorized software
- ✅ Configure account lockout
- ✅ Disable Remote Desktop (if not needed)
- ✅ Remove unauthorized scheduled tasks
- ✅ Secure file permissions

### Takes More Time
- ✅ Install all Windows updates
- ✅ Set passwords for all users
- ✅ Review and answer forensics questions
- ✅ Check for prohibited files (media, hacking tools)
- ✅ Review Group Policy settings

## Troubleshooting

### Script Won't Run
```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### No Points After Changes
- Check if changes actually applied (use Advanced-SecurityCheck.ps1)
- Restart scoring service if available
- Ensure you're making the right changes for your scenario

### System Breaks After Changes
- Review the log file: `CyberPatriot-Log-*.txt`
- Check Event Viewer for errors
- Revert specific changes if needed

## Time Management

**Total Time Available:** Usually 4-6 hours

**Suggested Timeline:**
- 0-15 min: Read README, plan approach
- 15-20 min: Run auto-hardening scripts
- 20-40 min: User management and passwords
- 40-60 min: Software review and removal
- 60-90 min: Windows updates
- 90-110 min: Forensics questions
- 110-180 min: Advanced security configurations
- 180-240+ min: Final checks and optimization

## Important Commands Reference

```powershell
# User Management
Get-LocalUser                           # List users
Get-LocalGroupMember -Group "Administrators"  # List admins
Disable-LocalUser -Name "user"          # Disable user
Remove-LocalUser -Name "user"           # Delete user

# Services
Get-Service                             # List all services
Stop-Service -Name "servicename"        # Stop service
Set-Service -Name "servicename" -StartupType Disabled  # Disable service

# Firewall
Get-NetFirewallProfile                  # Check firewall status
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Windows Defender
Get-MpComputerStatus                    # Check Defender status
Update-MpSignature                      # Update definitions
Start-MpScan -ScanType QuickScan        # Start scan

# Updates
Get-Service -Name wuauserv              # Check update service
Start-Service -Name wuauserv            # Start update service

# Password Policy
net accounts                            # View current policy
net accounts /maxpwage:90               # Set max password age

# System Information
systeminfo                              # System details
Get-ComputerInfo                        # Detailed system info
```

## Best Practices

1. **Document Everything** - Keep notes of changes made
2. **Check Scoring Often** - Verify changes are worth points
3. **Don't Break Things** - Read README for authorized services/users
4. **Work Systematically** - Complete one area before moving to next
5. **Use Your Team** - Divide tasks among team members
6. **Save Time for Forensics** - Don't spend all time on hardening
7. **Test Changes** - Make sure system still works properly

## Resources

- Competition README (Desktop)
- Scoring Report (Desktop)
- Log files from scripts
- Event Viewer (eventvwr.msc)
- Windows Security Center
- Microsoft Documentation

## Good Luck! 🎯

Remember: The goal is to make the system secure while maintaining functionality for authorized users and services. Always read the scenario README carefully!
