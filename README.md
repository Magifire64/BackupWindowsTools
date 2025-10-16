# CyberPatriot Windows Auto-Hardening Tool

An automated security hardening tool for the Windows CyberPatriot competition that handles everything except forensics questions.

## Features

This tool automates the following security tasks:

- ✅ **User Account Management** - Checks for unauthorized users and disables Guest account
- ✅ **Password Policy Configuration** - Sets strong password requirements and lockout policies
- ✅ **Windows Update** - Enables Windows Update service
- ✅ **Firewall Configuration** - Enables Windows Firewall for all profiles
- ✅ **Service Management** - Disables potentially vulnerable services
- ✅ **Audit Policy** - Configures comprehensive audit logging
- ✅ **Registry Security** - Applies security-focused registry settings
- ✅ **File Permissions** - Checks critical file permissions
- ✅ **Malware Scanning** - Runs Windows Defender quick scan

## Requirements

- Windows 10/11 or Windows Server
- PowerShell 5.1 or later
- Administrator privileges

## Usage

### Basic Usage

1. **Right-click** on PowerShell and select **"Run as Administrator"**
2. Navigate to the script directory:
   ```powershell
   cd C:\path\to\BackupWindowsTools
   ```
3. Run the script:
   ```powershell
   .\CyberPatriot-AutoHarden.ps1
   ```

### Advanced Usage

You can skip specific security checks using parameters:

```powershell
# Skip specific modules
.\CyberPatriot-AutoHarden.ps1 -SkipUserManagement -SkipMalwareScan

# Run only password policy and firewall configuration
.\CyberPatriot-AutoHarden.ps1 -SkipUserManagement -SkipWindowsUpdate -SkipServices -SkipAuditPolicy -SkipRegistry -SkipFilePermissions -SkipMalwareScan
```

### Available Parameters

- `-SkipUserManagement` - Skip user account checks
- `-SkipPasswordPolicy` - Skip password policy configuration
- `-SkipWindowsUpdate` - Skip Windows Update configuration
- `-SkipFirewall` - Skip firewall configuration
- `-SkipServices` - Skip service management
- `-SkipAuditPolicy` - Skip audit policy configuration
- `-SkipRegistry` - Skip registry security settings
- `-SkipFilePermissions` - Skip file permission checks
- `-SkipMalwareScan` - Skip malware scanning

## What This Tool Does

### User Account Management
- Lists all local user accounts
- Disables Guest account
- Identifies potentially unauthorized users

### Password Policy
- Sets maximum password age to 90 days
- Sets minimum password age to 1 day
- Sets minimum password length to 12 characters
- Enables password history (24 passwords)
- Configures account lockout after 5 failed attempts
- Sets lockout duration to 30 minutes

### Windows Update
- Enables Windows Update service
- Sets service to automatic startup

### Firewall Configuration
- Enables Windows Firewall for Domain, Public, and Private profiles
- Sets default inbound action to Block
- Sets default outbound action to Allow

### Service Management
Disables potentially vulnerable services:
- Remote Registry
- Remote Access
- Telnet Server
- SSDP Discovery
- UPnP Device Host

### Audit Policy
Enables auditing for:
- Account Logon events
- Account Management
- Logon/Logoff events
- Policy Changes
- Privilege Use
- System events

### Registry Security
- Restricts anonymous access
- Enables ASLR (Address Space Layout Randomization)
- Disables AutoRun for all drives
- Enables Windows Defender

### Malware Scanning
- Updates Windows Defender definitions
- Initiates a quick scan in the background

## Important Manual Tasks

After running this script, you must still complete these tasks manually:

1. ✋ **Review and remove unauthorized user accounts**
2. ✋ **Set strong passwords for all authorized users**
3. ✋ **Install all available Windows Updates**
4. ✋ **Review and uninstall unauthorized software**
5. ✋ **Complete all forensics questions** (this tool does NOT handle forensics)
6. ✋ **Review Local Security Policy settings**
7. ✋ **Check for suspicious scheduled tasks**
8. ✋ **Review network shares and remove unauthorized ones**

## Logs

The script creates a detailed log file in the same directory with the format:
```
CyberPatriot-Log-YYYYMMDD-HHMMSS.txt
```

This log contains timestamps for all actions taken and any errors encountered.

## Safety

This script is designed to be safe and non-destructive:
- It does not delete user accounts automatically
- It does not uninstall software
- It does not modify system files
- All changes can be reviewed in the log file
- Most changes can be reversed through Windows settings

## Troubleshooting

### "Script cannot be loaded because running scripts is disabled"

Run this command in PowerShell as Administrator:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "Access Denied" errors

Ensure you are running PowerShell as Administrator.

### Script completes but changes not applied

Check the log file for specific error messages. Some policies may require additional configuration through Group Policy Editor (gpedit.msc).

## CyberPatriot Competition Tips

1. **Read the README first** - The competition README contains specific requirements
2. **Answer forensics questions** - This tool does NOT handle forensics
3. **Keep the scoring report open** - Watch for points as you make changes
4. **Document your changes** - Keep notes of what you've done
5. **Test carefully** - Some changes may break authorized services
6. **Time management** - Use this tool to save time on common tasks

## Disclaimer

This tool is designed for educational purposes and CyberPatriot competition use only. Always understand the changes being made and ensure they comply with your specific competition requirements. The tool performs security hardening but does not guarantee a perfect score or complete system security.

## License

This project is provided as-is for educational purposes.

## Contributing

Contributions are welcome! Please ensure any changes maintain compatibility with CyberPatriot competition requirements.