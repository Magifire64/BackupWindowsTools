# CyberPatriot Windows Security Checklist

## Pre-Competition Setup
- [ ] Read the Competition README thoroughly
- [ ] Note all authorized users and their roles
- [ ] Note all authorized software and services
- [ ] Create VM snapshot (if applicable)
- [ ] Verify PowerShell execution policy allows scripts

## Automated Hardening (Run Scripts)
- [ ] Run `CyberPatriot-AutoHarden.ps1` as Administrator
- [ ] Review the log file for any errors
- [ ] Run `Advanced-SecurityCheck.ps1` to identify issues
- [ ] Save/screenshot the security check results

## User Account Security
- [ ] Disable Guest account
- [ ] Disable or remove unauthorized user accounts
- [ ] Verify only authorized users are in Administrators group
- [ ] Remove unauthorized users from other privileged groups
- [ ] Ensure all users have strong passwords (12+ characters)
- [ ] Check for accounts with blank passwords
- [ ] Verify no users have "Password never expires" set
- [ ] Check for duplicate Administrator accounts

## Password Policy
- [ ] Set minimum password length to 12+ characters
- [ ] Set maximum password age to 90 days
- [ ] Set minimum password age to 1 day
- [ ] Enable password history (24 passwords)
- [ ] Enable password complexity requirements
- [ ] Configure account lockout threshold (5 attempts)
- [ ] Set account lockout duration (30 minutes)

## Windows Updates
- [ ] Enable Windows Update service
- [ ] Check for and install all available updates
- [ ] Verify automatic updates are enabled
- [ ] Restart system if required by updates

## Firewall Configuration
- [ ] Enable Windows Firewall for all profiles (Domain, Public, Private)
- [ ] Set default inbound action to Block
- [ ] Set default outbound action to Allow
- [ ] Review firewall rules for unauthorized entries
- [ ] Remove unnecessary inbound rules

## Service Management
- [ ] Disable Remote Registry service
- [ ] Disable Telnet service (if present)
- [ ] Disable Remote Access service (if not authorized)
- [ ] Disable SSDP Discovery service
- [ ] Disable UPnP Device Host service
- [ ] Review all running services for unauthorized ones
- [ ] Check service accounts for proper permissions

## Software Management
- [ ] List all installed programs
- [ ] Uninstall unauthorized software
- [ ] Remove hacking tools (Wireshark, Nmap, Metasploit, etc.)
- [ ] Remove P2P/file sharing software (Torrents, LimeWire, etc.)
- [ ] Remove unauthorized remote access tools (VNC, TeamViewer, etc.)
- [ ] Remove unauthorized games
- [ ] Update authorized software to latest versions

## Security Policies (secpol.msc)
- [ ] Configure audit policies for:
  - [ ] Account Logon Events
  - [ ] Account Management
  - [ ] Logon/Logoff Events
  - [ ] Policy Changes
  - [ ] Privilege Use
  - [ ] System Events
- [ ] Review User Rights Assignments
- [ ] Check Security Options settings
- [ ] Verify Event Log settings

## Windows Features
- [ ] Disable Telnet Client (if present)
- [ ] Disable Telnet Server (if present)
- [ ] Disable TFTP Client
- [ ] Disable Simple TCP/IP Services
- [ ] Remove unnecessary Windows Features

## Remote Access Settings
- [ ] Disable Remote Desktop (unless specifically authorized)
- [ ] Disable Remote Assistance
- [ ] Check for unauthorized VPN configurations
- [ ] Review remote management settings

## Windows Defender / Antivirus
- [ ] Ensure Windows Defender is enabled
- [ ] Update Windows Defender definitions
- [ ] Run full system scan
- [ ] Enable real-time protection
- [ ] Configure scan schedule
- [ ] Check for malware detections

## Registry Security
- [ ] Disable AutoRun for all drives
- [ ] Restrict anonymous access to SAM and shares
- [ ] Enable ASLR (Address Space Layout Randomization)
- [ ] Review startup programs in registry
- [ ] Check for suspicious registry entries

## File System Security
- [ ] Check for prohibited media files (MP3, MP4, AVI, etc.)
- [ ] Review file permissions on critical directories
- [ ] Check for world-writable files
- [ ] Look for suspicious executables
- [ ] Check desktop and downloads folders for all users
- [ ] Review hidden files and folders

## Network Security
- [ ] Review network shares and remove unauthorized ones
- [ ] Disable NetBIOS over TCP/IP (if not needed)
- [ ] Configure DNS settings properly
- [ ] Check hosts file for suspicious entries
- [ ] Review network adapter settings

## Scheduled Tasks
- [ ] Open Task Scheduler (taskschd.msc)
- [ ] Review all scheduled tasks
- [ ] Disable or delete unauthorized tasks
- [ ] Check task permissions and execution accounts
- [ ] Look for tasks that run suspicious scripts

## Browser Security
- [ ] Clear browser history and cache
- [ ] Remove suspicious browser extensions
- [ ] Configure secure browser settings
- [ ] Check browser default security settings
- [ ] Review saved passwords (if applicable)

## System Configuration
- [ ] Review startup programs (msconfig.exe)
- [ ] Disable unnecessary startup items
- [ ] Check system boot configuration
- [ ] Review system restore settings
- [ ] Check Event Viewer for security events

## Group Policy (gpedit.msc)
- [ ] Configure Computer Configuration → Windows Settings → Security Settings
- [ ] Review Local Policies → Security Options
- [ ] Check software restriction policies
- [ ] Review administrative templates
- [ ] Verify applied group policies

## Forensics Questions (Manual)
- [ ] Read all forensics questions carefully
- [ ] Use Event Viewer to find security events
- [ ] Check user documents and browser history
- [ ] Review installed programs list with dates
- [ ] Check recent files and file modifications
- [ ] Use Task Manager history if available
- [ ] Check registry for evidence
- [ ] Answer all forensics questions

## Final Verification
- [ ] Re-run `Advanced-SecurityCheck.ps1`
- [ ] Check Scoring Report for points
- [ ] Review Event Viewer for new errors
- [ ] Test system functionality
- [ ] Verify authorized services still work
- [ ] Check that authorized users can log in
- [ ] Review all log files
- [ ] Document all changes made

## Bonus/Advanced (If Time Permits)
- [ ] Configure BitLocker (if scenario requires)
- [ ] Enable Secure Boot in BIOS
- [ ] Configure Windows Credential Guard
- [ ] Set up AppLocker policies
- [ ] Configure advanced audit policies
- [ ] Review TPM settings
- [ ] Check for rootkits with advanced tools
- [ ] Configure User Account Control (UAC)
- [ ] Review printer settings and drivers
- [ ] Check for unauthorized certificates

## Before Submitting
- [ ] Final scoring report check
- [ ] Ensure all forensics questions answered
- [ ] Verify no authorized services broken
- [ ] Review competition README one more time
- [ ] Check time remaining
- [ ] Make final optimization changes

---

## Notes Section
Use this space to track specific competition requirements:

**Authorized Users:**
- 

**Authorized Software:**
- 

**Authorized Services:**
- 

**Special Requirements:**
- 

**Points Progress:**
- Starting Points: ___
- Current Points: ___
- Target Points: ___

---

## Common Scoring Items (Prioritize These!)

### High Point Value (Usually)
- ✅ Disable Guest account
- ✅ Set strong password policy
- ✅ Enable Windows Firewall
- ✅ Remove unauthorized users
- ✅ Install Windows updates
- ✅ Answer forensics questions correctly

### Medium Point Value
- ✅ Disable vulnerable services
- ✅ Remove unauthorized software
- ✅ Configure audit policies
- ✅ Enable Windows Defender
- ✅ Set account lockout policy

### Variable Point Value
- ✅ Remove prohibited files
- ✅ Configure proper file permissions
- ✅ Remove unauthorized scheduled tasks
- ✅ Secure registry settings
- ✅ Remove unauthorized shares

---

**Remember:** Quality over quantity! It's better to do fewer tasks correctly than to rush through everything. Always verify changes don't break authorized functionality!
