# CyberPatriot Tools Overview

This repository contains a complete suite of automation and helper tools for the Windows CyberPatriot competition.

## 🚀 Quick Start

**For Competition Day:**

1. **Run the Auto-Hardening Script** (5 minutes)
   - Double-click `Run-AutoHarden.bat` OR
   - Run PowerShell as Administrator: `.\CyberPatriot-AutoHarden.ps1`

2. **Run the Security Check** (3 minutes)
   - Double-click `Run-SecurityCheck.bat` OR
   - Run PowerShell as Administrator: `.\Advanced-SecurityCheck.ps1`

3. **Use Forensics Helper** (as needed)
   - Double-click `Run-ForensicsHelper.bat` OR
   - Run PowerShell as Administrator: `.\Forensics-Helper.ps1`

4. **Follow the Checklist**
   - Open `CHECKLIST.md` and work through items systematically

## 📁 Files in This Repository

### Main Scripts

| File | Purpose | When to Use |
|------|---------|-------------|
| **CyberPatriot-AutoHarden.ps1** | Automates security hardening | First thing on competition day |
| **Advanced-SecurityCheck.ps1** | Identifies security issues | After auto-hardening, and periodically |
| **Forensics-Helper.ps1** | Gathers forensics data | When answering forensics questions |

### Batch Launchers (Easy to Use)

| File | Purpose |
|------|---------|
| **Run-AutoHarden.bat** | Launches auto-hardening script |
| **Run-SecurityCheck.bat** | Launches security check script |
| **Run-ForensicsHelper.bat** | Launches forensics helper |

### Documentation

| File | Contents |
|------|----------|
| **README.md** | Main documentation and usage guide |
| **QUICKSTART.md** | Step-by-step competition guide |
| **CHECKLIST.md** | Complete security checklist |
| **FORENSICS-GUIDE.md** | Detailed forensics investigation guide |
| **TOOLS-OVERVIEW.md** | This file - overview of all tools |

## 🔧 Tool Details

### 1. CyberPatriot-AutoHarden.ps1

**What It Does:**
- ✅ Configures strong password policies
- ✅ Enables Windows Firewall for all profiles
- ✅ Disables vulnerable services (Remote Registry, Telnet, etc.)
- ✅ Enables comprehensive audit logging
- ✅ Applies security registry settings
- ✅ Disables AutoRun for all drives
- ✅ Enables Windows Defender
- ✅ Starts malware quick scan
- ✅ Checks user accounts and disables Guest

**Time Required:** ~5 minutes

**Parameters:**
```powershell
# Skip specific modules
.\CyberPatriot-AutoHarden.ps1 -SkipUserManagement
.\CyberPatriot-AutoHarden.ps1 -SkipPasswordPolicy
.\CyberPatriot-AutoHarden.ps1 -SkipWindowsUpdate
.\CyberPatriot-AutoHarden.ps1 -SkipFirewall
.\CyberPatriot-AutoHarden.ps1 -SkipServices
.\CyberPatriot-AutoHarden.ps1 -SkipAuditPolicy
.\CyberPatriot-AutoHarden.ps1 -SkipRegistry
.\CyberPatriot-AutoHarden.ps1 -SkipFilePermissions
.\CyberPatriot-AutoHarden.ps1 -SkipMalwareScan
```

**Output:**
- Creates a log file: `CyberPatriot-Log-YYYYMMDD-HHMMSS.txt`
- Color-coded console output (green = success, red = error, yellow = warning)
- List of manual tasks still required

### 2. Advanced-SecurityCheck.ps1

**What It Does:**
- 🔍 Lists all user accounts and identifies issues
- 🔍 Checks for multiple administrators
- 🔍 Verifies password policy settings
- 🔍 Scans for potentially unauthorized software
- 🔍 Checks vulnerable services status
- 🔍 Verifies firewall configuration
- 🔍 Lists suspicious scheduled tasks
- 🔍 Identifies custom network shares
- 🔍 Checks Windows Defender status
- 🔍 Verifies Windows Update service

**Time Required:** ~3 minutes

**Parameters:**
```powershell
# Generate a report file
.\Advanced-SecurityCheck.ps1 -GenerateReport
```

**Output:**
- Color-coded findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Summary of issues found
- Recommended actions
- Optional report file: `SecurityCheck-Report-YYYYMMDD-HHMMSS.txt`

### 3. Forensics-Helper.ps1

**What It Does:**
- 📊 Gathers system information
- 📊 Shows user account history and last logons
- 📊 Displays recent security events (logons, account changes)
- 📊 Lists software with installation dates
- 📊 Shows recent files by user
- 📊 Searches for prohibited media files
- 📊 Lists browser history locations
- 📊 Shows non-Microsoft scheduled tasks
- 📊 Displays active network connections
- 📊 Lists startup programs
- 📊 Provides useful investigation commands

**Time Required:** ~2 minutes to run, 10-20 minutes to analyze

**Parameters:**
```powershell
# Export findings to a file
.\Forensics-Helper.ps1 -ExportReport
```

**Output:**
- Comprehensive forensics data display
- Optional report file: `Forensics-Report-YYYYMMDD-HHMMSS.txt`
- Reference commands for further investigation

**Important:** This tool does NOT answer forensics questions automatically - it provides data for manual analysis.

## 📋 Documentation Guide

### When to Use Each Document:

**Before Competition:**
- Read **README.md** to understand all tools
- Review **QUICKSTART.md** for the competition workflow
- Print **CHECKLIST.md** to bring with you

**During Competition:**
- Follow **QUICKSTART.md** step-by-step
- Use **CHECKLIST.md** to track progress
- Reference **FORENSICS-GUIDE.md** when answering forensics questions
- Keep **TOOLS-OVERVIEW.md** (this file) open for quick reference

## 🎯 Typical Competition Workflow

### Phase 1: Initial Setup (5 minutes)
1. Read competition README on Desktop
2. Note authorized users, software, and services
3. Take VM snapshot if available

### Phase 2: Automated Hardening (10 minutes)
1. Run `CyberPatriot-AutoHarden.ps1`
2. Review log file for any errors
3. Run `Advanced-SecurityCheck.ps1`
4. Note findings for manual remediation

### Phase 3: Manual Security Tasks (60-90 minutes)
1. User account management
   - Remove/disable unauthorized users
   - Set strong passwords
   - Verify Administrator group members

2. Software management
   - Uninstall unauthorized software
   - Remove hacking tools and P2P clients
   - Check for prohibited media files

3. Windows Updates
   - Install all available updates
   - This takes the longest - start early!

4. Additional hardening
   - Review and apply findings from security check
   - Check scheduled tasks
   - Review network shares
   - Verify security policies

### Phase 4: Forensics Questions (20-30 minutes)
1. Run `Forensics-Helper.ps1 -ExportReport`
2. Read each forensics question carefully
3. Use Event Viewer and file system to investigate
4. Verify answers before submitting

### Phase 5: Final Verification (10 minutes)
1. Re-run `Advanced-SecurityCheck.ps1`
2. Check scoring report
3. Review checklist for missed items
4. Test system functionality

## 🔐 What These Tools DON'T Do

These tools are designed to save time, but you still need to:

❌ **Manually remove unauthorized user accounts**
- The script identifies them but doesn't remove them (to prevent accidents)

❌ **Manually set user passwords**
- Password changes must be done manually for each user

❌ **Manually uninstall unauthorized software**
- You must review and uninstall software yourself

❌ **Manually install Windows Updates**
- The script enables updates but you must install them through Settings

❌ **Manually answer forensics questions**
- Forensics require investigation and analysis - cannot be automated

❌ **Manually review and edit the README**
- Always read the competition README for specific requirements

❌ **Manually remove prohibited files**
- The tool identifies them but you must delete them

❌ **Manually configure authorized exceptions**
- If something needs to stay enabled, you configure that yourself

## ⚠️ Important Warnings

1. **Always read the competition README first!**
   - Some users, services, or software may be authorized
   - Breaking authorized functionality loses points

2. **Test in a safe environment**
   - These scripts make system changes
   - Practice before competition day

3. **Review logs**
   - Check log files for any errors
   - Some changes might not apply on certain systems

4. **Don't rely 100% on automation**
   - These tools help but don't guarantee all points
   - Manual verification is essential

5. **Time management**
   - Don't spend all time on one area
   - Forensics questions are worth significant points

## 🏆 Point Optimization Strategy

### Quick Wins (Do First) - ~50% of points
- Disable Guest account
- Set password policy
- Enable Windows Firewall
- Remove obvious unauthorized users
- Enable Windows Defender

### Medium Priority - ~30% of points
- Disable vulnerable services
- Configure audit policies
- Remove unauthorized software
- Install Windows Updates (start early!)
- Answer forensics questions

### Advanced (If Time Permits) - ~20% of points
- Advanced registry settings
- File permission hardening
- Detailed service review
- Network share configuration
- Advanced audit policies

## 📞 Troubleshooting

### "Script won't run" / "Execution Policy" error
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "Access Denied" errors
- Ensure you're running PowerShell as Administrator
- Right-click PowerShell → "Run as Administrator"

### "No points after running script"
- Check the scoring report for specific requirements
- Review log file for errors
- Some changes require restart
- Verify changes actually applied

### Scripts complete but system broken
- Review log files for what changed
- Check Event Viewer for errors
- Some legitimate services may have been disabled
- Re-enable authorized services per README

## 🤝 Contributing

Found a bug? Have a suggestion? Contributions are welcome!

Remember: These tools should help CyberPatriot competitors learn and succeed, not just automate everything without understanding.

## 📚 Additional Resources

### Official CyberPatriot Resources
- CyberPatriot Website: https://www.uscyberpatriot.org/
- Competition materials and practice images
- Training modules and documentation

### Windows Security Documentation
- Microsoft Security Baselines
- Windows Security Best Practices
- PowerShell Documentation

### Practice Resources
- CyberPatriot practice images
- Online Windows security tutorials
- Capture the Flag (CTF) challenges

## 📝 License

These tools are provided for educational purposes for CyberPatriot competition use.

---

**Good luck with your competition! 🎯🔒**

Remember: The goal is to learn cybersecurity skills while securing systems. Understanding what these scripts do is more important than just running them!
