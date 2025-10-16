# Forensics Questions Guide for CyberPatriot

## Overview

Forensics questions test your ability to investigate what happened on the system. These questions are worth significant points and **cannot be automated** - you must analyze evidence and answer manually.

## Common Forensics Question Types

### 1. "What unauthorized software was installed?"

**How to Find:**
- Use `Forensics-Helper.ps1` to list installed software
- Look at installation dates and publishers
- Check Programs and Features in Control Panel

**PowerShell Command:**
```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, Publisher, InstallDate |
Sort-Object InstallDate -Descending
```

**Common Unauthorized Software:**
- Hacking tools (Wireshark, Nmap, Metasploit, Burp Suite)
- P2P/Torrents (BitTorrent, uTorrent, LimeWire)
- Remote access (VNC, TeamViewer without authorization)
- Games (if not authorized)
- Media players with codec issues

### 2. "Which user did [malicious action]?"

**How to Find:**
- Check Event Viewer (eventvwr.msc)
- Look at Security logs for specific events
- Check file ownership and modification times
- Review user account last logon times

**Useful Event IDs:**
- 4624: Successful logon
- 4625: Failed logon attempt
- 4720: User account created
- 4722: User account enabled
- 4724: Password reset attempted
- 4726: User account deleted
- 4732: User added to security group

**PowerShell Command:**
```powershell
# Check recent security events
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4720,4722,4724,4726,4732} -MaxEvents 50

# Check file ownership
Get-Acl "C:\Path\To\File" | Select-Object Owner
```

### 3. "What suspicious files were found in [location]?"

**How to Find:**
- Navigate to the specified location
- Look for files with suspicious names
- Check file properties (right-click → Properties)
- Look at file timestamps and sizes
- Check for hidden files

**PowerShell Commands:**
```powershell
# Show hidden files in a directory
Get-ChildItem "C:\Path" -Force

# Find recently modified files
Get-ChildItem "C:\Path" -Recurse | 
Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

# Find executable files
Get-ChildItem "C:\Path" -Recurse -Include *.exe, *.bat, *.ps1
```

**Common Suspicious File Locations:**
- Desktop
- Downloads folder
- Temp folders (C:\Temp, C:\Windows\Temp, %TEMP%)
- Root of C: drive
- User AppData folders

### 4. "What media files violate policy?"

**How to Find:**
- Use `Forensics-Helper.ps1` which searches for media files
- Search user directories for audio/video files
- Common extensions: .mp3, .mp4, .avi, .mkv, .mov, .wav

**PowerShell Command:**
```powershell
Get-ChildItem C:\Users -Recurse -Include *.mp3,*.mp4,*.avi,*.mkv,*.mov -ErrorAction SilentlyContinue |
Select-Object FullName, Length, LastWriteTime
```

**Note:** Some media files may be legitimate (system sounds, authorized training videos, etc.)

### 5. "When was [event] performed?"

**How to Find:**
- Event Viewer for system events
- File/folder creation or modification dates
- User account creation dates
- Software installation dates
- Event logs with timestamps

**PowerShell Commands:**
```powershell
# Get file creation time
Get-Item "C:\Path\To\File" | Select-Object CreationTime, LastWriteTime

# Get user account creation time
Get-LocalUser | Select-Object Name, @{Name='Created';Expression={$_.AccountExpires}}

# Search Event Viewer for specific time
Get-WinEvent -LogName Security |
Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) }
```

### 6. "What service/scheduled task is suspicious?"

**How to Find:**
- Task Scheduler (taskschd.msc)
- Services console (services.msc)
- Look for non-Microsoft tasks/services
- Check what executables they run
- Review task triggers and schedules

**PowerShell Commands:**
```powershell
# List non-Microsoft scheduled tasks
Get-ScheduledTask | 
Where-Object { $_.TaskPath -notmatch "^\\Microsoft\\" } |
Select-Object TaskName, State, TaskPath

# List services
Get-Service | 
Where-Object { $_.Status -eq 'Running' } |
Select-Object Name, DisplayName, StartType
```

### 7. "What was the command/script that was run?"

**How to Find:**
- Check Event Viewer → Windows PowerShell log
- Look at command history files
- Check scheduled tasks for commands
- Review startup items
- Look for .bat, .ps1, .cmd files

**Locations to Check:**
```
PowerShell History:
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Command Prompt History:
%USERPROFILE%\AppData\Local\Microsoft\Windows\History

Startup Scripts:
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

## Investigation Tools

### Event Viewer (eventvwr.msc)
- **Windows Logs → Security**: User logons, account changes, policy changes
- **Windows Logs → System**: Service starts/stops, driver issues
- **Windows Logs → Application**: Software events, crashes
- **Setup Log**: Installation events

### Registry Editor (regedit)
Key locations:
```
Startup Programs:
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Installed Software:
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

User Assist (tracks program usage):
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

### Task Scheduler (taskschd.msc)
- Review all scheduled tasks
- Check task triggers and actions
- Look for tasks running suspicious executables
- Note task authors and creation dates

### Services Console (services.msc)
- Check service descriptions
- Note which services are running
- Check service executables paths
- Review service dependencies

### File Explorer
- Show hidden files: View → Options → Show hidden files
- Show file extensions: View → Options → Uncheck "Hide extensions"
- Sort by Date Modified to find recent changes
- Check Properties for file details

## Tips for Answering Forensics Questions

### 1. Read Carefully
- Note exact wording of questions
- Some questions ask for file names, others for paths
- Check if answers are case-sensitive
- Verify format required (e.g., "username" vs "DOMAIN\username")

### 2. Document Your Findings
- Take screenshots of evidence
- Note timestamps
- Write down file paths
- Keep track of event IDs

### 3. Verify Before Answering
- Double-check your evidence
- Look for multiple sources confirming the answer
- Ensure the answer makes sense in context
- Test your answer format if possible

### 4. Use Multiple Methods
- Cross-reference Event Viewer with file timestamps
- Verify user actions with multiple event types
- Check both GUI tools and PowerShell commands

### 5. Common Mistakes to Avoid
- ❌ Guessing without evidence
- ❌ Assuming based on file names alone
- ❌ Not checking file timestamps
- ❌ Ignoring Event Viewer logs
- ❌ Forgetting to check all user profiles

## Useful PowerShell One-Liners

```powershell
# Find all executables modified in last 7 days
Get-ChildItem C:\ -Recurse -Include *.exe -ErrorAction SilentlyContinue |
Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

# List all local users with last logon
Get-LocalUser | Select-Object Name, Enabled, LastLogon

# Find files containing specific text
Get-ChildItem C:\Users -Recurse -Include *.txt,*.log |
Select-String -Pattern "suspicious text"

# Check when Windows was installed
Get-ComputerInfo | Select-Object OsInstallDate

# List all shares
Get-SmbShare

# View recent application events
Get-WinEvent -LogName Application -MaxEvents 50

# Find large files (over 100MB)
Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue |
Where-Object { $_.Length -gt 100MB } |
Select-Object FullName, Length

# Check browser history (Chrome example)
Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
```

## Time Management for Forensics

**Total Time for Forensics: 15-30 minutes** (depending on number of questions)

**Suggested Approach:**
1. (2 min) Read all forensics questions first
2. (3 min) Run `Forensics-Helper.ps1` to gather data
3. (10-20 min) Investigate each question systematically
4. (3 min) Double-check answers before submitting
5. (2 min) Move on if stuck - come back later

**Don't spend too long on one question!** If you're stuck after 5 minutes, mark it and move on. You can return to it after completing other security tasks.

## Example Forensics Investigation

**Question:** "What unauthorized software was most recently installed?"

**Investigation Steps:**

1. **Run Forensics Helper:**
   ```powershell
   .\Forensics-Helper.ps1 -ExportReport
   ```

2. **Check Installed Software:**
   ```powershell
   Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
   Select-Object DisplayName, InstallDate, Publisher |
   Sort-Object InstallDate -Descending | Select-Object -First 10
   ```

3. **Review Event Viewer:**
   - Open eventvwr.msc
   - Go to Windows Logs → Application
   - Look for MsiInstaller events
   - Note recent installation events

4. **Cross-Reference:**
   - Compare install dates from registry with Event Viewer
   - Check if software is in authorized list from README
   - Verify publisher is suspicious

5. **Answer:**
   - Format answer exactly as shown in question
   - Usually just the program name (e.g., "Wireshark" not "Wireshark 3.0.1")

## Practice Questions

To prepare, practice finding:
- Last user to log in
- When a specific file was created
- What services are running but shouldn't be
- What scheduled tasks exist
- What software was installed in the last month
- What media files exist on the system
- What network shares are available

## Remember

**Forensics questions cannot be automated** - they test your investigation skills. Use the tools provided to gather information, but you must analyze and answer manually. Take your time, be thorough, and verify your answers before submitting!
