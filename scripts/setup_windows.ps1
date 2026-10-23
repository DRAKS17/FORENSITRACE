# ForensiTrace - Windows Setup & Audit Policy Configuration Script (DAKSH)
# Run this script in an elevated PowerShell prompt (Run as Administrator)

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " FORENSITRACE - WINDOWS ENDPOINT AUDIT POLICY SETUP" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# 1. Verify Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[!] This script must be executed as Administrator to configure Windows Audit Policies."
    Write-Warning "[!] Please right-click PowerShell and select 'Run as administrator'."
    exit 1
}

Write-Host "[+] Confirmed Administrator privileges." -ForegroundColor Green

# 2. Enable Process Creation Auditing (Event ID 4688)
Write-Host "[*] Enabling Audit Process Creation (Security Event 4688)..." -ForegroundColor Yellow
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# 3. Enable Command-Line Process Auditing (Registry Setting)
Write-Host "[*] Enabling Command-Line Auditing in Process Creation events..." -ForegroundColor Yellow
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Host "[+] Process command-line auditing enabled successfully." -ForegroundColor Green

# 4. Enable Logon Auditing (Security Event 4624)
Write-Host "[*] Enabling Logon Auditing (Security Event 4624)..." -ForegroundColor Yellow
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# 5. Enable System & Security Audit Log Size and Retention
Write-Host "[*] Configuring Event Log channels (Security and System)..." -ForegroundColor Yellow
wevtutil sl Security /ms:134217728 # 128 MB max log size
wevtutil sl System /ms:67108864    # 64 MB max log size

# 6. Verify Settings
Write-Host "`n[*] Verification of Process Creation Audit Setting:" -ForegroundColor Cyan
auditpol /get /subcategory:"Process Creation"

Write-Host "`n=====================================================================" -ForegroundColor Green
Write-Host " FORENSITRACE SETUP COMPLETE: Endpoint is ready for agent monitoring." -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
