# ForensiTrace - Windows VM & Endpoint Setup Guide

**Author:** DAKSH  
**Reviewed by:** CHETNA  
**Target OS:** Windows 10 / Windows 11 / Windows Server 2022 (VM or Bare Metal)

This guide provides step-by-step instructions for configuring a fresh Windows machine to run the ForensiTrace agent with complete Security and System Event Log monitoring.

---

## 1. Prerequisites
- Administrator access on the target Windows system.
- Python 3.10+ (64-bit) installed with "Add Python to PATH" enabled.
- Node.js 18+ and npm installed for the React dashboard.
- Git installed.

---

## 2. Automated Configuration (Recommended)
Open PowerShell as **Administrator** and run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup_windows.ps1
```

---

## 3. Manual Audit Policy Configuration (Alternative)
If you prefer configuring via the Windows GUI or Group Policy Editor (`gpedit.msc`):

1. **Enable Process Creation Auditing (Event ID 4688):**
   - Press `Win + R`, type `secpol.msc` and press Enter.
   - Navigate to: `Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking`.
   - Double-click **Audit Process Creation**, check **Success** and **Failure**, then click **OK**.

2. **Include Command Line in Process Creation Events:**
   - Press `Win + R`, type `gpedit.msc` and press Enter.
   - Navigate to: `Computer Configuration -> Administrative Templates -> System -> Audit Process Creation`.
   - Double-click **Include command line in process creation events**, select **Enabled**, then click **OK**.

3. **Verify Event Log Access:**
   - The ForensiTrace Event Log collector monitors `Security` and `System` channels.
   - Reading the `Security` channel requires elevated privileges. Always run `agent/main.py` from an elevated prompt.

---

## 4. Software Dependencies Installation
In PowerShell or CMD:
```powershell
cd C:\mini\ForensiTrace

# 1. Install Backend and Agent dependencies
pip install -r backend/requirements.txt
pip install -r agent/requirements.txt

# 2. Install Frontend Node modules
cd frontend
npm install
cd ..
```

---

## 5. Verification Check
Run a quick smoke test to verify all collectors and backend are functional:
```powershell
python -m pytest tests/
```
All tests should pass. The VM is now fully prepared for live demos and evaluation experiments!
