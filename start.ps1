# ForensiTrace One-Click Launcher for Windows
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " LAUNCHING FORENSITRACE END-TO-END DEMO" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

$env:PYTHONPATH = $PSScriptRoot
python "$PSScriptRoot\scripts\start_demo.py"
