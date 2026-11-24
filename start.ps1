# ForensiTrace One-Click Launcher for Windows
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " LAUNCHING FORENSITRACE HYBRID ML DEMO" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

$env:PYTHONPATH = $PSScriptRoot
python "$PSScriptRoot\scripts\run_demo.py"
