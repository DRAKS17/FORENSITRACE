# ForensiTrace - Remove Auto-Start on Windows Boot
$startupFolder = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup')
$shortcutPath = [System.IO.Path]::Combine($startupFolder, 'ForensiTrace_Collector.lnk')

if (Test-Path $shortcutPath) {
    Remove-Item $shortcutPath -Force
    Write-Host "[+] ForensiTrace auto-start shortcut removed successfully." -ForegroundColor Yellow
} else {
    Write-Host "[!] Auto-start shortcut not found in startup folder." -ForegroundColor Gray
}
