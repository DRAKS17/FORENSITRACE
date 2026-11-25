# ForensiTrace - Enable Auto-Start on Windows Boot
$startupFolder = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup')
$targetVbs = "C:\mini\ForensiTrace\scripts\silent_collector.vbs"
$shortcutPath = [System.IO.Path]::Combine($startupFolder, 'ForensiTrace_Collector.lnk')

$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "wscript.exe"
$shortcut.Arguments = "`"$targetVbs`""
$shortcut.WorkingDirectory = "C:\mini\ForensiTrace"
$shortcut.Description = "ForensiTrace Silent Background Telemetry Collector"
$shortcut.Save()

Write-Host "[+] ForensiTrace auto-start shortcut created successfully in:" -ForegroundColor Green
Write-Host "    $shortcutPath"
Write-Host "[+] ForensiTrace will now silently start collecting data whenever you turn on your laptop." -ForegroundColor Cyan
