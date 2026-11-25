Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\mini\ForensiTrace"
WshShell.Run "cmd /c C:\mini\ForensiTrace\start_collection.bat", 0, False
Set WshShell = Nothing
