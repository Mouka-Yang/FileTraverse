@echo off
powershell.exe -command "set-executionpolicy -executionpolicy remotesigned -scope currentuser -confirm:$false"
powershell.exe -command "& '%~dp0\traverse.ps1'"
powershell.exe -command "set-executionpolicy -executionpolicy allsigned -scope currentuser -confirm:$false"

pause