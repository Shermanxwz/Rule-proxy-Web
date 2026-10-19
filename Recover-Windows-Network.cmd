@echo off
setlocal
set "RP_RECOVERY_SCRIPT=%~dp0scripts\windows-network-recover.ps1"
set "RP_RECOVERY_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "RP_RECOVERY_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%RP_RECOVERY_SCRIPT%" (
  echo Keep this file beside the scripts folder. Extract the ZIP first.
  pause
  exit /b 3
)
echo RuleProxy offline recovery. Only verified RuleProxy objects are repaired.
echo Use the Windows account affected by the proxy. Approve the UAC prompt.
"%RP_RECOVERY_PS%" -NoProfile -ExecutionPolicy Bypass -Command "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $a='-NoProfile -ExecutionPolicy Bypass -File '+[char]34+$env:RP_RECOVERY_SCRIPT+[char]34+' -Apply -CheckInternet -PauseAtEnd -ExpectedUserSid '+$sid; try { $p=Start-Process -FilePath $env:RP_RECOVERY_PS -ArgumentList $a -Verb RunAs -Wait -PassThru; exit $p.ExitCode } catch { Write-Host $_.Exception.Message; exit 3 }"
if errorlevel 1 pause
endlocal
