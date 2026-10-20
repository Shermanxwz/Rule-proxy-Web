# Disposable direct exploratory guest only. SYSTEM specialize, ordinary Startup test.
$ErrorActionPreference = 'Stop'
$destination = 'C:\RuleProxyCI'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-run.ps1') $destination
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') $destination
# Only inherited disposable guest policies; no servicing worker/task is installed.
& reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v BypassNRO /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Guest OOBE policy failed' }
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Guest stock-build policy failed' }
& icacls.exe $destination /grant '*S-1-5-32-545:(OI)(CI)M' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Guest workspace ACL failed' }
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup\RuleProxyCi.cmd'
$command = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCI\ruleproxy-vm-run.ps1`r`n"
[IO.File]::WriteAllText($startup, $command, [Text.Encoding]::ASCII)
