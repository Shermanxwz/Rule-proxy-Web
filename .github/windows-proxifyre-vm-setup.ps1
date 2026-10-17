# Disposable official Windows 11 VM only; runs during specialize as SYSTEM.
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$root = 'C:\RuleProxyProductBootstrap'
New-Item -ItemType Directory -Path $root -Force | Out-Null
& icacls.exe $root /setowner '*S-1-5-18' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot set disposable bootstrap owner' }
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect disposable bootstrap' }
$setupLog = Join-Path $root 'setup.log'
[IO.File]::AppendAllText($setupLog, [DateTime]::UtcNow.ToString('o') + ' protected_bootstrap_ready' + [Environment]::NewLine)
# The global suite keeps the NIC unplugged through OOBE; never wait on a network-required page.
& reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v BypassNRO /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot allow offline OOBE' }
# The disposable guest is online only for its tests; automatic Windows Update and Store app
# downloads would compete with the timed experiment and may restart the guest.
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot pause automatic updates' }
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' /v AutoDownload /t REG_DWORD /d 2 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot pause Store app downloads' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-run.ps1') -Destination $root
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') -Destination $root
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powershell -Argument '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\RuleProxyProductBootstrap\ruleproxy-vm-run.ps1'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# Queue the real user logon if an earlier OOBE gate is still waiting. The
# runner's atomic claim prevents queued triggers from repeating a claimed run.
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 40) -MultipleInstances Queue
# Specialize runs before OOBE creates RuleProxyCI, so the task cannot resolve
# that account yet. The runner verifies its active console SID and Explorer
# before its atomic claim; unrelated/OOBE logons do not claim or post a result.
Register-ScheduledTask -TaskName 'RuleProxyProduct-Qualification' -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Principal $principal -Settings $settings -Force | Out-Null
[IO.File]::AppendAllText($setupLog, [DateTime]::UtcNow.ToString('o') + ' system_task_registered' + [Environment]::NewLine)
