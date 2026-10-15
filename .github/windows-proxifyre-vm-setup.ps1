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
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-run.ps1') -Destination $root
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') -Destination $root
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powershell -Argument '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\RuleProxyProductBootstrap\ruleproxy-vm-run.ps1'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 40) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'RuleProxyProduct-Qualification' -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Principal $principal -Settings $settings -Force | Out-Null
[IO.File]::AppendAllText($setupLog, [DateTime]::UtcNow.ToString('o') + ' system_task_registered' + [Environment]::NewLine)
