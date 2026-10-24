# Disposable serviced guest only. SYSTEM specialize, ordinary Startup test.
$ErrorActionPreference = 'Stop'
$destination = 'C:\RuleProxyCI'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-run.ps1') $destination
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') $destination
# Inherited disposable guest policies are unchanged; the protected servicing worker is installed below.
& reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v BypassNRO /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Guest OOBE policy failed' }
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Guest stock-build policy failed' }
& icacls.exe $destination /grant '*S-1-5-32-545:(OI)(CI)M' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Guest workspace ACL failed' }
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup\RuleProxyCi.cmd'
$command = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCI\ruleproxy-vm-run.ps1`r`n"
[IO.File]::WriteAllText($startup, $command, [Text.Encoding]::ASCII)

# SYSTEM code and receipt are never inside the ordinary user's writable workspace.
$protected='C:\RuleProxyCIUpdates'
if (Test-Path -LiteralPath $protected) { throw 'Servicing directory must be new' }
New-Item -ItemType Directory -Path $protected | Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$users=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
$acl.SetOwner($system); $acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @($system,$admins)) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $protected -AclObject $acl
$worker=Join-Path $protected 'windows-identity-serviced-update.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows-identity-serviced-update.ps1') -Destination $worker
. $worker
Assert-ProtectedUpdatePath $protected -Directory -ProtectedDacl
Assert-ProtectedUpdatePath $worker
$telemetryHelper=Join-Path $protected 'windows-identity-serviced-telemetry.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows-identity-serviced-telemetry.ps1') -Destination $telemetryHelper
Assert-ProtectedUpdatePath $telemetryHelper
function Write-SetupReadDiagnostic {
        Assert-ProtectedUpdatePath $protected -Directory -ProtectedDacl
        $setupDiagnosticPath=Join-Path $protected 'setup-read-diagnostic.json'
        if (Test-Path -LiteralPath $setupDiagnosticPath) { throw 'Fresh setup diagnostic required' }
        $setupDiagnosticJson=$script:ServicingReadDiagnostic | ConvertTo-Json -Compress
        if ([Text.Encoding]::ASCII.GetByteCount($setupDiagnosticJson) -gt 1024) { throw 'Setup diagnostic bound' }
        $setupDiagnosticStream=[IO.File]::Open($setupDiagnosticPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $setupDiagnosticBytes=[Text.Encoding]::ASCII.GetBytes($setupDiagnosticJson); $setupDiagnosticStream.Write($setupDiagnosticBytes,0,$setupDiagnosticBytes.Length) } finally { $setupDiagnosticStream.Dispose() }
        Assert-ProtectedUpdatePath $setupDiagnosticPath
}
# Persist closed setup clock/budget observation after directory trust is established.
try {
Assert-ServicedClock
# Read only the original immutable seed, never the user-writable workspace copy.
$script:ServicingReadDiagnostic.step='budget_read'
$seedBudgetPath=Join-Path $PSScriptRoot 'service-budget.json'
if (-not (Test-Path -LiteralPath $seedBudgetPath)) { $script:ServicingReadDiagnostic.reason='missing'; throw 'Host budget missing' }
try {
    if ((Get-Item -LiteralPath $seedBudgetPath).Length -gt 1024) { $script:ServicingReadDiagnostic.reason='over_bound'; throw 'Host budget bound' }
    $seedRaw=Get-Content -LiteralPath $seedBudgetPath -Raw
} catch { if ($script:ServicingReadDiagnostic.reason -eq 'none') { $script:ServicingReadDiagnostic.reason='read' }; throw }
$script:ServicingReadDiagnostic.step='budget_json'
try { $seedBudget=$seedRaw | ConvertFrom-Json } catch { $script:ServicingReadDiagnostic.reason='json'; throw }
$script:ServicingReadDiagnostic.step='budget_schema'
if ($null -eq $seedBudget -or 'schema' -notin @($seedBudget.PSObject.Properties.Name) -or $seedBudget.schema -ne 1 -or 'deadline_unix_seconds' -notin @($seedBudget.PSObject.Properties.Name)) { $script:ServicingReadDiagnostic.reason='schema'; throw 'Invalid host budget' }
$now=[DateTime]::UtcNow
$hostDeadline=ConvertTo-ServicedDeadline $seedBudget.deadline_unix_seconds $now
$serviceDeadline=$now.AddMinutes(110)
if ($serviceDeadline -gt $hostDeadline) { $serviceDeadline=$hostDeadline }
$budgetPath=Join-Path $protected 'service-budget.json'
$budgetJson=@{schema=1;deadline_unix_seconds=([DateTimeOffset]$serviceDeadline).ToUnixTimeSeconds()} | ConvertTo-Json -Compress
[IO.File]::WriteAllText($budgetPath,$budgetJson,[Text.Encoding]::ASCII)
Assert-ProtectedUpdatePath $budgetPath
Write-SetupReadDiagnostic

} catch {
    if ($script:ServicingReadDiagnostic.reason -eq 'none') { $script:ServicingReadDiagnostic.reason='operation_failed' }
    try { Write-SetupReadDiagnostic } catch { }
    throw
}

$powerShell=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action=New-ScheduledTaskAction -Execute $powerShell -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$worker+'"')
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 110) -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName $script:UpdateTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $script:UpdateTaskName
