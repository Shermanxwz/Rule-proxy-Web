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
$updateSource = Join-Path $PSScriptRoot 'ruleproxy-updates'
if (Test-Path -LiteralPath $updateSource) {
    $updateDirectory = 'C:\RuleProxyCIUpdates'
    New-Item -ItemType Directory -Path $updateDirectory -Force | Out-Null
    # Ordinary tests may read state/logs, but cannot replace a SYSTEM script,
    # manifest or MSU. This folder is separate from their writable workspace.
    & icacls.exe $updateDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the disposable VM update directory' }
    Get-ChildItem -LiteralPath $updateSource | Copy-Item -Destination $updateDirectory -Recurse
    $updateWorker = Join-Path $updateDirectory 'windows-vm-update.ps1'
    # Verify the copied SYSTEM entry point before dot sourcing its log helper.
    foreach ($protectedPath in @($updateDirectory, $updateWorker)) {
        $item = Get-Item -LiteralPath $protectedPath -Force
        $acl = Get-Acl -LiteralPath $protectedPath
        $trustedOwners = @('S-1-5-18', 'S-1-5-32-544')
        $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedOwners -or
            ($protectedPath -eq $updateDirectory -and -not $acl.AreAccessRulesProtected)) {
            throw 'Could not verify the protected update bootstrap'
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($rule.FileSystemRights -band $writeMask) -ne 0 -and $rule.IdentityReference.Value -notin $trustedOwners) {
                throw 'Update bootstrap permits untrusted writes'
            }
        }
    }
    . $updateWorker
    Write-UpdateWorkerEvent 'setup_root_verified'
    # Specialize only installs this owned task. Servicing runs after Windows
    # Setup completes and survives its required restart before ordinary tests.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCIUpdates\windows-vm-update.ps1'
    # The native runner starts this task only after its offline-OOBE beacon
    # and private host connection succeed, including after a servicing reboot.
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 85) -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'RuleProxyCI-InstallOfficialUpdate' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Write-UpdateWorkerEvent 'setup_task_registered'
}

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powershell -Argument '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\RuleProxyProductBootstrap\ruleproxy-vm-run.ps1'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# Queue the real user logon if an earlier OOBE gate is still waiting. The
# runner's atomic claim prevents queued triggers from repeating a claimed run.
$taskMinutes = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-updates')) { 100 } else { 40 }
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $taskMinutes) -MultipleInstances Queue
# Specialize runs before OOBE creates RuleProxyCI, so the task cannot resolve
# that account yet. The runner verifies its active console SID and Explorer
# before its atomic claim; unrelated/OOBE logons do not claim or post a result.
Register-ScheduledTask -TaskName 'RuleProxyProduct-Qualification' -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Principal $principal -Settings $settings -Force | Out-Null
[IO.File]::AppendAllText($setupLog, [DateTime]::UtcNow.ToString('o') + ' system_task_registered' + [Environment]::NewLine)
