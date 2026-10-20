# Owned disposable Windows client only. No package downloads or guest-side copies.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:UpdateDirectory = 'C:\RuleProxyCIUpdates'
$script:UpdateTaskName = 'RuleProxyCI-InstallOfficialUpdate'
$script:Packages = @(
    @{ filename='windows11.0-kb5043080-x64.msu'; bytes=533761740L; sha256='819632610a101af11c72907fb13ff05b5fb4222c0e263ee9a03bcc1d1d5f26a4' },
    @{ filename='windows11.0-kb5127648-x64.msu'; bytes=4775050195L; sha256='8a1067c763121953876e2e0dcbf5e2c5832545a44ef6baba362938287e05fcfb' }
)
function Assert-UpdateFile($Path, [switch]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'update_reparse_point' }
    if ($Directory) {
        if (-not $item.PSIsContainer) { throw 'update_directory_required' }
    } elseif ($item.PSIsContainer) { throw 'update_file_required' }
    return $item
}

function Assert-ProtectedUpdatePath($Path, [switch]$Directory, [switch]$ProtectedDacl) {
    $null = Assert-UpdateFile $Path -Directory:$Directory
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trusted) { throw 'update_untrusted_owner' }
    if ($ProtectedDacl -and -not $acl.AreAccessRulesProtected) { throw 'update_directory_inherits_permissions' }
    # An untrusted principal must not change bytes, children, ownership or ACLs.
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
                 [Security.AccessControl.FileSystemRights]::Delete -bor
                 [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                 [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                 [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band $writeMask) -ne 0 -and $rule.IdentityReference.Value -notin $trusted) {
            throw 'update_untrusted_write_permission'
        }
    }
}

function Get-UpdateSHA256($Path) {
    # Streaming .NET hashing also works in Windows PowerShell 5 launched from
    # PS7, where inherited module paths can hide the FileHash script cmdlet.
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '')
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $algorithm.Dispose()
    }
}


function Write-ServicedState($State) {
    Assert-ProtectedUpdatePath $script:UpdateDirectory -Directory -ProtectedDacl
    $path=Join-Path $script:UpdateDirectory 'update-state.json'
    $temporary=Join-Path $script:UpdateDirectory 'update-state.json.tmp'
    foreach ($existing in @($path,$temporary)) {
        if (Test-Path -LiteralPath $existing) { Assert-ProtectedUpdatePath $existing }
    }
    $raw=ConvertTo-Json -InputObject $State -Depth 5 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 4096) { throw 'state_bound' }
    [IO.File]::WriteAllText($temporary,$raw,[Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $path) {
        [IO.File]::Replace($temporary,$path,[System.Management.Automation.Language.NullString]::Value)
    } else { [IO.File]::Move($temporary,$path) }
}
function Get-ServicedBoot {
    # Protected receipt uses an OS boot identity, not a user-writable marker.
    return (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
}
function Test-ServicedPendingReboot {
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { return $true }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
    $session=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    return ('PendingFileRenameOperations' -in @($session.PSObject.Properties.Name) -and
        @($session.PendingFileRenameOperations).Count -gt 0)
}
function Get-ServicedOpticalRoot {
    $matches=@(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=5' |
        Where-Object { $_.VolumeName -ceq 'RULEPROXY_UPDATE' })
    if ($matches.Count -ne 1) { return $null }
    if ($matches[0].DeviceID -cnotmatch '^[A-Z]:$') { throw 'optical_device' }
    return $matches[0].DeviceID + '\'
}
function Assert-ServicedMedia($Root) {
    if ($Root -cnotmatch '^[A-Z]:\\$') { throw 'optical_root' }
    $items=@(Get-ChildItem -LiteralPath $Root -Force)
    if ($items.Count -ne 2) { throw 'optical_members' }
    foreach ($package in $script:Packages) {
        $path=Join-Path $Root $package.filename
        $item=Assert-UpdateFile $path
        if ($item.Length -ne $package.bytes -or
            (Get-UpdateSHA256 $path) -cne $package.sha256.ToUpperInvariant()) { throw 'optical_package' }
    }
    # Re-observe device identity after long hashing, before invoking servicing.
    if ((Get-ServicedOpticalRoot) -cne $Root) { throw 'optical_changed' }
}
function Invoke-ServicedUpdate {
    $state=@{ schema_version=1; status='installing'; phase='initializing'; completed=$false;
        target_build=26200; target_ubr=9711; actual_build=0; actual_ubr=0;
        packages_verified=$false; reboot_required=$false; reboot_observed=$false;
        task_unregistered=$false; dism_exit_code=$null; before_boot=''; after_boot=''; failure='none' }
    $trusted=$false
    try {
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') { throw 'system_required' }
        Assert-ProtectedUpdatePath $script:UpdateDirectory -Directory -ProtectedDacl
        Assert-ProtectedUpdatePath $PSCommandPath
        $trusted=$true
        $statePath=Join-Path $script:UpdateDirectory 'update-state.json'
        $prior=$null
        if (Test-Path -LiteralPath $statePath) {
            Assert-ProtectedUpdatePath $statePath
            if ((Get-Item -LiteralPath $statePath).Length -gt 4096) { throw 'prior_bound' }
            $prior=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            if ($prior.schema_version -ne 1 -or $prior.target_build -ne 26200 -or $prior.target_ubr -ne 9711 -or
                $prior.status -cne 'reboot_pending' -or $prior.dism_exit_code -notin @(0,3010) -or
                $prior.before_boot -isnot [string] -or $prior.before_boot -cnotmatch '^[0-9]{15,20}$' -or
                $prior.packages_verified -ne $true) { throw 'prior_state' }
            $state.before_boot=$prior.before_boot
            $state.dism_exit_code=[int]$prior.dism_exit_code
        }
        # Do not race specialize or OOBE even if the startup task starts early.
        $setupDeadline=[DateTime]::UtcNow.AddMinutes(10)
        do {
            $setup=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
            $image=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'
            $busy=($setup.SystemSetupInProgress -ne 0 -or
                ('OOBEInProgress' -in @($setup.PSObject.Properties.Name) -and $setup.OOBEInProgress -ne 0) -or
                $image.ImageState -cne 'IMAGE_STATE_COMPLETE')
            if (-not $busy) { break }
            if ([DateTime]::UtcNow -ge $setupDeadline) { throw 'setup_deadline' }
            Start-Sleep -Seconds 5
        } while ($true)
        $state.phase='waiting_for_optical'; Write-ServicedState $state
        $mediaDeadline=[DateTime]::UtcNow.AddMinutes(25)
        do {
            $optical=Get-ServicedOpticalRoot
            if ($null -ne $optical) { break }
            if ([DateTime]::UtcNow -ge $mediaDeadline) { throw 'optical_deadline' }
            Start-Sleep -Seconds 2
        } while ($true)
        $state.phase='verifying_optical'; Write-ServicedState $state
        Assert-ServicedMedia $optical
        $state.packages_verified=$true
        $os=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $state.actual_build=[int]$os.CurrentBuildNumber; $state.actual_ubr=[int]$os.UBR
        if ($null -ne $prior) {
            $state.phase='post_reboot_verify'
            $state.after_boot=Get-ServicedBoot
            if ($state.after_boot -ceq $state.before_boot) { throw 'reboot_not_observed' }
            if ($state.actual_build -ne 26200 -or $state.actual_ubr -ne 9711) { throw 'exact_serviced_build' }
            if (Test-ServicedPendingReboot) { throw 'reboot_still_pending' }
            $state.reboot_observed=$true
            Unregister-ScheduledTask -TaskName $script:UpdateTaskName -Confirm:$false -ErrorAction Stop
            if (@(Get-ScheduledTask | Where-Object { $_.TaskName -ceq $script:UpdateTaskName }).Count -ne 0) { throw 'task_remains' }
            $state.task_unregistered=$true
            $state.status='completed'; $state.phase='completed'; $state.completed=$true
            Write-ServicedState $state
            return 0
        }
        if ($state.actual_build -ne 26200 -or $state.actual_ubr -ne 6584) { throw 'exact_stock_build' }
        $state.before_boot=Get-ServicedBoot
        $state.phase='installing_official_cu'; Write-ServicedState $state
        $dism=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\dism.exe'
        $packagePath=Join-Path $optical $script:Packages[1].filename
        $logPath=Join-Path $script:UpdateDirectory 'dism.log'
        if (Test-Path -LiteralPath $logPath) { throw 'dism_log_exists' }
        # Same optical directory contains the checkpoint; never copy or IgnoreCheck.
        $arguments=@('/Online','/Add-Package',('/PackagePath:"'+$packagePath+'"'),'/Quiet','/NoRestart',('/LogPath:"'+$logPath+'"'))
        $process=Start-Process -FilePath $dism -ArgumentList $arguments -PassThru -WindowStyle Hidden
        try {
            if ($process.Handle -eq [IntPtr]::Zero) { throw 'dism_handle' }
            if (-not $process.WaitForExit(40*60*1000)) { throw 'dism_deadline' }
            $process.Refresh()
            if ($null -eq $process.ExitCode) { throw 'dism_exit_absent' }
            $state.dism_exit_code=[int]$process.ExitCode
        } finally { $process.Dispose() }
        if ($state.dism_exit_code -notin @(0,3010)) { throw 'dism_failed' }
        # Even exit 0 requires a real subsequent boot before acceptance.
        $state.status='reboot_pending'; $state.phase='reboot_pending'; $state.reboot_required=$true
        Write-ServicedState $state
        Restart-Computer -Force -ErrorAction Stop
        return 0
    } catch {
        $state.status='failed'; $state.completed=$false; $state.reboot_required=$false
        $message=$_.Exception.Message
        $allowed=@('system_required','prior_bound','prior_state','setup_deadline','optical_deadline',
            'optical_device','optical_root','optical_members','optical_package','optical_changed',
            'reboot_not_observed','exact_serviced_build','reboot_still_pending','task_remains',
            'exact_stock_build','dism_log_exists','dism_handle','dism_deadline','dism_exit_absent','dism_failed')
        $state.failure=if ($message -cin $allowed) { $message } else { 'operation_failed' }
        if ($trusted) { try { Write-ServicedState $state } catch {} }
        return 1
    }
}
if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-ServicedUpdate) }
