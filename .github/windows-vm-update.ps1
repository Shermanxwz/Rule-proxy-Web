# Test VM tooling only. The seed/setup owns this protected directory and task.
# Dot sourcing defines validation helpers without installing or restarting.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:UpdateDirectory = 'C:\RuleProxyCIUpdates'
$script:UpdateTaskName = 'RuleProxyCI-InstallOfficialUpdate'

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

function Test-UpdateFilename($Name) {
    return ($Name -is [string] -and $Name.Length -le 180 -and
            $Name -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.msu$' -and -not $Name.Contains('..'))
}

function Read-UpdateManifest($Directory) {
    $null = Assert-UpdateFile $Directory -Directory
    $path = Join-Path $Directory 'update-manifest.json'
    $item = Assert-UpdateFile $path
    if ($item.Length -gt 65536) { throw 'update_manifest_oversized' }
    $manifest = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $names = @($manifest.PSObject.Properties.Name)
    foreach ($required in @('target_build', 'target_ubr', 'packages', 'target_package')) {
        if ($required -notin $names) { throw 'update_manifest_missing_field' }
    }
    if ($manifest.target_build -ne 26300 -or $manifest.target_ubr -ne 9711 -or
        $manifest.target_build -is [string] -or $manifest.target_ubr -is [string]) {
        throw 'update_manifest_unexpected_target'
    }
    if (-not (Test-UpdateFilename $manifest.target_package)) { throw 'update_invalid_target_filename' }
    $packages = @($manifest.packages)
    if ($packages.Count -lt 1 -or $packages.Count -gt 8) { throw 'update_invalid_package_count' }
    $seen = @{}
    $packageDirectory = Join-Path $Directory 'packages'
    $null = Assert-UpdateFile $packageDirectory -Directory
    foreach ($package in $packages) {
        $fields = @($package.PSObject.Properties.Name)
        if ('filename' -notin $fields -or 'sha256' -notin $fields -or
            -not (Test-UpdateFilename $package.filename) -or
            $package.sha256 -isnot [string] -or $package.sha256 -cnotmatch '^[0-9a-fA-F]{64}$') {
            throw 'update_invalid_package_entry'
        }
        $key = $package.filename.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { throw 'update_duplicate_filename' }
        $seen[$key] = $true
        $packagePath = Join-Path $packageDirectory $package.filename
        $null = Assert-UpdateFile $packagePath
        $actual = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
        if ($actual -cne $package.sha256.ToUpperInvariant()) { throw 'update_package_hash_mismatch' }
    }
    if (-not $seen.ContainsKey($manifest.target_package.ToLowerInvariant())) { throw 'update_target_not_verified' }
    foreach ($item in @(Get-ChildItem -LiteralPath $packageDirectory -Force)) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $seen.ContainsKey($item.Name.ToLowerInvariant())) { throw 'update_unlisted_package' }
    }
    return $manifest
}

function Get-UpdateOS {
    $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    return @{ build = [int]$version.CurrentBuildNumber; ubr = [int]$version.UBR }
}

function Write-UpdateState($State) {
    $path = Join-Path $script:UpdateDirectory 'update-state.json'
    $temporary = Join-Path $script:UpdateDirectory 'update-state.json.tmp'
    foreach ($existing in @($path, $temporary)) {
        if (Test-Path -LiteralPath $existing) { Assert-ProtectedUpdatePath $existing }
    }
    $raw = ConvertTo-Json -InputObject $State -Depth 8
    if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 65536) { throw 'update_state_oversized' }
    [IO.File]::WriteAllText($temporary, $raw, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $path) {
        [IO.File]::Replace($temporary, $path, $null)
    } else {
        [IO.File]::Move($temporary, $path)
    }
}

function Remove-UpdateTask {
    # The only task this worker may unregister; never stop or kill another task.
    Unregister-ScheduledTask -TaskName $script:UpdateTaskName -Confirm:$false -ErrorAction Stop
}

function Invoke-RuleProxyCIUpdate {
    $state = @{ schema_version = 1; status = 'installing'; completed = $false;
        target_build = 26300; target_ubr = 9711; actual_build = 0; actual_ubr = 0;
        attempts = 0; reboot_count = 0; reboot_required = $false; packages_verified = $false;
        task_unregistered = $false;
        servicing_signature_verification = 'Windows servicing verifies MSU catalog signatures' }
    $trustedDirectory = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($identity.User.Value -ne 'S-1-5-18') { throw 'update_SYSTEM_required' }
        Assert-ProtectedUpdatePath $script:UpdateDirectory -Directory -ProtectedDacl
        $trustedDirectory = $true
        Assert-ProtectedUpdatePath (Join-Path $script:UpdateDirectory 'windows-vm-update.ps1')
        Assert-ProtectedUpdatePath (Join-Path $script:UpdateDirectory 'update-manifest.json')
        $manifest = Read-UpdateManifest $script:UpdateDirectory
        $packageDirectory = Join-Path $script:UpdateDirectory 'packages'
        Assert-ProtectedUpdatePath $packageDirectory -Directory
        foreach ($package in @($manifest.packages)) {
            Assert-ProtectedUpdatePath (Join-Path $packageDirectory $package.filename)
        }
        $state.packages_verified = $true
        $statePath = Join-Path $script:UpdateDirectory 'update-state.json'
        if (Test-Path -LiteralPath $statePath) {
            Assert-ProtectedUpdatePath $statePath
            $item = Get-Item -LiteralPath $statePath
            if ($item.Length -gt 65536) { throw 'update_state_oversized' }
            $previous = [IO.File]::ReadAllText($statePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
            $previousNames = @($previous.PSObject.Properties.Name)
            if ($previous.schema_version -ne 1 -or $previous.target_build -ne 26300 -or $previous.target_ubr -ne 9711 -or
                $previous.attempts -is [string] -or $previous.reboot_count -is [string] -or
                $previous.attempts -lt 0 -or $previous.attempts -gt 2 -or
                $previous.reboot_count -lt 0 -or $previous.reboot_count -gt 2) { throw 'update_invalid_prior_state' }
            $state.attempts, $state.reboot_count = [int]$previous.attempts, [int]$previous.reboot_count
            if ('dism_exit_code' -in $previousNames) { $state.dism_exit_code = [int]$previous.dism_exit_code }
            if ($previous.status -eq 'failed') { throw 'update_prior_failure' }
        }
        # Startup tasks can run before specialize/OOBE has finished. Do not
        # service or reboot while Windows Setup still owns the machine.
        $setupDeadline = [DateTime]::UtcNow.AddMinutes(10)
        do {
            $setup = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
            $setupNames = @($setup.PSObject.Properties.Name)
            $image = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'
            $busy = ($setup.SystemSetupInProgress -ne 0 -or
                     ('OOBEInProgress' -in $setupNames -and $setup.OOBEInProgress -ne 0) -or
                     $image.ImageState -cne 'IMAGE_STATE_COMPLETE')
            if (-not $busy) { break }
            $state.phase = 'waiting_for_windows_setup'
            Write-UpdateState $state
            if ([DateTime]::UtcNow -ge $setupDeadline) { throw 'update_windows_setup_timeout' }
            Start-Sleep -Seconds 5
        } while ($true)
        $state.phase = 'verifying'
        $os = Get-UpdateOS
        $state.actual_build, $state.actual_ubr = $os.build, $os.ubr
        if ($os.build -ne 26300) { throw 'update_wrong_OS_build' }
        if ($state.attempts -gt 0 -and $state.ContainsKey('dism_exit_code') -and
            $state.dism_exit_code -in @(0, 3010) -and $os.ubr -ge 9711) {
            $state.status, $state.completed, $state.reboot_required = 'completed', $true, $false
            Remove-UpdateTask
            $state.task_unregistered = $true
            Write-UpdateState $state
            return 0
        }
        if ($state.attempts -ge 2) { throw 'update_attempt_limit' }
        $state.attempts++
        $state.phase = 'installing_official_CU'
        Write-UpdateState $state
        $dism = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\dism.exe'
        $packagePath = Join-Path $packageDirectory $manifest.target_package
        $logPath = Join-Path $script:UpdateDirectory 'dism.log'
        if (Test-Path -LiteralPath $logPath) { Assert-ProtectedUpdatePath $logPath }
        # Windows 11 servicing locates required checkpoint MSUs in this same
        # directory and verifies their package catalogs. Never IgnoreCheck.
        $arguments = @('/Online', '/Add-Package', ('/PackagePath:"' + $packagePath + '"'),
                       '/Quiet', '/NoRestart', ('/LogPath:"' + $logPath + '"'))
        $process = Start-Process -FilePath $dism -ArgumentList $arguments -PassThru -WindowStyle Hidden
        try {
            # Retain the kernel handle before a fast exit; PS5 otherwise may
            # expose a null ExitCode that must never become successful zero.
            $null = $process.Handle
            if (-not $process.WaitForExit(40 * 60 * 1000)) {
                # Leave Windows servicing alone. Failed state blocks ordinary tests.
                $state.installer_running = $true
                throw 'update_DISM_timeout'
            }
            $process.Refresh()
            if ($null -eq $process.ExitCode) { throw 'update_DISM_exit_code_unavailable' }
            $state.dism_exit_code = [int]$process.ExitCode
        } finally {
            $process.Dispose()
        }
        if ($state.dism_exit_code -notin @(0, 3010)) { throw 'update_DISM_failed' }
        $os = Get-UpdateOS
        $state.actual_build, $state.actual_ubr = $os.build, $os.ubr
        if ($os.build -ne 26300) { throw 'update_wrong_OS_build' }
        if ($state.dism_exit_code -eq 0 -and $os.ubr -ge 9711) {
            $state.status, $state.completed, $state.reboot_required = 'completed', $true, $false
            Remove-UpdateTask
            $state.task_unregistered = $true
            Write-UpdateState $state
            return 0
        }
        $state.phase = 'reboot_pending'
        $state.reboot_required = $true
        $state.reboot_count++
        Write-UpdateState $state
        # This is the disposable test VM. Graceful restart, no process kill.
        Restart-Computer -ErrorAction Stop
        return 0
    } catch {
        $state.status, $state.completed, $state.reboot_required = 'failed', $false, $false
        $message = $_.Exception.Message
        $state.error = if ($message -cmatch '^update_[A-Za-z0-9_]+$') { $message } else { 'update_worker_error' }
        if ($trustedDirectory) {
            try { Remove-UpdateTask; $state.task_unregistered = $true } catch { }
            try { Write-UpdateState $state } catch { }
        }
        return 1
    }
}

if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-RuleProxyCIUpdate) }
