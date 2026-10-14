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

function Read-UpdateManifestDefinition($Directory) {
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
    }
    if (-not $seen.ContainsKey($manifest.target_package.ToLowerInvariant())) { throw 'update_target_not_verified' }
    return $manifest
}

function Read-UpdateManifest($Directory) {
    $manifest = Read-UpdateManifestDefinition $Directory
    $packageDirectory = Join-Path $Directory 'packages'
    $null = Assert-UpdateFile $packageDirectory -Directory
    $seen = @{}
    foreach ($package in @($manifest.packages)) {
        $seen[$package.filename.ToLowerInvariant()] = $true
        $packagePath = Join-Path $packageDirectory $package.filename
        $item = Assert-UpdateFile $packagePath
        if ('bytes' -in @($package.PSObject.Properties.Name) -and $item.Length -ne $package.bytes) {
            throw 'update_package_size_mismatch'
        }
        $actual = Get-UpdateSHA256 $packagePath
        if ($actual -cne $package.sha256.ToUpperInvariant()) { throw 'update_package_hash_mismatch' }
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $packageDirectory -Force)) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $seen.ContainsKey($item.Name.ToLowerInvariant())) { throw 'update_unlisted_package' }
    }
    return $manifest
}

function Assert-UpdateDownloadEntry($Entry) {
    $names = @($Entry.PSObject.Properties.Name)
    if ('bytes' -notin $names -or 'url' -notin $names -or
        -not ($Entry.bytes -is [int] -or $Entry.bytes -is [long]) -or
        $Entry.bytes -le 0 -or $Entry.bytes -gt (5L * 1024 * 1024 * 1024) -or
        $Entry.url -isnot [string] -or $Entry.url.Length -gt 4096) { throw 'update_invalid_download_entry' }
    $pattern = '^http://10\.0\.2\.2:[0-9]{1,5}/[0-9a-f]{64}/updates/' + [regex]::Escape($Entry.filename) + '$'
    if ($Entry.url -cnotmatch $pattern) { throw 'update_download_endpoint_rejected' }
    $uri = [Uri]::new($Entry.url)
    if ($uri.Port -lt 1 -or $uri.Port -gt 65535 -or $uri.Host -cne '10.0.2.2' -or
        $uri.Scheme -cne 'http' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'update_download_endpoint_rejected'
    }
}

function New-UpdateHttpRequest($Url) {
    return [Net.HttpWebRequest]::Create($Url)
}

function Save-UpdatePackage($Entry, $Directory, $Clock) {
    Assert-UpdateDownloadEntry $Entry
    $destination = Join-Path (Join-Path $Directory 'packages') $Entry.filename
    if (Test-Path -LiteralPath $destination) {
        Assert-ProtectedUpdatePath $destination
        $item = Assert-UpdateFile $destination
        if ($item.Length -eq $Entry.bytes -and (Get-UpdateSHA256 $destination) -ceq $Entry.sha256.ToUpperInvariant()) {
            return $false
        }
        throw 'update_existing_package_mismatch'
    }
    $temporary = Join-Path $Directory ('stage-' + [Guid]::NewGuid().ToString('N') + '.part')
    $request = $response = $inputStream = $outputStream = $algorithm = $null
    $created = $false
    try {
        $remaining = 25 * 60 * 1000 - $Clock.ElapsedMilliseconds
        if ($remaining -le 0) { throw 'update_download_deadline' }
        $request = New-UpdateHttpRequest $Entry.url
        $request.Proxy = $null
        $request.AllowAutoRedirect = $false
        $request.UseDefaultCredentials = $false
        $request.AutomaticDecompression = [Net.DecompressionMethods]::None
        $request.KeepAlive = $false
        $request.Timeout = [int][Math]::Min(30000, $remaining)
        $request.ReadWriteTimeout = 30000
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -ne $Entry.bytes) {
            throw 'update_download_length_or_status_mismatch'
        }
        $inputStream = $response.GetResponseStream()
        $outputStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $created = $true
        $null = Assert-UpdateFile $temporary
        $algorithm = [Security.Cryptography.SHA256]::Create()
        $buffer = [byte[]]::new(65536)
        $total = 0L
        while ($true) {
            $remaining = 25 * 60 * 1000 - $Clock.ElapsedMilliseconds
            if ($remaining -le 0) { throw 'update_download_deadline' }
            $read = $inputStream.ReadAsync($buffer, 0, $buffer.Length)
            try { $completed = $read.Wait([int][Math]::Min(30000, $remaining)) } catch {
                if ($read.IsCompleted) { $read.Dispose() }
                throw 'update_download_read_failed'
            }
            if (-not $completed) {
                $request.Abort()
                try { $null = $read.Wait(5000) } catch { }
                if (-not $read.IsCompleted) { throw 'update_download_cleanup_unproven' }
                $read.Dispose()
                throw 'update_download_timeout'
            }
            $count = $read.Result
            $read.Dispose()
            if ($count -eq 0) { break }
            $total += $count
            if ($total -gt $Entry.bytes) { throw 'update_download_overrun' }
            $outputStream.Write($buffer, 0, $count)
            $null = $algorithm.TransformBlock($buffer, 0, $count, $buffer, 0)
        }
        if ($total -ne $Entry.bytes) { throw 'update_download_ended_early' }
        $null = $algorithm.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $actual = [BitConverter]::ToString($algorithm.Hash).Replace('-', '')
        if ($actual -cne $Entry.sha256.ToUpperInvariant()) { throw 'update_download_hash_mismatch' }
        $outputStream.Flush($true)
        $outputStream.Dispose(); $outputStream = $null
        Assert-ProtectedUpdatePath $temporary
        [IO.File]::Move($temporary, $destination)
        $created = $false
        return $true
    } finally {
        if ($null -ne $request) { $request.Abort() }
        foreach ($resource in @($inputStream, $outputStream, $response, $algorithm)) {
            if ($null -ne $resource) { $resource.Dispose() }
        }
        if ($created -and (Test-Path -LiteralPath $temporary)) {
            $null = Assert-UpdateFile $temporary
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Stage-UpdatePackages($Manifest, $Directory, $State) {
    $packageDirectory = Join-Path $Directory 'packages'
    if (-not (Test-Path -LiteralPath $packageDirectory)) { $null = [IO.Directory]::CreateDirectory($packageDirectory) }
    Assert-ProtectedUpdatePath $packageDirectory -Directory
    # Validate the whole download list before the first request or file write.
    foreach ($entry in @($Manifest.packages)) { Assert-UpdateDownloadEntry $entry }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $State.phase = 'staging_official_MSU'
    $State.downloaded_package_count = 0
    $State.staged_package_count = 0
    Write-UpdateState $State
    foreach ($entry in @($Manifest.packages)) {
        if (Save-UpdatePackage $entry $Directory $clock) { $State.downloaded_package_count++ }
        $State.staged_package_count++
        Write-UpdateState $State
    }
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
        $manifest = Read-UpdateManifestDefinition $script:UpdateDirectory
        $packageDirectory = Join-Path $script:UpdateDirectory 'packages'
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
        Stage-UpdatePackages $manifest $script:UpdateDirectory $state
        $manifest = Read-UpdateManifest $script:UpdateDirectory
        foreach ($package in @($manifest.packages)) {
            Assert-ProtectedUpdatePath (Join-Path $packageDirectory $package.filename)
        }
        $state.packages_verified = $true
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
        $detail = ($message -replace '(?i)\bhttps?://[^\s]+', '[redacted-url]' -replace '(?i)[0-9a-f]{64}', '[redacted-token]' -replace '[\x00-\x1f\x7f]', ' ')
        $state.error_detail = $detail.Substring(0, [Math]::Min(400, $detail.Length))
        $state.error_type = $_.Exception.GetType().Name
        $state.error_line = [int]$_.InvocationInfo.ScriptLineNumber
        if ($trustedDirectory) {
            try { Remove-UpdateTask; $state.task_unregistered = $true } catch { }
            try { Write-UpdateState $state } catch { }
        }
        return 1
    }
}

if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-RuleProxyCIUpdate) }
