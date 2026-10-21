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

# Closed read diagnostics only; never grants trust or changes deadline acceptance.
$script:ServicingReadDiagnostic=@{step='not_started';reason='none';remaining_seconds=$null;zone_pacific=$null;utc_offset_minutes=$null}
function Get-ServicedClockFacts([TimeZoneInfo]$Zone, [DateTime]$UtcNow) {
    if ($UtcNow.Kind -ne [DateTimeKind]::Utc) { throw 'clock_contract' }
    $expected=[TimeZoneInfo]::FindSystemTimeZoneById('Pacific Standard Time')
    $offset=[int]$Zone.GetUtcOffset($UtcNow).TotalMinutes
    return @{zone_pacific=($Zone.Id -ceq 'Pacific Standard Time');utc_offset_minutes=$offset;
        offset_matches=($offset -eq [int]$expected.GetUtcOffset($UtcNow).TotalMinutes)}
}
function Assert-ServicedClock([TimeZoneInfo]$Zone=[TimeZoneInfo]::Local, [DateTime]$UtcNow=[DateTime]::UtcNow) {
    $script:ServicingReadDiagnostic.step='clock_contract'
    try {
        $facts=Get-ServicedClockFacts $Zone $UtcNow
        $script:ServicingReadDiagnostic.zone_pacific=$facts.zone_pacific
        $script:ServicingReadDiagnostic.utc_offset_minutes=if ($facts.utc_offset_minutes -in @(-480,-420)) { $facts.utc_offset_minutes } else { $null }
        if (-not $facts.zone_pacific -or -not $facts.offset_matches) { throw 'clock_contract' }
    } catch { $script:ServicingReadDiagnostic.reason='clock_contract'; throw }
}
function ConvertTo-ServicedDeadline($Epoch, [DateTime]$Now) {
    $script:ServicingReadDiagnostic.step='budget_epoch'
    if (($Epoch -isnot [int] -and $Epoch -isnot [long])) { $script:ServicingReadDiagnostic.reason='type'; throw 'service_deadline' }
    try { $deadline=[DateTimeOffset]::FromUnixTimeSeconds([long]$Epoch).UtcDateTime }
    catch { $script:ServicingReadDiagnostic.reason='over_bound'; throw 'service_deadline' }
    $remaining=($deadline-$Now).TotalSeconds
    if ($remaining -ge -172800 -and $remaining -le 172800) { $script:ServicingReadDiagnostic.remaining_seconds=[int][Math]::Floor($remaining) }
    if ($Epoch -le 0 -or $deadline -le $Now) { $script:ServicingReadDiagnostic.reason='expired'; throw 'service_deadline' }
    if ($remaining -gt 9600) { $script:ServicingReadDiagnostic.reason='over_bound'; throw 'service_deadline' }
    return $deadline
}
function Get-ServicedDeadline {
    $path=Join-Path 'C:\RuleProxyCIUpdates' 'service-budget.json'
    $script:ServicingReadDiagnostic.step='budget_acl'
    if (-not (Test-Path -LiteralPath $path)) { $script:ServicingReadDiagnostic.reason='missing'; throw 'service_deadline' }
    try { Assert-ProtectedUpdatePath $path } catch { $script:ServicingReadDiagnostic.reason='acl'; throw }
    $script:ServicingReadDiagnostic.step='budget_read'
    try {
        if ((Get-Item -LiteralPath $path).Length -gt 1024) { $script:ServicingReadDiagnostic.reason='over_bound'; throw 'service_deadline' }
        $rawBudget=Get-Content -LiteralPath $path -Raw
    } catch { if ($script:ServicingReadDiagnostic.reason -eq 'none') { $script:ServicingReadDiagnostic.reason='read' }; throw }
    $script:ServicingReadDiagnostic.step='budget_json'
    try { $budget=$rawBudget | ConvertFrom-Json } catch { $script:ServicingReadDiagnostic.reason='json'; throw }
    $script:ServicingReadDiagnostic.step='budget_schema'
    if ($null -eq $budget -or 'schema' -notin @($budget.PSObject.Properties.Name) -or $budget.schema -ne 1 -or 'deadline_unix_seconds' -notin @($budget.PSObject.Properties.Name)) { $script:ServicingReadDiagnostic.reason='schema'; throw 'service_deadline' }
    return ConvertTo-ServicedDeadline $budget.deadline_unix_seconds ([DateTime]::UtcNow)
}

function Assert-ServicedTime([DateTime]$Deadline) {
    if ([DateTime]::UtcNow -ge $Deadline) { throw 'service_deadline' }
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
function Write-ServicedProgress($State, [bool]$Resuming) {
    # A previously admitted reboot_pending receipt is the durable checkpoint.
    # Resume progress is in memory only until final completed/failed publication.
    if (-not $Resuming) { Write-ServicedState $State }
}
function Get-ServicedBoot {
    # Protected receipt uses an OS boot identity, not a user-writable marker.
    return (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
}
function Get-ServicedPendingFacts {
    # Adjacent independent observations only; the unchanged predicate below is authoritative.
    $facts=@{c=$null;w=$null;r=$null}
    try { $facts.c=[bool](Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop) } catch {}
    try { $facts.w=[bool](Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop) } catch {}
    try {
        $session=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        $facts.r=('PendingFileRenameOperations' -in @($session.PSObject.Properties.Name) -and
            @($session.PendingFileRenameOperations).Count -gt 0)
    } catch {}
    return $facts
}
function Test-ServicedPendingReboot {
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { return $true }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
    $session=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    return ('PendingFileRenameOperations' -in @($session.PSObject.Properties.Name) -and
        @($session.PendingFileRenameOperations).Count -gt 0)
}
function Get-ServicedOpticalRoot {
    $opticalDrives=@(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=5' |
        Where-Object { $_.VolumeName -ceq 'RULEPROXY_UPDATE' })
    if ($opticalDrives.Count -ne 1) { return $null }
    $device=$opticalDrives[0].DeviceID
    if ($device -cnotmatch '^[A-Z]:$') { throw 'optical_device' }
    return $device + '\'
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
function Wait-ServicedDism($Process, [int]$Milliseconds, $State) {
    try {
        if (-not $Process.WaitForExit($Milliseconds)) { $State.dism_wait_timed_out=$true; throw 'dism_deadline' }
        $Process.Refresh()
        if ($null -eq $Process.ExitCode) { throw 'dism_exit_absent' }
        $State.dism_exit_code=[int]$Process.ExitCode
    } finally {
        # This bounds waiting, not Windows servicing work. Never kill servicing
        # processes/services here; failed receipt blocks proof, host destroys VM.
        try {
            # PowerShell adapted getters can yield null instead of propagating
            # their exception. Only an actual Boolean is an exit observation.
            $exitObservation=$Process.HasExited
            if ($exitObservation -is [bool]) {
                $State.dism_exit_observed=$exitObservation
                $State.dism_exit_observation_available=$true
            } else {
                $State.dism_exit_observed=$false
                $State.dism_exit_observation_available=$false
            }
        } catch { $State.dism_exit_observation_available=$false }
    }
}
function Get-ClosedPriorService($Value) {
    $closed=@{s='absent';p='not_observed';f='unclassified';e=$null;b=$null}
    if ($null -eq $Value) { return $closed }
    $keys=if ($Value -is [System.Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties.Name) }
    $statuses=@('absent','unclassified','installing','reboot_pending','completed','failed')
    $phases=@('not_observed','unclassified','initializing','waiting_for_optical','verifying_optical','post_reboot_verify','installing_official_cu','reboot_pending','completed')
    $failures=@('none','unclassified','service_deadline','system_required','prior_bound','prior_state','setup_deadline','optical_deadline','optical_device','optical_root','optical_members','optical_package','optical_changed','reboot_not_observed','exact_serviced_build','reboot_still_pending','task_remains','exact_stock_build','dism_log_exists','dism_handle','dism_deadline','dism_exit_absent','dism_failed','operation_failed')
    if ('s' -in $keys -and $Value.s -is [string]) { $closed.s=if ($Value.s -cin $statuses) { $Value.s } else { 'unclassified' } }
    if ('p' -in $keys -and $Value.p -is [string]) { $closed.p=if ($Value.p -cin $phases) { $Value.p } else { 'unclassified' } }
    if ('f' -in $keys -and $Value.f -is [string]) { $closed.f=if ($Value.f -cin $failures) { $Value.f } else { 'unclassified' } }
    if ('e' -in $keys -and ($Value.e -is [int] -or $Value.e -is [long]) -and $Value.e -ge -2147483648 -and $Value.e -le 4294967295) { $closed.e=[long]$Value.e }
    if ('b' -in $keys -and ($Value.b -is [int] -or $Value.b -is [long]) -and $Value.b -ge 0 -and $Value.b -le 127) { $closed.b=[int]$Value.b }
    return $closed
}
function Get-PriorServiceFacts($Prior) {
    if ($null -eq $Prior) { return Get-ClosedPriorService $null }
    $keys=if ($Prior -is [System.Collections.IDictionary]) { @($Prior.Keys) } else { @($Prior.PSObject.Properties.Name) }
    $facts=@{s='unclassified';p='unclassified';f='unclassified';e=$null;b=0}
    foreach ($pair in @(@('status','s'),@('phase','p'),@('failure','f'),@('dism_exit_code','e'))) {
        if ($pair[0] -in $keys) { $facts[$pair[1]]=$Prior.($pair[0]) }
    }
    # These bits negate the original rejection clauses; they do not impose new types.
    if ('schema_version' -in $keys -and -not ($Prior.schema_version -ne 1)) { $facts.b=$facts.b -bor 1 }
    if ('target_build' -in $keys -and -not ($Prior.target_build -ne 26200)) { $facts.b=$facts.b -bor 2 }
    if ('target_ubr' -in $keys -and -not ($Prior.target_ubr -ne 9711)) { $facts.b=$facts.b -bor 4 }
    if ('status' -in $keys -and -not ($Prior.status -cne 'reboot_pending')) { $facts.b=$facts.b -bor 8 }
    if ('dism_exit_code' -in $keys -and -not ($Prior.dism_exit_code -notin @(0,3010))) { $facts.b=$facts.b -bor 16 }
    if ('before_boot' -in $keys -and $Prior.before_boot -is [string] -and -not ($Prior.before_boot -cnotmatch '^[0-9]{15,20}$')) { $facts.b=$facts.b -bor 32 }
    if ('packages_verified' -in $keys -and -not ($Prior.packages_verified -ne $true)) { $facts.b=$facts.b -bor 64 }
    return Get-ClosedPriorService $facts
}
function Get-RetainedPriorService($Prior,$Facts) {
    $existing=Get-ClosedPriorService $null
    $keys=if ($Prior -is [System.Collections.IDictionary]) { @($Prior.Keys) } else { @($Prior.PSObject.Properties.Name) }
    if ('prior_service' -in $keys) { $existing=Get-ClosedPriorService $Prior.prior_service }
    if ($null -ne $existing.b) { return $existing }
    return Get-ClosedPriorService $Facts
}
function Assert-ServicedPriorState($prior) {
    if ($prior.schema_version -ne 1 -or $prior.target_build -ne 26200 -or $prior.target_ubr -ne 9711 -or
                $prior.status -cne 'reboot_pending' -or $prior.dism_exit_code -notin @(0,3010) -or
                $prior.before_boot -isnot [string] -or $prior.before_boot -cnotmatch '^[0-9]{15,20}$' -or
                $prior.packages_verified -ne $true) { throw 'prior_state' }
}
function Assert-ServicedRebootMetadata($Value) {
    $keys=if ($Value -is [System.Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties.Name) }
    foreach ($key in @('extra_reboots','latest_reboot_boot','before_boot')) { if ($key -notin $keys) { throw 'prior_state' } }
    if (($Value.extra_reboots -isnot [int] -and $Value.extra_reboots -isnot [long]) -or $Value.extra_reboots -notin @(0,1) -or
        $Value.latest_reboot_boot -isnot [string] -or $Value.latest_reboot_boot -cnotmatch '^[0-9]{15,20}$' -or
        $Value.before_boot -isnot [string] -or $Value.before_boot -cnotmatch '^[0-9]{15,20}$') { throw 'prior_state' }
    if (($Value.extra_reboots -eq 0 -and $Value.latest_reboot_boot -cne $Value.before_boot) -or
        ($Value.extra_reboots -eq 1 -and $Value.latest_reboot_boot -ceq $Value.before_boot)) { throw 'prior_state' }
}
function Assert-ServicedLatestBoot($State) {
    $State.latest_reboot_changed=($State.after_boot -cne $State.latest_reboot_boot)
    if ($State.after_boot -ceq $State.before_boot -or -not $State.latest_reboot_changed) { throw 'reboot_not_observed' }
}
function Send-ServicedTelemetry($TelemetryRole,$TelemetryStage,$TelemetryState=$null) {
    # Advisory only: no failure may replace or relax the real worker/launcher checks.
    try {
        $telemetryHelper='C:\RuleProxyCIUpdates\windows-identity-serviced-telemetry.ps1'
        Assert-ProtectedUpdatePath 'C:\RuleProxyCIUpdates' -Directory -ProtectedDacl
        Assert-ProtectedUpdatePath $telemetryHelper
        . $telemetryHelper
        Invoke-ServicedTelemetry $TelemetryRole $TelemetryStage $TelemetryState
    } catch { }
}
function Get-ServicedRestartUtcNow { return [DateTime]::UtcNow }
function Assert-ServicedRestartReserve([DateTime]$Deadline) {
    if (($Deadline-(Get-ServicedRestartUtcNow)).TotalSeconds -lt 3000) { throw 'service_deadline' }
}
function Request-ServicedExtraReboot($State,[DateTime]$Deadline) {
    Assert-ServicedRebootMetadata $State
    if ($State.extra_reboots -ne 0) { throw 'reboot_still_pending' }
    if ($State.after_boot -isnot [string] -or $State.after_boot -cnotmatch '^[0-9]{15,20}$' -or
        $State.after_boot -ceq $State.before_boot -or $State.after_boot -ceq $State.latest_reboot_boot) { throw 'reboot_not_observed' }
    if ($State.packages_verified -ne $true -or $State.actual_build -ne 26200 -or $State.actual_ubr -ne 9711 -or
        $State.dism_exit_code -notin @(0,3010) -or $State.dism_wait_timed_out -ne $false -or
        $State.dism_exit_observed -ne $true -or $State.dism_exit_observation_available -ne $true) { throw 'prior_state' }
    Assert-ServicedRestartReserve $Deadline
    $State.extra_reboots=1; $State.latest_reboot_boot=$State.after_boot; $State.latest_reboot_changed=$null
    $State.status='reboot_pending'; $State.phase='reboot_pending'; $State.reboot_required=$true
    # Persist the consumed request before requesting restart. Never retry/reset on the same boot.
    Write-ServicedState $State
    Send-ServicedTelemetry 'system' 'extra_reboot_before' $State
    Assert-ServicedRestartReserve $Deadline
    Restart-Computer -Force -ErrorAction Stop
    Send-ServicedTelemetry 'system' 'extra_reboot_returned' $State
}
function Invoke-ServicedUpdate {
    $state=@{ extra_reboots=$null; latest_reboot_boot=''; latest_reboot_changed=$null; pending_reboot=@{c=$null;w=$null;r=$null}; prior_service=(Get-ClosedPriorService $null); schema_version=1; status='installing'; phase='initializing'; completed=$false;
        target_build=26200; target_ubr=9711; actual_build=0; actual_ubr=0;
        packages_verified=$false; reboot_required=$false; reboot_observed=$false;
        task_unregistered=$false; dism_exit_code=$null; dism_wait_timed_out=$false;
        dism_exit_observed=$false; dism_exit_observation_available=$false; before_boot=''; after_boot=''; failure='none' }
    $trusted=$false
    Send-ServicedTelemetry 'system' 'entry' $state
    try {
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') { throw 'system_required' }
        Assert-ProtectedUpdatePath $script:UpdateDirectory -Directory -ProtectedDacl
        Assert-ProtectedUpdatePath $PSCommandPath
        $trusted=$true
        Assert-ServicedClock
        $serviceDeadline=Get-ServicedDeadline
        $statePath=Join-Path $script:UpdateDirectory 'update-state.json'
        $prior=$null
        if (Test-Path -LiteralPath $statePath) {
            Assert-ProtectedUpdatePath $statePath
            if ((Get-Item -LiteralPath $statePath).Length -gt 4096) { throw 'prior_bound' }
            $prior=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            $priorFacts=Get-PriorServiceFacts $prior
            try { Assert-ServicedPriorState $prior } catch {
                # Keep only the first closed rejected-prior snapshot, never raw or nested state.
                $state.prior_service=Get-RetainedPriorService $prior $priorFacts
                throw
            }
            Assert-ServicedRebootMetadata $prior
            $state.extra_reboots=[int]$prior.extra_reboots; $state.latest_reboot_boot=$prior.latest_reboot_boot
            $state.before_boot=$prior.before_boot
            $state.dism_exit_code=[int]$prior.dism_exit_code
            foreach ($name in @('dism_wait_timed_out','dism_exit_observed','dism_exit_observation_available')) { $state[$name]=($prior.$name -eq $true) }
            Send-ServicedTelemetry 'system' 'prior_valid' $state
        }
        # Do not race specialize or OOBE even if the startup task starts early.
        $setupDeadline=[DateTime]::UtcNow.AddMinutes(10)
        if ($setupDeadline -gt $serviceDeadline) { $setupDeadline=$serviceDeadline }
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
        $state.phase='waiting_for_optical'; Write-ServicedProgress $state ($null -ne $prior)
        $mediaDeadline=[DateTime]::UtcNow.AddMinutes(45)
        if ($mediaDeadline -gt $serviceDeadline) { $mediaDeadline=$serviceDeadline }
        do {
            $optical=Get-ServicedOpticalRoot
            if ($null -ne $optical) { break }
            if ([DateTime]::UtcNow -ge $mediaDeadline) { throw 'optical_deadline' }
            Start-Sleep -Seconds 2
        } while ($true)
        $state.phase='verifying_optical'; Write-ServicedProgress $state ($null -ne $prior)
        Assert-ServicedTime $serviceDeadline
        Assert-ServicedMedia $optical
        Assert-ServicedTime $serviceDeadline
        $state.packages_verified=$true
        Send-ServicedTelemetry 'system' 'media_verified' $state
        $os=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $state.actual_build=[int]$os.CurrentBuildNumber; $state.actual_ubr=[int]$os.UBR
        if ($null -ne $prior) {
            $state.phase='post_reboot_verify'
            $state.after_boot=Get-ServicedBoot
            Assert-ServicedLatestBoot $state
            if ($state.actual_build -ne 26200 -or $state.actual_ubr -ne 9711) { throw 'exact_serviced_build' }
            $state.pending_reboot=Get-ServicedPendingFacts
            if (Test-ServicedPendingReboot) {
                Request-ServicedExtraReboot $state $serviceDeadline
                return 0
            }
            $state.reboot_observed=$true
            Assert-ServicedTime $serviceDeadline
            Unregister-ScheduledTask -TaskName $script:UpdateTaskName -Confirm:$false -ErrorAction Stop
            if (@(Get-ScheduledTask | Where-Object { $_.TaskName -ceq $script:UpdateTaskName }).Count -ne 0) { throw 'task_remains' }
            $state.task_unregistered=$true
            $state.status='completed'; $state.phase='completed'; $state.completed=$true
            Write-ServicedState $state
            Send-ServicedTelemetry 'system' 'completed' $state
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
        Assert-ServicedTime $serviceDeadline
        $dismMilliseconds=[int][Math]::Floor([Math]::Min(40*60*1000,($serviceDeadline-[DateTime]::UtcNow).TotalMilliseconds))
        if ($dismMilliseconds -le 0) { throw 'service_deadline' }
        $process=Start-Process -FilePath $dism -ArgumentList $arguments -PassThru -WindowStyle Hidden
        try {
            if ($process.Handle -eq [IntPtr]::Zero) { throw 'dism_handle' }
            Wait-ServicedDism $process $dismMilliseconds $state
        } finally { $process.Dispose() }
        if ($state.dism_exit_code -notin @(0,3010)) { throw 'dism_failed' }
        # Even exit 0 requires a real subsequent boot before acceptance.
        Assert-ServicedTime $serviceDeadline
        $state.extra_reboots=0; $state.latest_reboot_boot=$state.before_boot
        $state.status='reboot_pending'; $state.phase='reboot_pending'; $state.reboot_required=$true
        Write-ServicedState $state
        Send-ServicedTelemetry 'system' 'initial_reboot_before' $state
        Assert-ServicedTime $serviceDeadline
        Restart-Computer -Force -ErrorAction Stop
        Send-ServicedTelemetry 'system' 'initial_reboot_returned' $state
        return 0
    } catch {
        $state.status='failed'; $state.completed=$false; $state.reboot_required=$false
        $message=$_.Exception.Message
        $allowed=@('service_deadline','system_required','prior_bound','prior_state','setup_deadline','optical_deadline',
            'optical_device','optical_root','optical_members','optical_package','optical_changed',
            'reboot_not_observed','exact_serviced_build','reboot_still_pending','task_remains',
            'exact_stock_build','dism_log_exists','dism_handle','dism_deadline','dism_exit_absent','dism_failed')
        $state.failure=if ($message -cin $allowed) { $message } else { 'operation_failed' }
        if ($trusted) { try { Write-ServicedState $state } catch {} }
        Send-ServicedTelemetry 'system' 'failed' $state
        return 1
    }
}
if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-ServicedUpdate) }
