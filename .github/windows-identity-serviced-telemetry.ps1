# Advisory COM2 only. Same-token, short-lived sender; never a task or acceptance input.
param([switch]$Send,[string]$Role,[string]$Stage,[string]$Mask='null',[string]$Count='null',[string]$Failure='null')
function Get-TelemetryStages($Role) {
    if ($Role -ceq 'system') { return @('entry','prior_valid','media_verified','initial_reboot_before','initial_reboot_returned','extra_reboot_before','extra_reboot_returned','completed','failed') }
    if ($Role -ceq 'ordinary') { return @('entry','service_wait','report_attempt') }
    throw 'telemetry_role'
}
function Get-TelemetryFailures {
    return @('unclassified','service_deadline','system_required','prior_bound','prior_state','setup_deadline','optical_deadline','optical_device','optical_root','optical_members','optical_package','optical_changed','reboot_not_observed','exact_serviced_build','reboot_still_pending','task_remains','exact_stock_build','dism_log_exists','dism_handle','dism_deadline','dism_exit_absent','dism_failed','operation_failed')
}
function Get-TelemetryKeys($Value) {
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IDictionary]) { return @($Value.Keys) }
    return @($Value.PSObject.Properties.Name)
}
function Get-ServicedTelemetryRecord($Role,$Stage,$State) {
    if ($Stage -cnotin @(Get-TelemetryStages $Role)) { throw 'telemetry_stage' }
    $record=[ordered]@{v=1;s=$Role;p=$Stage;m=$null;n=$null;f=$null}
    if ($Stage -ceq 'entry' -or ($Role -ceq 'ordinary' -and $Stage -ceq 'service_wait')) { return $record }
    $keys=@(Get-TelemetryKeys $State)
    if ($Stage -cin @('extra_reboot_before','extra_reboot_returned','completed','failed','report_attempt') -and 'pending_reboot' -in $keys) {
        $pending=$State.pending_reboot;$pendingKeys=@(Get-TelemetryKeys $pending)
        if ('c' -in $pendingKeys -and 'w' -in $pendingKeys -and 'r' -in $pendingKeys -and
            $pending.c -is [bool] -and $pending.w -is [bool] -and $pending.r -is [bool]) {
            $record.m=([int]$pending.c)+2*([int]$pending.w)+4*([int]$pending.r)
        }
    }
    if ('extra_reboots' -in $keys -and ($State.extra_reboots -is [int] -or $State.extra_reboots -is [long]) -and $State.extra_reboots -in @(0,1)) { $record.n=[int]$State.extra_reboots }
    if (($Stage -ceq 'failed' -or $Stage -ceq 'report_attempt') -and 'failure' -in $keys -and $State.failure -is [string] -and $State.failure -cin @(Get-TelemetryFailures)) { $record.f=$State.failure }
    return $record
}
function ConvertTo-TelemetryLine($Record) {
    $keys=@($Record.Keys)
    if ($keys.Count -ne 6 -or @($keys | Where-Object { $_ -cnotin @('v','s','p','m','n','f') }).Count -ne 0 -or
        $Record.v -isnot [int] -or $Record.v -ne 1 -or $Record.s -isnot [string] -or $Record.p -isnot [string] -or $Record.p -cnotin @(Get-TelemetryStages $Record.s)) { throw 'telemetry_record' }
    if ($null -ne $Record.m -and ($Record.m -isnot [int] -or $Record.m -lt 0 -or $Record.m -gt 7)) { throw 'telemetry_mask' }
    if ($null -ne $Record.n -and ($Record.n -isnot [int] -or $Record.n -notin @(0,1))) { throw 'telemetry_count' }
    if ($null -ne $Record.f -and ($Record.f -isnot [string] -or $Record.f -cnotin @(Get-TelemetryFailures))) { throw 'telemetry_failure' }
    if (($Record.p -ceq 'entry' -or ($Record.s -ceq 'ordinary' -and $Record.p -ceq 'service_wait')) -and ($null -ne $Record.m -or $null -ne $Record.n -or $null -ne $Record.f)) { throw 'telemetry_irrelevant' }
    if ($Record.p -cnotin @('extra_reboot_before','extra_reboot_returned','completed','failed','report_attempt') -and $null -ne $Record.m) { throw 'telemetry_irrelevant' }
    if ($Record.p -cnotin @('failed','report_attempt') -and $null -ne $Record.f) { throw 'telemetry_irrelevant' }
    $line='RPS2 '+($Record | ConvertTo-Json -Compress -Depth 3)+"`r`n"
    if ($line.Length -gt 256 -or @($line.ToCharArray() | Where-Object { [int]$_ -gt 127 }).Count -ne 0) { throw 'telemetry_bound' }
    return $line
}
function Assert-TelemetryPath($Path,[switch]$Directory,[switch]$Trusted) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer -ne [bool]$Directory) { throw 'telemetry_path' }
    if ($Trusted) {
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop;$owners=@('S-1-5-18','S-1-5-32-544')
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $owners) { throw 'telemetry_owner' }
        if ($Directory -and -not $acl.AreAccessRulesProtected) { throw 'telemetry_inherited' }
        $writeMask=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($rule.FileSystemRights -band $writeMask) -ne 0 -and $rule.IdentityReference.Value -notin $owners) { throw 'telemetry_write' }
        }
    }
}
function Reserve-TelemetrySlot($Role,$Root) {
    $limit=if ($Role -ceq 'system') { 20 } elseif ($Role -ceq 'ordinary') { 12 } else { throw 'telemetry_role' }
    Assert-TelemetryPath $Root -Directory -Trusted:($Role -ceq 'system')
    for ($slot=0;$slot -lt $limit;$slot++) {
        $path=Join-Path $Root ('telemetry-'+$Role+'-'+$slot.ToString('D2')+'.slot')
        if (Test-Path -LiteralPath $path) { Assert-TelemetryPath $path -Trusted:($Role -ceq 'system');continue }
        $stream=$null
        try { $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None) }
        catch [IO.IOException] { continue }
        if ($null -ne $stream) { $stream.Dispose();return $true }
    }
    return $false
}
function Write-TelemetryPort($Line) {
    $port=New-Object IO.Ports.SerialPort('COM2',115200)
    try { $port.WriteTimeout=500;$port.Open();$port.Write($Line) } finally { $port.Dispose() }
}
function Wait-TelemetryChild($Process) {
    $facts=@{exited=$false;kill_attempted=$false;disposed=$false}
    try {
        try { $observed=$Process.WaitForExit(3000);if ($observed -is [bool]) { $facts.exited=$observed } } catch { }
        if (-not $facts.exited) {
            $facts.kill_attempted=$true
            try { $Process.Kill() } catch { }
            try { $observed=$Process.WaitForExit(1000);if ($observed -is [bool]) { $facts.exited=$observed } } catch { }
        }
    } finally {
        try { $Process.Dispose();$facts.disposed=$true } catch { }
    }
    return $facts
}
function Start-TelemetryChild($Info) { return [Diagnostics.Process]::Start($Info) }
function Test-TelemetrySystemToken {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { return [bool]$identity.IsSystem } finally { $identity.Dispose() }
}
function Assert-TelemetryRoleToken($Role) {
    $null=Get-TelemetryStages $Role
    $system=Test-TelemetrySystemToken
    if (($Role -ceq 'system' -and -not $system) -or ($Role -ceq 'ordinary' -and $system)) { throw 'telemetry_role_token' }
}
function Invoke-ServicedTelemetry($Role,$Stage,$State) {
    if ($null -ne (Get-Variable -Scope Script -Name TelemetryDisabled -ErrorAction SilentlyContinue) -and $script:TelemetryDisabled) { return }
    try {
        Assert-TelemetryRoleToken $Role
        $record=Get-ServicedTelemetryRecord $Role $Stage $State
        $null=ConvertTo-TelemetryLine $record
        $helper='C:\RuleProxyCIUpdates\windows-identity-serviced-telemetry.ps1'
        Assert-TelemetryPath 'C:\RuleProxyCIUpdates' -Directory -Trusted
        Assert-TelemetryPath $helper -Trusted
        $root=if ($Role -ceq 'system') { 'C:\RuleProxyCIUpdates' } else { 'C:\RuleProxyCI' }
        if (-not (Reserve-TelemetrySlot $Role $root)) { return }
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $mask=if ($null -eq $record.m) { 'null' } else { [string]$record.m }
        $count=if ($null -eq $record.n) { 'null' } else { [string]$record.n }
        $failure=if ($null -eq $record.f) { 'null' } else { [string]$record.f }
        $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$helper+'" -Send -Role '+$Role+' -Stage '+$Stage+' -Mask '+$mask+' -Count '+$count+' -Failure '+$failure
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=Start-TelemetryChild $info
        if ($null -eq $process) { $script:TelemetryDisabled=$true;return }
        $facts=Wait-TelemetryChild $process
        if (-not $facts.exited -or -not $facts.disposed) { $script:TelemetryDisabled=$true }
    } catch { }
}
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $Send) { exit 1 }
        $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
        Assert-TelemetryRoleToken $Role
        Assert-TelemetryPath 'C:\RuleProxyCIUpdates' -Directory -Trusted
        Assert-TelemetryPath $PSCommandPath -Trusted
        $record=[ordered]@{v=1;s=$Role;p=$Stage;m=$null;n=$null;f=$null}
        if ($Mask -cne 'null') { if ($Mask -cnotmatch '^[0-7]$') { throw 'telemetry_mask' };$record.m=[int]$Mask }
        if ($Count -cne 'null') { if ($Count -cnotmatch '^[01]$') { throw 'telemetry_count' };$record.n=[int]$Count }
        if ($Failure -cne 'null') { $record.f=$Failure }
        $line=ConvertTo-TelemetryLine $record
        Write-TelemetryPort $line
        exit 0
    } catch { exit 1 }
}
