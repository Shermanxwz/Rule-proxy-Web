# Windows compile gate only: owned temp ACL/files and same-token disposable child fixtures.
# No serial hardware, registry, account, task, clock, actor or VM changes.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$helper=Join-Path $PSScriptRoot 'windows-identity-serviced-telemetry.ps1'
$tokens=$null;$errors=$null
$helperAst=[System.Management.Automation.Language.Parser]::ParseFile($helper,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Telemetry parser failed' }
. $helper
$passed=0;$wireRecords=@()
foreach ($role in @('system','ordinary')) {
    foreach ($stage in @(Get-TelemetryStages $role)) {
        $state=@{pending_reboot=@{c=$true;w=$false;r=$true};extra_reboots=1;failure='reboot_still_pending'}
        $record=Get-ServicedTelemetryRecord $role $stage $state
        $line=ConvertTo-TelemetryLine $record
        if (-not $line.StartsWith('RPS2 ') -or $line.Length -gt 256 -or $record.Count -ne 6) { throw 'Telemetry valid frame failed' }
        $wireRecords+=@($line.Trim())
        $parsed=$line.Substring(5).Trim() | ConvertFrom-Json
        if ($parsed.v -ne 1 -or $parsed.s -cne $role -or $parsed.p -cne $stage) { throw 'Telemetry roundtrip failed' };$passed++
    }
}
foreach ($mask in 0..7) {
    $state=@{pending_reboot=@{c=[bool]($mask -band 1);w=[bool]($mask -band 2);r=[bool]($mask -band 4)};extra_reboots=0;failure='none'}
    $record=Get-ServicedTelemetryRecord 'system' 'failed' $state
    if ($record.m -ne $mask -or $record.n -ne 0 -or $null -ne $record.f) { throw 'Telemetry mask fixture failed' };$passed++
}
foreach ($unknown in @($null,'false',0)) {
    $record=Get-ServicedTelemetryRecord 'ordinary' 'report_attempt' @{pending_reboot=@{c=$true;w=$unknown;r=$false};extra_reboots=$true;failure='PRIVATE_FIXTURE'}
    $line=ConvertTo-TelemetryLine $record
    if ($null -ne $record.m -or $null -ne $record.n -or $null -ne $record.f -or $line.Contains('PRIVATE_FIXTURE')) { throw 'Telemetry unknown leaked' };$passed++
}
foreach ($bad in @('role','stage','mask_bool','mask_range','count_bool','count_range','failure','extra_key','irrelevant')) {
    $record=[ordered]@{v=1;s='system';p='failed';m=$null;n=$null;f=$null}
    switch ($bad) {
        'role' {$record.s='PRIVATE_FIXTURE'} 'stage' {$record.p='PRIVATE_FIXTURE'}
        'mask_bool' {$record.m=$true} 'mask_range' {$record.m=8}
        'count_bool' {$record.n=$false} 'count_range' {$record.n=2}
        'failure' {$record.f='PRIVATE_FIXTURE'} 'extra_key' {$record.raw='PRIVATE_FIXTURE'}
        'irrelevant' {$record.p='entry';$record.n=0}
    }
    $rejected=$false;try {$null=ConvertTo-TelemetryLine $record} catch {$rejected=$true}
    if (-not $rejected) { throw 'Telemetry invalid frame accepted' };$passed++
}
# Read-only current native token query plus actual role-guard branches with a mock.
$nativeSystem=Test-TelemetrySystemToken
if($nativeSystem -isnot [bool]){throw 'Native telemetry token observation failed'};$passed++
$realSystemToken=${function:Test-TelemetrySystemToken}
function Test-TelemetrySystemToken {return $script:FixtureSystemToken}
try {
    foreach($isSystem in @($false,$true)) {
        $script:FixtureSystemToken=$isSystem
        foreach($role in @('system','ordinary')) {
            $rejected=$false;try{Assert-TelemetryRoleToken $role}catch{$rejected=$true}
            if($rejected -ne (($role -ceq 'system') -ne $isSystem)){throw 'Telemetry token role boundary failed'};$passed++
        }
    }
    $rolePath=${function:Assert-TelemetryPath};$roleStart=${function:Start-TelemetryChild}
    function Assert-TelemetryPath {param($Path,[switch]$Directory,[switch]$Trusted) $script:RolePathTouches++;throw 'fixture_path_access'}
    function Start-TelemetryChild {param($Info) $script:RoleStarts++;throw 'fixture_start'}
    try {
        $script:FixtureSystemToken=$true;$script:RolePathTouches=0;$script:RoleStarts=0;$script:TelemetryDisabled=$false
        Invoke-ServicedTelemetry 'ordinary' 'entry' $null
        if($script:RolePathTouches -ne 0 -or $script:RoleStarts -ne 0){throw 'SYSTEM ordinary role touched quota path'};$passed++
    } finally {Set-Item Function:\Assert-TelemetryPath $rolePath;Set-Item Function:\Start-TelemetryChild $roleStart}
} finally {Set-Item Function:\Test-TelemetrySystemToken $realSystemToken}
# Execute actual COM2 routine with an in-memory port; never open host serial hardware.
function New-Object { param($TypeName,$ArgumentList) if ($TypeName -cne 'IO.Ports.SerialPort') { throw 'Unexpected port factory' };return $script:MockTelemetryPort }
try {
    foreach ($scenario in @('success','open_failed','write_failed','dispose_failed')) {
        $script:MockTelemetryPort=[PSCustomObject]@{Scenario=$scenario;WriteTimeout=0;Opened=$false;Wrote=$false;Disposed=$false}
        $script:MockTelemetryPort | Add-Member ScriptMethod Open { $this.Opened=$true;if($this.Scenario -ceq 'open_failed'){throw 'fixture'} }
        $script:MockTelemetryPort | Add-Member ScriptMethod Write { param($line) $this.Wrote=$true;if($this.Scenario -ceq 'write_failed'){throw 'fixture'} }
        $script:MockTelemetryPort | Add-Member ScriptMethod Dispose { $this.Disposed=$true;if($this.Scenario -ceq 'dispose_failed'){throw 'fixture'} }
        $failed=$false;try { Write-TelemetryPort "RPS2 {}`r`n" } catch {$failed=$true}
        if (-not $script:MockTelemetryPort.Disposed -or $script:MockTelemetryPort.WriteTimeout -ne 500 -or ($failed -ne ($scenario -cne 'success'))) { throw 'Telemetry port cleanup failed' };$passed++
    }
} finally { Remove-Item Function:\New-Object -ErrorAction SilentlyContinue }
foreach ($scenario in @('exited','timeout','wait_failed','kill_failed','dispose_failed','unknown_wait')) {
    $process=[PSCustomObject]@{Scenario=$scenario;Waits=0;Kills=0;Disposed=$false;Bounds=@();ExitCode=0}
    $process | Add-Member ScriptMethod WaitForExit { param($milliseconds) $this.Waits++;$this.Bounds+=@($milliseconds);if($this.Scenario -ceq 'wait_failed'){throw 'fixture'};if($this.Scenario -ceq 'unknown_wait'){return 'true'};if($this.Scenario -ceq 'kill_failed'){return $false};return ($this.Scenario -in @('exited','dispose_failed') -or $this.Waits -gt 1) }
    $process | Add-Member ScriptMethod Kill { $this.Kills++;if($this.Scenario -ceq 'kill_failed'){throw 'fixture'} }
    $process | Add-Member ScriptMethod Dispose { $this.Disposed=$true;if($this.Scenario -ceq 'dispose_failed'){throw 'fixture'} }
    $facts=Wait-TelemetryChild $process
    $shouldKill=$scenario -notin @('exited','dispose_failed')
    if (-not $process.Disposed -or $process.Kills -ne [int]$shouldKill -or $process.Bounds[0] -ne 3000 -or ($shouldKill -and $process.Bounds[1] -ne 1000)) { throw 'Telemetry process wait bounds failed' }
    if ($facts.exited -ne ($scenario -in @('exited','timeout','dispose_failed')) -or $facts.disposed -ne ($scenario -cne 'dispose_failed')) { throw 'Telemetry process observation failed' };$passed++
    if($facts.timed_out -ne ($scenario -in @('timeout','kill_failed'))){throw 'Initial wait false counter failed'}
    if($facts.exited -and $facts.exit_kind -cne 'zero'){throw 'Observed child exitcode lost'}
}
# Actual launcher suppresses further helpers if exact-child exit cannot be observed.
$realTelemetryPath=${function:Assert-TelemetryPath};$realTelemetryStart=${function:Start-TelemetryChild}
$realRoleToken=${function:Assert-TelemetryRoleToken};$realQuota=${function:Reserve-TelemetrySlot}
function Assert-TelemetryRoleToken { param($Role) if($Role -cne 'system'){throw 'fixture_role'} }
function Reserve-TelemetrySlot { param($Role,$Root) return $script:TelemetryQuotaAvailable }
function Assert-TelemetryPath { param($Path,[switch]$Directory,[switch]$Trusted) if (-not $Trusted -or -not $Path.StartsWith('C:\RuleProxyCIUpdates')) { throw 'fixture_trust' } }
function Start-TelemetryChild { param($Info) $script:TelemetryStarts++;if($Info.Arguments.Contains('PRIVATE_FIXTURE') -or $Info.UseShellExecute){throw 'fixture_arguments'};return $script:UnexitedTelemetryProcess }
try {
    $script:TelemetryStarts=0;$script:TelemetryDisabled=$false;$script:TelemetryQuotaAvailable=$true;$script:TelemetryCounters=@(0,0,0,0)
    $script:UnexitedTelemetryProcess=[PSCustomObject]@{}
    $script:UnexitedTelemetryProcess | Add-Member ScriptMethod WaitForExit { param($milliseconds) return $false }
    $script:UnexitedTelemetryProcess | Add-Member ScriptMethod Kill { throw 'fixture' }
    $script:UnexitedTelemetryProcess | Add-Member ScriptMethod Dispose { }
    Invoke-ServicedTelemetry 'system' 'failed' @{failure='PRIVATE_FIXTURE'}
    Invoke-ServicedTelemetry 'system' 'failed' $null
    if($script:TelemetryStarts -ne 1 -or -not $script:TelemetryDisabled){throw 'Unobserved helper exit did not disable telemetry'};$passed++
    if(($script:TelemetryCounters -join ',') -cne '1,0,0,1'){throw 'Unknown exit sender counters failed'}
    $script:TelemetryDisabled=$false;$script:TelemetryQuotaAvailable=$false
    Invoke-ServicedTelemetry 'system' 'failed' $null
    if($script:TelemetryStarts -ne 1){throw 'Exhausted quota spawned helper'};$passed++
    foreach($exitValue in @(0,7)) {
        $script:TelemetryDisabled=$false;$script:TelemetryQuotaAvailable=$true;$script:TelemetryCounters=@(0,0,0,0)
        $script:UnexitedTelemetryProcess=[PSCustomObject]@{ExitCode=$exitValue}
        $script:UnexitedTelemetryProcess | Add-Member ScriptMethod WaitForExit {param($milliseconds) return $true}
        $script:UnexitedTelemetryProcess | Add-Member ScriptMethod Kill {throw 'unexpected_kill'}
        $script:UnexitedTelemetryProcess | Add-Member ScriptMethod Dispose {}
        Invoke-ServicedTelemetry 'system' 'failed' $null
        $expected=if($exitValue -eq 0){'1,1,0,0'}else{'1,0,1,0'}
        if(($script:TelemetryCounters -join ',') -cne $expected){throw 'Natural exit sender counters failed'};$passed++
    }

} finally {
    Set-Item Function:\Assert-TelemetryPath $realTelemetryPath
    Set-Item Function:\Start-TelemetryChild $realTelemetryStart
    Set-Item Function:\Assert-TelemetryRoleToken $realRoleToken
    Set-Item Function:\Reserve-TelemetrySlot $realQuota
    $script:TelemetryDisabled=$false
}
# Closed report projection preserves role availability and counter consistency.
$runnerSource=Join-Path $PSScriptRoot 'windows-identity-serviced-stage0-run.ps1'
$runnerAst=[System.Management.Automation.Language.Parser]::ParseFile($runnerSource,[ref]$tokens,[ref]$errors)
$counterFunctions=@($runnerAst.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-ClosedSenderCounters'},$false))
if($counterFunctions.Count -ne 1){throw 'Sender counter projector missing'};Invoke-Expression $counterFunctions[0].Extent.Text
foreach($invalid in @(@(1,1,1,0),@(0,0,0,1),@($true,0,0,0),@(33,0,0,0),@(1,0,0))) {
    $closed=Get-ClosedSenderCounters $invalid
    if($closed.Count -ne 4 -or @($closed | Where-Object {$null -ne $_}).Count -ne 0){throw 'Invalid sender counters accepted'};$passed++
}
$closed=Get-ClosedSenderCounters @(2,1,1,1)
if(($closed -join ',') -cne '2,1,1,1'){throw 'Valid sender counters lost'};$passed++
# Actual extra-reboot helpers: telemetry elapsed time is consumed, never rebased.
$worker=Join-Path $PSScriptRoot 'windows-identity-serviced-update.ps1'
$workerAst=[System.Management.Automation.Language.Parser]::ParseFile($worker,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'Telemetry deadline worker parse failed'}
foreach($name in @('Assert-ServicedRebootMetadata','Assert-ServicedRestartReserve','Request-ServicedExtraReboot')) {
    $definitions=@($workerAst.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($definitions.Count -ne 1){throw 'Telemetry deadline helper missing'};Invoke-Expression $definitions[0].Extent.Text
}
function Get-ServicedRestartUtcNow { return $script:TelemetryNow }
function Send-ServicedTelemetry { param($Role,$Stage,$State) $script:TelemetryNow=$script:TelemetryNow.AddSeconds(2) }
function Write-ServicedState { param($State) $script:TelemetryCheckpoint=$State.extra_reboots }
function Restart-Computer { param([switch]$Force,$ErrorAction) $script:TelemetryRestarts++ }
try {
    $script:TelemetryNow=[DateTime]::SpecifyKind([DateTime]'2026-01-01T00:00:00',[DateTimeKind]::Utc)
    $script:TelemetryRestarts=0;$script:TelemetryCheckpoint=$null
    $state=@{extra_reboots=0;latest_reboot_boot='123456789012345';before_boot='123456789012345';after_boot='123456789012346';packages_verified=$true;actual_build=26200;actual_ubr=9711;dism_exit_code=3010;dism_wait_timed_out=$false;dism_exit_observed=$true;dism_exit_observation_available=$true}
    $failure=$null;try{Request-ServicedExtraReboot $state ($script:TelemetryNow.AddSeconds(3000))}catch{$failure=$_.Exception.Message}
    if($failure -cne 'service_deadline' -or $script:TelemetryRestarts -ne 0 -or $script:TelemetryCheckpoint -ne 1){throw 'Telemetry extended restart reserve'};$passed++
} finally {
    foreach($name in @('Get-ServicedRestartUtcNow','Send-ServicedTelemetry','Write-ServicedState','Restart-Computer')) {Remove-Item ('Function:\'+$name) -ErrorAction SilentlyContinue}
}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ruleproxy-telemetry-'+[Guid]::NewGuid().ToString('N'))
$created=$false;$observer=$null;$process=$null
try {
    $null=New-Item -ItemType Directory -Path $fixture;$created=$true
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $users=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $acl.SetOwner($admins);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($admins,$system)) {$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $fixture -AclObject $acl
    Assert-TelemetryPath $fixture -Directory -Trusted
    foreach($role in @('system','ordinary')) {
        $limit=if($role -ceq 'system'){20}else{12}
        for($index=0;$index -lt $limit;$index++) {
            if(-not (Reserve-TelemetrySlot $role $fixture)){throw 'Telemetry quota early stop'}
            # Hosted runner natural owner is not guest SYSTEM; explicitly trust fixture files.
            $slot=Join-Path $fixture ('telemetry-'+$role+'-'+$index.ToString('D2')+'.slot')
            $slotAcl=Get-Acl -LiteralPath $slot;$slotAcl.SetOwner($admins);Set-Acl -LiteralPath $slot -AclObject $slotAcl
        }
        if(Reserve-TelemetrySlot $role $fixture){throw 'Telemetry quota exceeded'};$passed++
    }
    # Actual cooperative wrapper + actual durable quota across local reset.
    # Only test root mapping/token role are mocked; no SYSTEM identity is claimed.
    $savedQuota=${function:Reserve-TelemetrySlot};$savedPath=${function:Assert-TelemetryPath}
    $savedStart=${function:Start-TelemetryChild};$savedRole=${function:Assert-TelemetryRoleToken}
    function Assert-TelemetryRoleToken {param($Role) $null=Get-TelemetryStages $Role}
    function Assert-TelemetryPath {param($Path,[switch]$Directory,[switch]$Trusted)
        if($Path -eq $fixture -or $Path.StartsWith($fixture+[IO.Path]::DirectorySeparatorChar)){& $savedPath $Path -Directory:$Directory -Trusted:$Trusted}
        elseif($Path -cnotin @('C:\RuleProxyCIUpdates','C:\RuleProxyCIUpdates\windows-identity-serviced-telemetry.ps1')){throw 'fixture_fixed_path'}
    }
    function Reserve-TelemetrySlot {param($Role,$Root) return (& $savedQuota $Role $fixture)}
    function Start-TelemetryChild {param($Info) $script:QuotaStarts++;throw 'fixture_start_failure'}
    try {
        foreach($role in @('system','ordinary')) {
            $script:QuotaStarts=0;$script:TelemetryDisabled=$false
            Invoke-ServicedTelemetry $role 'entry' $null
            $script:TelemetryDisabled=$false
            Invoke-ServicedTelemetry $role 'entry' $null
            if($script:QuotaStarts -ne 0){throw 'Durable exhausted quota launched child'}
            # Remove only this exact owned final slot to allow one attempted start.
            $last=if($role -ceq 'system'){19}else{11}
            $lastSlot=Join-Path $fixture ('telemetry-'+$role+'-'+$last.ToString('D2')+'.slot')
            Remove-Item -LiteralPath $lastSlot -Force
            Invoke-ServicedTelemetry $role 'entry' $null
            $slotAcl=Get-Acl -LiteralPath $lastSlot;$slotAcl.SetOwner($admins);Set-Acl -LiteralPath $lastSlot -AclObject $slotAcl
            $script:TelemetryDisabled=$false
            Invoke-ServicedTelemetry $role 'entry' $null
            if($script:QuotaStarts -ne 1){throw 'Spawn failure refunded durable quota'};$passed++
        }
    } finally {
        Set-Item Function:Reserve-TelemetrySlot $savedQuota;Set-Item Function:Assert-TelemetryPath $savedPath
        Set-Item Function:Start-TelemetryChild $savedStart;Set-Item Function:Assert-TelemetryRoleToken $savedRole
        $script:TelemetryDisabled=$false
    }
    # Actual PS-produced ASCII frames through the actual Python host parser.
    $wire=Join-Path $fixture 'wire.txt';$parity=Join-Path $fixture 'wire.py';$parityErr=Join-Path $fixture 'wire-error.txt'
    $wireStream=[IO.File]::Open($wire,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.Encoding]::ASCII.GetBytes(($wireRecords -join "`n"));$wireStream.Write($bytes,0,$bytes.Length)}finally{$wireStream.Dispose()}
    $paritySource=@'
import importlib.util, pathlib, sys
spec=importlib.util.spec_from_file_location('telemetry_host',sys.argv[1])
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
lines=pathlib.Path(sys.argv[2]).read_bytes().splitlines()
assert len(lines)==12
assert all(host.parse_progress(line) is not None for line in lines)
print('{"fixture":"telemetry_wire_parity","accepted":12}')
'@
    $parityStream=[IO.File]::Open($parity,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.Encoding]::ASCII.GetBytes($paritySource);$parityStream.Write($bytes,0,$bytes.Length)}finally{$parityStream.Dispose()}
    & python -B $parity (Join-Path $PSScriptRoot 'windows_identity_serviced_stage0.py') $wire 2> $parityErr
    if($LASTEXITCODE -ne 0){throw 'Actual telemetry host parser parity failed'};$passed++
    # Execute the actual -File param block, functions and entry body. Only the
    # environment-specific guards and COM2 sink are substituted in this owned copy.
    $entry=@($helperAst.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.StartsWith("if (`$MyInvocation.InvocationName")})
    if($entry.Count -ne 1){throw 'Unique telemetry child entry required'}
    $sourceText=[IO.File]::ReadAllText($helper)
    $seam=@'
function Assert-TelemetryRoleToken($Role) {
    $null=Get-TelemetryStages $Role
    $script:FixtureRoleGuard=$true
}
function Assert-TelemetryPath($Path,[switch]$Directory,[switch]$Trusted) {
    if(-not $Trusted -or ($Path -cne 'C:\RuleProxyCIUpdates' -and $Path -cne $PSCommandPath)){throw 'fixture_guard'}
    $script:FixturePathGuard=$true
}
function Write-TelemetryPort($Line) {
    if(-not $script:FixtureRoleGuard -or -not $script:FixturePathGuard){throw 'fixture_entry_guards'}
    $sink=$env:RULEPROXY_TELEMETRY_FIXTURE_SINK
    $stream=[IO.File]::Open($sink,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.Encoding]::ASCII.GetBytes($Line);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
}
'@
    $entrySource=$sourceText.Insert($entry[0].Extent.StartOffset,$seam+"`r`n")
    $entryFile=Join-Path $fixture 'entry-child.ps1'
    [IO.File]::WriteAllText($entryFile,$entrySource,[Text.Encoding]::ASCII)
    $childRecords=New-Object 'Collections.Generic.List[byte]';$childIndex=0
    foreach($role in @('system','ordinary')) {
        foreach($stage in @(Get-TelemetryStages $role)) {
            $sink=Join-Path $fixture ('entry-'+$childIndex.ToString('D2')+'.bin')
            $mask=if($stage -cin @('extra_reboot_before','extra_reboot_returned','completed','failed','report_attempt')){'5'}else{'null'}
            $count=if($stage -cin @('entry','service_wait')){'null'}else{'1'}
            $failure=if($stage -cin @('failed','report_attempt')){'reboot_still_pending'}else{'null'}
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$entryFile+'" -Send -Role '+$role+' -Stage '+$stage+' -Mask '+$mask+' -Count '+$count+' -Failure '+$failure
            $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $info.EnvironmentVariables['RULEPROXY_TELEMETRY_FIXTURE_SINK']=$sink
            $process=Start-TelemetryChild $info
            $observer=[Diagnostics.Process]::GetProcessById($process.Id);$null=$observer.Handle
            $facts=Wait-TelemetryChild $process
            if(-not $facts.exited -or -not $facts.disposed -or $facts.timed_out -or $facts.exit_kind -cne 'zero' -or -not $observer.WaitForExit(1000)){throw 'Actual telemetry child entry failed'}
            $observer.Dispose();$observer=$null;$process=$null
            $bytes=[IO.File]::ReadAllBytes($sink)
            if($bytes.Length -gt 256 -or $bytes.Length -lt 2 -or $bytes[$bytes.Length-2] -ne 13 -or $bytes[$bytes.Length-1] -ne 10){throw 'Actual telemetry child framing failed'}
            $childRecords.AddRange($bytes);$childIndex++;$passed++
        }
    }
    # Exact bytes, including CRLF, feed the real streaming parser without Trim.
    [IO.File]::WriteAllBytes($wire,$childRecords.ToArray())
    $streamParity=@'
import importlib.util,pathlib,sys
spec=importlib.util.spec_from_file_location('telemetry_host',sys.argv[1]);host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
data=pathlib.Path(sys.argv[2]).read_bytes();observer=host.ProgressSerial()
for byte in data: observer.feed(bytes([byte]))
facts=observer.snapshot()
assert facts['accepted']==12 and facts['rejected']==0 and len(facts['records'])==12
expected=[]
for role, stages in [('system', ('entry','prior_valid','media_verified','initial_reboot_before','initial_reboot_returned','extra_reboot_before','extra_reboot_returned','completed','failed')), ('ordinary', ('entry','service_wait','report_attempt'))]:
    for stage in stages:
        expected.append({'v':1,'s':role,'p':stage,
                         'm':5 if stage in ('extra_reboot_before','extra_reboot_returned','completed','failed','report_attempt') else None,
                         'n':None if stage in ('entry','service_wait') else 1,
                         'f':'reboot_still_pending' if stage in ('failed','report_attempt') else None})
assert facts['records']==expected
print('{"fixture":"telemetry_actual_child_entry","accepted":12,"guards_substituted":true,"serial_sink_substituted":true}')
'@
    [IO.File]::WriteAllText($parity,$streamParity,[Text.Encoding]::ASCII)
    & python -B $parity (Join-Path $PSScriptRoot 'windows_identity_serviced_stage0.py') $wire 2> $parityErr
    if($LASTEXITCODE -ne 0){throw 'Actual child telemetry stream parity failed'};$passed++
    $badAcl=Get-Acl -LiteralPath $fixture
    $badAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'Write','None','None','Allow')))
    Set-Acl -LiteralPath $fixture -AclObject $badAcl
    $rejected=$false;try {Assert-TelemetryPath $fixture -Directory -Trusted}catch{$rejected=$true}
    if(-not $rejected){throw 'Telemetry untrusted write accepted'};Set-Acl -LiteralPath $fixture -AclObject $acl;$passed++
    $junction=Join-Path $fixture 'owned-junction'
    try {
        $null=New-Item -ItemType Junction -Path $junction -Target $fixture
        $rejected=$false;try {Assert-TelemetryPath $junction -Directory}catch{$rejected=$true}
        if(-not $rejected){throw 'Telemetry reparse accepted'};$passed++
    } finally {
        if(Test-Path -LiteralPath $junction){[IO.Directory]::Delete($junction)}
    }
    $child=Join-Path $fixture 'owned-child.ps1'
    [IO.File]::WriteAllText($child,"param([string]`$Mode)`r`nif (`$Mode -ceq 'hang') { Start-Sleep -Seconds 30 } else { Start-Sleep -Milliseconds 400 }",[Text.Encoding]::ASCII)
    foreach($mode in @('exit','hang')) {
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$child+'" -Mode '+$mode
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=Start-TelemetryChild $info
        # Hold an independent handle to this exact owned process before disposal/races.
        $observer=[Diagnostics.Process]::GetProcessById($process.Id);$null=$observer.Handle
        $facts=Wait-TelemetryChild $process
        if(-not $facts.exited -or -not $facts.disposed -or $facts.kill_attempted -ne ($mode -ceq 'hang') -or -not $observer.WaitForExit(1000)){throw 'Actual owned telemetry child cleanup failed'}
        $observer.Dispose();$observer=$null;$process=$null;$passed++
    }
    Write-Output ((@{fixture='telemetry_owned_windows';quota_system=20;quota_ordinary=12;trusted_owner_explicit=$true;ordinary_token_tested=$false;actual_child_exit=$true;actual_child_timeout_kill=$true;serial_hardware_tested=$false})|ConvertTo-Json -Compress)
} catch {
    Write-Output ((@{fixture='telemetry_owned_windows';failed=$true;hresult=[int]$_.Exception.HResult})|ConvertTo-Json -Compress)
    throw 'Owned telemetry Windows fixture failed'
} finally {
    $cleanupOk=$true
    $cleanupProcess=if($null -ne $observer){$observer}else{$process}
    if($null -ne $cleanupProcess){
        try {if(-not $cleanupProcess.HasExited){$cleanupProcess.Kill();if(-not $cleanupProcess.WaitForExit(1000)){$cleanupOk=$false}}}catch{$cleanupOk=$false}
        finally {try{$cleanupProcess.Dispose()}catch{$cleanupOk=$false}}
    }
    $rootRemovalSkipped=($created -and -not $cleanupOk)
    try {
        if($created -and $cleanupOk){
            foreach($item in @(Get-ChildItem -LiteralPath $fixture -Force)) {
                if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Telemetry fixture cleanup boundary'}
                Remove-Item -LiteralPath $item.FullName -Force
            }
            Remove-Item -LiteralPath $fixture -Force
            if(Test-Path -LiteralPath $fixture){throw 'Telemetry fixture cleanup failed'}
        }
    } catch {$cleanupOk=$false}
    Write-Output ((@{fixture='telemetry_owned_cleanup';confirmed=$cleanupOk;root_removal_skipped=$rootRemovalSkipped})|ConvertTo-Json -Compress)
    if(-not $cleanupOk){throw 'Owned telemetry cleanup not confirmed'}
}

Write-Output ((@{fixture='serviced_telemetry';passed=$passed;advisory_only=$true;acceptance_changed=$false})|ConvertTo-Json -Compress)
