# Windows compile-job only. Pure synthetic predicates plus read-only runner facts.
# Never invoke the guest entrypoint, create an identity, change ACLs or start a VM.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'windows-identity-serviced-stage0-run.ps1'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Guest parser failed' }
$names=@('Test-InstalledDriveC','Test-InstalledWindowsDirectory','Get-InstalledBootGates','Get-ClosedEarlyDiagnostic')
foreach ($name in $names) {
    $definitions=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if ($definitions.Count -ne 1) { throw 'Unique pure function required' }
    # Evaluate only these reviewed function definitions, not the entrypoint body.
    Invoke-Expression $definitions[0].Extent.Text
}
$passed=0
foreach ($value in @('C:','c:')) {
    if (-not (Test-InstalledDriveC $value)) { throw 'Drive case variant rejected' }; $passed++
}
foreach ($value in @($null,'','D:','C:\','C',' C:','C: ')) {
    if (Test-InstalledDriveC $value) { throw 'Invalid drive accepted' }; $passed++
}
foreach ($value in @('C:\Windows','C:\WINDOWS','c:\windows','c:\Windows')) {
    if (-not (Test-InstalledWindowsDirectory $value)) { throw 'Directory case variant rejected' }; $passed++
}
foreach ($value in @($null,'','C:Windows','D:\Windows','C:\Windows\','C:\Windows\..','C:\x\..\Windows','\\server\Windows','C:/Windows','C:\WindowsX',' C:\Windows','C:\Windows ')) {
    if (Test-InstalledWindowsDirectory $value) { throw 'Invalid directory accepted' }; $passed++
}
$valid=@{product='WinNT';architecture='AMD64';system_setup=0;oobe_present=$true;oobe=0;
    image='IMAGE_STATE_COMPLETE';env_drive='c:';os_drive='C:';windows_directory='C:\WINDOWS';drive_type=3;build='26200';ubr=6584}
$gates=Get-InstalledBootGates $valid
if (@($gates.Values | Where-Object { $_ -ne $true }).Count -ne 0) { throw 'Valid synthetic gates rejected' }; $passed++
foreach ($pair in @(@('product','ServerNT'),@('architecture','ARM64'),@('system_setup',1),@('oobe',1),
    @('image','IMAGE_STATE_UNDEPLOYABLE'),@('env_drive','D:'),@('os_drive','D:'),@('windows_directory','D:\Windows'),
    @('drive_type',5),@('build','26100'),@('ubr',9000))) {
    $negative=$valid.Clone();$negative[$pair[0]]=$pair[1]
    $negativeGates=Get-InstalledBootGates $negative
    if (@($negativeGates.Values | Where-Object { $_ -eq $false }).Count -eq 0) { throw 'Invalid synthetic gates accepted' }; $passed++
}
$unknown=Get-InstalledBootGates @{}
if (@($unknown.Values | Where-Object { $null -ne $_ }).Count -ne 0) { throw 'Unknown facts must stay unknown' }; $passed++
$raw=Get-ClosedEarlyDiagnostic -Phase 'PRIVATE_SENTINEL' -Operation 'PRIVATE_SENTINEL' -Category 'PRIVATE_SENTINEL' -HResult 2147483648L -Gates @{product_winnt='PRIVATE_SENTINEL';secret='PRIVATE_SENTINEL'}
if ($raw.Contains('PRIVATE_SENTINEL') -or [Text.Encoding]::ASCII.GetByteCount($raw) -gt 2048) { throw 'Closed projection failed' }
$record=$raw | ConvertFrom-Json
if ($record.schema -ne 1 -or $null -ne $record.hresult -or $null -ne $record.gates.product_winnt) { throw 'Closed types failed' }; $passed++
$expected=@('failure_category','gates','hresult','operation','phase','schema')
if ((@($record.PSObject.Properties.Name | Sort-Object) -join ',') -cne ($expected -join ',')) { throw 'Closed field set changed' }; $passed++
# Production catches Exception.HResult as Int32. Exercise typed values and
# reject noninteger/out-of-range values without coercing the closed emitter.
$hresultCases=@(
    @{value=([int]-2146233087); expected=([long]-2146233087)},
    @{value=[int]::MinValue; expected=([long][int]::MinValue)},
    @{value=[int]::MaxValue; expected=([long][int]::MaxValue)},
    @{value=([int]0); expected=([long]0)},
    @{value=([long]-2147483648); expected=([long]-2147483648)},
    @{value=([long]2147483647); expected=([long]2147483647)},
    @{value=([long]-2147483649); expected=$null},
    @{value=([long]2147483648); expected=$null},
    @{value='-2146233087'; expected=$null},
    @{value=([double]-2146233087); expected=$null},
    @{value=$true; expected=$null},
    @{value=$null; expected=$null})
$hresultCaseIndex=0
foreach ($hresultCase in $hresultCases) {
    $typedRaw=Get-ClosedEarlyDiagnostic -Phase 'identity' -Operation 'identity' -Category 'identity_gate' -HResult $hresultCase.value -Gates $gates
    $typedRecord=$typedRaw | ConvertFrom-Json
    if ($null -eq $hresultCase.expected) {
        if ($null -ne $typedRecord.hresult) { throw ('Invalid HRESULT was coerced at fixture index ' + $hresultCaseIndex) }
    } elseif (($typedRecord.hresult -isnot [int] -and $typedRecord.hresult -isnot [long]) -or $typedRecord.hresult -ne $hresultCase.expected) {
        throw ('Typed HRESULT value or JSON numeric type changed at fixture index ' + $hresultCaseIndex)
    }
    $passed++; $hresultCaseIndex++
}
# Executable cross-language wire parity: feed actual PS-emitted JSON to the
# actual host parser. This catches new enum/type/key drift before any VM job.
$wireRecords=New-Object 'Collections.Generic.List[string]'
foreach ($case in @(@('configuration','configuration_read','operation_failed'),
    @('identity','identity','identity_gate'),@('installed_boot_gate','cim_os','operation_failed'),
    @('installed_boot_gate','cim_drive','operation_failed'),@('installed_boot_gate','version','operation_failed'),
    @('installed_boot_gate','product','operation_failed'),@('installed_boot_gate','gate','installed_boot_gate'),
    @('installed_setup_wait','setup','operation_failed'),@('installed_setup_wait','image','operation_failed'),
    @('installed_setup_wait','waiting_setup','installed_setup_deadline'),@('beacon','beacon','operation_failed'))) {
    $item=Get-ClosedEarlyDiagnostic -Phase $case[0] -Operation $case[1] -Category $case[2] -HResult ([int]-2146233087) -Gates $gates
    $decoded=$item | ConvertFrom-Json
    if ($decoded.phase -cne $case[0] -or $decoded.operation -cne $case[1] -or $decoded.failure_category -cne $case[2]) { throw 'Emitter enum unexpectedly sanitized' }
    if (($decoded.hresult -isnot [int] -and $decoded.hresult -isnot [long]) -or $decoded.hresult -ne ([int]-2146233087)) { throw 'Wire HRESULT value or JSON numeric type changed' }
    $wireRecords.Add('RPDIAG1 '+$item)
}
$parityCode=@'
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("serviced_wire_parity",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
with open(sys.argv[2], encoding="ascii") as wire_file:
    rows=json.load(wire_file)
assert len(rows)==11
for row in rows:
    value=m.parse_early_guest(row)
    assert value is not None, "PowerShell wire rejected by host"
    assert value["hresult"]==-2146233087
print(json.dumps({"actual_powershell_host_wire_records_passed":len(rows),"runtime_acceptance":False}))
'@
$parityPath=Join-Path ([IO.Path]::GetTempPath()) ('ruleproxy-wire-'+[Guid]::NewGuid().ToString('N')+'.py')
$wirePath=Join-Path ([IO.Path]::GetTempPath()) ('ruleproxy-wire-'+[Guid]::NewGuid().ToString('N')+'.json')
$parityOwned=$false; $wireOwned=$false
try {
    if ($wireRecords.Count -ne 11) { throw 'Exactly eleven wire records required' }
    $parityFile=[IO.File]::Open($parityPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $parityOwned=$true
    try {
        $bytes=[Text.Encoding]::ASCII.GetBytes($parityCode)
        $parityFile.Write($bytes,0,$bytes.Length)
    } finally { $parityFile.Dispose() }
    $wireFile=[IO.File]::Open($wirePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $wireOwned=$true
    try {
        $wireJson=ConvertTo-Json -InputObject @($wireRecords.ToArray()) -Compress
        $wireBytes=[Text.Encoding]::ASCII.GetBytes($wireJson)
        if ($wireBytes.Length -eq 0) { throw 'Wire input must not be empty' }
        $wireFile.Write($wireBytes,0,$wireBytes.Length)
    } finally { $wireFile.Dispose() }
    & python -B $parityPath (Join-Path $PSScriptRoot 'windows_identity_serviced_stage0.py') $wirePath
    if ($LASTEXITCODE -ne 0) { throw 'PowerShell to host wire parity failed' }
} finally {
    # Only delete exact paths successfully created by this invocation.
    try { if ($wireOwned) { Remove-Item -LiteralPath $wirePath -Force } }
    finally { if ($parityOwned) { Remove-Item -LiteralPath $parityPath -Force } }
}
$passed+=$wireRecords.Count

# Regression: regex operators mutate automatic $Matches; optical device selection
# must not store its array in that variable. Execute the actual helper with a mock.
$helper=Join-Path $PSScriptRoot 'windows-identity-serviced-update.ps1'
$helperAst=[System.Management.Automation.Language.Parser]::ParseFile($helper,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Servicing helper parser failed' }
$definitions=@($helperAst.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-ServicedOpticalRoot'},$false))
if ($definitions.Count -ne 1) { throw 'Unique optical function required' }
. $helper # Guarded dot-source defines actual worker helpers; never invokes servicing.
# Execute actual pure deadline conversion without servicing or a guest. The
# protected host-derived epoch is immutable across retries/reboots, never renewed.
$fixedNow=[DateTime]::SpecifyKind([DateTime]'2030-01-01T00:00:00',[DateTimeKind]::Utc)
$fixedEpoch=([DateTimeOffset]$fixedNow).ToUnixTimeSeconds()
foreach ($offset in @(1,6600,9600)) {
    $converted=ConvertTo-ServicedDeadline ([long]($fixedEpoch+$offset)) $fixedNow
    if (($converted-$fixedNow).TotalSeconds -ne $offset) { throw 'Deadline conversion changed' }
    $passed++
}
foreach ($invalid in @($null,$true,'1893456001',[long]0,[long]($fixedEpoch-1),[long]$fixedEpoch,[long]($fixedEpoch+9601))) {
    $rejected=$false
    try { $null=ConvertTo-ServicedDeadline $invalid $fixedNow } catch { $rejected=$true }
    if (-not $rejected) { throw 'Invalid or expired deadline accepted' }
    $passed++
}
$rejected=$false
try { Assert-ServicedTime ([DateTime]::UtcNow.AddSeconds(-1)) } catch { $rejected=$true }
if (-not $rejected) { throw 'Expired shared deadline accepted' }; $passed++
Assert-ServicedTime ([DateTime]::UtcNow.AddMinutes(1)); $passed++

# Execute the actual wait helper with owned mock objects, never DISM/processes.
foreach ($scenario in @('success','timeout','unknown_exit')) {
    $state=@{dism_exit_code=$null;dism_wait_timed_out=$false;dism_exit_observed=$false;dism_exit_observation_available=$false}
    $process=[PSCustomObject]@{Scenario=$scenario;ExitCode=0;WaitArgument=0}
    $process | Add-Member ScriptMethod WaitForExit { param($milliseconds) $this.WaitArgument=$milliseconds; return ($this.Scenario -ceq 'success') }
    $process | Add-Member ScriptMethod Refresh { }
    $process | Add-Member ScriptProperty HasExited { if ($this.Scenario -ceq 'unknown_exit') { throw 'fixture_observation_unavailable' }; return ($this.Scenario -ceq 'success') }
    $failure=$null
    try { Wait-ServicedDism $process 1234 $state } catch { $failure=$_.Exception.Message }
    if ($process.WaitArgument -ne 1234) { throw 'DISM wait bound not forwarded' }
    if ($scenario -ceq 'success') {
        if ($null -ne $failure -or $state.dism_exit_code -ne 0 -or $state.dism_wait_timed_out -or -not $state.dism_exit_observed -or -not $state.dism_exit_observation_available) { throw 'Successful DISM wait fixture failed' }
    } else {
        if ($failure -cne 'dism_deadline' -or -not $state.dism_wait_timed_out -or $null -ne $state.dism_exit_code -or $state.dism_exit_observed) { throw 'DISM timeout fixture failed' }
        if ($state.dism_exit_observation_available -ne ($scenario -ceq 'timeout')) { throw 'DISM observation fixture failed' }
    }
    $passed++
}

function Get-CimInstance { param($ClassName,$Filter) return $script:OpticalFixtures }
try {
    Set-StrictMode -Version Latest
    $Matches=@{0='PREPOPULATED_TEST_VALUE'}
    $script:OpticalFixtures=@([PSCustomObject]@{VolumeName='RULEPROXY_UPDATE';DeviceID='D:'})
    if ((Get-ServicedOpticalRoot) -cne 'D:\') { throw 'Optical root regex regression' }; $passed++
    $script:OpticalFixtures=@()
    if ($null -ne (Get-ServicedOpticalRoot)) { throw 'Absent optical root accepted' }; $passed++
    $script:OpticalFixtures=@([PSCustomObject]@{VolumeName='RULEPROXY_UPDATE';DeviceID='D:'},[PSCustomObject]@{VolumeName='RULEPROXY_UPDATE';DeviceID='E:'})
    if ($null -ne (Get-ServicedOpticalRoot)) { throw 'Ambiguous optical root accepted' }; $passed++
    $script:OpticalFixtures=@([PSCustomObject]@{VolumeName='RULEPROXY_UPDATE';DeviceID='D:\alias'})
    $rejected=$false
    try { $null=Get-ServicedOpticalRoot } catch { $rejected=$true }
    if (-not $rejected) { throw 'Invalid optical device accepted' }; $passed++
} finally {
    Remove-Item -LiteralPath Function:\Get-CimInstance
    Set-StrictMode -Off
}

# The hosted runner is often Windows Server. These facts are diagnostic only;
# it is correct for its client/exact-build predicates to fail. Never accept it.
$runnerFacts=@{};$observation='unavailable'
try {
    $os=Get-CimInstance -ClassName Win32_OperatingSystem
    $drive=Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $product=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions'
    $runnerFacts=@{product=[string]$product.ProductType;architecture=$env:PROCESSOR_ARCHITECTURE;
        env_drive=$env:SystemDrive;os_drive=$os.SystemDrive;windows_directory=$os.WindowsDirectory;
        drive_type=$drive.DriveType;build=$version.CurrentBuildNumber;ubr=$version.UBR}
    $observation='observed'
} catch { $observation='read_failed' }
[ordered]@{schema=1;synthetic_checks_passed=$passed;runner_observation=$observation;
    runner_gates=(Get-InstalledBootGates $runnerFacts);runtime_acceptance=$false} | ConvertTo-Json -Depth 3 -Compress
