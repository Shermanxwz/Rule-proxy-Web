# Windows compile-job only. Pure synthetic predicates plus read-only runner facts.
# Never invoke the guest entrypoint, create an identity, change ACLs or start a VM.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'windows-identity-direct-stage0-run.ps1'
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
    image='IMAGE_STATE_COMPLETE';env_drive='c:';os_drive='C:';windows_directory='C:\WINDOWS';drive_type=3;build='26300';ubr=9457}
$gates=Get-InstalledBootGates $valid
if (@($gates.Values | Where-Object { $_ -ne $true }).Count -ne 0) { throw 'Valid synthetic gates rejected' }; $passed++
foreach ($pair in @(@('product','ServerNT'),@('architecture','ARM64'),@('system_setup',1),@('oobe',1),
    @('image','IMAGE_STATE_UNDEPLOYABLE'),@('env_drive','D:'),@('os_drive','D:'),@('windows_directory','D:\Windows'),
    @('drive_type',5),@('build','26200'),@('ubr',9550))) {
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
spec=importlib.util.spec_from_file_location("direct_wire_parity",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
with open(sys.argv[2], encoding="ascii") as wire_file:
    rows=json.load(wire_file)
assert len(rows)==11
for row in rows:
    value=m.parse_early_guest(row)
    assert value is not None, "PowerShell wire rejected by host"
    assert value["hresult"]==-2146233087
# Execute the actual proof validator on Windows, without launching an actor.
proof_spec=importlib.util.spec_from_file_location("direct_environment_regression",sys.argv[3])
proof=importlib.util.module_from_spec(proof_spec);proof_spec.loader.exec_module(proof)
from pathlib import Path
native={"SYSTEMROOT":r"C:\Windows", "LOCALAPPDATA":r"C:\Users\FixtureUser\AppData\Local"}
valid=dict(native)
expected=["SYSTEMROOT="+valid["SYSTEMROOT"], "LOCALAPPDATA="+valid["LOCALAPPDATA"]]
assert proof.validate_required_environment(valid,native)==expected
case_variant={"SYSTEMROOT":r"c:\WINDOWS", "LOCALAPPDATA":r"c:\USERS\FixtureUser\APPDATA\LOCAL"}
assert len(proof.validate_required_environment(case_variant,native))==2
invalid=[]
for key in ("SYSTEMROOT","LOCALAPPDATA"):
    missing=dict(valid);missing.pop(key);invalid.append((missing,native))
    for value in ("", "relative", r"C:relative", r"\\server\share", "C:\\bad\x00path"):
        candidate=dict(valid);candidate[key]=value;invalid.append((candidate,native))
    mismatch=dict(native);mismatch[key]=r"D:\WrongNative";invalid.append((valid,mismatch))
extra=dict(valid);extra["PATH"]="PRIVATE_SENTINEL";invalid.append((extra,native))
for environment,native_paths in invalid:
    try:
        proof.validate_required_environment(environment,native_paths)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid synthetic environment accepted")
required=proof.validate_required_environment(valid,native)
config=proof.policy(Path("C:/Fixture/inputs"),Path("C:/Fixture/profile"),Path("C:/Fixture/inputs/actor.exe"),"a"*32,required_environment=required)
assert config["process"]["env"]==expected
assert config["process"]["inheritDefaultEnv"] is False
assert config["network"]=={"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"deny"}}
assert config["filesystem"]=={"readonlyPaths":[str(Path("C:/Fixture/inputs"))],"readwritePaths":[str(Path("C:/Fixture/profile"))]}
assert config["ui"]=={"disable":True,"clipboard":"none"}
assert config["fallback"]=={"allowDaclMutation":False}
assert "processContainer" not in config and "runtimeConfig" not in config
for denied in (None, [], required+["PATH=PRIVATE_SENTINEL"]):
    try:
        proof.policy(Path("C:/Fixture/inputs"),Path("C:/Fixture/profile"),Path("C:/Fixture/inputs/actor.exe"),"a"*32,required_environment=denied)
    except ValueError:
        pass
    else:
        raise AssertionError("missing or expanded environment accepted")
def run_capability_regression(proof,observer):
    catalog=observer.catalog()
    assert set(catalog)==set(proof.CAPABILITY_LABELS) and len(catalog)==16
    for name,kind in proof.CAPABILITY_LEGACY_TYPES.items():
        assert observer.equal_sid(catalog[name],observer.known_sid(kind))
    source=observer.source()
    self_actor={"queriesSucceeded":True,"errors":[],"tokenCapabilities":source}
    source_facts=proof.capability_diagnostic(self_actor,source,catalog,equal_sid=observer.equal_sid)
    assert source_facts["catalog_complete"] and source_facts["observed"] and source_facts["source_observed"]
    assert source_facts["invalid"]==[0,0] and source_facts["duplicates"]==[0,0]
    assert source_facts["same_sid_set"] and source_facts["same_attributes"]
    known_actor={"queriesSucceeded":True,"errors":[],"tokenCapabilities":[{"sid":catalog[name],"attributes":6} for name in proof.CAPABILITY_LABELS]}
    known=proof.capability_diagnostic(known_actor,[],catalog,equal_sid=observer.equal_sid)
    assert known["catalog_complete"] and all(row==[1,1,1,0,0,0,0,0,0,0] for row in known["known"])
    unknown_sid="S-1-15-3-4294967294"
    assert not any(observer.equal_sid(unknown_sid,sid) for sid in catalog.values())
    private_name="PRIVATE_CAPABILITY_SENTINEL"
    unknown_actor={"queriesSucceeded":True,"errors":[],"tokenCapabilities":[{"sid":unknown_sid,"attributes":0x80000016}],"private_name":private_name}
    unknown=proof.capability_diagnostic(unknown_actor,[],catalog,equal_sid=observer.equal_sid)
    assert unknown["unknown"]==[1,1,1,1,1,0,0,0,0,0]
    assert all(row==[0]*10 for row in unknown["known"])
    assert proof.closed_capability_diagnostic(unknown)==unknown
    closed=json.dumps(unknown)
    assert unknown_sid not in closed and private_name not in closed
    return {"capability_catalog_validated":True,"capability_source_validated":True,
            "capability_unknown_redacted":True,"legacy_sid_crosschecks_passed":len(proof.CAPABILITY_LEGACY_TYPES)}

# Hosted Server identity/environment is only a read-only diagnostic, never proof
# of an ordinary Windows client or BaseContainer acceptance. Never print paths.
runner_environment="rejected"
runner_environment_error_class="none"
try:
    observed=proof.observe_required_environment()
    if len(observed)==2 and all(type(item) is str for item in observed):
        runner_environment="validated"
except Exception as exc:
    kind=type(exc).__name__
    runner_environment_error_class=kind if kind in ("PermissionError","ValueError","OSError") else "unclassified"
capability_gate_passed=False
capability_error_class="none"
capability_summary={}
try:
    capability_summary=run_capability_regression(proof,proof.WindowsCapabilityObserver())
    capability_gate_passed=True
except Exception as exc:
    kind=type(exc).__name__
    capability_error_class=kind if kind in ("PermissionError","ValueError","OSError","AssertionError") else "unclassified"
print(json.dumps({"actual_powershell_host_wire_records_passed":len(rows),
    "synthetic_environment_cases_passed":2+len(invalid),
    "deny_only_policy_unchanged":True,"policy_environment_negatives_passed":3,
    "runner_environment":runner_environment,"runner_environment_error_class":runner_environment_error_class,
    "runtime_acceptance":False,"capability_gate_passed":capability_gate_passed,
    "capability_error_class":capability_error_class,**capability_summary}))
if runner_environment != "validated" or not capability_gate_passed:
    raise SystemExit(1)
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
    & python -B $parityPath (Join-Path $PSScriptRoot 'windows_identity_direct_stage0.py') $wirePath (Join-Path $PSScriptRoot 'windows_identity_proof.py')
    if ($LASTEXITCODE -ne 0) { throw 'PowerShell to host wire parity failed' }
} finally {
    # Only delete exact paths successfully created by this invocation.
    try { if ($wireOwned) { Remove-Item -LiteralPath $wirePath -Force } }
    finally { if ($parityOwned) { Remove-Item -LiteralPath $parityPath -Force } }
}
$passed+=$wireRecords.Count

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
