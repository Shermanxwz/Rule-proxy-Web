# Windows compile-job only. Pure synthetic predicates plus read-only runner facts.
# Never invoke the guest entrypoint, create an account/task or start a VM.
# ACL changes are restricted to the exact newly owned temporary test fixture.
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
# Native Windows zone rules, no machine clock/timezone mutation. UTC instants
# avoid ambiguous local-time reverse conversion at the autumn transition.
$pacificZone=[TimeZoneInfo]::FindSystemTimeZoneById('Pacific Standard Time')
$clockFixtures=@(
    @{utc='2026-01-15T12:00:00Z';offset=-480},@{utc='2026-07-15T12:00:00Z';offset=-420},
    @{utc='2026-03-08T09:59:59Z';offset=-480},@{utc='2026-03-08T10:00:00Z';offset=-420},
    @{utc='2026-11-01T08:59:59Z';offset=-420},@{utc='2026-11-01T09:00:00Z';offset=-480})
foreach ($clockFixture in $clockFixtures) {
    $clockNow=([DateTimeOffset]::Parse($clockFixture.utc,[Globalization.CultureInfo]::InvariantCulture)).UtcDateTime
    $clockFacts=Get-ServicedClockFacts $pacificZone $clockNow
    if (-not $clockFacts.zone_pacific -or -not $clockFacts.offset_matches -or $clockFacts.utc_offset_minutes -ne $clockFixture.offset) { throw 'Pacific native seasonal rule failed' }
    Assert-ServicedClock -Zone $pacificZone -UtcNow $clockNow
    $passed++
}
$summerNow=([DateTimeOffset]::Parse('2026-07-15T12:00:00Z')).UtcDateTime
$fixedPacific=[TimeZoneInfo]::CreateCustomTimeZone('Pacific Standard Time',[TimeSpan]::FromHours(-8),'fixture','fixture')
foreach ($wrongZone in @([TimeZoneInfo]::Utc,$fixedPacific)) {
    $script:ServicingReadDiagnostic=@{step='not_started';reason='none';remaining_seconds=$null;zone_pacific=$null;utc_offset_minutes=$null}
    $clockRejected=$false
    try { Assert-ServicedClock -Zone $wrongZone -UtcNow $summerNow } catch { $clockRejected=$true }
    if (-not $clockRejected -or $script:ServicingReadDiagnostic.reason -cne 'clock_contract') { throw 'Wrong clock contract accepted' }; $passed++
}
$runnerClock=Get-ServicedClockFacts ([TimeZoneInfo]::Local) ([DateTime]::UtcNow)
Write-Output ((@{fixture='runner_clock_observation';zone_pacific=$runnerClock.zone_pacific;utc_offset_minutes=$runnerClock.utc_offset_minutes;guest_acceptance=$false})|ConvertTo-Json -Compress)
$script:ServicingReadDiagnostic=@{step='not_started';reason='none';remaining_seconds=$null;zone_pacific=$null;utc_offset_minutes=$null}
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

# Real owned NTFS ACL + serialization/reader regression. No account/task/VM.
# Hosted runner is not guest SYSTEM: explicit trusted fixture owner is deliberate.
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('rp-serviced-acl-'+[Guid]::NewGuid().ToString('N'))
$fixtureCreated=$false; $fixtureCleanup=$false
try {
    $null=New-Item -ItemType Directory -Path $fixtureRoot
    $fixtureCreated=$true
    $fixtureAdmins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $fixtureSystem=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $fixtureUsers=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $fixtureAcl=New-Object Security.AccessControl.DirectorySecurity
    $fixtureAcl.SetOwner($fixtureAdmins); $fixtureAcl.SetAccessRuleProtection($true,$false)
    foreach ($fixtureSid in @($fixtureSystem,$fixtureAdmins)) {
        $fixtureAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($fixtureSid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    $fixtureAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($fixtureUsers,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $fixtureRoot -AclObject $fixtureAcl
    $fixtureWorker=[IO.Path]::Combine($fixtureRoot,'copied-worker.ps1')
    Copy-Item -LiteralPath $helper -Destination $fixtureWorker
    $callerRootBefore=$PSScriptRoot
    . $fixtureWorker
    if ($PSScriptRoot -cne $callerRootBefore) { throw 'Dot-source caller root changed' }
    Write-Output ((@{fixture='dot_source_root';caller_root_preserved=$true;worker_entry_not_invoked=$true})|ConvertTo-Json -Compress)
    $passed++
    $closedReadDefinitions=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-ClosedServicingReadDiagnostic'},$false))
    if ($closedReadDefinitions.Count -ne 1) { throw 'Closed service reader ambiguous' }
    . ([ScriptBlock]::Create($closedReadDefinitions[0].Extent.Text))
    $closedRead=Get-ClosedServicingReadDiagnostic ([PSCustomObject]@{step='PRIVATE_PATH';reason='PRIVATE_IDENTITY';remaining_seconds=172801;zone_pacific='PRIVATE_RAW';utc_offset_minutes=841;private='PRIVATE_RAW'})
    if ($closedRead.Count -ne 5 -or $closedRead.step -cne 'not_started' -or $closedRead.reason -cne 'none' -or $null -ne $closedRead.remaining_seconds -or $null -ne $closedRead.zone_pacific -or $null -ne $closedRead.utc_offset_minutes -or ($closedRead|ConvertTo-Json -Compress).Contains('PRIVATE')) { throw 'Closed setup reader leaked fixture' }
    foreach ($boundary in @(-172800,0,172800)) {
        $closedRead=Get-ClosedServicingReadDiagnostic ([PSCustomObject]@{step='budget_epoch';reason='expired';remaining_seconds=$boundary})
        if ($closedRead.remaining_seconds -ne $boundary -or $closedRead.step -cne 'budget_epoch' -or $closedRead.reason -cne 'expired') { throw 'Closed setup reader boundary failed' }; $passed++
    }
    foreach ($offsetValue in @(-480,-420,0,'-420',$true,$null)) {
        $closedOffset=Get-ClosedServicingReadDiagnostic ([PSCustomObject]@{zone_pacific=$true;utc_offset_minutes=$offsetValue})
        $offsetAllowed=($offsetValue -is [int] -and $offsetValue -in @(-480,-420))
        if ($closedOffset.zone_pacific -ne $true -or ($offsetAllowed -and $closedOffset.utc_offset_minutes -ne $offsetValue) -or (-not $offsetAllowed -and $null -ne $closedOffset.utc_offset_minutes)) { throw 'Clock projection type or allowlist failed' }; $passed++
    }
    $script:BudgetFixtureRoot=$fixtureRoot
    # Redirect only the production fixed root; file, ACL and JSON cmdlets are real.
    function Join-Path {
        param($Path,$ChildPath)
        if ($Path -cne 'C:\RuleProxyCIUpdates' -or $ChildPath -cne 'service-budget.json') { throw 'Unexpected fixture path operation' }
        return [IO.Path]::Combine($script:BudgetFixtureRoot,$ChildPath)
    }
    foreach ($fixtureSource in @($source,$helper)) {
        $fixtureAst=[System.Management.Automation.Language.Parser]::ParseFile($fixtureSource,[ref]$tokens,[ref]$errors)
        if ($errors.Count -ne 0) { throw 'ACL fixture parser failed' }
        foreach ($fixtureName in @('Assert-UpdateFile','Assert-ProtectedUpdatePath','ConvertTo-ServicedDeadline','Get-ServicedDeadline')) {
            $fixtureDefinitions=@($fixtureAst.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $fixtureName},$false))
            if ($fixtureDefinitions.Count -ne 1) { throw 'ACL fixture function ambiguous' }
            . ([ScriptBlock]::Create($fixtureDefinitions[0].Extent.Text))
        }
        Assert-ProtectedUpdatePath $fixtureRoot -Directory -ProtectedDacl
        $fixtureFile=[IO.Path]::Combine($fixtureRoot,'service-budget.json')
        $fixtureEpoch=([DateTimeOffset]::UtcNow.AddMinutes(30)).ToUnixTimeSeconds()
        $fixtureCases=@(
            @{name='valid';raw=(@{schema=1;deadline_unix_seconds=$fixtureEpoch}|ConvertTo-Json -Compress);reason='none'},
            @{name='missing';raw=$null;reason='missing'},
            @{name='json';raw='{';reason='json'},
            @{name='schema';raw='{"schema":2,"deadline_unix_seconds":1}';reason='schema'},
            @{name='type';raw='{"schema":1,"deadline_unix_seconds":"1"}';reason='type'},
            @{name='expired';raw='{"schema":1,"deadline_unix_seconds":1}';reason='expired'},
            @{name='future';raw=(@{schema=1;deadline_unix_seconds=([DateTimeOffset]::UtcNow.AddHours(3)).ToUnixTimeSeconds()}|ConvertTo-Json -Compress);reason='over_bound'},
            @{name='size';raw=('x'*1025);reason='over_bound'},
            @{name='write_acl';raw=(@{schema=1;deadline_unix_seconds=$fixtureEpoch}|ConvertTo-Json -Compress);reason='acl'},
            @{name='owner';raw=(@{schema=1;deadline_unix_seconds=$fixtureEpoch}|ConvertTo-Json -Compress);reason='acl'}
        )
        foreach ($fixtureCase in $fixtureCases) {
            if (Test-Path -LiteralPath $fixtureFile) { Remove-Item -LiteralPath $fixtureFile -Force }
            if ($null -ne $fixtureCase.raw) {
                [IO.File]::WriteAllText($fixtureFile,$fixtureCase.raw,[Text.Encoding]::ASCII)
                $fileAcl=Get-Acl -LiteralPath $fixtureFile
                $naturalOwnerTrusted=$fileAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18','S-1-5-32-544')
                $fileAcl.SetOwner($fixtureAdmins)
                if ($fixtureCase.name -ceq 'write_acl') { $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($fixtureUsers,'Write','Allow'))) }
                if ($fixtureCase.name -ceq 'owner') { $fileAcl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User) }
                Set-Acl -LiteralPath $fixtureFile -AclObject $fileAcl
            }
            $script:ServicingReadDiagnostic=@{step='not_started';reason='none';remaining_seconds=$null}
            $fixtureRejected=$false; $fixtureDeadline=$null
            try { $fixtureDeadline=Get-ServicedDeadline } catch { $fixtureRejected=$true }
            $fixturePass=($fixtureRejected -eq ($fixtureCase.reason -cne 'none')) -and ($script:ServicingReadDiagnostic.reason -ceq $fixtureCase.reason)
            if ($fixtureCase.name -ceq 'valid') {
                $observedFileAcl=Get-Acl -LiteralPath $fixtureFile
                $usersReadRules=@($observedFileAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ceq 'S-1-5-32-545' -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow })
                $readMask=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::ReadPermissions
                $writeMask=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
                $usersReadVerified=$usersReadRules.Count -eq 1 -and $usersReadRules[0].IsInherited -and (($usersReadRules[0].FileSystemRights -band $readMask) -eq $readMask) -and (($usersReadRules[0].FileSystemRights -band $writeMask) -eq 0)
                $roundtripBudget=Get-Content -LiteralPath $fixtureFile -Raw | ConvertFrom-Json
                $epochIsInteger=$roundtripBudget.deadline_unix_seconds -is [int] -or $roundtripBudget.deadline_unix_seconds -is [long]
                if (-not $usersReadVerified -or -not $epochIsInteger) { throw 'Inherited Users read or serialized epoch fixture failed' }
                $fixturePass=$fixturePass -and (([DateTimeOffset]$fixtureDeadline).ToUnixTimeSeconds() -eq $fixtureEpoch)
                Write-Output ((@{fixture='trusted_acl_roundtrip';natural_owner_trusted=$naturalOwnerTrusted;explicit_trusted_owner=$true;directory_acl_verified=$true;users_inherited_read_verified=$usersReadVerified;ordinary_token_read_tested=$false;epoch_is_integer=$epochIsInteger;roundtrip_passed=$fixturePass})|ConvertTo-Json -Compress)
            }
            Write-Output ((@{fixture=$fixtureCase.name;rejected=$fixtureRejected;reason=$script:ServicingReadDiagnostic.reason;step=$script:ServicingReadDiagnostic.step;passed=$fixturePass})|ConvertTo-Json -Compress)
            if (-not $fixturePass) { throw 'Real ACL budget fixture failed' }
            $passed++
        }
    }
    # Production writer/reader/guard, using an actual native CIM boot witness.
    # This is NOT a reboot or ordinary-user acceptance test.
    Remove-Item Function:\Join-Path -ErrorAction SilentlyContinue
    $originalUpdateDirectory=$script:UpdateDirectory
    $script:UpdateDirectory=$fixtureRoot
    try {
        $nativeBoot=Get-ServicedBoot
        $bootBeforeString=$nativeBoot -is [string]
        $bootBeforeShape=$bootBeforeString -and $nativeBoot -cmatch '^[0-9]{15,20}$'
        if (-not $bootBeforeShape) { throw 'Native boot producer type or shape failed' }
        $priorPath=[IO.Path]::Combine($fixtureRoot,'update-state.json')
        foreach ($exitFixture in @(0,3010)) {
            $producer=@{schema_version=1;target_build=26200;target_ubr=9711;status='reboot_pending';phase='reboot_pending';failure='none';dism_exit_code=$exitFixture;before_boot=$nativeBoot;packages_verified=$true;prior_service=(Get-ClosedPriorService $null)}
            $replaceExpected=Test-Path -LiteralPath $priorPath
            Write-ServicedState $producer
            $priorFileAcl=Get-Acl -LiteralPath $priorPath
            $writerOwnerTrusted=$priorFileAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18','S-1-5-32-544')
            $priorFileAcl.SetOwner($fixtureAdmins); Set-Acl -LiteralPath $priorPath -AclObject $priorFileAcl
            $roundtrip=Get-Content -LiteralPath $priorPath -Raw | ConvertFrom-Json
            $roundtripFacts=Get-PriorServiceFacts $roundtrip
            $bootAfterString=$roundtrip.before_boot -is [string]
            $bootSame=$bootAfterString -and $roundtrip.before_boot -ceq $nativeBoot
            $exitInteger=$roundtrip.dism_exit_code -is [int] -or $roundtrip.dism_exit_code -is [long]
            $packageBoolean=$roundtrip.packages_verified -is [bool] -and $roundtrip.packages_verified -eq $true
            $guardPassed=$false
            try { Assert-ServicedPriorState $roundtrip; $guardPassed=$true } catch { }
            Write-Output ((@{fixture='native_boot_state_roundtrip';replace=$replaceExpected;writer_owner_trusted=$writerOwnerTrusted;before_string=$bootBeforeString;before_shape=$bootBeforeShape;after_string=$bootAfterString;same_value=$bootSame;exit_integer=$exitInteger;package_boolean=$packageBoolean;predicate_mask=$roundtripFacts.b;guard_passed=$guardPassed;reboot_tested=$false})|ConvertTo-Json -Compress)
            if (-not $bootSame -or -not $exitInteger -or -not $packageBoolean -or $roundtripFacts.b -ne 127 -or -not $guardPassed) { throw 'Native state serialization regression' }; $passed++
        }
        $tamperCases=@(
            @{field='schema_version';value=2;bit=1},@{field='target_build';value=0;bit=2},@{field='target_ubr';value=0;bit=4},
            @{field='status';value='installing';bit=8},@{field='status';value='failed';bit=8},@{field='status';value='completed';bit=8},
            @{field='dism_exit_code';value=87;bit=16},@{field='before_boot';value=123;bit=32},@{field='before_boot';value='PRIVATE_BOOT';bit=32},
            @{field='packages_verified';value=$false;bit=64})
        foreach ($tamper in $tamperCases) {
            $changed=$producer.Clone(); $changed[$tamper.field]=$tamper.value
            if ($tamper.field -ceq 'status' -and $tamper.value -ceq 'failed') { $changed.failure='dism_deadline' }
            Write-ServicedState $changed
            $readChanged=Get-Content -LiteralPath $priorPath -Raw | ConvertFrom-Json
            $changedFacts=Get-PriorServiceFacts $readChanged
            $rejected=$false
            try { Assert-ServicedPriorState $readChanged } catch { $rejected=$true }
            if (-not $rejected -or $changedFacts.b -ne (127 -bxor $tamper.bit)) { throw 'Prior field rejection or predicate changed' }
            if ($tamper.field -ceq 'status' -and $tamper.value -ceq 'failed' -and $changedFacts.f -cne 'dism_deadline') { throw 'Original failed cause lost' }
            $passed++
        }
        foreach ($missing in @('schema_version','target_build','target_ubr','status','dism_exit_code','before_boot','packages_verified')) {
            $changed=$producer.Clone(); $changed.Remove($missing)
            Write-ServicedState $changed
            $readChanged=Get-Content -LiteralPath $priorPath -Raw | ConvertFrom-Json
            $changedFacts=Get-PriorServiceFacts $readChanged
            $rejected=$false
            try { Assert-ServicedPriorState $readChanged } catch { $rejected=$true }
            if (-not $rejected -or $changedFacts.b -eq 127) { throw 'Missing prior field accepted' }; $passed++
        }
        # Closed snapshot survives a later failed receipt without raw/nested data.
        $first=Get-PriorServiceFacts ([PSCustomObject]@{status='failed';phase='installing_official_cu';failure='dism_deadline';dism_exit_code=$null})
        $later=$producer.Clone();$later.status='failed';$later.failure='prior_state';$later.prior_service=$first
        Write-ServicedState $later
        $readLater=Get-Content -LiteralPath $priorPath -Raw | ConvertFrom-Json
        $preserved=Get-RetainedPriorService $readLater (Get-PriorServiceFacts $readLater)
        foreach ($key in @('s','p','f','e','b')) { if ($preserved[$key] -cne $first[$key]) { throw 'First closed prior snapshot changed' } }
        if ($preserved.f -cne 'dism_deadline' -or $preserved.Count -ne 5) { throw 'First closed prior snapshot shape changed' };$passed++
        $redacted=Get-ClosedPriorService ([PSCustomObject]@{s='PRIVATE';p='PRIVATE';f='PRIVATE';e='PRIVATE';b=128;raw=$nativeBoot})
        if (($redacted|ConvertTo-Json -Compress).Contains('PRIVATE') -or $null -ne $redacted.b -or $redacted.Count -ne 5) { throw 'Prior snapshot redaction failed' };$passed++
        [IO.File]::WriteAllText($priorPath,'{',[Text.UTF8Encoding]::new($false))
        $rejected=$false
        try { $null=Get-Content -LiteralPath $priorPath -Raw | ConvertFrom-Json } catch { $rejected=$true }
        if (-not $rejected) { throw 'Malformed prior JSON accepted' };$passed++
    } finally { $script:UpdateDirectory=$originalUpdateDirectory }
} catch {
    Write-Output ((@{fixture='acl_operation';failed=$true;hresult=[int]$_.Exception.HResult})|ConvertTo-Json -Compress)
    throw 'Real owned ACL fixture operation failed'
} finally {
    Remove-Item Function:\Join-Path -ErrorAction SilentlyContinue
    if ($fixtureCreated) {
        # Exact freshly owned tree only; reject unexpected reparse children.
        foreach ($fixtureItem in @(Get-ChildItem -LiteralPath $fixtureRoot -Force)) {
            if ($fixtureItem.PSIsContainer -or ($fixtureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Fixture cleanup boundary' }
            Remove-Item -LiteralPath $fixtureItem.FullName -Force
        }
        Remove-Item -LiteralPath $fixtureRoot -Force
        $fixtureCleanup=-not (Test-Path -LiteralPath $fixtureRoot)
        Write-Output ((@{fixture='acl_cleanup';removed=$fixtureCleanup})|ConvertTo-Json -Compress)
        if (-not $fixtureCleanup) { throw 'Fixture cleanup failed' }
    }
}

# Execute the actual wait helper with owned mock objects, never DISM/processes.
foreach ($scenario in @('success','timeout','unknown_exit','null_exit','string_exit')) {
    $state=@{dism_exit_code=$null;dism_wait_timed_out=$false;dism_exit_observed=$false;dism_exit_observation_available=$false}
    $process=[PSCustomObject]@{Scenario=$scenario;ExitCode=0;WaitArgument=0}
    $process | Add-Member ScriptMethod WaitForExit { param($milliseconds) $this.WaitArgument=$milliseconds; return ($this.Scenario -ceq 'success') }
    $process | Add-Member ScriptMethod Refresh { }
    $process | Add-Member ScriptProperty HasExited { if ($this.Scenario -ceq 'unknown_exit') { throw 'fixture_observation_unavailable' }; if ($this.Scenario -ceq 'null_exit') { return $null }; if ($this.Scenario -ceq 'string_exit') { return 'False' }; return ($this.Scenario -ceq 'success') }
    $failure=$null
    try { Wait-ServicedDism $process 1234 $state } catch { $failure=$_.Exception.Message }
    # Fixed fixture label and closed flags make any failed branch identifiable.
    Write-Output (([ordered]@{fixture=$scenario;wait_timed_out=$state.dism_wait_timed_out;exit_observed=$state.dism_exit_observed;observation_available=$state.dism_exit_observation_available;deadline_failure=($failure -ceq 'dism_deadline');exit_code_zero=($state.dism_exit_code -ceq 0)}) | ConvertTo-Json -Compress)
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
