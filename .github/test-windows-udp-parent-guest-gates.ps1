# Pure helper/owned-process mocks only; never invoke the guest entrypoint or network.
$ErrorActionPreference='Stop'
$script:fixtureStage='initializing';$script:fixtureMode='none';$script:checks=0
$script:emptyConfigurationRejected=$null
trap {
    $kind=$_.Exception.GetType().Name
    if ($kind -cnotin @('RuntimeException','MethodInvocationException','PropertyNotFoundException','InvalidOperationException','ArgumentException')) { $kind='unclassified' }
    $category=$_.FullyQualifiedErrorId
    if ($category -cnotin @('PropertyNotFoundStrict','PropertyNotFoundException','MethodInvocationException','n0a_fixture')) { $category='unclassified' }
    $closedChecks=if ($script:checks -is [int] -and $script:checks -ge 0 -and $script:checks -le 256) { $script:checks } else { 0 }
    [ordered]@{schema_version=1;passed=$false;failure='guest_fixture';stage=$script:fixtureStage;mode=$script:fixtureMode;checks=$closedChecks;exception_class=$kind;error_category=$category;empty_configuration_rejected=$script:emptyConfigurationRejected} | ConvertTo-Json -Compress
    exit 1
}
Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'windows-identity-direct-stage0-run.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'n0a_parse' }
$names=@('Test-N0aUdpParentConfiguration','Get-N0aRemainingMilliseconds','Wait-N0aOwnedChild','Write-N0aBoundedBody','Invoke-N0aUdpParentGuestDiagnostic','Test-N0aCaptureConfiguration','Get-N0aSha256','Get-N0aUdpParentFlowCommitment','Read-N0aUdpParentPrivateFlow','Send-N0aUdpParentReports')
foreach ($name in $names) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'n0a_function' }
    . ([ScriptBlock]::Create($nodes[0].Extent.Text))
}
$checks=0
function Check([bool]$Value) { if (-not $Value) { throw 'n0a_fixture' }; $script:checks++ }
$config=[PSCustomObject]@{enabled=$true;case_nonce=('a'*32);runner_port=12345;parent_sha256=('b'*64);parent_manifest_sha256=('c'*64);parent_source_sha256=('d'*64);child_sha256=('e'*64);child_manifest_sha256=('f'*64);child_source_sha256=('1'*64);identity_source_sha256=('2'*64);executor_sha256=('3'*64)}
Check (Test-N0aUdpParentConfiguration $config)
$config|Add-Member NoteProperty actor_sha256 ('a'*64);Check (-not (Test-N0aUdpParentConfiguration $config));$config.PSObject.Properties.Remove('actor_sha256')
$config.parent_sha256='bad';Check (-not (Test-N0aUdpParentConfiguration $config));$config.parent_sha256=('b'*64)
$config.enabled='true'; Check (-not (Test-N0aUdpParentConfiguration $config)); $config.enabled=$true
$config.runner_port=$true; Check (-not (Test-N0aUdpParentConfiguration $config)); $config.runner_port=12345
Check ((Get-N0aRemainingMilliseconds 120000 1000 0) -eq 120000)
Check ((Get-N0aRemainingMilliseconds 120000 1000 119999) -eq 1)
Check ((Get-N0aRemainingMilliseconds 120000 1000 120000) -eq 0)
Check ((Get-N0aRemainingMilliseconds 120000 0 0) -eq 0)
$child=[PSCustomObject]@{calls=0;kills=0;ExitCode=7}
$child | Add-Member ScriptMethod WaitForExit { param($ms) $this.calls++; return ($this.calls -gt 1) }
$child | Add-Member ScriptMethod Kill { $this.kills++ }
$f=Wait-N0aOwnedChild $child 10
Check ($f.timed_out -and $f.process_exit_confirmed -and $f.python_exit_code -eq 7 -and $child.kills -eq 1 -and $child.calls -eq 2)
$child=[PSCustomObject]@{calls=0;kills=0;ExitCode=0}
$child | Add-Member ScriptMethod WaitForExit { param($ms) $this.calls++; throw 'fixture' }
$child | Add-Member ScriptMethod Kill { $this.kills++; throw 'fixture' }
$f=Wait-N0aOwnedChild $child 10
Check (-not $f.process_exit_confirmed -and $child.kills -eq 1 -and $child.calls -eq 2)
$sink=[PSCustomObject]@{CanTimeout=$false;WriteTimeout=0;Writes=0}
$sink | Add-Member ScriptMethod Write { param($bytes,$offset,$count) $this.Writes++ }
Check (-not (Write-N0aBoundedBody $sink ([byte[]]@(1)) 200))
Check ($sink.Writes -eq 0)
$sink.CanTimeout=$true
Check (Write-N0aBoundedBody $sink ([byte[]]@(1)) 200)
Check ($sink.Writes -eq 1 -and $sink.WriteTimeout -eq 200)
Check (-not (Write-N0aBoundedBody $sink ([byte[]]@(1)) 0))
Check ($sink.Writes -eq 1)
$script:posted=@()
function Send-N0aUdpParentReports($Configuration,[string]$Workspace,$Envelope) {
    $script:posted+=@($Envelope)
    return $true
}
$full=[PSCustomObject]@{n0a_udp_parent=$config;host_url='http://127.0.0.1/fixture';capture=[PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}}
$r=Invoke-N0aUdpParentGuestDiagnostic $full 'unused' 'unused' 0 1000 $true $true
Check ($r.launcher.failure -ceq 'work_budget_exhausted' -and $r.launcher.budget_exhausted -and $null -eq $r.launcher.process_exit_confirmed -and $null -eq $r.report)
$r=Invoke-N0aUdpParentGuestDiagnostic $full 'unused' 'unused' 0 1000 $false $true
Check ($r.launcher.failure -ceq 'original_unavailable')
$r=Invoke-N0aUdpParentGuestDiagnostic $full 'unused' 'unused' 0 1000 $true $false
Check ($r.launcher.failure -ceq 'original_transport')
Check ($posted.Count -eq 3)
foreach ($entry in $posted) { Check ([Text.Encoding]::ASCII.GetByteCount(($entry | ConvertTo-Json -Depth 16 -Compress)) -le 4096) }
# Execute the real optional orchestrator against an exact owned mock child and file.
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('n0a-guest-gate-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureRoot)
$script:fixtureChild=[PSCustomObject]@{StartInfo=$null;Handle=[IntPtr]1;ExitCode=0;OutputPath=(Join-Path $fixtureRoot 'public-n0a-udp-parent.json');Starts=0;Waits=0;Kills=0;Disposed=$false}
$fixtureChild | Add-Member ScriptMethod Start { $this.Starts++; [IO.File]::WriteAllText($this.OutputPath,'null',[Text.Encoding]::ASCII); return $true }
$fixtureChild | Add-Member ScriptMethod WaitForExit { param($ms) $this.Waits++; return $true }
$fixtureChild | Add-Member ScriptMethod Kill { $this.Kills++ }
$fixtureChild | Add-Member ScriptMethod Dispose { $this.Disposed=$true }
function New-Object {
    param([Parameter(Position=0)][string]$TypeName)
    if ($TypeName -ceq 'Diagnostics.Process') { return $script:fixtureChild }
    return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
}
try {
    $frequency=[Diagnostics.Stopwatch]::Frequency
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+120*$frequency
    $r=Invoke-N0aUdpParentGuestDiagnostic $full $fixtureRoot 'fixture-not-executed.exe' $deadline $frequency $true $true
    Check ($fixtureChild.Starts -eq 1 -and $fixtureChild.Waits -eq 1 -and $fixtureChild.Kills -eq 0 -and $fixtureChild.Disposed)
    Check ($r.launcher.process_exit_confirmed -and $r.launcher.python_exit_code -eq 0 -and $null -eq $r.report -and $r.launcher.failure -ceq 'operation_failed')
    Check ($fixtureChild.StartInfo.Arguments.Contains('--deadline-qpc '+($deadline-20*$frequency).ToString([Globalization.CultureInfo]::InvariantCulture)))
    Check ($posted.Count -eq 4)
    # A pre-existing result is retained on timeout/unknown child exit, never promoted.
    [IO.File]::Delete($fixtureChild.OutputPath)
    $fixtureChild | Add-Member ScriptMethod Start { $this.Starts++; [IO.File]::WriteAllText($this.OutputPath,'{"result":{"status":"selected_echo_observed"}}',[Text.Encoding]::ASCII); return $true } -Force
    $fixtureChild | Add-Member ScriptMethod WaitForExit { param($ms) $this.Waits++; return $false } -Force
    $fixtureChild | Add-Member ScriptMethod Kill { $this.Kills++; throw 'fixture' } -Force
    $r=Invoke-N0aUdpParentGuestDiagnostic $full $fixtureRoot 'fixture-not-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.timed_out -and -not $r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'timeout')
    Check ($r.report.result.status -ceq 'selected_echo_observed')
    Check ($posted.Count -eq 5 -and $posted[4].report.result.status -ceq 'selected_echo_observed')

} finally {
    Remove-Item Function:\New-Object
    $owned=Join-Path $fixtureRoot 'public-n0a-udp-parent.json'
    if (Test-Path -LiteralPath $owned) { [IO.File]::Delete($owned) }
    [IO.Directory]::Delete($fixtureRoot,$false)
}
# Restore actual UDP reporter after orchestrator mocks. No sockets/guest entrypoint.
$node=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Send-N0aUdpParentReports'},$true))
. ([ScriptBlock]::Create($node[0].Extent.Text))
$capture=[PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}
Check (Test-N0aCaptureConfiguration $capture)
$capture.enabled=1; Check (-not (Test-N0aCaptureConfiguration $capture)); $capture.enabled=$true
$capture.vm_mac='535400123456'; Check (-not (Test-N0aCaptureConfiguration $capture)); $capture.vm_mac='525400123456'
$reports=[ordered]@{};$index=0
foreach($role in @('before','sample','after','contained')) {
    $index++
    $chain=[ordered]@{};foreach($key in @('parent_profile','child_profile','parent_pid_bound','child_pid_bound','sid_equal','child_hash_bound','resume_verified','wait_verified','child_report_bound','deadline_verified')){$chain[$key]=$false}
    $reports[$role]=[ordered]@{parent_source=@{sha256=([string]$index*64);bytes=100*$index};child_source=@{sha256=([string]($index+4)*64);bytes=200*$index};
        udp=@{version=1;endpoint='runner';phase=$role;port=12345;profileMatched=$true;startupError=0;qpcFrequency=1000;windowStartQpc=1;windowEndQpc=2;attempts=@();testOnly=$false;socketsCleanupConfirmed=$true};chain=$chain}
}
$binding=[ordered]@{run_nonce=('1'*32);case_nonce=('a'*32);source_commit=('2'*40);build=26300;ubr=9457}
foreach($key in @('parent_sha256','parent_manifest_sha256','parent_source_sha256','child_sha256','child_manifest_sha256','child_source_sha256','identity_source_sha256','executor_sha256')){$binding[$key]=$config.$key}
$flow=[ordered]@{schema_version=1;protocol='udp-parent';binding=$binding;endpoint=@{vm_mac='525400123456';destination_ipv4='10.0.2.2';destination_port=12345};reports=$reports}
$raw=[Text.Encoding]::ASCII.GetBytes(($flow|ConvertTo-Json -Depth 16 -Compress))
$invalidRejected=$false
try { [void](Get-N0aUdpParentFlowCommitment ([Text.Encoding]::ASCII.GetBytes('{}'))) } catch { $invalidRejected=$true }
Check $invalidRejected
foreach($invalid in @([byte[]]::new(65537),[byte[]]@(255),[Text.Encoding]::ASCII.GetBytes('{"schema_version":true,"protocol":"udp-parent"}'))) {
    $rejected=$false;try{$null=Get-N0aUdpParentFlowCommitment $invalid}catch{$rejected=$true};Check $rejected
}
$commitment=Get-N0aUdpParentFlowCommitment $raw
Check ($commitment.ordinary_report_sha256 -cmatch '^[0-9a-f]{64}$')
Check ($commitment.sha256 -ceq (Get-N0aSha256 $raw) -and $commitment.bytes -eq $raw.Length)
$root=Join-Path ([IO.Path]::GetTempPath()) ('n0a-flow-gate-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'private-parent-udp'))
$path=Join-Path $root 'private-parent-udp/runner-flow.json'
try {
    [IO.File]::WriteAllBytes($path,$raw)
    $actual=Read-N0aUdpParentPrivateFlow $root
    Check ([Convert]::ToBase64String($actual.body) -ceq [Convert]::ToBase64String($raw))
    Check ($actual.commitment.sha256 -ceq $commitment.sha256)
    $parity=Join-Path $root 'parity.py';$expected=Join-Path $root 'expected.json';$errorFile=Join-Path $root 'parity-error.txt'
    $code=@'
import importlib.util,json,pathlib,sys
try:
    spec=importlib.util.spec_from_file_location('parent_flow_parity',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    raw=pathlib.Path(sys.argv[2]).read_bytes()
    result=module.commitment(raw)
    pathlib.Path(sys.argv[3]).write_text(json.dumps(result,separators=(',',':')),encoding='ascii')
except Exception:
    print('{"failure":"parent_flow_parity"}');raise SystemExit(1)
'@
    [IO.File]::WriteAllText($parity,$code,[Text.Encoding]::ASCII)
    & python -B $parity (Join-Path $PSScriptRoot 'windows_n0a_udp_parent_flow.py') $path $expected 2> $errorFile
    Check ($LASTEXITCODE -eq 0)
    $pythonCommitment=Get-Content -LiteralPath $expected -Raw|ConvertFrom-Json
    foreach($key in @('sha256','bytes','contained_report_sha256','ordinary_report_sha256')){Check ($actual.commitment[$key] -ceq $pythonCommitment.$key)}
} finally { foreach($name in @('parity.py','expected.json','parity-error.txt')){[IO.File]::Delete((Join-Path $root $name))};[IO.File]::Delete($path); [IO.Directory]::Delete((Join-Path $root 'private-parent-udp')); [IO.Directory]::Delete($root) }
$script:flowBody=$raw; $script:flowCommitment=$commitment; $script:prepareThrows=$false
function Read-N0aUdpParentPrivateFlow([string]$Workspace) {
    if ($script:prepareThrows) { throw 'fixture' }
    return @{body=$script:flowBody;commitment=$script:flowCommitment}
}
$script:calls=@(); $script:clocks=@(); $script:resultOkay=$true; $script:consume=$false; $script:clockCount=0
function New-N0aReportingClock { $script:clockCount++; return [PSCustomObject]@{ElapsedMilliseconds=0} }
function Send-N0aCaptureRequest([string]$Url,[byte[]]$Body,$Clock) {
    $script:calls+=@(@{url=$Url;body=$Body}); $script:clocks+=@($Clock)
    if ($script:consume) { $Clock.ElapsedMilliseconds=10000 }
    if ($Url.EndsWith('/udp-parent-capture-result')) { return $script:resultOkay }
    return $false
}
$envelope=@{schema_version=1;report=@{result=@{status='selected_echo_observed'}}}
Check (Send-N0aUdpParentReports $full 'unused' $envelope)
Check ($calls.Count -eq 2 -and $calls[0].url.EndsWith('/udp-parent-capture-result') -and $calls[1].url.EndsWith('/udp-parent-runner-flow'))
$wire=[Text.Encoding]::ASCII.GetString($calls[0].body)|ConvertFrom-Json
Check ($wire.schema_version -eq 4 -and 'parent_udp' -cin @($wire.PSObject.Properties.Name) -and 'udp' -cnotin @($wire.PSObject.Properties.Name))
Check ([object]::ReferenceEquals($clocks[0],$clocks[1]) -and $clockCount -eq 1)
Check ([Convert]::ToBase64String($calls[1].body) -ceq [Convert]::ToBase64String($raw))
$script:calls=@();$script:clocks=@();$script:resultOkay=$false
Check (-not (Send-N0aUdpParentReports $full 'unused' $envelope)); Check ($calls.Count -eq 1)
$script:calls=@();$script:resultOkay=$true;$script:consume=$true
Check (Send-N0aUdpParentReports $full 'unused' $envelope); Check ($calls.Count -eq 1)
$script:calls=@();$script:consume=$false;$script:prepareThrows=$true
Check (Send-N0aUdpParentReports $full 'unused' $envelope); Check ($calls.Count -eq 1)
$sent=[Text.Encoding]::ASCII.GetString($calls[0].body) | ConvertFrom-Json
Check ($null -eq $sent.flow_commitment -and $sent.parent_udp.report.result.status -ceq 'selected_echo_observed')
Check ([Text.Encoding]::ASCII.GetByteCount(($sent|ConvertTo-Json -Depth 20 -Compress)) -le 4096)


[ordered]@{schema_version=1;passed=$true;checks=$script:checks;process_and_transport_mocked=$true;udp_guest_execution=$false;runtime_acceptance=$false} | ConvertTo-Json -Compress
