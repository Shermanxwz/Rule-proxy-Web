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
$names=@('Test-N0aConfiguration','Get-N0aRemainingMilliseconds','Wait-N0aOwnedChild','Write-N0aBoundedBody','Invoke-N0aUdp6GuestDiagnostic','Test-N0aCaptureConfiguration','Get-N0aSha256','Get-N0aUdp6FlowCommitment','Read-N0aUdp6PrivateFlow','Send-N0aUdp6Reports')
foreach ($name in $names) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'n0a_function' }
    . ([ScriptBlock]::Create($nodes[0].Extent.Text))
}
$checks=0
function Check([bool]$Value) { if (-not $Value) { throw 'n0a_fixture' }; $script:checks++ }
$config=[PSCustomObject]@{enabled=$true;case_nonce=('a'*32);runner_port=12345;actor_sha256=('b'*64);manifest_sha256=('c'*64);actor_source_sha256=('d'*64);identity_source_sha256=('e'*64)}
Check (Test-N0aConfiguration $config)
$config.enabled='true'; Check (-not (Test-N0aConfiguration $config)); $config.enabled=$true
$config.runner_port=$true; Check (-not (Test-N0aConfiguration $config)); $config.runner_port=12345
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
function Send-N0aUdp6Reports($Configuration,[string]$Workspace,$Envelope) {
    $script:posted+=@($Envelope)
    return $true
}
$full=[PSCustomObject]@{n0a_udp6=$config;host_url='http://127.0.0.1/fixture';capture=[PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}}
$r=Invoke-N0aUdp6GuestDiagnostic $full 'unused' 'unused' 0 1000 $true $true
Check ($r.launcher.failure -ceq 'work_budget_exhausted' -and $r.launcher.budget_exhausted -and $null -eq $r.launcher.process_exit_confirmed -and $null -eq $r.report)
$r=Invoke-N0aUdp6GuestDiagnostic $full 'unused' 'unused' 0 1000 $false $true
Check ($r.launcher.failure -ceq 'original_unavailable')
$r=Invoke-N0aUdp6GuestDiagnostic $full 'unused' 'unused' 0 1000 $true $false
Check ($r.launcher.failure -ceq 'original_transport')
Check ($posted.Count -eq 3)
foreach ($entry in $posted) { Check ([Text.Encoding]::ASCII.GetByteCount(($entry | ConvertTo-Json -Depth 16 -Compress)) -le 4096) }
# Execute the real optional orchestrator against an exact owned mock child and file.
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('n0a-guest-gate-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureRoot)
$script:fixtureChild=[PSCustomObject]@{StartInfo=$null;Handle=[IntPtr]1;ExitCode=0;OutputPath=(Join-Path $fixtureRoot 'public-n0a-udp6.json');Starts=0;Waits=0;Kills=0;Disposed=$false}
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
    $r=Invoke-N0aUdp6GuestDiagnostic $full $fixtureRoot 'fixture-not-executed.exe' $deadline $frequency $true $true
    Check ($fixtureChild.Starts -eq 1 -and $fixtureChild.Waits -eq 1 -and $fixtureChild.Kills -eq 0 -and $fixtureChild.Disposed)
    Check ($r.launcher.process_exit_confirmed -and $r.launcher.python_exit_code -eq 0 -and $null -eq $r.report -and $r.launcher.failure -ceq 'operation_failed')
    Check ($fixtureChild.StartInfo.Arguments.Contains('--deadline-qpc '+($deadline-20*$frequency).ToString([Globalization.CultureInfo]::InvariantCulture)))
    Check ($posted.Count -eq 4)
    # A pre-existing result is retained on timeout/unknown child exit, never promoted.
    [IO.File]::Delete($fixtureChild.OutputPath)
    $fixtureChild | Add-Member ScriptMethod Start { $this.Starts++; [IO.File]::WriteAllText($this.OutputPath,'{"result":{"status":"selected_echo_observed"}}',[Text.Encoding]::ASCII); return $true } -Force
    $fixtureChild | Add-Member ScriptMethod WaitForExit { param($ms) $this.Waits++; return $false } -Force
    $fixtureChild | Add-Member ScriptMethod Kill { $this.Kills++; throw 'fixture' } -Force
    $r=Invoke-N0aUdp6GuestDiagnostic $full $fixtureRoot 'fixture-not-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.timed_out -and -not $r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'timeout')
    Check ($r.report.result.status -ceq 'selected_echo_observed')
    Check ($posted.Count -eq 5 -and $posted[4].report.result.status -ceq 'selected_echo_observed')

} finally {
    Remove-Item Function:\New-Object
    $owned=Join-Path $fixtureRoot 'public-n0a-udp6.json'
    if (Test-Path -LiteralPath $owned) { [IO.File]::Delete($owned) }
    [IO.Directory]::Delete($fixtureRoot,$false)
}
# Restore actual UDP reporter after orchestrator mocks. No sockets/guest entrypoint.
$node=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Send-N0aUdp6Reports'},$true))
. ([ScriptBlock]::Create($node[0].Extent.Text))
$capture=[PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}
Check (Test-N0aCaptureConfiguration $capture)
$capture.enabled=1; Check (-not (Test-N0aCaptureConfiguration $capture)); $capture.enabled=$true
$capture.vm_mac='535400123456'; Check (-not (Test-N0aCaptureConfiguration $capture)); $capture.vm_mac='525400123456'
$raw=[Text.Encoding]::ASCII.GetBytes('{"schema_version":1,"protocol":"udp6","reports":{"before":{"sha256":"'+('1'*64)+'","bytes":100},"sample":{"sha256":"'+('2'*64)+'","bytes":200},"after":{"sha256":"'+('3'*64)+'","bytes":300},"contained":{"sha256":"'+('4'*64)+'","bytes":400}}}')
$invalidRejected=$false
try { [void](Get-N0aUdp6FlowCommitment ([Text.Encoding]::ASCII.GetBytes('{}'))) } catch { $invalidRejected=$true }
Check $invalidRejected
$commitment=Get-N0aUdp6FlowCommitment $raw
Check ($commitment.ordinary_report_sha256 -ceq '13d96232743ee170fd8df8db4ac71e6529a7bd14b44a9b0364512f962a4e02a2')
Check ($commitment.sha256 -ceq (Get-N0aSha256 $raw) -and $commitment.bytes -eq $raw.Length)
$root=Join-Path ([IO.Path]::GetTempPath()) ('n0a-flow-gate-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'private-udp6'))
$path=Join-Path $root 'private-udp6/runner-flow.json'
try {
    [IO.File]::WriteAllBytes($path,$raw)
    $actual=Read-N0aUdp6PrivateFlow $root
    Check ([Convert]::ToBase64String($actual.body) -ceq [Convert]::ToBase64String($raw))
    Check ($actual.commitment.sha256 -ceq $commitment.sha256)
    # Actual Python strict bundle/commitment versus actual PS helper; synthetic
    # network facts only, no socket/native actor or guest entrypoint.
    $parityFlow=Join-Path $root 'parity-flow.json'
    $parityCommitment=Join-Path $root 'parity-commitment.json'
    $program=@'
import pathlib,sys,importlib.util,json
try:
    source=pathlib.Path(sys.argv[1])/'tests/test_windows_client_n0a_udp6_flow.py'
    spec=importlib.util.spec_from_file_location('udp6_ps_fixture',source)
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    raw=fixture.f.encode(fixture.value());commit=fixture.f.commitment(raw)
    with open(sys.argv[2],'xb') as stream:stream.write(raw)
    with open(sys.argv[3],'xb') as stream:stream.write(json.dumps(commit,separators=(',',':')).encode('ascii'))
except Exception:
    print('udp6_parity_failed');raise SystemExit(1)
'@
    & python -B -c $program (Split-Path $PSScriptRoot -Parent) $parityFlow $parityCommitment
    Check ($LASTEXITCODE -eq 0)
    $actualParity=Get-N0aUdp6FlowCommitment ([IO.File]::ReadAllBytes($parityFlow))
    $expectedParity=[IO.File]::ReadAllText($parityCommitment,[Text.Encoding]::ASCII)|ConvertFrom-Json
    foreach($key in @('sha256','bytes','contained_report_sha256','ordinary_report_sha256')) { Check ($actualParity[$key] -ceq $expectedParity.$key) }
    $badBodies=[Collections.Generic.List[byte[]]]::new()
    $badBodies.Add([Text.Encoding]::ASCII.GetBytes('{"schema_version":true,"protocol":"udp6"}'))
    $badBodies.Add([Text.Encoding]::ASCII.GetBytes('{"schema_version":1,"protocol":"udp"}'))
    $badBodies.Add([byte[]]::new(65537));$badBodies.Add([byte[]]@(255))
    foreach($bad in $badBodies) {
        $reject=$false;try{[void](Get-N0aUdp6FlowCommitment $bad)}catch{$reject=$true};Check $reject
    }

} finally { foreach($name in @('parity-flow.json','parity-commitment.json')) { $exact=Join-Path $root $name;if(Test-Path -LiteralPath $exact){[IO.File]::Delete($exact)} };[IO.File]::Delete($path); [IO.Directory]::Delete((Join-Path $root 'private-udp6')); [IO.Directory]::Delete($root) }
$script:flowBody=$raw; $script:flowCommitment=$commitment; $script:prepareThrows=$false
function Read-N0aUdp6PrivateFlow([string]$Workspace) {
    if ($script:prepareThrows) { throw 'fixture' }
    return @{body=$script:flowBody;commitment=$script:flowCommitment}
}
$script:calls=@(); $script:clocks=@(); $script:resultOkay=$true; $script:consume=$false; $script:clockCount=0
function New-N0aReportingClock { $script:clockCount++; return [PSCustomObject]@{ElapsedMilliseconds=0} }
function Send-N0aCaptureRequest([string]$Url,[byte[]]$Body,$Clock) {
    $script:calls+=@(@{url=$Url;body=$Body}); $script:clocks+=@($Clock)
    if ($script:consume) { $Clock.ElapsedMilliseconds=10000 }
    if ($Url.EndsWith('/udp6-capture-result')) { return $script:resultOkay }
    return $false
}
$envelope=@{schema_version=1;report=@{result=@{status='selected_echo_observed'}}}
Check (Send-N0aUdp6Reports $full 'unused' $envelope)
Check ($calls.Count -eq 2 -and $calls[0].url.EndsWith('/udp6-capture-result') -and $calls[1].url.EndsWith('/udp6-runner-flow'))
Check ([object]::ReferenceEquals($clocks[0],$clocks[1]) -and $clockCount -eq 1)
Check ([Convert]::ToBase64String($calls[1].body) -ceq [Convert]::ToBase64String($raw))
$script:calls=@();$script:clocks=@();$script:resultOkay=$false
Check (-not (Send-N0aUdp6Reports $full 'unused' $envelope)); Check ($calls.Count -eq 1)
$script:calls=@();$script:resultOkay=$true;$script:consume=$true
Check (Send-N0aUdp6Reports $full 'unused' $envelope); Check ($calls.Count -eq 1)
$script:calls=@();$script:consume=$false;$script:prepareThrows=$true
Check (Send-N0aUdp6Reports $full 'unused' $envelope); Check ($calls.Count -eq 1)
$sent=[Text.Encoding]::ASCII.GetString($calls[0].body) | ConvertFrom-Json
Check ($sent.schema_version -eq 5 -and $null -eq $sent.flow_commitment -and $sent.udp6.report.result.status -ceq 'selected_echo_observed')


[ordered]@{schema_version=1;passed=$true;checks=$script:checks;process_and_transport_mocked=$true;udp6_guest_execution=$false;runtime_acceptance=$false} | ConvertTo-Json -Compress
