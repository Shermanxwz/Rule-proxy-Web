# Pure helper/owned-process mocks only; never invoke the guest entrypoint or network.
$ErrorActionPreference='Stop'
trap { Write-Output '{"schema_version":1,"passed":false,"failure":"guest_fixture"}'; exit 1 }
Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'windows-identity-direct-stage0-run.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'n0a_parse' }
$names=@('Test-N0aConfiguration','Get-N0aRemainingMilliseconds','Wait-N0aOwnedChild','Write-N0aBoundedBody','Invoke-N0aGuestDiagnostic','Test-N0aCaptureConfiguration','Get-N0aSha256','Get-N0aFlowCommitment','Read-N0aPrivateFlow','Send-N0aCaptureReports')
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
function Send-N0aClosedReport([string]$Url,[byte[]]$Body) {
    $script:posted+=@([Text.Encoding]::ASCII.GetString($Body) | ConvertFrom-Json)
    return $true
}
$full=[PSCustomObject]@{n0a=$config;host_url='http://127.0.0.1/fixture'}
$r=Invoke-N0aGuestDiagnostic $full 'unused' 'unused' 0 1000 $true $true
Check ($r.launcher.failure -ceq 'work_budget_exhausted' -and $r.launcher.budget_exhausted -and $null -eq $r.launcher.process_exit_confirmed -and $null -eq $r.report)
$r=Invoke-N0aGuestDiagnostic $full 'unused' 'unused' 0 1000 $false $true
Check ($r.launcher.failure -ceq 'original_unavailable')
$r=Invoke-N0aGuestDiagnostic $full 'unused' 'unused' 0 1000 $true $false
Check ($r.launcher.failure -ceq 'original_transport')
Check ($posted.Count -eq 3)
foreach ($entry in $posted) { Check ([Text.Encoding]::ASCII.GetByteCount(($entry | ConvertTo-Json -Depth 16 -Compress)) -le 4096) }
# Execute the real optional orchestrator against an exact owned mock child and file.
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('n0a-guest-gate-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureRoot)
$script:fixtureChild=[PSCustomObject]@{StartInfo=$null;Handle=[IntPtr]1;ExitCode=0;OutputPath=(Join-Path $fixtureRoot 'public-n0a.json');Starts=0;Waits=0;Kills=0;Disposed=$false}
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
    $r=Invoke-N0aGuestDiagnostic $full $fixtureRoot 'fixture-not-executed.exe' $deadline $frequency $true $true
    Check ($fixtureChild.Starts -eq 1 -and $fixtureChild.Waits -eq 1 -and $fixtureChild.Kills -eq 0 -and $fixtureChild.Disposed)
    Check ($r.launcher.process_exit_confirmed -and $r.launcher.python_exit_code -eq 0 -and $null -eq $r.report -and $r.launcher.failure -ceq 'operation_failed')
    Check ($fixtureChild.StartInfo.Arguments.Contains('--deadline-qpc '+($deadline-20*$frequency).ToString([Globalization.CultureInfo]::InvariantCulture)))
    Check ($posted.Count -eq 4)
    # A pre-existing result is retained on timeout/unknown child exit, never promoted.
    [IO.File]::Delete($fixtureChild.OutputPath)
    $fixtureChild | Add-Member ScriptMethod Start { $this.Starts++; [IO.File]::WriteAllText($this.OutputPath,'{"result":{"status":"connect_succeeded"}}',[Text.Encoding]::ASCII); return $true } -Force
    $fixtureChild | Add-Member ScriptMethod WaitForExit { param($ms) $this.Waits++; return $false } -Force
    $fixtureChild | Add-Member ScriptMethod Kill { $this.Kills++; throw 'fixture' } -Force
    $r=Invoke-N0aGuestDiagnostic $full $fixtureRoot 'fixture-not-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.timed_out -and -not $r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'timeout')
    Check ($r.report.result.status -ceq 'connect_succeeded')
    Check ($posted.Count -eq 5 -and $posted[4].report.result.status -ceq 'connect_succeeded')

} finally {
    Remove-Item Function:\New-Object
    $owned=Join-Path $fixtureRoot 'public-n0a.json'
    if (Test-Path -LiteralPath $owned) { [IO.File]::Delete($owned) }
    [IO.Directory]::Delete($fixtureRoot,$false)
}
# Capture preparation and dual transport are mocked; no sockets or guest entrypoint.
$capture=[PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}
Check (Test-N0aCaptureConfiguration $capture)
$capture.enabled=1; Check (-not (Test-N0aCaptureConfiguration $capture)); $capture.enabled=$true
$capture.vm_mac='535400123456'; Check (-not (Test-N0aCaptureConfiguration $capture)); $capture.vm_mac='525400123456'
$raw=[Text.Encoding]::ASCII.GetBytes('{"reports":{"before":{"sha256":"'+('1'*64)+'","bytes":100},"sample":{"sha256":"'+('2'*64)+'","bytes":200},"after":{"sha256":"'+('3'*64)+'","bytes":300},"contained":{"sha256":"'+('4'*64)+'","bytes":400}}}')
$invalidRejected=$false
try { [void](Get-N0aFlowCommitment ([Text.Encoding]::ASCII.GetBytes('{}'))) } catch { $invalidRejected=$true }
Check $invalidRejected
$commitment=Get-N0aFlowCommitment $raw
Check ($commitment.ordinary_report_sha256 -ceq 'dc9af386dc5d72f1ba97ddb2876fa8cb8255bccbca11a886f3ab62352993b62a')
Check ($commitment.sha256 -ceq (Get-N0aSha256 $raw) -and $commitment.bytes -eq $raw.Length)
$root=Join-Path ([IO.Path]::GetTempPath()) ('n0a-flow-gate-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'private-n0a'))
$path=Join-Path $root 'private-n0a/runner-flow.json'
try {
    [IO.File]::WriteAllBytes($path,$raw)
    $actual=Read-N0aPrivateFlow $root
    Check ([Convert]::ToBase64String($actual.body) -ceq [Convert]::ToBase64String($raw))
    Check ($actual.commitment.sha256 -ceq $commitment.sha256)
} finally { [IO.File]::Delete($path); [IO.Directory]::Delete((Join-Path $root 'private-n0a')); [IO.Directory]::Delete($root) }
$script:flowBody=$raw; $script:flowCommitment=$commitment; $script:prepareThrows=$false
function Read-N0aPrivateFlow([string]$Workspace) {
    if ($script:prepareThrows) { throw 'fixture' }
    return @{body=$script:flowBody;commitment=$script:flowCommitment}
}
$script:calls=@(); $script:clocks=@(); $script:resultOkay=$true; $script:consume=$false; $script:clockCount=0
function New-N0aReportingClock { $script:clockCount++; return [PSCustomObject]@{ElapsedMilliseconds=0} }
function Send-N0aCaptureRequest([string]$Url,[byte[]]$Body,$Clock) {
    $script:calls+=@(@{url=$Url;body=$Body}); $script:clocks+=@($Clock)
    if ($script:consume) { $Clock.ElapsedMilliseconds=10000 }
    if ($Url.EndsWith('/n0a-capture-result')) { return $script:resultOkay }
    return $false
}
$envelope=@{schema_version=1;report=@{result=@{status='connect_succeeded'}}}
Check (Send-N0aCaptureReports $full 'unused' $envelope)
Check ($calls.Count -eq 2 -and $calls[0].url.EndsWith('/n0a-capture-result') -and $calls[1].url.EndsWith('/n0a-runner-flow'))
Check ([object]::ReferenceEquals($clocks[0],$clocks[1]) -and $clockCount -eq 1)
Check ([Convert]::ToBase64String($calls[1].body) -ceq [Convert]::ToBase64String($raw))
$script:calls=@();$script:clocks=@();$script:resultOkay=$false
Check (-not (Send-N0aCaptureReports $full 'unused' $envelope)); Check ($calls.Count -eq 1)
$script:calls=@();$script:resultOkay=$true;$script:consume=$true
Check (Send-N0aCaptureReports $full 'unused' $envelope); Check ($calls.Count -eq 1)
$script:calls=@();$script:consume=$false;$script:prepareThrows=$true
Check (Send-N0aCaptureReports $full 'unused' $envelope); Check ($calls.Count -eq 1)
$sent=[Text.Encoding]::ASCII.GetString($calls[0].body) | ConvertFrom-Json
Check ($null -eq $sent.flow_commitment -and $sent.legacy.report.result.status -ceq 'connect_succeeded')

[ordered]@{schema_version=1;checks=$checks;guest_entrypoint_executed=$false;network_executed=$false;native_acceptance=$false} | ConvertTo-Json -Compress
