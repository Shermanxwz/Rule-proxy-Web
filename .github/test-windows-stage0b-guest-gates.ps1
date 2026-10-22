# Actual extracted helpers, inert owned files and process mocks; no native actor/guest entrypoint/network.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:checks=0;$passed=$false;$cleanup=$false;$root=$null;$phase='parse'
function Check([bool]$Value){if(-not $Value){throw 'stage0b_fixture'};$script:checks++}
$script:batchStage='not_started';$script:batchIndex=$null;$script:batchCount=$null;$script:caseIndex=$null;$legacyRootArrayNested=$null
function Add-Stage0bFixtureBatch($Batch,[int]$Expected,$Destination,$Names) {
    $script:batchStage='shape'
    if($Batch -isnot [array]){throw 'stage0b_fixture_batch'}
    $script:batchCount=if($Batch.Count -le 160){[int]$Batch.Count}else{$null}
    $script:batchStage='count'
    if($Batch.Count -ne $Expected){throw 'stage0b_fixture_batch'}
    $script:batchStage='entries'
    foreach($entry in $Batch) {
        if($entry -isnot [PSCustomObject]){throw 'stage0b_fixture_batch'}
        $keys=@($entry.PSObject.Properties.Name)
        if($keys.Count -ne 3 -or 'name' -cnotin $keys -or 'valid' -cnotin $keys -or 'value' -cnotin $keys){throw 'stage0b_fixture_batch'}
        if($entry.name -isnot [string] -or $entry.name -cnotmatch '^[a-z0-9_]{1,80}$' -or $entry.valid -isnot [bool] -or $entry.value -isnot [PSCustomObject]){throw 'stage0b_fixture_batch'}
        if(-not $Names.Add($entry.name)){throw 'stage0b_fixture_batch'}
        [void]$Destination.Add($entry)
    }
}
try {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows-identity-direct-stage0-run.ps1'),[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0)
    foreach($name in @('Test-Stage0bConfiguration','Get-Stage0bPayloadNames','Test-Stage0bStagingBound','Test-Stage0bPublic','Test-Stage0bDiagnostic','Test-Stage0bChildEnvironment','Get-N0aSha256','Get-N0aRemainingMilliseconds','Wait-Stage0bOwnedChild','ConvertFrom-Stage0bPublic','Invoke-Stage0bGuestDiagnostic')) {
        $nodes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
        Check ($nodes.Count -eq 1);. ([ScriptBlock]::Create($nodes[0].Extent.Text))
    }
    $phase='configuration'
    $config=[PSCustomObject]@{enabled=$true;actor_sha256=('b'*64);case_nonce=('a'*32)}
    Check (Test-Stage0bConfiguration $config)
    $config.enabled=1;Check (-not(Test-Stage0bConfiguration $config));$config.enabled=$true
    $config.case_nonce=('a'*32)+"`n";Check (-not(Test-Stage0bConfiguration $config));$config.case_nonce='a'*32
    $limit=134217728-24405990-1048576-1024-10000
    Check (Test-Stage0bStagingBound $limit 10000 512)
    Check (-not(Test-Stage0bStagingBound ($limit+1) 10000 512))
    Check (-not(Test-Stage0bStagingBound $true 10000 512))
    Check (-not(Test-Stage0bStagingBound 1 10000 511))
    Check (-not(Test-Stage0bStagingBound 1 10000 8388609))
    $phase='python_public_parity'
    $root=Join-Path ([IO.Path]::GetTempPath()) ('stage0b-gate-'+[Guid]::NewGuid().ToString('N'))
    Check (-not(Test-Path -LiteralPath $root));[void][IO.Directory]::CreateDirectory($root)
    $fixture=Join-Path $root 'fixture.json'
    $casesPath=Join-Path $root 'diagnostic-cases.json'
    $casesPath2=Join-Path $root 'environment-cases.json'
    $program=@'
import importlib.util,json,pathlib,sys
try:
 p=pathlib.Path(sys.argv[1])/'tests/test_windows_stage0b_guest_transport.py'
 spec=importlib.util.spec_from_file_location('stage0b_ps_parity',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 g,cases=m.diagnostic_fixture_cases()
 for case in cases:
  try:g.validate_public(case['value'],'a'*32,'b'*64);accepted=True
  except Exception:accepted=False
  if accepted is not case['valid']:raise ValueError('fixture')
 with open(sys.argv[2],'xb') as f:f.write(json.dumps(g.default_public('a'*32,'b'*64),separators=(',',':')).encode('ascii'))
 for path,batch in zip(sys.argv[3:5],(cases[:70],cases[70:])):
  raw=json.dumps(batch,separators=(',',':')).encode('ascii')
  if len(raw)>131072:raise ValueError('fixture_bound')
  with open(path,'xb') as f:f.write(raw)
except Exception:
 print('stage0b_parity_failed');raise SystemExit(1)
'@
    & python -B -c $program (Split-Path $PSScriptRoot -Parent) $fixture $casesPath $casesPath2
    Check ($LASTEXITCODE -eq 0)
    $phase='diagnostic_parity'
    $phase='batch_fixture'
    $synthetic='[{"name":"one","valid":true,"value":{}},{"name":"two","valid":false,"value":{}}]'
    $legacy=@($synthetic|ConvertFrom-Json)
    $legacyRootArrayNested=($legacy.Count -eq 1 -and $legacy[0] -is [array])
    $parsed=$synthetic|ConvertFrom-Json
    $destination=[Collections.Generic.List[object]]::new();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    Add-Stage0bFixtureBatch $parsed 2 $destination $names
    Check ($destination.Count -eq 2 -and $destination[0].name -ceq 'one' -and $destination[1].name -ceq 'two')
    $badBatches=@((,$parsed),$null,'not-an-array',@($parsed[0],$parsed[0]),@($parsed[0],$null),@($parsed[0],'not-an-object'))
    foreach($badBatch in $badBatches) {
        $destination=[Collections.Generic.List[object]]::new();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $rejected=$false;try{Add-Stage0bFixtureBatch $badBatch 2 $destination $names}catch{$rejected=$true}
        Check $rejected
    }
    $phase='diagnostic_parity'
    $cases=[Collections.Generic.List[object]]::new();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $batchPaths=@($casesPath,$casesPath2);$expectedCounts=@(70,74)
    for($i=0;$i -lt 2;$i++) {
        $script:batchIndex=$i;$script:batchCount=$null;$script:batchStage='read'
        Check ((Get-Item -LiteralPath $batchPaths[$i]).Length -le 131072)
        $batch=[IO.File]::ReadAllText($batchPaths[$i],[Text.Encoding]::ASCII)|ConvertFrom-Json
        Add-Stage0bFixtureBatch $batch $expectedCounts[$i] $cases $names
    }
    $script:batchStage='total'
    Check ($cases.Count -eq 144)
    $script:batchStage='validate'
    for($i=0;$i -lt $cases.Count;$i++){$script:caseIndex=$i;Check ((Test-Stage0bPublic $cases[$i].value $config) -eq $cases[$i].valid)}
    $script:batchStage='complete'
    $script:reportText=[IO.File]::ReadAllText($fixture,[Text.Encoding]::ASCII)
    $value=$script:reportText|ConvertFrom-Json
    Check (Test-Stage0bPublic $value $config)
    $value.actor_creation_observed=$null;Check (-not(Test-Stage0bPublic $value $config))
    $value=$script:reportText|ConvertFrom-Json;$value.case_nonce_sha256='0'*64;Check (-not(Test-Stage0bPublic $value $config))
    $value=$script:reportText|ConvertFrom-Json;$value.pipe_echo_verified=$true;Check (-not(Test-Stage0bPublic $value $config))
    Check ($null -ne (ConvertFrom-Stage0bPublic $script:reportText $config))
    $duplicate=$script:reportText.Replace('"schema_version":3','"schema_version":3,"schema_version":3')
    Check ($duplicate -cne $script:reportText)
    $rejected=$false;try{[void](ConvertFrom-Stage0bPublic $duplicate $config)}catch{$rejected=$true};Check $rejected
    $duplicateHeld=$script:reportText.Replace('"created":false','"created":false,"created":false')
    Check ($duplicateHeld -cne $script:reportText)
    $rejected=$false;try{[void](ConvertFrom-Stage0bPublic $duplicateHeld $config)}catch{$rejected=$true};Check $rejected
    $duplicateCase=$script:reportText.Replace('"created":false','"created":false,"Created":true')
    $rejected=$false;try{[void](ConvertFrom-Stage0bPublic $duplicateCase $config)}catch{$rejected=$true};Check $rejected
    # New child-environment object keys also remain duplicate-aware before parsing.
    $environmentCase=@($cases|Where-Object {$_.name -ceq 'environment_ready'})
    Check ($environmentCase.Count -eq 1)
    $environmentText=$environmentCase[0].value|ConvertTo-Json -Depth 12 -Compress
    Check ($null -ne (ConvertFrom-Stage0bPublic $environmentText $config))
    $duplicateEnvironment=$environmentText.Replace('"environment_version":1','"environment_version":1,"environment_version":1')
    Check ($duplicateEnvironment -cne $environmentText)
    $rejected=$false;try{[void](ConvertFrom-Stage0bPublic $duplicateEnvironment $config)}catch{$rejected=$true};Check $rejected
    $phase='orchestrator' 
    $script:posted=@()
    function Send-N0aClosedReport([string]$Url,[byte[]]$Body){Check ($Body.Length -le 4096);Check ($Url.EndsWith('/stage0b-result'));$script:posted+=@([Text.Encoding]::ASCII.GetString($Body)|ConvertFrom-Json);return $true}
    $full=[PSCustomObject]@{stage0b=$config;host_url='http://127.0.0.1/inert'}
    $r=Invoke-Stage0bGuestDiagnostic $full $root 'never-executed.exe' 0 1000 $true $true
    Check ($r.launcher.failure -ceq 'work_budget_exhausted' -and $null -eq $r.stage0b -and $null -eq $r.launcher.process_exit_confirmed)
    $r=Invoke-Stage0bGuestDiagnostic $full $root 'never-executed.exe' 0 1000 $false $true
    Check ($r.launcher.failure -ceq 'original_unavailable')
    $r=Invoke-Stage0bGuestDiagnostic $full $root 'never-executed.exe' 0 1000 $true $false
    Check ($r.launcher.failure -ceq 'original_transport')
    $script:child=[PSCustomObject]@{StartInfo=$null;Handle=[IntPtr]1;ExitCode=0;Starts=0;Waits=0;Kills=0;Disposed=$false;OutputPath=(Join-Path $root 'public-stage0b.json');Timeout=$false}
    $child|Add-Member ScriptMethod Start {$this.Starts++;[IO.File]::WriteAllText($this.OutputPath,$script:reportText,[Text.Encoding]::ASCII);return $true}
    $child|Add-Member ScriptMethod WaitForExit {param($ms)$this.Waits++;return (-not $this.Timeout)}
    $child|Add-Member ScriptMethod Kill {$this.Kills++}
    $child|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
    function New-Object {param([Parameter(Position=0)][string]$TypeName)if($TypeName -ceq 'Diagnostics.Process'){return $script:child};return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName}
    $frequency=[Diagnostics.Stopwatch]::Frequency;$deadline=[Diagnostics.Stopwatch]::GetTimestamp()+120*$frequency
    $r=Invoke-Stage0bGuestDiagnostic $full $root 'never-executed.exe' $deadline $frequency $true $true
    Check ($child.Starts -eq 1 -and $child.Waits -eq 1 -and $child.Disposed)
    Check ($child.StartInfo.Arguments.Contains('--deadline-qpc '+$deadline.ToString([Globalization.CultureInfo]::InvariantCulture)))
    Check ($child.StartInfo.Arguments.Contains('--qpc-frequency '+$frequency.ToString([Globalization.CultureInfo]::InvariantCulture)))
    Check ($null -ne $r.stage0b -and $r.stage0b.actor_creation_observed -eq $false -and $r.launcher.process_exit_confirmed)
    [IO.File]::Delete($child.OutputPath);$child.Timeout=$true
    $r=Invoke-Stage0bGuestDiagnostic $full $root 'never-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.timed_out -and -not $r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'timeout')
    Check ($null -ne $r.stage0b -and $posted[-1].stage0b.case_nonce_sha256 -ceq $r.stage0b.case_nonce_sha256)
    Check ($posted.Count -eq 5)
    [IO.File]::Delete($child.OutputPath);$child.Timeout=$false
    $child|Add-Member ScriptMethod Dispose {throw 'fixture'} -Force
    $r=Invoke-Stage0bGuestDiagnostic $full $root 'never-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'handle_dispose' -and $null -ne $r.stage0b)
    $phase='late_return'
    $script:remainingCalls=0
    function Get-N0aRemainingMilliseconds([long]$Deadline,[long]$Frequency,[long]$Now){$script:remainingCalls++;if($script:remainingCalls -eq 1){return 10};return 0}
    $child.Timeout=$false;$child.Waits=0
    $wait=Wait-Stage0bOwnedChild $child $deadline $frequency
    Check ($wait.process_exit_confirmed -and $wait.budget_exhausted -and $child.Waits -eq 1)
    $node=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-N0aRemainingMilliseconds'},$true))
    . ([ScriptBlock]::Create($node[0].Extent.Text))
    $phase='expired_wait'
    $child.Timeout=$true;$child.Waits=0
    $wait=Wait-Stage0bOwnedChild $child 0 $frequency
    Check ($wait.timed_out -and $child.Waits -eq 1 -and -not $wait.process_exit_confirmed)
    $passed=$true
} catch {$passed=$false} finally {
    if(Test-Path Function:\New-Object){Remove-Item Function:\New-Object}
    try {
        if($null -ne $root){
            foreach($name in @('fixture.json','diagnostic-cases.json','environment-cases.json','public-stage0b.json')){$path=Join-Path $root $name;if(Test-Path -LiteralPath $path){[IO.File]::Delete($path)}}
            [IO.Directory]::Delete($root,$false)
        }
        $cleanup=$true
    }catch{$cleanup=$false}
}
[ordered]@{schema_version=1;passed=($passed -and $cleanup);phase=$phase;checks=$script:checks;batch_stage=$script:batchStage;batch_index=$script:batchIndex;batch_count=$script:batchCount;case_index=$script:caseIndex;legacy_root_array_nested=$legacyRootArrayNested;cleanup_confirmed=$cleanup;process_and_transport_mocked=$true;native_actor_executed=$false}|ConvertTo-Json -Compress
if(-not($passed -and $cleanup)){exit 1}
