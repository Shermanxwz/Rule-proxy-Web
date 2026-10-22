# Actual extracted helpers, inert owned files and process mocks; no native actor/guest entrypoint/network.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:checks=0;$passed=$false;$cleanup=$false;$root=$null;$phase='parse'
function Check([bool]$Value){if(-not $Value){throw 'stage0b_fixture'};$script:checks++}
try {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows-identity-direct-stage0-run.ps1'),[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0)
    foreach($name in @('Test-Stage0bConfiguration','Get-Stage0bPayloadNames','Test-Stage0bStagingBound','Test-Stage0bPublic','Get-N0aSha256','Get-N0aRemainingMilliseconds','Wait-Stage0bOwnedChild','ConvertFrom-Stage0bPublic','Invoke-Stage0bGuestDiagnostic')) {
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
    $program=@'
import importlib.util,json,pathlib,sys
try:
 p=pathlib.Path(sys.argv[1])/'.github/windows_identity_stage0b_guest.py'
 s=importlib.util.spec_from_file_location('stage0b_ps_parity',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
 v=m.default_public('a'*32,'b'*64);m.validate_public(v,'a'*32,'b'*64)
 with open(sys.argv[2],'xb') as f:f.write(json.dumps(v,separators=(',',':')).encode('ascii'))
except Exception:
 print('stage0b_parity_failed');raise SystemExit(1)
'@
    & python -B -c $program (Split-Path $PSScriptRoot -Parent) $fixture
    Check ($LASTEXITCODE -eq 0)
    $script:reportText=[IO.File]::ReadAllText($fixture,[Text.Encoding]::ASCII)
    $value=$script:reportText|ConvertFrom-Json
    Check (Test-Stage0bPublic $value $config)
    $value.actor_creation_observed=$null;Check (-not(Test-Stage0bPublic $value $config))
    $value=$script:reportText|ConvertFrom-Json;$value.case_nonce_sha256='0'*64;Check (-not(Test-Stage0bPublic $value $config))
    $value=$script:reportText|ConvertFrom-Json;$value.pipe_echo_verified=$true;Check (-not(Test-Stage0bPublic $value $config))
    Check ($null -ne (ConvertFrom-Stage0bPublic $script:reportText $config))
    $duplicate=$script:reportText.Replace('"schema_version":1','"schema_version":1,"schema_version":1')
    Check ($duplicate -cne $script:reportText)
    $rejected=$false;try{[void](ConvertFrom-Stage0bPublic $duplicate $config)}catch{$rejected=$true};Check $rejected
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
            foreach($name in @('fixture.json','public-stage0b.json')){$path=Join-Path $root $name;if(Test-Path -LiteralPath $path){[IO.File]::Delete($path)}}
            [IO.Directory]::Delete($root,$false)
        }
        $cleanup=$true
    }catch{$cleanup=$false}
}
[ordered]@{schema_version=1;passed=($passed -and $cleanup);phase=$phase;checks=$script:checks;cleanup_confirmed=$cleanup;process_and_transport_mocked=$true;native_actor_executed=$false}|ConvertTo-Json -Compress
if(-not($passed -and $cleanup)){exit 1}
