# Extracted production validators and dispatch with inert process/HTTP substitutes only.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:checks=0;$passed=$false;$cleanup=$false;$owned=$false;$phase='parse';$caseIndex=$null
function Check([bool]$Value){if(-not $Value){throw 'ac_fixture'};$script:checks++}
$root=Join-Path ([IO.Path]::GetTempPath()) ('ac-transport-gate-'+[Guid]::NewGuid().ToString('N'))
try {
    Check (-not (Test-Path -LiteralPath $root))
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows-identity-direct-stage0-run.ps1'),[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0)
    foreach($name in @('Test-ProxyPipeACConfiguration','Get-ProxyPipeACPayloadNames','Test-ProxyPipeACStagingBound','Test-ProxyPipeACKeys','Test-ProxyPipeACPair','Test-ProxyPipeACPairPassed','Test-ProxyPipeACPublic','ConvertFrom-ProxyPipeACPublic','Invoke-ProxyPipeACGuestDiagnostic','Get-N0aSha256','Get-N0aRemainingMilliseconds','Wait-Stage0bOwnedChild')) {
        $nodes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
        Check ($nodes.Count -eq 1);. ([ScriptBlock]::Create($nodes[0].Extent.Text))
    }
    $phase='export'
    & python -B (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests/test_windows_proxy_pipe_ac_transport.py') --export-ac-fixture $root
    Check ($LASTEXITCODE -eq 0);$owned=$true
    $config=[PSCustomObject]@{enabled=$true;run_nonce=('a'*32);case_nonce=('b'*32);actor_sha256=('c'*64);manifest_sha256=('d'*64)}
    Check (Test-ProxyPipeACConfiguration $config)
    $config.enabled=1;Check (-not(Test-ProxyPipeACConfiguration $config));$config.enabled=$true
    Check (Test-ProxyPipeACStagingBound 108760089 1 512 2048 512)
    Check (-not(Test-ProxyPipeACStagingBound 108760090 1 512 2048 512))
    $phase='parity';$path=Join-Path $root 'cases.json'
    Check ((Get-Item -LiteralPath $path).Length -le 131072)
    $cases=[IO.File]::ReadAllText($path,[Text.Encoding]::ASCII)|ConvertFrom-Json
    Check ($cases -is [array] -and $cases.Count -eq 28)
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for($i=0;$i -lt $cases.Count;$i++) {
        $caseIndex=$i;$row=$cases[$i]
        Check ($row -is [PSCustomObject] -and $row.valid -is [bool] -and $row.value -is [PSCustomObject])
        Check ($names.Add($row.name))
        Check ((Test-ProxyPipeACPublic $row.value $config) -eq $row.valid)
    }
    $phase='duplicate';$script:reportText=[IO.File]::ReadAllText((Join-Path $root 'passed.json'),[Text.Encoding]::ASCII)
    Check ($null -ne (ConvertFrom-ProxyPipeACPublic $script:reportText $config))
    foreach($token in @('"schema_version":1','"created":3')) {
        $bad=$script:reportText.Replace($token,($token+','+$token));Check ($bad -cne $script:reportText)
        $rejected=$false;try{[void](ConvertFrom-ProxyPipeACPublic $bad $config)}catch{$rejected=$true};Check $rejected
    }
    $phase='dispatch';$script:posted=@()
    function Send-N0aClosedReport([string]$Url,[byte[]]$Body){Check ($Body.Length -le 4096);Check ($Url.EndsWith('/proxy-pipe-ac-result'));$script:posted+=@([Text.Encoding]::ASCII.GetString($Body)|ConvertFrom-Json);return $true}
    $full=[PSCustomObject]@{proxy_pipe_ac=$config;host_url='http://127.0.0.1/inert'}
    $r=Invoke-ProxyPipeACGuestDiagnostic $full $root 'never-executed.exe' 0 1000 $true $true
    Check ($r.launcher.failure -ceq 'work_budget_exhausted' -and $null -eq $r.proxy_pipe_ac)
    $r=Invoke-ProxyPipeACGuestDiagnostic $full $root 'never-executed.exe' 0 1000 $false $true
    Check ($r.launcher.failure -ceq 'original_unavailable')
    $r=Invoke-ProxyPipeACGuestDiagnostic $full $root 'never-executed.exe' 0 1000 $true $false
    Check ($r.launcher.failure -ceq 'original_transport')
    $script:child=[PSCustomObject]@{StartInfo=$null;Handle=[IntPtr]1;ExitCode=0;Starts=0;Waits=0;Kills=0;Disposed=$false;OutputPath=(Join-Path $root 'public-proxy-pipe-ac.json');Timeout=$false}
    $child|Add-Member ScriptMethod Start {$this.Starts++;[IO.File]::WriteAllText($this.OutputPath,$script:reportText,[Text.Encoding]::ASCII);return $true}
    $child|Add-Member ScriptMethod WaitForExit {param($ms)$this.Waits++;return (-not $this.Timeout)}
    $child|Add-Member ScriptMethod Kill {$this.Kills++}
    $child|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
    function New-Object {param([Parameter(Position=0)][string]$TypeName)if($TypeName -ceq 'Diagnostics.Process'){return $script:child};return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName}
    $frequency=[Diagnostics.Stopwatch]::Frequency;$deadline=[Diagnostics.Stopwatch]::GetTimestamp()+120*$frequency
    $r=Invoke-ProxyPipeACGuestDiagnostic $full $root 'never-executed.exe' $deadline $frequency $true $true
    Check ($child.Starts -eq 1 -and $child.Waits -eq 1 -and $child.Disposed)
    Check ($child.StartInfo.Arguments.Contains('--deadline-qpc '+$deadline.ToString([Globalization.CultureInfo]::InvariantCulture)))
    Check ($child.StartInfo.Arguments.Contains('windows_identity_proxy_pipe_ac_guest.py'))
    Check ($r.proxy_pipe_ac.ac_pipe_passed -and $r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'none')
    [IO.File]::Delete($child.OutputPath);$child.Timeout=$true
    $r=Invoke-ProxyPipeACGuestDiagnostic $full $root 'never-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.timed_out -and -not $r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'timeout' -and $r.proxy_pipe_ac.ac_pipe_passed)
    [IO.File]::Delete($child.OutputPath);$child.Timeout=$false
    $child|Add-Member ScriptMethod Dispose {throw 'fixture'} -Force
    $r=Invoke-ProxyPipeACGuestDiagnostic $full $root 'never-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.process_exit_confirmed -and $r.launcher.failure -ceq 'handle_dispose' -and $r.proxy_pipe_ac.ac_pipe_passed)
    [IO.File]::Delete($child.OutputPath)
    $child|Add-Member ScriptMethod Dispose {$this.Disposed=$true} -Force
    # Substitute only the already-tested wait seam to exercise a positive report with late exit.
    function Wait-Stage0bOwnedChild($Process,[long]$Deadline,[long]$Frequency){return @{process_exit_confirmed=$true;timed_out=$false;python_exit_code=0;budget_exhausted=$true}}
    $r=Invoke-ProxyPipeACGuestDiagnostic $full $root 'never-executed.exe' $deadline $frequency $true $true
    Check ($r.launcher.process_exit_confirmed -and $r.launcher.budget_exhausted -and $r.launcher.failure -ceq 'work_budget_exhausted' -and $r.proxy_pipe_ac.ac_pipe_passed)
    Check ($posted.Count -eq 7)
    $passed=$true
} catch {$passed=$false} finally {
    try {
        if(-not $owned){throw 'ownership'}
        if(Test-Path -LiteralPath $root) {
            $item=Get-Item -LiteralPath $root -Force
            if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'ownership'}
            foreach($item in @(Get-ChildItem -LiteralPath $root -Force)) {
                if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Name -cnotin @('cases.json','passed.json','public-proxy-pipe-ac.json')){throw 'ownership'}
                [IO.File]::Delete($item.FullName)
            }
            [IO.Directory]::Delete($root)
        }
        $cleanup=-not(Test-Path -LiteralPath $root)
    }catch{$cleanup=$false}
}
[ordered]@{passed=($passed -and $cleanup);phase=$phase;case_index=$caseIndex;checks=$script:checks;cleanup_confirmed=$cleanup;native_executed=$false;process_and_http_mocked=$true}|ConvertTo-Json -Compress
if(-not($passed -and $cleanup)){exit 1}
