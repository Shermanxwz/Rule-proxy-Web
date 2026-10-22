# Only actual ZIP selector/extractor helpers with inert synthetic inputs; no guest entrypoint.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:stage='initializing';$script:checks=0;$cleanup=$false;$passed=$false;$cleanupAuthorized=$false
function Check([bool]$Value) { if (-not $Value) { throw 'udp_payload_fixture' };$script:checks++ }
$owned=Join-Path ([IO.Path]::GetTempPath()) ('udp-payload-gate-'+[Guid]::NewGuid().ToString('N'))
try {
    Check (-not (Test-Path -LiteralPath $owned))
    $source=Join-Path $PSScriptRoot 'windows-identity-direct-stage0-run.ps1'
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0)
    foreach($name in @('Test-ProxyPipeACConfiguration','Get-ProxyPipeACPayloadNames','Test-Stage0bConfiguration','Get-Stage0bPayloadNames','Get-N0aUdp6PayloadNames','Get-N0aUdpPayloadNames','Get-N0aUdpParentPayloadNames','Test-N0aUdpParentConfiguration','Test-N0aConfiguration','Test-N0aCaptureConfiguration','Test-Stage0bStagingBound','Assert-Stage0bStagingBound','Test-ProxyPipeACStagingBound','Assert-ProxyPipeACStagingBound','Expand-CheckedStage0Zip')) {
        $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
        Check ($nodes.Count -eq 1)
        . ([ScriptBlock]::Create($nodes[0].Extent.Text))
    }
    $starts=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$payloadNames' -and $n.Operator -eq [Management.Automation.Language.TokenKind]::Equals},$true))
    $ends=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$phase' -and $n.Right.Extent.Text -ceq "'payload_extract'"},$true))
    Check ($starts.Count -eq 1 -and $ends.Count -eq 1)
    $selection=$ast.Extent.Text.Substring($starts[0].Extent.StartOffset,$ends[0].Extent.StartOffset-$starts[0].Extent.StartOffset)
    $t=$null;$e=$null;$selectionAst=[Management.Automation.Language.Parser]::ParseInput($selection,[ref]$t,[ref]$e)
    Check ($e.Count -eq 0)
    foreach($command in @($selectionAst.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true))) {
        Check ($command.GetCommandName() -cin @('Test-ProxyPipeACConfiguration','Get-ProxyPipeACPayloadNames','Test-Stage0bConfiguration','Get-Stage0bPayloadNames','Get-N0aUdp6PayloadNames','Get-N0aUdpPayloadNames','Get-N0aUdpParentPayloadNames','Test-N0aUdpParentConfiguration','Test-N0aConfiguration','Test-N0aCaptureConfiguration'))
    }
    $branches=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.Contains('-MemberCount 22') -and $n.Extent.Text.Contains('-MemberCount 17') -and $n.Extent.Text.Contains('-MemberCount 15') -and $n.Extent.Text.Contains('-MemberCount 14') -and $n.Extent.Text.Contains('-MemberCount 10')},$true))
    Check ($branches.Count -eq 1)
    $script:stage='generate'
    & python -B (Join-Path $PSScriptRoot 'test_windows_udp_payload.py') --root $owned
    Check ($LASTEXITCODE -eq 0)
    $cleanupAuthorized=$true # Fresh generator completed; failed admission/generation never authorizes deletion.
    $config=[PSCustomObject]@{enabled=$true;case_nonce=('a'*32);runner_port=12345;actor_sha256=('b'*64);manifest_sha256=('c'*64);actor_source_sha256=('d'*64);identity_source_sha256=('e'*64)}
    $parentConfig=[PSCustomObject]@{enabled=$true;case_nonce=('a'*32);runner_port=12345;parent_sha256=('b'*64);parent_manifest_sha256=('c'*64);parent_source_sha256=('d'*64);child_sha256=('e'*64);child_manifest_sha256=('f'*64);child_source_sha256=('1'*64);identity_source_sha256=('2'*64);executor_sha256=('3'*64)}
    $savedNames=@{}
    foreach($mode in @('baseline','n0a','capture','udp','parent_udp','udp6','stage0b','proxy_pipe_ac')) {
        $script:stage='extract_'+$mode
        $configuration=[PSCustomObject]@{host_url='http://127.0.0.1/fixture';payload_sha256=('a'*64);python_sha256=('b'*64);actor_sha256=('c'*64)}
        if($mode -in @('n0a','capture')) { $configuration | Add-Member NoteProperty n0a $config }
        if($mode -eq 'proxy_pipe_ac') { $configuration | Add-Member NoteProperty proxy_pipe_ac ([PSCustomObject]@{enabled=$true;run_nonce=('a'*32);case_nonce=('b'*32);actor_sha256=('c'*64);manifest_sha256=('d'*64)}) }
        if($mode -eq 'stage0b') { $configuration | Add-Member NoteProperty stage0b ([PSCustomObject]@{enabled=$true;case_nonce=('a'*32);actor_sha256=('c'*64)}) }
        if($mode -eq 'udp6') { $configuration | Add-Member NoteProperty n0a_udp6 $config }
        if($mode -eq 'udp') { $configuration | Add-Member NoteProperty n0a_udp $config }
        if($mode -eq 'parent_udp') { $configuration | Add-Member NoteProperty n0a_udp_parent $parentConfig }
        if($mode -in @('capture','udp','parent_udp','udp6')) { $configuration | Add-Member NoteProperty capture ([PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}) }
        $proxyPipeAcEnabled=$false;$stage0bEnabled=$false;$udp6Enabled=$false;$parentUdpEnabled=$false;$udpEnabled=$false;$n0aEnabled=$false
        . ([ScriptBlock]::Create($selection))
        $payload=Join-Path $owned ($mode+'.zip');$workspace=Join-Path $owned ($mode+'-expanded')
        . ([ScriptBlock]::Create($branches[0].Extent.Text))
        $expected=@{baseline=10;n0a=14;capture=15;udp=17;parent_udp=22;udp6=17;stage0b=14;proxy_pipe_ac=17}[$mode]
        $savedNames[$mode]=@($payloadNames)
        Check ($payloadNames.Count -eq $expected)
        Check (@(Get-ChildItem -LiteralPath $workspace -Recurse -File).Count -eq $expected)
    }
    $script:stage='forbidden'
    foreach($badMode in @('udp','parent_udp','udp6','stage0b','proxy_pipe_ac')) {
        $payloadNames=$savedNames[$badMode];$proxyPipeAcEnabled=($badMode -ceq 'proxy_pipe_ac');$stage0bEnabled=($badMode -ceq 'stage0b');$udp6Enabled=($badMode -ceq 'udp6');$parentUdpEnabled=($badMode -ceq 'parent_udp');$udpEnabled=($badMode -ceq 'udp');$captureEnabled=$false;$n0aEnabled=$false
        foreach($index in 0..3) {
            $payload=Join-Path $owned ($badMode+'-bad-'+$index+'.zip');$workspace=Join-Path $owned ($badMode+'-bad-'+$index+'-expanded')
            $rejected=$false
            try { . ([ScriptBlock]::Create($branches[0].Extent.Text)) } catch { $rejected=$true }
            Check $rejected;Check (-not (Test-Path -LiteralPath $workspace))
        }
    }
    $script:stage='exclusive_configuration'
    foreach($conflict in @('n0a','n0a_udp','n0a_udp6')) {
        $configuration=[PSCustomObject]@{n0a_udp_parent=$parentConfig;capture=[PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}}
        $configuration|Add-Member NoteProperty $conflict $config
        $proxyPipeAcEnabled=$false;$stage0bEnabled=$false;$udp6Enabled=$false;$parentUdpEnabled=$false;$udpEnabled=$false;$n0aEnabled=$false
        $rejected=$false;try{. ([ScriptBlock]::Create($selection))}catch{$rejected=$true};Check $rejected
    }
    foreach($conflict in @('n0a','n0a_udp','n0a_udp_parent')) {
        $configuration=[PSCustomObject]@{n0a_udp6=$config;capture=[PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}}
        $configuration|Add-Member NoteProperty $conflict $config
        $proxyPipeAcEnabled=$false;$stage0bEnabled=$false;$udp6Enabled=$false;$parentUdpEnabled=$false;$udpEnabled=$false;$n0aEnabled=$false
        $rejected=$false;try{. ([ScriptBlock]::Create($selection))}catch{$rejected=$true};Check $rejected
    }
    foreach($conflict in @('stage0b','n0a','n0a_udp','n0a_udp_parent','n0a_udp6','capture')) {
        $configuration=[PSCustomObject]@{proxy_pipe_ac=[PSCustomObject]@{enabled=$true;run_nonce=('a'*32);case_nonce=('b'*32);actor_sha256=('c'*64);manifest_sha256=('d'*64)}}
        # Presence alone, even disabled, must refuse every conflicting optional mode.
        $configuration|Add-Member NoteProperty $conflict ([PSCustomObject]@{enabled=$false})
        $proxyPipeAcEnabled=$false;$stage0bEnabled=$false;$udp6Enabled=$false;$parentUdpEnabled=$false;$udpEnabled=$false;$n0aEnabled=$false
        $rejected=$false;try{. ([ScriptBlock]::Create($selection))}catch{$rejected=$true};Check $rejected
    }
    $passed=$true
} catch { $passed=$false } finally {
    try {
        if(-not $cleanupAuthorized) { throw 'ownership_unconfirmed' }
        if(Test-Path -LiteralPath $owned) {
            $rootItem=Get-Item -LiteralPath $owned -Force
            if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'owned_root' }
            foreach($item in @(Get-ChildItem -LiteralPath $owned -Recurse -Force)) {
                if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'owned_child' }
            }
            Remove-Item -LiteralPath $owned -Recurse -Force
        }
        $cleanup=-not (Test-Path -LiteralPath $owned)
    } catch { $cleanup=$false }
}
[ordered]@{schema_version=1;passed=($passed -and $cleanup);stage=$script:stage;checks=$script:checks;cleanup_confirmed=$cleanup;inert_boundary_mocks=$true;guest_entrypoint_executed=$false;runtime_artifact=$false} | ConvertTo-Json -Compress
if(-not ($passed -and $cleanup)) { exit 1 }
