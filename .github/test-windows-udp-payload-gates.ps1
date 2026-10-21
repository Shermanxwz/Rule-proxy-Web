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
    foreach($name in @('Get-N0aUdpPayloadNames','Test-N0aConfiguration','Test-N0aCaptureConfiguration','Expand-CheckedStage0Zip')) {
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
        Check ($command.GetCommandName() -cin @('Get-N0aUdpPayloadNames','Test-N0aConfiguration','Test-N0aCaptureConfiguration'))
    }
    $branches=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.Contains('-MemberCount 17') -and $n.Extent.Text.Contains('-MemberCount 15') -and $n.Extent.Text.Contains('-MemberCount 14') -and $n.Extent.Text.Contains('-MemberCount 10')},$true))
    Check ($branches.Count -eq 1)
    $script:stage='generate'
    & python -B (Join-Path $PSScriptRoot 'test_windows_udp_payload.py') --root $owned
    Check ($LASTEXITCODE -eq 0)
    $cleanupAuthorized=$true # Fresh generator completed; failed admission/generation never authorizes deletion.
    $config=[PSCustomObject]@{enabled=$true;case_nonce=('a'*32);runner_port=12345;actor_sha256=('b'*64);manifest_sha256=('c'*64);actor_source_sha256=('d'*64);identity_source_sha256=('e'*64)}
    foreach($mode in @('baseline','n0a','capture','udp')) {
        $script:stage='extract_'+$mode
        $configuration=[PSCustomObject]@{host_url='http://127.0.0.1/fixture';payload_sha256=('a'*64);python_sha256=('b'*64);actor_sha256=('c'*64)}
        if($mode -in @('n0a','capture')) { $configuration | Add-Member NoteProperty n0a $config }
        if($mode -eq 'udp') { $configuration | Add-Member NoteProperty n0a_udp $config }
        if($mode -in @('capture','udp')) { $configuration | Add-Member NoteProperty capture ([PSCustomObject]@{enabled=$true;run_nonce=('1'*32);source_commit=('2'*40);vm_mac='525400123456'}) }
        $udpEnabled=$false;$n0aEnabled=$false
        . ([ScriptBlock]::Create($selection))
        $payload=Join-Path $owned ($mode+'.zip');$workspace=Join-Path $owned ($mode+'-expanded')
        . ([ScriptBlock]::Create($branches[0].Extent.Text))
        $expected=@{baseline=10;n0a=14;capture=15;udp=17}[$mode]
        Check ($payloadNames.Count -eq $expected)
        Check (@(Get-ChildItem -LiteralPath $workspace -Recurse -File).Count -eq $expected)
    }
    $script:stage='forbidden'
    foreach($index in 0..3) {
        $payload=Join-Path $owned ('udp-bad-'+$index+'.zip');$workspace=Join-Path $owned ('udp-bad-'+$index+'-expanded')
        $rejected=$false
        try { . ([ScriptBlock]::Create($branches[0].Extent.Text)) } catch { $rejected=$true }
        Check $rejected;Check (-not (Test-Path -LiteralPath $workspace))
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
