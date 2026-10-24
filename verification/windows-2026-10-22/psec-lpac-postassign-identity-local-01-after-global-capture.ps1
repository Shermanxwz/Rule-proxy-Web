param([Parameter(Mandatory=$true)][ValidateSet('before-postassign01','after-postassign01')][string]$Phase)
$ErrorActionPreference='Stop'
$name='psec-lpac-postassign-identity-'+$Phase+'-global-snapshot.json'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'c_local_baseline.ps1')).Replace('model2-first-01-global-baseline.json',$name)
$expanded=Join-Path $PSScriptRoot ('psec_lpac_postassign_identity_'+$Phase+'_expanded.ps1')
if(Test-Path -LiteralPath $expanded){throw 'Fresh expanded capture required'}
[IO.File]::WriteAllText($expanded,$source,(New-Object Text.UTF8Encoding($false)))
& $expanded
$private=Join-Path $PSScriptRoot 'Rule-proxy-Web/private'
$original=Get-Content -LiteralPath (Join-Path $private 'model2-first-01-global-baseline.json') -Raw | ConvertFrom-Json
$current=Get-Content -LiteralPath (Join-Path $private $name) -Raw | ConvertFrom-Json
$result=[ordered]@{ReadOnly=$true;Phase=$Phase;ObjectsCompared=4;NrptIncluded=$false}
foreach($key in @('firewall_profiles','dns','routes','user_proxy')){
    $result[$key+'_equal_original']=(($original.$key|ConvertTo-Json -Depth 8 -Compress) -ceq ($current.$key|ConvertTo-Json -Depth 8 -Compress))
}
if($Phase -eq 'after-postassign01'){
    $before=Get-Content -LiteralPath (Join-Path $private 'psec-lpac-postassign-identity-before-postassign01-global-snapshot.json') -Raw | ConvertFrom-Json
    foreach($key in @('firewall_profiles','dns','routes','user_proxy')){
        $result[$key+'_equal_before-postassign01']=(($before.$key|ConvertTo-Json -Depth 8 -Compress) -ceq ($current.$key|ConvertTo-Json -Depth 8 -Compress))
    }
}
$result|ConvertTo-Json -Compress
