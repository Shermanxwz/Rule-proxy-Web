$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'c_local_baseline.ps1')).Replace('model2-first-01-global-baseline.json','model2-dns-after01-global-snapshot.json')
$expanded=Join-Path $PSScriptRoot 'model2_dns_after01_expanded.ps1'
if(Test-Path -LiteralPath $expanded){throw 'fresh expanded script required'}
[IO.File]::WriteAllText($expanded,$source,(New-Object Text.UTF8Encoding($false)))
& $expanded
$private=Join-Path $PSScriptRoot 'Rule-proxy-Web/private'
$before=Get-Content -LiteralPath (Join-Path $private 'model2-first-01-global-baseline.json') -Raw | ConvertFrom-Json
$after=Get-Content -LiteralPath (Join-Path $private 'model2-dns-after01-global-snapshot.json') -Raw | ConvertFrom-Json
$same=[ordered]@{ReadOnly=$true}
foreach($key in @('firewall_profiles','dns','routes','user_proxy')){
    $same[$key+'_unchanged']=(($before.$key|ConvertTo-Json -Depth 8 -Compress) -ceq ($after.$key|ConvertTo-Json -Depth 8 -Compress))
}
$same|ConvertTo-Json -Compress
