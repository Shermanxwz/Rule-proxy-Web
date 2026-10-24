$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'c_local_baseline.ps1')).Replace('model2-first-01-global-baseline.json','model2-after04-global-snapshot.json')
$temporary=Join-Path $PSScriptRoot 'c_after04_capture.ps1'
if (Test-Path -LiteralPath $temporary) { throw 'fresh script required' }
[IO.File]::WriteAllText($temporary,$source,(New-Object Text.UTF8Encoding($false)))
& $temporary
$private=Join-Path $PSScriptRoot 'Rule-proxy-Web/private'
$before=Get-Content -LiteralPath (Join-Path $private 'model2-first-01-global-baseline.json') -Raw | ConvertFrom-Json
$after=Get-Content -LiteralPath (Join-Path $private 'model2-after04-global-snapshot.json') -Raw | ConvertFrom-Json
$same=[ordered]@{ReadOnly=$true}
foreach ($key in @('firewall_profiles','dns','routes','user_proxy')) {
    $same[$key+'_unchanged']=(($before.$key|ConvertTo-Json -Depth 8 -Compress) -ceq ($after.$key|ConvertTo-Json -Depth 8 -Compress))
}
$same|ConvertTo-Json -Compress
