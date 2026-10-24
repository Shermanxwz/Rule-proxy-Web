param([switch]$Capture,[ValidateSet('before-stream01','after-stream01')][string]$Phase)
$ErrorActionPreference='Stop'
if(-not $Capture){
 [ordered]@{ReadOnlyPreview=$true;CapturePerformed=$false;Phases=@('before-stream01','after-stream01');Objects=4;NrptIncluded=$false;GlobalConfigurationWrites=$false}|ConvertTo-Json -Compress
 return
}
if(-not $Phase){throw 'Explicit before/after phase required'}
$baselineSource=Join-Path $PSScriptRoot 'c_local_baseline.ps1'
if((Get-FileHash -LiteralPath $baselineSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne '98610b0eeeba3457b1bd289e399acfa1744c2c2220c4b1ee53d474418e5df05b'){throw 'Exact read-only four-object source required'}
$private=Join-Path $PSScriptRoot 'Rule-proxy-Web/private'
$name='lpac-stream-origin-'+$Phase+'-global-snapshot.json'
$target=Join-Path $private $name
$expanded=Join-Path $PSScriptRoot ('lpac_stream_origin_'+$Phase+'_expanded.ps1')
if((Test-Path -LiteralPath $expanded) -or (Test-Path -LiteralPath $target)){throw 'Fresh capture paths required'}
$source=[IO.File]::ReadAllText($baselineSource).Replace('model2-first-01-global-baseline.json',$name)
[IO.File]::WriteAllText($expanded,$source,(New-Object Text.UTF8Encoding($false)))
& $expanded
if((Get-Item -LiteralPath $target).Length -gt 262144){throw 'Bounded four-object capture required'}
$originalPath=Join-Path $private 'model2-first-01-global-baseline.json'
$original=Get-Content -LiteralPath $originalPath -Raw | ConvertFrom-Json
$current=Get-Content -LiteralPath $target -Raw | ConvertFrom-Json
$result=[ordered]@{ReadOnly=$true;Phase=$Phase;ObjectsCompared=4;NrptIncluded=$false;Bytes=(Get-Item -LiteralPath $target).Length;Sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant();ByteEqualOriginal=((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ceq (Get-FileHash -LiteralPath $originalPath -Algorithm SHA256).Hash)}
foreach($key in @('firewall_profiles','dns','routes','user_proxy')){
 $result[$key+'_equal_original']=(($original.$key|ConvertTo-Json -Depth 8 -Compress) -ceq ($current.$key|ConvertTo-Json -Depth 8 -Compress))
}
if($Phase -eq 'after-stream01'){
 $beforePath=Join-Path $private 'lpac-stream-origin-before-stream01-global-snapshot.json'
 $before=Get-Content -LiteralPath $beforePath -Raw | ConvertFrom-Json
 $result['ByteEqualBefore']=((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ceq (Get-FileHash -LiteralPath $beforePath -Algorithm SHA256).Hash)
 foreach($key in @('firewall_profiles','dns','routes','user_proxy')){
  $result[$key+'_equal_before-stream01']=(($before.$key|ConvertTo-Json -Depth 8 -Compress) -ceq ($current.$key|ConvertTo-Json -Depth 8 -Compress))
 }
}
$result|ConvertTo-Json -Compress
