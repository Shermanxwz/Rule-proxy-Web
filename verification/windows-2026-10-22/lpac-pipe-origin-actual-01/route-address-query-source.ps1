param([switch]$Query)
$ErrorActionPreference='Stop'
if(-not $Query){[ordered]@{Preview=$true;QueriesPerformed=$false;ConfigurationWrites=$false}|ConvertTo-Json -Compress;return}
$private=Join-Path $PSScriptRoot 'Rule-proxy-Web/private'
$beforePath=Join-Path $private 'lpac-pipe-origin-before-ipc01-global-snapshot.json'
$afterPath=Join-Path $private 'lpac-pipe-origin-after-ipc01-global-snapshot.json'
if((Get-FileHash -LiteralPath $beforePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'){throw 'Exact before snapshot required'}
if((Get-FileHash -LiteralPath $afterPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '96ba4618bdcee58d28de676038b661681b955502799cdce7aae5fa24d61e8f95'){throw 'Exact after snapshot required'}
$before=Get-Content -LiteralPath $beforePath -Raw|ConvertFrom-Json
$after=Get-Content -LiteralPath $afterPath -Raw|ConvertFrom-Json
$old=@($before.routes|ForEach-Object {$_|ConvertTo-Json -Compress})
$added=@($after.routes|Where-Object {($_|ConvertTo-Json -Compress) -cnotin $old})
if($added.Count -ne 2){throw 'Exactly two added route records required'}
$rows=@()
for($i=0;$i -lt $added.Count;$i++){
 $route=$added[$i]
 if($route.DestinationPrefix -notlike '*:*/128' -or [int]$route.Protocol -ne 2 -or $route.NextHop -cne '::'){throw 'Bound IPv6 local host route shape required'}
 $address=$route.DestinationPrefix.Substring(0,$route.DestinationPrefix.Length-4)
 $matches=@(Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex $route.InterfaceIndex -IPAddress $address -ErrorAction Stop)
 $views=@($matches|ForEach-Object {[ordered]@{PrefixLength=[int]$_.PrefixLength;PrefixOrigin=$_.PrefixOrigin.ToString();SuffixOrigin=$_.SuffixOrigin.ToString();AddressState=$_.AddressState.ToString();Type=$_.Type.ToString();SkipAsSource=[bool]$_.SkipAsSource;ValidLifetimeSeconds=[math]::Floor($_.ValidLifetime.TotalSeconds);PreferredLifetimeSeconds=[math]::Floor($_.PreferredLifetime.TotalSeconds)}})
 $rows+=[ordered]@{AddedRouteIndex=$i;MatchingLocalAddressCount=$matches.Count;MatchingLocalAddresses=$views}
}
$result=[ordered]@{schema_version=1;stage='read-only-added-local-ipv6-address-query';AfterSnapshotSha256='96ba4618bdcee58d28de676038b661681b955502799cdce7aae5fa24d61e8f95';Rows=$rows;ConfigurationWrites=$false;NetworkSocketCreated=$false;Attribution='Current address properties do not establish creator or creation time of the changed routes.'}
$raw=($result|ConvertTo-Json -Depth 8)+[Environment]::NewLine
$bytes=[Text.Encoding]::UTF8.GetBytes($raw)
$output=Join-Path $PSScriptRoot 'lpac-pipe-origin-added-local-ipv6-query-01.json'
$stream=[IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
[ordered]@{Bytes=$bytes.Length;Sha256=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant();Result=$result}|ConvertTo-Json -Depth 8 -Compress
