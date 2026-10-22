$ErrorActionPreference='Stop'
$pins=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'flatbuffers-25.12.19-dependency-pins.json') -Raw | ConvertFrom-Json
$dep=Join-Path $PSScriptRoot 'psec-lpac-bridge-deps'
if(Test-Path -LiteralPath $dep){throw 'Fresh dependency directory required'}
$null=New-Item -ItemType Directory -Path $dep
$settings=Get-ItemProperty -LiteralPath 'HKCU:/Software/Microsoft/Windows/CurrentVersion/Internet Settings'
if($settings.ProxyEnable -ne 1){throw 'Existing manual proxy unavailable'}
$raw=[string]$settings.ProxyServer
if($raw.Contains('=')){
    $items=@($raw.Split(';') | Where-Object {$_ -cmatch '^https='})
    if($items.Count -ne 1){throw 'Ambiguous existing HTTPS proxy'}
    $server=$items[0].Substring(6)
}else{$server=$raw}
if($server -cnotmatch '^(127\.0\.0\.1|localhost):([0-9]{1,5})$'){throw 'Existing credential-free loopback proxy required'}
$port=[int]$Matches[2]
if($port -lt 1025 -or $port -gt 65535){throw 'Invalid proxy port'}
$proxy='http://'+$server
$flat=Join-Path $dep 'Windows.flatc.binary.zip'
Invoke-WebRequest -Uri $pins.flatc_zip.url -Proxy $proxy -OutFile $flat -TimeoutSec 55 -MaximumRedirection 5
if((Get-Item -LiteralPath $flat).Length -ne $pins.flatc_zip.bytes -or (Get-FileHash -LiteralPath $flat -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pins.flatc_zip.sha256){throw 'Official flatc ZIP pin mismatch'}
$source=Join-Path $dep 'flatbuffers-source.zip'
Invoke-WebRequest -Uri $pins.source_zip_url -Proxy $proxy -OutFile $source -TimeoutSec 55 -MaximumRedirection 5
if((Get-Item -LiteralPath $source).Length -gt 33554432){throw 'Source archive exceeds bound'}
[pscustomobject]@{Downloaded=$true;FlatcZipHashVerified=$true;GlobalSettingsChanged=$false;DownloadedCodeExecuted=$false;SourceZipBytes=(Get-Item -LiteralPath $source).Length;SourceZipSha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()}
