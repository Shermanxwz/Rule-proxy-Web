$ErrorActionPreference='Stop'
$repo=Join-Path $PSScriptRoot 'Rule-proxy-Web'
$target=Join-Path $repo 'private/lpac-dns-after02-global-snapshot.json'
if (Test-Path -LiteralPath $target) { throw 'fresh baseline required' }
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
    Sort-Object Name | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules)
$dns=@(Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily |
    Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
$routes=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Sort-Object InterfaceIndex,DestinationPrefix,NextHop |
    Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,Protocol)
if ($profiles.Count -ne 3 -or $dns.Count -gt 256 -or $routes.Count -gt 1024) { throw 'inventory bound' }
$proxy=Get-ItemProperty -LiteralPath 'HKCU:/Software/Microsoft/Windows/CurrentVersion/Internet Settings' -ErrorAction Stop
$proxyValues=[ordered]@{}
foreach ($name in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL','AutoDetect')) {
    $property=$proxy.PSObject.Properties[$name]
    $proxyValues[$name]=if ($null -eq $property) {$null} else {$property.Value}
}
$snapshot=[ordered]@{schema_version=1;stage='model2-first-global-readonly-baseline';firewall_profiles=$profiles;dns=$dns;routes=$routes;user_proxy=$proxyValues}
$raw=($snapshot|ConvertTo-Json -Depth 8 -Compress)+[Environment]::NewLine
$bytes=[Text.Encoding]::UTF8.GetBytes($raw)
if ($bytes.Length -gt 262144) { throw 'baseline bound' }
$stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
[pscustomobject]@{ReadOnly=$true;BaselineSaved=$true;Bytes=$bytes.Length;Sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()}
