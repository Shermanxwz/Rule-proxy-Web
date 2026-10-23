#requires -Version 5.1
<# Read-only once. No DNS query, socket, bind, registry/policy/global write. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{32}$')][string]$Run,
    [Parameter(Mandatory=$true)][long]$Frequency,
    [Parameter(Mandatory=$true)][long]$StartQpc,
    [Parameter(Mandatory=$true)][long]$DeadlineQpc
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:lastQpc=0L
function Read-Clock {
    $now=[Diagnostics.Stopwatch]::GetTimestamp()
    if ($Frequency -lt 1 -or $Frequency -gt 1000000000 -or
        [Diagnostics.Stopwatch]::Frequency -ne $Frequency -or $StartQpc -le 0 -or
        $DeadlineQpc -le $StartQpc -or $DeadlineQpc-$StartQpc -gt 120*$Frequency -or
        $now -lt $StartQpc -or $now -lt $script:lastQpc -or $now -ge $DeadlineQpc) {
        throw 'original QPC budget required'
    }
    $script:lastQpc=$now
    return $now
}
function Bounded-String($Value,[int]$Maximum,[bool]$AllowEmpty) {
    if ($Value -isnot [string] -or $Value.Length -gt $Maximum -or
        (-not $AllowEmpty -and $Value.Length -eq 0)) { throw 'inventory string type or bound' }
}
$begin=Read-Clock
$dns=@(Get-DnsClientServerAddress -ErrorAction Stop)
$null=Read-Clock
if ($dns.Count -gt 256) { throw 'DNS row bound' }
$servers=New-Object 'System.Collections.Generic.List[string]'
foreach ($row in $dns) {
    $property=$row.CimInstanceProperties['ServerAddresses']
    if ($null -eq $property -or $property.CimType.ToString() -cne 'StringArray' -or
        $null -eq $property.Value -or $property.Value -isnot [array]) { throw 'DNS addresses unknown' }
    foreach ($address in $property.Value) {
        Bounded-String $address 96 $false
        if ($servers.Count -ge 256) { throw 'DNS address bound' }
        $servers.Add($address)
    }
}

# Only CIM transport metadata is excluded. Every semantic property must be
# present once, with its declared type; a new/unknown semantic field stops here.
$types=[ordered]@{
    Namespace='String';DirectAccessEnabled='Boolean';QueryPolicy='String';
    SecureNameQueryFallback='String';DnsSecIPsecCARestriction='String';
    DnsSecValidationRequired='Boolean';DnsSecQueryIPsecRequired='Boolean';
    DnsSecQueryIPsecEncryption='String';DirectAccessIPsecCARestriction='String';
    DirectAccessQueryIPsecRequired='Boolean';DirectAccessQueryIPsecEncryption='String';
    DirectAccessDnsServers='StringArray';DirectAccessProxyType='String';
    DirectAccessProxyName='String';NameServers='StringArray';NameEncoding='String'
}
$nrpt=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
$null=Read-Clock
if ($nrpt.Count -gt 256) { throw 'NRPT row bound' }
$rules=New-Object 'System.Collections.Generic.List[object]'
foreach ($row in $nrpt) {
    if ($null -eq $row.CimInstanceProperties) { throw 'NRPT semantic properties unknown' }
    $properties=@($row.CimInstanceProperties)
    if ($properties.Count -ne 16) { throw 'NRPT semantic field count' }
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($property in $properties) {
        if (-not $types.Contains($property.Name) -or -not $seen.Add($property.Name) -or
            $property.CimType.ToString() -cne $types[$property.Name]) { throw 'NRPT semantic field or type' }
    }
    $entry=[ordered]@{}
    foreach ($name in $types.Keys) {
        if (-not $seen.Contains($name)) { throw 'NRPT semantic property missing' }
        $value=$row.CimInstanceProperties[$name].Value
        if ($name -ceq 'Namespace') {
            Bounded-String $value 253 $false
        } elseif ($null -ne $value) {
            if ($types[$name] -ceq 'Boolean') {
                if ($value -isnot [bool]) { throw 'NRPT actual boolean required' }
            } elseif ($types[$name] -ceq 'StringArray') {
                if ($value -isnot [array] -or $value.Count -gt 64) { throw 'NRPT server array bound' }
                foreach ($server in $value) { Bounded-String $server 96 $false }
            } else {
                Bounded-String $value 1024 $true
            }
        }
        # Do not cast, join, null-fill or filter the provider's original value.
        $entry[$name]=$value
    }
    $rules.Add($entry)
    $null=Read-Clock
}
$udp=@(Get-NetUDPEndpoint -ErrorAction Stop)
$null=Read-Clock
$tcp=@(Get-NetTCPConnection -ErrorAction Stop)
$null=Read-Clock
if ($udp.Count -gt 32768 -or $tcp.Count -gt 32768) { throw 'endpoint row bound' }
$udp53=0;$tcp53=0
foreach ($row in $udp) {
    $port=$row.CimInstanceProperties['LocalPort']
    if ($null -eq $port -or $port.CimType.ToString() -cne 'UInt16' -or
        $port.Value -isnot [uint16] -or $port.Value -lt 1) { throw 'UDP port unknown' }
    if ($port.Value -eq 53) { $udp53++ }
}
foreach ($row in $tcp) {
    $port=$row.CimInstanceProperties['LocalPort']
    if ($null -eq $port -or $port.CimType.ToString() -cne 'UInt16' -or
        $port.Value -isnot [uint16] -or $port.Value -lt 1) { throw 'TCP port unknown' }
    if ($port.Value -eq 53) { $tcp53++ }
}
$end=Read-Clock
$report=[ordered]@{schema_version=1;stage='dns-exact-nrpt-readonly-inventory';run=$Run;pid=$PID;
    qpc_frequency=$Frequency;start_qpc=$StartQpc;deadline_qpc=$DeadlineQpc;begin_qpc=$begin;end_qpc=$end;
    read_only=$true;dns_servers=@($servers.ToArray());effective_nrpt_count=$nrpt.Count;
    effective_nrpt_rules=@($rules.ToArray());udp53_count=$udp53;tcp53_count=$tcp53}
$raw=($report|ConvertTo-Json -Depth 6 -Compress)+[Environment]::NewLine
if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 32768) { throw 'inventory stdout bound' }
$null=Read-Clock
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
[Console]::Out.Write($raw)
