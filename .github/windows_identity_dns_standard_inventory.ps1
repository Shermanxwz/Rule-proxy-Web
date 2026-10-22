#requires -Version 5.1
<# Read-only, no DNS query/bind. Any cmdlet error or bound failure emits no report. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{32}$')][string]$Run,
    [Parameter(Mandatory=$true)][long]$Frequency,
    [Parameter(Mandatory=$true)][long]$StartQpc,
    [Parameter(Mandatory=$true)][long]$DeadlineQpc
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Read-Clock {
    $now=[Diagnostics.Stopwatch]::GetTimestamp()
    if ($Frequency -le 0 -or [Diagnostics.Stopwatch]::Frequency -ne $Frequency -or
        $StartQpc -le 0 -or $DeadlineQpc -le $StartQpc -or $now -lt $StartQpc -or $now -ge $DeadlineQpc) {
        throw 'original QPC budget required'
    }
    return $now
}
$begin=Read-Clock
$dns=@(Get-DnsClientServerAddress -ErrorAction Stop)
$null=Read-Clock
if ($dns.Count -gt 256) { throw 'DNS inventory bound' }
$servers=New-Object 'System.Collections.Generic.List[string]'
foreach ($row in $dns) {
    if ($null -eq $row.PSObject.Properties['ServerAddresses'] -or $null -eq $row.ServerAddresses) { throw 'DNS addresses unknown' }
    foreach ($address in @($row.ServerAddresses)) {
        if ($address -isnot [string] -or $address.Length -lt 1 -or $address.Length -gt 96 -or $servers.Count -ge 256) {
            throw 'DNS address bound'
        }
        $servers.Add($address)
    }
}
$nrpt=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
$null=Read-Clock
if ($nrpt.Count -gt 256) { throw 'NRPT inventory bound' }
# Deliberately reject every nonempty effective NRPT inventory in Python. We do
# not claim that every rule affects n0a.invalid or implement partial matching.
$udp=@(Get-NetUDPEndpoint -ErrorAction Stop)
$null=Read-Clock
$tcp=@(Get-NetTCPConnection -ErrorAction Stop)
$null=Read-Clock
if ($udp.Count -gt 32768 -or $tcp.Count -gt 32768) { throw 'endpoint inventory bound' }
$udp53=0; $tcp53=0
foreach ($row in $udp) {
    if ($null -eq $row.PSObject.Properties['LocalPort'] -or $null -eq $row.LocalPort) { throw 'UDP port unknown' }
    if ([int]$row.LocalPort -lt 1 -or [int]$row.LocalPort -gt 65535) { throw 'UDP port invalid' }
    if ([int]$row.LocalPort -eq 53) { $udp53++ }
}
foreach ($row in $tcp) {
    if ($null -eq $row.PSObject.Properties['LocalPort'] -or $null -eq $row.LocalPort) { throw 'TCP port unknown' }
    if ([int]$row.LocalPort -lt 1 -or [int]$row.LocalPort -gt 65535) { throw 'TCP port invalid' }
    if ([int]$row.LocalPort -eq 53) { $tcp53++ }
}
$end=Read-Clock
$report=[ordered]@{schema_version=1;stage='dns-standard-readonly-inventory';run=$Run;pid=$PID;
    qpc_frequency=$Frequency;start_qpc=$StartQpc;deadline_qpc=$DeadlineQpc;begin_qpc=$begin;end_qpc=$end;
    read_only=$true;dns_servers=@($servers.ToArray());effective_nrpt_count=$nrpt.Count;udp53_count=$udp53;tcp53_count=$tcp53}
$raw=($report|ConvertTo-Json -Depth 4 -Compress)+[Environment]::NewLine
if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 32768) { throw 'inventory report bound' }
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
[Console]::Out.Write($raw)
