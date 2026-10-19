param([string]$ScriptPath)
$ErrorActionPreference='Stop'
. $ScriptPath -LibraryOnly
$script:Tests=0
function Assert($Condition,[string]$Message){if(-not $Condition){throw $Message};$script:Tests++}
function Record($Kind,$Key,$Provider,$Sublayer,$Marker){
    $r=New-Object RuleProxyRecover.Record
    $r.Kind=$Kind;$r.Key=$Key;$r.ProviderRef=$Provider;$r.SubLayerRef=$Sublayer
    $r.Description=$Marker;$r.Flags=1;$r.ServiceName='RuleProxyControl';$r.Layer='c38d57d1-05a7-4c33-904f-7fbceee60e82'
    return $r
}
$id='a'*64;$marker='RuleProxyGuard-v1:'+$id
Assert ((Get-StableGuid $id 'provider') -eq '470e833b-6492-5dda-9698-fd8d5f56e983') 'uuid5 differs from Python product'
$p=Record provider (Get-StableGuid $id provider) '' '' $marker
$s=Record sublayer (Get-StableGuid $id sublayer) $p.Key '' $marker
$f=Record filter (Get-StableGuid $id '4/block') $p.Key $s.Key $marker
$plan=Get-WfpPlan @($p,$s,$f)
Assert ($plan.Filters.Count -eq 1 -and $plan.Providers.Count -eq 1) 'owned filter missed'
$foreign=Record filter ([guid]::NewGuid().ToString()) $p.Key $s.Key 'AnotherProduct'
$plan=Get-WfpPlan @($p,$s,$f,$foreign)
Assert ($plan.Filters.Count -eq 1 -and $plan.Providers.Count -eq 0 -and $plan.Sublayers.Count -eq 0) 'foreign reference must retain container, not prevent owned-filter recovery'
$fake=Record provider ([guid]::NewGuid().ToString()) '' '' $marker
$plan=Get-WfpPlan @($fake)
Assert ($plan.Providers.Count -eq 0 -and $plan.Unresolved.Count -eq 1) 'marker alone is not ownership'
$old=$f.Description;$f.Description='RuleProxyGuard-v1:'+('b'*64)
$plan=Get-WfpPlan @($p,$s,$f)
Assert ($plan.Filters.Count -eq 0 -and $plan.Unresolved.Count -eq 1) 'cross-install marker must not match'
$f.Description=$old
$dns=[pscustomobject]@{Name='fixture';Namespace=@('.');NameServers=@('198.18.0.2','fdfe:dcba:8879::2');Comment=('RuleProxyDNS-v1:'+$id);DisplayName=('RuleProxy global DNS '+$id.Substring(0,16))}
Assert (Test-NrptCandidate $dns) 'owned NRPT missed'
$dns.DisplayName='RuleProxy global DNS fake'
Assert (-not (Test-NrptCandidate $dns)) 'partial NRPT identity accepted'
$dns.DisplayName='RuleProxy global DNS '+$id.Substring(0,16);$dns.Namespace=@('.example.com')
Assert (-not (Test-NrptCandidate $dns)) 'foreign DNS namespace accepted'
function Get-DnsClientNrptRule {return @()}
function Get-DnsClientNrptPolicy {throw 'effective policy unreadable'}
$threw=$false;try{$null=Get-NrptState}catch{$threw=$true}
Assert $threw 'DNS read error falsely reported clean'
Assert ($null -eq (Get-LoopbackPorts 'proxy.example.com:7890')) 'foreign remote proxy accepted'
Assert ($null -eq (Get-LoopbackPorts '127.0.0.1:0')) 'invalid proxy port accepted'
Assert (@(Get-LoopbackPorts 'http=127.0.0.1:12345;https=[::1]:12346')[0].Count -eq 2) 'loopback proxy parsing'
Assert (-not (Test-ValueEqual @('a',1) @('b',1))) 'proxy conflict equality'

# Mock the OS boundary, exercise the real orchestration / failure semantics.
$empty=[pscustomobject]@{
    Runtime=[pscustomobject]@{Processes=@();Services=@();ForeignMihomo=@()}
    Wfp=[pscustomobject]@{Filters=@();Unresolved=@()}
    Dns=[pscustomobject]@{Candidates=@();Virtual=@();Unresolved=@()}
    Adapter=[pscustomobject]@{Owned=@();Unresolved=@()}
    Proxy=[pscustomobject]@{Previous=$null;DeadManual=$false;DeadPac=$false;DeadWinHttp=$false;OtherUserJournals=@()}
}
$script:Calls=New-Object System.Collections.ArrayList
function Get-RecoveryState {return $empty}
function New-RecoveryLog {return $null}
function Invoke-RuntimeRepair {[void]$script:Calls.Add('runtime')}
function Invoke-WfpRepair {[void]$script:Calls.Add('wfp')}
function Invoke-NrptRepair {[void]$script:Calls.Add('dns')}
function Invoke-AdapterRepair {[void]$script:Calls.Add('adapter')}
function Invoke-ProxyRepair {[void]$script:Calls.Add('proxy')}
$Apply=$false;$Json=$false;$CheckInternet=$false
$code=Invoke-Recovery
Assert ($code -eq 0 -and $script:Calls.Count -eq 0) 'dry run changed network'
$Apply=$true;$code=Invoke-Recovery
Assert ($code -eq 0 -and ($script:Calls -join ',') -eq 'runtime,wfp,dns,adapter,proxy') 'repair order'
$script:Calls.Clear()
function Invoke-WfpRepair {[void]$script:Calls.Add('wfp');Changed 'committed fixture change';throw 'fixture WFP failure'}
$code=Invoke-Recovery
Assert ($code -eq 3 -and ($script:Calls -join ',') -eq 'runtime,wfp' -and $script:Changed.Count -eq 1) 'partial apply must stop and retain changes record'
$script:Calls.Clear()
function Get-RecoveryState {throw 'fixture preflight failure'}
$code=Invoke-Recovery
Assert ($code -eq 3 -and $script:Calls.Count -eq 0) 'preflight error must stop all writes'
Assert ($script:Changed.Count -eq 0) 'changes from a previous invocation leaked into this report'
Write-Host ('PASS: '+$script:Tests+' recovery behavioral assertions')
