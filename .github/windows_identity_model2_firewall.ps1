#requires -Version 5.1
<# Internal elevated maintenance child. Parent holds image/token/Job before resume.
   No profile/default policy, global firewall, proxy, DNS, route or exemption edits. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$InputPlan,
      [Parameter(Mandatory=$true)][string]$OutputReport)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$WarningPreference='Stop'
$ProgressPreference='SilentlyContinue'
$result=[ordered]@{schema_version=1;stage='model2-firewall-operation';operation=$null;
    attempted=$false;success=$false;record=$null;failure='input'}

function Require-ExactKeys($Value, [string[]]$Keys) {
    if ($null -eq $Value -or @($Value.PSObject.Properties).Count -ne $Keys.Count) { throw 'schema' }
    foreach ($key in $Keys) { if ($null -eq $Value.PSObject.Properties[$key]) { throw 'schema' } }
}
function Require-Time($Plan) {
    if ($Plan.frequency -isnot [long] -and $Plan.frequency -isnot [int]) { throw 'clock' }
    if ($Plan.deadline_qpc -isnot [long] -and $Plan.deadline_qpc -isnot [int]) { throw 'clock' }
    $frequency=[Diagnostics.Stopwatch]::Frequency
    $now=[Diagnostics.Stopwatch]::GetTimestamp()
    if ($frequency -cne $Plan.frequency -or $frequency -le 0 -or $Plan.deadline_qpc -le $now -or
        $Plan.deadline_qpc-$now -gt 120*$frequency) { throw 'clock' }
}
function Read-ExactRule([string]$Name,[string]$Store) {
    try { $rows=@(NetSecurity\Get-NetFirewallRule -PolicyStore $Store -Name $Name -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound_Name*') { return $null }
        throw
    }
    if ($rows.Count -ne 1 -or $rows[0].Name -cne $Name) { throw 'rule_count' }
    return $rows[0]
}
function Check-Rule($Row,$Expected,[string]$Store,[bool]$RequireEffective=$false) {
    if ($null -eq $Row) { throw 'missing_rule' }
    $apps=@($Row | NetSecurity\Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $ports=@($Row | NetSecurity\Get-NetFirewallPortFilter -ErrorAction Stop)
    $addresses=@($Row | NetSecurity\Get-NetFirewallAddressFilter -ErrorAction Stop)
    $security=@($Row | NetSecurity\Get-NetFirewallSecurityFilter -ErrorAction Stop)
    if ($apps.Count -ne 1 -or $ports.Count -ne 1 -or $addresses.Count -ne 1 -or $security.Count -ne 1) { throw 'filters' }
    if ($Row.Name -cne $Expected.name -or [string]$Row.Direction -cne 'Inbound' -or
        [string]$Row.Action -cne 'Allow' -or [string]$Row.Profile -cne 'Any' -or
        [string]$Row.Enabled -cne 'True' -or [string]$Row.EdgeTraversalPolicy -cne 'Block' -or
        [string]$security[0].OverrideBlockRules -cne 'False' -or
        [string]$apps[0].Package -cne $Expected.package_sid -or
        -not [string]::Equals([string]$apps[0].Program,[string]$Expected.program,[StringComparison]::OrdinalIgnoreCase) -or
        [string]$ports[0].Protocol -cne 'TCP' -or @($ports[0].LocalPort).Count -ne 1 -or
        [string]$ports[0].LocalPort -cne [string]$Expected.local_port -or
        [string]$ports[0].RemotePort -cne 'Any' -or @($addresses[0].LocalAddress).Count -ne 1 -or
        @($addresses[0].RemoteAddress).Count -ne 1 -or
        [string]$addresses[0].LocalAddress -cne '127.0.0.1' -or
        [string]$addresses[0].RemoteAddress -cne '127.0.0.1') { throw 'scope' }
    # A local object that is rejected by the effective policy cannot authorize use.
    if ($RequireEffective -and $Store -ceq 'ActiveStore' -and [string]$Row.EnforcementStatus -cne 'Full') { throw 'effective_policy' }
    return $Expected
}

try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal=New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'elevated_required' }
    } finally { $identity.Dispose() }
    $file=Get-Item -LiteralPath $InputPlan -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt 8192 -or
        ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'plan' }
    # The owner writes canonical JSON with no duplicate/non-finite values and pins
    # these bytes before this suspended child is admitted and resumed.
    $plan=([IO.File]::ReadAllText($file.FullName,[Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop)
    Require-ExactKeys $plan @('schema_version','stage','run','operation','frequency','deadline_qpc','rule')
    if ($plan.schema_version -cne 1 -or $plan.stage -cne 'model2-firewall-input' -or
        $plan.run -cnotmatch '^[0-9a-f]{32}$' -or @('read-persistent','read-active','create','remove') -cnotcontains $plan.operation) { throw 'plan' }
    $rule=$plan.rule
    Require-ExactKeys $rule @('name','package_sid','program','direction','action','protocol','local_address',
        'remote_address','local_port','remote_port','profile','enabled','edge_traversal','override_block_rules','policy_store')
    if ($rule.name -cnotmatch ('^RuleProxy\.Model2\.'+$plan.run+'\.(A-P|A-Q|B-P)$') -or
        $rule.package_sid -cnotmatch '^S-1-15-2-(?:[0-9]+-){6}[0-9]+$' -or
        $rule.local_port -isnot [int] -or $rule.local_port -lt 49153 -or $rule.local_port -gt 65535 -or
        $rule.direction -cne 'Inbound' -or $rule.action -cne 'Allow' -or $rule.protocol -cne 'TCP' -or
        $rule.local_address -cne '127.0.0.1' -or $rule.remote_address -cne '127.0.0.1' -or
        $rule.remote_port -cne 'Any' -or $rule.profile -cne 'Any' -or $rule.enabled -isnot [bool] -or
        $rule.enabled -cne $true -or $rule.edge_traversal -cne 'Block' -or
        $rule.override_block_rules -isnot [bool] -or $rule.override_block_rules -cne $false -or
        $rule.policy_store -cne 'PersistentStore') { throw 'scope' }
    $program=Get-Item -LiteralPath $rule.program -ErrorAction Stop
    if ($program.PSIsContainer -or ($program.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $program.Name -cne 'windows_identity_proxy_c_actor.exe' -or
        -not [string]::Equals($program.FullName,$rule.program,[StringComparison]::OrdinalIgnoreCase)) { throw 'program' }
    Require-Time $plan
    $modulePath=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\Modules\NetSecurity\NetSecurity.psd1'
    $moduleFile=Get-Item -LiteralPath $modulePath -ErrorAction Stop
    if ($moduleFile.PSIsContainer -or ($moduleFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'system_module' }
    $modules=@(Import-Module -Name $moduleFile.FullName -Force -PassThru -ErrorAction Stop)
    if ($modules.Count -ne 1 -or $modules[0].Name -cne 'NetSecurity' -or
        -not [string]::Equals($modules[0].ModuleBase,$moduleFile.DirectoryName,[StringComparison]::OrdinalIgnoreCase)) { throw 'system_module' }
    Require-Time $plan
    $result.operation=$plan.operation
    $result.failure='firewall_operation'
    if ($plan.operation -ceq 'read-persistent' -or $plan.operation -ceq 'read-active') {
        $store=if ($plan.operation -ceq 'read-active') {'ActiveStore'} else {'PersistentStore'}
        $row=Read-ExactRule $rule.name $store
        if ($null -ne $row) { $result.record=Check-Rule $row $rule $store }
    } elseif ($plan.operation -ceq 'create') {
        if ($null -ne (Read-ExactRule $rule.name 'PersistentStore') -or $null -ne (Read-ExactRule $rule.name 'ActiveStore')) { throw 'not_fresh' }
        Require-Time $plan
        $result.attempted=$true
        $null=NetSecurity\New-NetFirewallRule -PolicyStore PersistentStore -Name $rule.name -DisplayName $rule.name `
            -Direction Inbound -Action Allow -Enabled True -Profile Any -Package $rule.package_sid `
            -Program $rule.program -Protocol TCP -LocalPort $rule.local_port -RemotePort Any `
            -LocalAddress 127.0.0.1 -RemoteAddress 127.0.0.1 -EdgeTraversalPolicy Block `
            -OverrideBlockRules $false -ErrorAction Stop
        $null=Check-Rule (Read-ExactRule $rule.name 'PersistentStore') $rule 'PersistentStore'
        $result.record=Check-Rule (Read-ExactRule $rule.name 'ActiveStore') $rule 'ActiveStore' $true
    } else {
        $stored=Read-ExactRule $rule.name 'PersistentStore'
        $active=Read-ExactRule $rule.name 'ActiveStore'
        if ($null -ne $stored) { $null=Check-Rule $stored $rule 'PersistentStore' }
        if ($null -ne $active) { $null=Check-Rule $active $rule 'ActiveStore' }
        if ($null -eq $stored -and $null -ne $active) { throw 'unowned_effective_rule' }
        if ($null -ne $stored) {
            Require-Time $plan
            $result.attempted=$true
            $stored | NetSecurity\Remove-NetFirewallRule -ErrorAction Stop
        }
        if ($null -ne (Read-ExactRule $rule.name 'PersistentStore') -or $null -ne (Read-ExactRule $rule.name 'ActiveStore')) { throw 'rule_remains' }
    }
    Require-Time $plan
    $result.success=$true
    $result.failure=$null
} catch { }
$raw=($result | ConvertTo-Json -Depth 8 -Compress)+[Environment]::NewLine
$stream=New-Object IO.FileStream($OutputReport,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
    $bytes=[Text.Encoding]::ASCII.GetBytes($raw)
    if ($bytes.Length -gt 8192) { throw 'report_bound' }
    $stream.Write($bytes,0,$bytes.Length)
    $stream.Flush($true)
} finally { $stream.Dispose() }
if (-not $result.success) { exit 5 }
exit 0
