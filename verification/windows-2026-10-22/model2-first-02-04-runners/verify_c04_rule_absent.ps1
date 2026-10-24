param([Parameter(Mandatory=$true)][string]$OriginalPlan,[Parameter(Mandatory=$true)][string]$FirewallSource)
$ErrorActionPreference='Stop'
$module=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/Modules/NetSecurity/NetSecurity.psd1'
Import-Module -Name $module -Force -ErrorAction Stop
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($FirewallSource,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw 'source parse' }
$functions=@($ast.FindAll({param($item) $item -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -ceq 'Read-ExactRule'},$true))
if ($functions.Count -ne 1) { throw 'source function' }
. ([ScriptBlock]::Create($functions[0].Extent.Text))
$plan=Get-Content -LiteralPath $OriginalPlan -Raw | ConvertFrom-Json
if (@($plan.rules).Count -ne 1 -or $plan.rules[0].name -cnotmatch ('^RuleProxy\.Model2\.'+$plan.run+'\.A-P$')) { throw 'owned rule name' }
foreach ($store in @('PersistentStore','ActiveStore')) {
    if ($null -ne (Read-ExactRule $plan.rules[0].name $store)) { throw 'owned rule present' }
}
'{"owned_rule_absent":true,"rule_mutation_attempted":false}'
