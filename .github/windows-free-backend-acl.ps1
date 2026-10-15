# Exact ACL setup for the disposable free-backend VM payload.
# Dot-source this file, then call Protect-FreeBackendTree -Root 'C:\RuleProxyCI'.
# The root is deliberately fixed: this helper is not a general ACL utility.

function Protect-FreeBackendTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $expectedRoot = [IO.Path]::GetFullPath('C:\RuleProxyCI').TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not [string]::Equals($fullRoot, $expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'free_backend_acl_root_must_be_C_RuleProxyCI'
    }
    if (-not (Test-Path -LiteralPath $fullRoot -PathType Container)) {
        throw 'free_backend_acl_root_missing'
    }

    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $usersSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $noInherit = [Security.AccessControl.InheritanceFlags]::None
    $noPropagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $readExecute = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    $modify = [Security.AccessControl.FileSystemRights]::Modify

    # Output roots must exist before enumeration so every descendant receives
    # the output-only Modify policy explicitly.
    foreach ($name in @('results', 'artifacts')) {
        $path = Join-Path $fullRoot $name
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }

    # Enumerate without following reparse points. Refuse the entire operation
    # before changing any ACL if any entry redirects outside this trusted tree.
    $entries = New-Object 'Collections.Generic.List[object]'
    $pending = New-Object 'Collections.Generic.Stack[IO.DirectoryInfo]'
    $rootInfo = New-Object IO.DirectoryInfo($fullRoot)
    if (($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'free_backend_acl_root_reparse_point_rejected'
    }
    $entries.Add($rootInfo)
    $pending.Push($rootInfo)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in $directory.GetFileSystemInfos()) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'free_backend_acl_reparse_point_rejected'
            }
            $entries.Add($entry)
            if ($entry -is [IO.DirectoryInfo]) { $pending.Push($entry) }
        }
    }

    $resultsRoot = (Join-Path $fullRoot 'results').TrimEnd('\') + '\'
    $artifactsRoot = (Join-Path $fullRoot 'artifacts').TrimEnd('\') + '\'
    foreach ($entry in $entries) {
        $path = $entry.FullName
        $isDirectory = $entry -is [IO.DirectoryInfo]
        $inheritFlags = if ($isDirectory) { $inherit } else { $noInherit }
        $isOutput = [string]::Equals($path.TrimEnd('\'), $resultsRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($path.TrimEnd('\'), $artifactsRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
            $path.StartsWith($resultsRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $path.StartsWith($artifactsRoot, [StringComparison]::OrdinalIgnoreCase)

        if ($isDirectory) { $acl = New-Object Security.AccessControl.DirectorySecurity }
        else { $acl = New-Object Security.AccessControl.FileSecurity }
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($adminsSid)
        foreach ($sid in @($systemSid, $adminsSid)) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $sid, $full, $inheritFlags, $noPropagation, $allow)
            $acl.AddAccessRule($rule)
        }
        if ($isOutput) { $userRights = $modify }
        else { $userRights = $readExecute }
        $userRule = New-Object Security.AccessControl.FileSystemAccessRule(
            $usersSid, $userRights, $inheritFlags, $noPropagation, $allow)
        $acl.AddAccessRule($userRule)
        Set-Acl -LiteralPath $path -AclObject $acl
    }
}
