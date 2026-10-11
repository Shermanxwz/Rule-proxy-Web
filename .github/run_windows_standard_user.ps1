param([string]$OutputDirectory = 'standard-user-results')
$ErrorActionPreference = 'Stop'
$username = 'RPTest' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$password = [Guid]::NewGuid().ToString('N') + '!Aa9'
$secure = ConvertTo-SecureString $password -AsPlainText -Force
$root = Join-Path 'C:\RuleProxy 标准用户验收' ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $root | Out-Null
try {
    New-LocalUser -Name $username -Password $secure -AccountNeverExpires -PasswordNeverExpires | Out-Null
    $users = (Get-LocalGroup -SID 'S-1-5-32-545').Name
    Add-LocalGroupMember -Group $users -Member $username
    $account = "$env:COMPUTERNAME\$username"
    & icacls.exe $env:GITHUB_WORKSPACE /grant "${account}:(OI)(CI)RX" /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant the test user read access to the source' }
    & icacls.exe $root /grant "${account}:(OI)(CI)M" /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant the test user output access' }
    $credential = [System.Management.Automation.PSCredential]::new($account, $secure)
    $python = (Get-Command python).Source
    foreach ($script in @('windows_native_validation.py', 'windows_browser_validation.py')) {
        $path = Join-Path $env:GITHUB_WORKSPACE ".github\$script"
        $arguments = "-B `"$path`" --output `"$root`""
        $process = Start-Process -FilePath $python -ArgumentList $arguments -Credential $credential -LoadUserProfile -PassThru `
            -RedirectStandardOutput "$root\$script.stdout.txt" -RedirectStandardError "$root\$script.stderr.txt"
        if (-not $process.WaitForExit(180000)) { throw 'Standard user acceptance test timed out' }
        Get-Content "$root\$script.stdout.txt"
        Get-Content "$root\$script.stderr.txt"
        if ($process.ExitCode -ne 0) { throw "Standard user test failed: $script (exit $($process.ExitCode))" }
    }
    $report = Get-Content "$root\report.json" -Raw | ConvertFrom-Json
    if ($report.host.elevated -ne $false) { throw 'The acceptance test was not run as a standard user' }
} finally {
    New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
    Copy-Item "$root\*" $OutputDirectory -Force -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $username -ErrorAction SilentlyContinue
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}
