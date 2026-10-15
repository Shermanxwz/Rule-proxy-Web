# Orchestration is SYSTEM; the product suite explicitly logs on an ordinary user.
$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyProductBootstrap'
$configuration = Get-Content -LiteralPath (Join-Path $root 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
$result = @{status='failed'; reports=@{}; logs=@{}}
$userCreated = $false
$userName = 'RuleProxyNative'
$utf8 = New-Object Text.UTF8Encoding($false)
# Claim the single run before entering the reporting finally block. A duplicate
# logon must not overwrite a successful result with an empty failed result.
try {
    $claim = [IO.File]::Open((Join-Path $root 'started'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $claim.Dispose()
} catch [IO.IOException] { exit 0 }
try {
    Unregister-ScheduledTask -TaskName 'RuleProxyProduct-Qualification' -Confirm:$false
    $payload = Join-Path $root 'payload.zip'
    $client = New-Object Net.WebClient
    $client.Proxy = $null
    try { $client.DownloadFile(($configuration.host_url + '/payload.zip'), $payload) } finally { $client.Dispose() }
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) { throw 'Native VM payload digest mismatch' }
    $workspace = Join-Path $root 'workspace'
    Expand-Archive -LiteralPath $payload -DestinationPath $workspace
    # Only source fixtures are readable by actors; the capability configuration
    # and unattended bootstrap remain SYSTEM/Administrators-only.
    & icacls.exe $workspace /grant:r '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant actor source read access' }
    $packageDirectory = Join-Path $workspace 'package'
    $package = Get-ChildItem -LiteralPath $packageDirectory -Filter '*.zip'
    if (@($package).Count -ne 1 -or (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.package_sha256) { throw 'Native VM package digest mismatch' }
    $stage = Join-Path $root 'boot-runtime'
    Expand-Archive -LiteralPath $package.FullName -DestinationPath $stage
    $python = Join-Path $stage 'RuleProxy-Web\python\python.exe'
    if (-not (Test-Path -LiteralPath $python)) { throw 'Native VM bootstrap Python missing' }
    $passwordText = [guid]::NewGuid().ToString('N') + 'Q7!'
    $password = ConvertTo-SecureString $passwordText -AsPlainText -Force
    $user = New-LocalUser -Name $userName -Password $password -PasswordNeverExpires
    $userCreated = $true
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member $userName
    $env:RULEPROXY_TEST_USER = $userName
    $env:RULEPROXY_TEST_PASSWORD = $passwordText
    $env:RULEPROXY_TEST_SID = $user.SID.Value
    $evidence = Join-Path $workspace 'evidence'
    $log = Join-Path $root 'qualification.log'
    & $python -I -S (Join-Path $workspace '.github\windows_proxifyre_product_acceptance.py') --package-dir $packageDirectory --output $evidence *> $log
    $exitCode = $LASTEXITCODE
    $report = Get-Content -LiteralPath (Join-Path $evidence 'product-report.json') -Raw | ConvertFrom-Json
    $result.reports.product = $report
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.os = @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR; product_type=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType; native_architecture=$env:PROCESSOR_ARCHITECTURE}
    $result.exit_code = $exitCode
    if ($exitCode -ne 0 -or $report.status -notin @('passed_server_product_qualification','passed_windows_11_product_qualification')) { throw 'Native installed product checks failed' }
    if ($result.os.product_type -ne 'WinNT' -or $result.os.build -lt 22000 -or $result.os.native_architecture -ne 'AMD64') { throw 'Native client Windows 11 x64 identity failed' }
    $result.status = 'passed'
} catch {
    # Bootstrap exceptions can contain the private serving URL; keep only type/code.
    $result.error_type = $_.Exception.GetType().FullName
    $result.error_code = [long]$_.Exception.HResult
    $reportPath = Join-Path $root 'workspace\evidence\product-report.json'
    if (Test-Path -LiteralPath $reportPath) {
        try { $result.reports.product = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json } catch { }
    }
} finally {
    Remove-Item Env:RULEPROXY_TEST_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:RULEPROXY_TEST_USER -ErrorAction SilentlyContinue
    Remove-Item Env:RULEPROXY_TEST_SID -ErrorAction SilentlyContinue
    $passwordText = $null
    if ($null -ne $password) { $password.Dispose(); $password = $null }
    $result.user_cleanup_confirmed = $false
    try {
        if ($userCreated) { Remove-LocalUser -Name $userName -ErrorAction Stop }
        $result.user_cleanup_confirmed = $null -eq (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)
    } catch { $result.user_cleanup_confirmed = $false }
    if (-not $result.user_cleanup_confirmed) { $result.status = 'failed' }
    $body = $result | ConvertTo-Json -Depth 70 -Compress
    $bytes = $utf8.GetBytes($body)
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $request = [Net.HttpWebRequest]::Create($configuration.host_url + '/result')
        $request.Method = 'POST'
        $request.Proxy = $null
        $request.Timeout = 15000
        $request.ReadWriteTimeout = 15000
        $request.ContentType = 'application/json'
        $request.ContentLength = $bytes.Length
        try {
            $stream = $request.GetRequestStream()
            try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
            $response = $request.GetResponse()
            try { if ([int]$response.StatusCode -ne 200) { throw 'Result rejected' } } finally { $response.Dispose() }
            break
        } catch { $request.Abort() }
    }
}
