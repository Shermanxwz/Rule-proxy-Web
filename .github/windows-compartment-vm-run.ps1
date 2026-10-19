# Runs only in a disposable official Windows 11 VM, as SYSTEM after real-user logon.
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$root = 'C:\RuleProxyProductBootstrap'
$utf8 = New-Object Text.UTF8Encoding($false)
$configuration = $null
$captureStarted = $false
$result = @{schema_version=1; status='failed'; suite='compartment-lab'; reports=@{}; phase='logon_gate'; logs=@{}}

function Beacon([string]$Text) {
    $port = $null
    try {
        $port = New-Object IO.Ports.SerialPort('COM1',115200)
        $port.WriteTimeout = 2000
        $port.Open()
        $port.Write('RPBEACON compartment ' + $Text + "`r`n")
    } catch { } finally { if ($null -ne $port) { $port.Dispose() } }
}

# The specialize task also sees OOBE logons. Only the installed ordinary user's
# Explorer session may claim the run and cause the host to attach networking.
if (Test-Path -LiteralPath (Join-Path $root 'compartment-started')) { exit 0 }
$session = @((Get-Process explorer -ErrorAction SilentlyContinue) | Where-Object { $_.SessionId -gt 0 })
if ($session.Count -eq 0) { exit 0 }
try {
    $claim = [IO.File]::Open((Join-Path $root 'compartment-started'),[IO.FileMode]::CreateNew)
    $claim.Dispose()
} catch [IO.IOException] { exit 0 }
Beacon 'claimed'
try {
    $configuration = Get-Content -LiteralPath (Join-Path $root 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
    $payload = Join-Path $root 'compartment-payload.zip'
    $result.phase = 'download'
    $downloaded = $false
    for ($attempt=0; $attempt -lt 12; $attempt++) {
        $client = New-Object Net.WebClient
        $client.Proxy = $null
        try { $client.DownloadFile(($configuration.host_url + '/payload.zip'),$payload); $downloaded=$true; break }
        catch { Start-Sleep -Seconds 5 } finally { $client.Dispose() }
    }
    if (-not $downloaded) { throw 'Payload download failed' }
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) { throw 'Payload digest mismatch' }
    $workspace = Join-Path $root 'compartment-workspace'
    Expand-Archive -LiteralPath $payload -DestinationPath $workspace
    & icacls.exe $workspace /grant:r '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant source read access' }
    $package = @(Get-ChildItem -LiteralPath (Join-Path $workspace 'package') -Filter '*.zip')
    if ($package.Count -ne 1 -or (Get-FileHash -LiteralPath $package[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.package_sha256) { throw 'Package digest mismatch' }
    $result.package_sha256 = $configuration.package_sha256
    $runtime = Join-Path $root 'compartment-runtime'
    Expand-Archive -LiteralPath $package[0].FullName -DestinationPath $runtime
    & icacls.exe $runtime /grant:r '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant runtime read access' }
    $python = Join-Path $runtime 'RuleProxy-Web\python\python.exe'
    $output = Join-Path $workspace 'compartment-results'
    $env:GITHUB_SHA = [string]$configuration.source_commit
    $env:GITHUB_ACTIONS = 'true'
    $client = New-Object Net.WebClient
    $client.Proxy = $null
    try { [void]$client.UploadString(($configuration.host_url + '/capture/start'),'POST','{}'); $captureStarted=$true }
    finally { $client.Dispose() }
    $result.phase = 'experiment'
    Beacon 'experiment'
    $arguments = '-I -S -B "' + (Join-Path $workspace '.github\windows_compartment_lab.py') + '" driver --out "' + $output + '"'
    $process = Start-Process -FilePath $python -ArgumentList $arguments -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $root 'compartment-stdout.log') -RedirectStandardError (Join-Path $root 'compartment-stderr.log')
    try {
        if (-not $process.WaitForExit(1800000)) {
            & taskkill.exe /PID $process.Id /T /F | Out-Null
            throw 'Compartment experiment exceeded its bound'
        }
        $result.exit_code = $process.ExitCode
    } finally { $process.Dispose() }
    $result.reports.compartment = Get-Content -LiteralPath (Join-Path $output 'compartment-report.json') -Raw | ConvertFrom-Json
    $result.phase='primary_token_experiment'
    Beacon 'primary-token'
    $primaryWork='C:\RuleProxyRestrictedPrimaryLab'
    $primaryArgs='-I -S -B "' + (Join-Path $workspace '.github\windows_restricted_primary_lab.py') + '" --lab-script "' + (Join-Path $workspace '.github\windows_compartment_lab.py') + '" --probe-script "' + (Join-Path $workspace '.github\windows_dns_compartment_probe.py') + '" --work "' + $primaryWork + '" --variants plain,write_custom_logon,write_custom_rc_logon --browsers edge'
    $primary=Start-Process -FilePath $python -ArgumentList $primaryArgs -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $root 'primary-stdout.log') -RedirectStandardError (Join-Path $root 'primary-stderr.log')
    try {
        if (-not $primary.WaitForExit(600000)) {
            & taskkill.exe /PID $primary.Id /T /F | Out-Null
            throw 'Primary-token experiment exceeded its bound'
        }
        $result.primary_exit_code=$primary.ExitCode
    } finally { $primary.Dispose() }
    $result.reports.restricted_primary=Get-Content -LiteralPath (Join-Path $primaryWork 'report.json') -Raw | ConvertFrom-Json
    if ($result.primary_exit_code -ne 0) { throw 'Primary-token experiment setup failed' }
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.os = @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR;
        product_type=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType;
        native_architecture=$env:PROCESSOR_ARCHITECTURE}
    if ($result.exit_code -ne 0) { throw 'Experiment harness failed' }
    $result.phase='completed'; $result.status='passed'
} catch {
    $result.error_type=$_.Exception.GetType().FullName
    $result.error_code=$_.Exception.HResult
    Beacon ('failed ' + $result.phase + ' ' + $result.error_type)
} finally {
    if ($captureStarted -and $null -ne $configuration) {
        $client=New-Object Net.WebClient
        $client.Proxy=$null
        try { $result.wire_observations=($client.UploadString(($configuration.host_url + '/capture/finish'),'POST','{}') | ConvertFrom-Json) }
        catch { $result.capture_error_type=$_.Exception.GetType().FullName; $result.status='failed' }
        finally { $client.Dispose() }
    }
    foreach ($name in @('stdout','stderr')) {
        $path = Join-Path $root ('compartment-' + $name + '.log')
        if (Test-Path -LiteralPath $path) { $result.logs[$name] = ((Get-Content -LiteralPath $path -Tail 100) -join "`n") }
    }
    # URLs in diagnostic text may contain the per-VM host capability.
    $body = $result | ConvertTo-Json -Depth 90 -Compress
    if ($null -ne $configuration -and $configuration.host_url) {
        $body=$body.Replace([string]$configuration.host_url,'[HOST CAPABILITY REDACTED]')
        $bytes=$utf8.GetBytes($body)
        for ($attempt=0; $attempt -lt 3; $attempt++) {
            $request=[Net.HttpWebRequest]::Create($configuration.host_url + '/result')
            $request.Method='POST'; $request.Proxy=$null; $request.Timeout=15000; $request.ReadWriteTimeout=15000
            $request.ContentType='application/json'; $request.ContentLength=$bytes.Length
            try {
                $stream=$request.GetRequestStream()
                try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
                $response=$request.GetResponse()
                try { if ([int]$response.StatusCode -ne 200) { throw 'Result rejected' } } finally { $response.Dispose() }
                break
            } catch { $request.Abort() }
        }
    }
    [IO.File]::WriteAllText((Join-Path $root 'compartment-bootstrap-result.json'),$body,$utf8)
    Beacon 'report-ready'
}
