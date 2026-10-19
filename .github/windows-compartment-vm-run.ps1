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

function Invoke-OwnedPython([string]$Executable, [string]$Arguments, [int]$Seconds, [string]$LogName) {
    if ($Seconds -lt 1 -or $Seconds -gt 1800 -or $LogName -notmatch '^[a-z][a-z0-9-]{0,31}$') {
        throw 'Invalid bounded Python process parameters'
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = $Arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $child = New-Object Diagnostics.Process
    $child.StartInfo = $info
    $started = $false
    $stdout = $null; $stderr = $null; $outReader = $null; $errReader = $null
    $outPump = $null; $errPump = $null
    $receipt = @{pid=$null; handle_captured=$false; exited=$false; exit_code=$null;
        timed_out=$false; termination_confirmed=$false; drain_complete=$false;
        stdout=($LogName + '-stdout.log'); stderr=($LogName + '-stderr.log')}
    if (-not $script:result.ContainsKey('child_processes')) { $script:result.child_processes = @{} }
    $script:result.child_processes[$LogName] = $receipt
    try {
        $stdout = [IO.File]::Open((Join-Path $root $receipt.stdout), [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $stderr = [IO.File]::Open((Join-Path $root $receipt.stderr), [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $started = $child.Start()
        if (-not $started) { throw 'Owned Python process did not start' }
        # Process.Start owns this native handle before a fast child can exit.
        # Retain it until exit-code reading and cleanup have both finished.
        $heldHandle = $child.Handle
        if ($heldHandle -eq [IntPtr]::Zero) { throw 'Owned Python process handle is unavailable' }
        $receipt.pid = $child.Id
        $receipt.handle_captured = $true
        $outReader, $errReader = $child.StandardOutput.BaseStream, $child.StandardError.BaseStream
        $outPump = $outReader.CopyToAsync($stdout, 81920)
        $errPump = $errReader.CopyToAsync($stderr, 81920)
        if (-not $child.WaitForExit($Seconds * 1000)) {
            $receipt.timed_out = $true
            throw 'Owned Python process exceeded its deadline'
        }
        $receipt.exited = $child.HasExited
        try {
            $exitCode = $child.ExitCode
            if ($receipt.exited -ne $true -or $null -eq $exitCode -or $exitCode -isnot [int]) {
                throw 'Owned Python process exit code is unavailable'
            }
            $receipt.exit_code = $exitCode
        } catch {
            $receipt.exit_read_failed = $true
            $receipt.exit_read_error_type = $_.Exception.GetType().FullName
            throw
        }
        # Descendants holding inherited pipes cannot turn the final read into
        # an unbounded wait. Both pipes have already been draining concurrently.
        $drainDeadline = [DateTime]::UtcNow.AddSeconds(5)
        foreach ($pump in @($outPump, $errPump)) {
            $remaining = [int][Math]::Max(0, ($drainDeadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $pump.Wait($remaining)) { throw 'Owned Python output drain exceeded its deadline' }
        }
        $receipt.drain_complete = $true
        return $exitCode
    } finally {
        if ($started -and $receipt.exited -ne $true) {
            if ($receipt.handle_captured) {
                try {
                    # Kill uses the retained Process handle; never reopen by
                    # numeric PID, which could target a different process.
                    if (-not $child.HasExited) { $child.Kill() }
                    $receipt.termination_confirmed = $child.WaitForExit(5000)
                    $receipt.exited = $receipt.termination_confirmed
                    if (-not $receipt.termination_confirmed) { $receipt.cleanup_unconfirmed = $true }
                } catch {
                    $receipt.cleanup_unconfirmed = $true
                    $receipt.cleanup_error_type = $_.Exception.GetType().FullName
                }
            } else { $receipt.cleanup_unconfirmed = $true }
        }
        foreach ($reader in @($outReader, $errReader)) { if ($null -ne $reader) { try { $reader.Dispose() } catch {} } }
        foreach ($pump in @($outPump, $errPump)) {
            if ($null -ne $pump) { try { [void]$pump.Wait(1000) } catch {} }
        }
        foreach ($stream in @($stdout, $stderr)) { if ($null -ne $stream) { try { $stream.Dispose() } catch {} } }
        $child.Dispose()
    }
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
    $result.phase = 'os_validation'
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $nativeArchitecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $result.os = @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR;
        product_type=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType;
        native_architecture=$nativeArchitecture}
    if ($result.os.product_type -ne 'WinNT' -or $result.os.native_architecture -ne 'AMD64') {
        throw 'This experiment requires an AMD64 Windows client VM'
    }
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
    $result.exit_code = Invoke-OwnedPython $python $arguments 1800 'compartment'
    $result.reports.compartment = Get-Content -LiteralPath (Join-Path $output 'compartment-report.json') -Raw | ConvertFrom-Json
    $result.phase='primary_token_experiment'
    Beacon 'primary-token'
    $primaryWork='C:\RuleProxyRestrictedPrimaryLab'
    $primaryArgs='-I -S -B "' + (Join-Path $workspace '.github\windows_restricted_primary_lab.py') + '" --lab-script "' + (Join-Path $workspace '.github\windows_compartment_lab.py') + '" --probe-script "' + (Join-Path $workspace '.github\windows_dns_compartment_probe.py') + '" --work "' + $primaryWork + '" --variants plain,write_custom_logon,write_custom_rc_logon --browsers edge'
    $result.primary_exit_code = Invoke-OwnedPython $python $primaryArgs 1080 'primary'
    $result.reports.restricted_primary=Get-Content -LiteralPath (Join-Path $primaryWork 'report.json') -Raw | ConvertFrom-Json
    if ($result.primary_exit_code -ne 0) { throw 'Primary-token experiment setup failed' }
    if ($result.exit_code -ne 0) { throw 'Experiment harness failed' }
    $result.phase='completed'; $result.status='passed'
} catch {
    $result.error_type=$_.Exception.GetType().FullName
    $result.error_code=$_.Exception.HResult
    Beacon ('failed ' + $result.phase + ' ' + $result.error_type)
} finally {
    # Preserve completed or partial evidence even if handle/exit-code reading
    # failed before the normal report import. Missing exit status stays unknown.
    foreach ($entry in @(@('compartment', $(if ($output) { Join-Path $output 'compartment-report.json' })),
                         @('restricted_primary', $(if ($primaryWork) { Join-Path $primaryWork 'report.json' })))) {
        if (-not $result.reports.ContainsKey($entry[0]) -and $entry[1] -and (Test-Path -LiteralPath $entry[1])) {
            try { $result.reports[$entry[0]] = Get-Content -LiteralPath $entry[1] -Raw | ConvertFrom-Json }
            catch { $result[($entry[0] + '_report_error_type')] = $_.Exception.GetType().FullName }
        }
    }
    if ($captureStarted -and $null -ne $configuration) {
        $client=New-Object Net.WebClient
        $client.Proxy=$null
        try { $result.wire_observations=($client.UploadString(($configuration.host_url + '/capture/finish'),'POST','{}') | ConvertFrom-Json) }
        catch { $result.capture_error_type=$_.Exception.GetType().FullName; $result.status='failed' }
        finally { $client.Dispose() }
    }
    foreach ($label in @('compartment','primary')) {
        foreach ($name in @('stdout','stderr')) {
            $path = Join-Path $root ($label + '-' + $name + '.log')
            $key = if ($label -eq 'compartment') { $name } else { $label + '_' + $name }
            if (Test-Path -LiteralPath $path) { $result.logs[$key] = ((Get-Content -LiteralPath $path -Tail 100) -join "`n") }
        }
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
