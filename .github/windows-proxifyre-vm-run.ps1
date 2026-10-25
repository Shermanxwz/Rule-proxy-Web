# Disposable native qualification only; the product suite runs as an ordinary user.
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$root = 'C:\RuleProxyProductBootstrap'
$configuration = $null
$password = $null
$passwordText = $null
$userCreated = $false
$userName = 'RuleProxyCI'
$actorSession = $null
$ownerSid = $null
$utf8 = New-Object Text.UTF8Encoding($false)
$result = @{schema_version=2; status='failed'; reports=@{}; logs=@{}; steps=@(); errors=@();
    phase='initializing'; try_completed=$false; catch_entered=$false;
    error_type='BootstrapIncomplete'; error_code=0; user_cleanup_confirmed=$false}

function Protect-DiagnosticText([string]$Value) {
    if ($null -eq $Value) { return '' }
    foreach ($secret in @($script:passwordText, $env:RULEPROXY_TEST_PASSWORD)) {
        if (-not [string]::IsNullOrEmpty($secret)) { $Value = $Value.Replace($secret, '[PASSWORD REDACTED]') }
    }
    if ($null -ne $script:configuration -and $script:configuration.host_url) {
        $Value = $Value.Replace([string]$script:configuration.host_url, '[CAPABILITY URL REDACTED]')
        $capability = ([Uri]$script:configuration.host_url).AbsolutePath.Trim('/')
        if ($capability) { $Value = $Value.Replace($capability, '[CAPABILITY REDACTED]') }
    }
    return [regex]::Replace($Value, '(?i)https?://[^\\\s"''<>]+', '[URL REDACTED]')
}

function Send-SerialBeacon([string]$Text) {
    # Only the claimed ordinary-user qualification reaches this call. OOBE cannot
    # request a NIC; the host reads this bounded, redacted COM1 progress marker.
    $port = $null
    try {
        $clean = [regex]::Replace((Protect-DiagnosticText $Text), '[^\x20-\x7E]', '?')
        if ($clean.Length -gt 2000) { $clean = $clean.Substring(0, 2000) }
        $port = New-Object IO.Ports.SerialPort('COM1', 115200)
        $port.WriteTimeout = 2000
        $port.Open()
        $port.Write('RPBEACON ' + $clean + "`r`n")
    } catch { } finally {
        if ($null -ne $port) { try { $port.Dispose() } catch { } }
    }
}

function Test-HostReachable([Uri]$Uri) {
    $client = New-Object Net.Sockets.TcpClient
    try { return ($client.ConnectAsync($Uri.Host, $Uri.Port).Wait(3000) -and $client.Connected) }
    catch { return $false } finally { $client.Dispose() }
}

function Write-BootstrapStep([string]$Phase) {
    $script:result.phase = $Phase
    $step = @{phase=$Phase; utc=[DateTime]::UtcNow.ToString('o')}
    $script:result.steps += $step
    try {
        $line = Protect-DiagnosticText ($step | ConvertTo-Json -Compress)
        [IO.File]::AppendAllText((Join-Path $script:root 'bootstrap.log'), $line + [Environment]::NewLine, $script:utf8)
        [IO.File]::WriteAllText((Join-Path $script:root 'bootstrap-progress.json'),
            (Protect-DiagnosticText ($script:result | ConvertTo-Json -Depth 12 -Compress)), $script:utf8)
    } catch { } # Diagnostic I/O must not replace the original failure.
    Send-SerialBeacon ('phase ' + $Phase)
}

function Add-BootstrapError([string]$Phase, $Failure) {
    $item = @{phase=$Phase; utc=[DateTime]::UtcNow.ToString('o'); type=$Failure.Exception.GetType().FullName;
        hresult=[long]$Failure.Exception.HResult; id=[string]$Failure.FullyQualifiedErrorId;
        message=(Protect-DiagnosticText ([string]$Failure.Exception.Message));
        stack=(Protect-DiagnosticText ([string]$Failure.ScriptStackTrace))}
    $script:result.errors += $item
    return $item
}

function Read-DiagnosticTail([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { return '' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $first, $second = $stream.ReadByte(), $stream.ReadByte()
        $unicode = $first -eq 255 -and $second -eq 254
        $count = [int][Math]::Min(131072, $stream.Length)
        if ($unicode) { $count -= $count % 2 }
        [void]$stream.Seek(-$count, [IO.SeekOrigin]::End)
        $buffer = [byte[]]::new($count)
        $read = $stream.Read($buffer, 0, $count)
        $encoding = [Text.Encoding]::UTF8
        if ($unicode) { $encoding = [Text.Encoding]::Unicode }
        return Protect-DiagnosticText ($encoding.GetString($buffer, 0, $read))
    } finally { $stream.Dispose() }
}

# OOBE/defaultuser0 logons must not claim or report the product run. The actual
# fixture user owns the active console and Explorer before the SYSTEM task starts.
if ([IO.File]::Exists((Join-Path $root 'started'))) { exit 0 }
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RuleProxyConsoleSession {
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError=true)] public static extern bool WTSLogoffSession(IntPtr server, uint session, bool wait);
    [DllImport("wtsapi32.dll", SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server, uint session, int kind, out IntPtr value, out uint count);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
    public static string User(uint session) {
        IntPtr value; uint count;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, 5, out value, out count)) return null;
        try { return Marshal.PtrToStringUni(value); } finally { WTSFreeMemory(value); }
    }
}
'@
    $gateDeadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
        $session = [RuleProxyConsoleSession]::WTSGetActiveConsoleSessionId()
        if ($user -and $session -gt 0 -and $session -lt [uint32]::MaxValue -and
            [RuleProxyConsoleSession]::User($session) -eq $userName) {
            foreach ($desktop in @(Get-CimInstance Win32_Process -Filter ("Name='explorer.exe' AND SessionId=" + $session))) {
                $desktopOwner = Invoke-CimMethod -InputObject $desktop -MethodName GetOwnerSid
                if ($desktopOwner.Sid -eq $user.SID.Value) {
                    $actorSession = [int]$session
                    $ownerSid = $user.SID.Value
                    break
                }
            }
        }
        if ($null -ne $actorSession) { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $gateDeadline)
} catch {
    [IO.File]::AppendAllText((Join-Path $root 'bootstrap.log'), 'interactive_gate_failed:' + $_.Exception.GetType().FullName + [Environment]::NewLine)
    exit 0
}
if ($null -eq $actorSession) { exit 0 }
$result.actor_session_id = [int]$actorSession
$result.actor_sid = $ownerSid

# Claim before any reporting finally. A duplicate logon must not replace a result.
try {
    $claim = [IO.File]::Open((Join-Path $root 'started'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $claim.Dispose()
} catch [IO.IOException] { exit 0 }
$userCreated = $true # Exact local fixture SID was verified before claiming.
try {
    Write-BootstrapStep 'configuration_read_before'
    $configuration = [IO.File]::ReadAllText((Join-Path $root 'ruleproxy-vm-config.json')) | ConvertFrom-Json
    Write-BootstrapStep 'configuration_read_after'
    Write-BootstrapStep 'network_wait'
    $hostUri = [Uri]$configuration.host_url
    $networkDeadline = [DateTime]::UtcNow.AddSeconds(240)
    while (-not (Test-HostReachable $hostUri)) {
        if ([DateTime]::UtcNow -gt $networkDeadline) { throw 'Host endpoint unreachable after the NIC was plugged in' }
        Start-Sleep -Seconds 3
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $result.bootstrap = @{sid=$identity.User.Value; name=$identity.Name;
        session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId; pid=$PID;
        ps_version=$PSVersionTable.PSVersion.ToString(); ps_home=$PSHOME;
        process_64bit=[Environment]::Is64BitProcess; os_64bit=[Environment]::Is64BitOperatingSystem;
        module_path=$env:PSModulePath; user_profile=$env:USERPROFILE}
    $identity.Dispose()
    Write-BootstrapStep 'caller_identity_ready'
    $result.modules = @(Get-Module | ForEach-Object { @{name=$_.Name; version=$_.Version.ToString(); path=$_.Path} })
    Write-BootstrapStep 'module_facts_ready'
    # Atomic claim prevents repeats; do not mutate the running task before reporting.
    Write-BootstrapStep 'payload_download_before'
    $payload = Join-Path $root 'payload.zip'
    $client = New-Object Net.WebClient
    $client.Proxy = $null
    try { $client.DownloadFile(($configuration.host_url + '/payload.zip'), $payload) } finally { $client.Dispose() }
    Write-BootstrapStep 'payload_download_after'
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) { throw 'Native VM payload digest mismatch' }
    Write-BootstrapStep 'payload_hash_verified'
    $workspace = Join-Path $root 'workspace'
    Expand-Archive -LiteralPath $payload -DestinationPath $workspace
    Write-BootstrapStep 'payload_extracted'
    & icacls.exe $workspace /grant:r '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant actor source read access' }
    Write-BootstrapStep 'actor_source_acl_ready'
    $packageDirectory = Join-Path $workspace 'package'
    $package = Get-ChildItem -LiteralPath $packageDirectory -Filter '*.zip'
    if (@($package).Count -ne 1 -or (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.package_sha256) { throw 'Native VM package digest mismatch' }
    Write-BootstrapStep 'package_hash_verified'
    $stage = Join-Path $root 'boot-runtime'
    Expand-Archive -LiteralPath $package.FullName -DestinationPath $stage
    $python = Join-Path $stage 'RuleProxy-Web\python\python.exe'
    if (-not (Test-Path -LiteralPath $python)) { throw 'Native VM bootstrap Python missing' }
    Write-BootstrapStep 'bootstrap_python_ready'
    # The account/profile already belongs to the VM's real interactive logon.
    # WTS authenticates that token; the controller never needs its password.
    $env:RULEPROXY_TEST_USER = $userName
    $env:RULEPROXY_TEST_PASSWORD = 'WTS-token-no-password-used'
    $env:RULEPROXY_TEST_SID = $ownerSid
    $env:RULEPROXY_TEST_INTERACTIVE_SESSION = [string]$actorSession
    Write-BootstrapStep 'ordinary_account_ready'
    $evidence = Join-Path $workspace 'evidence'
    $log = Join-Path $root 'qualification.log'
    Write-BootstrapStep 'product_controller_before'
    & $python -I -S (Join-Path $workspace '.github\windows_proxifyre_product_acceptance.py') --package-dir $packageDirectory --output $evidence *> $log
    $exitCode = $LASTEXITCODE
    $result.exit_code = $exitCode
    Write-BootstrapStep 'product_controller_after'
    $report = Get-Content -LiteralPath (Join-Path $evidence 'product-report.json') -Raw | ConvertFrom-Json
    $result.reports.product = $report
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.os = @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR; product_type=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType; native_architecture=$env:PROCESSOR_ARCHITECTURE}
    if ($exitCode -ne 0 -or $report.status -notin @('passed_server_product_qualification','passed_windows_11_product_qualification')) { throw 'Native installed product checks failed' }
    if ($result.os.product_type -ne 'WinNT' -or $result.os.build -lt 22000 -or $result.os.native_architecture -ne 'AMD64') { throw 'Native client Windows 11 x64 identity failed' }
    $result.status = 'passed'
    $result.try_completed = $true
    $result.Remove('error_type')
    $result.Remove('error_code')
    Write-BootstrapStep 'product_evidence_verified'
} catch {
    $result.catch_entered = $true
    $result.failure_phase = $result.phase
    $failure = $_
    $errorItem = Add-BootstrapError $result.phase $failure
    $result.error_type = $errorItem.type
    $result.error_code = $errorItem.hresult
} finally {
    # exit/pipeline-stop can run finally without catch; retain an explicit incomplete cause.
    if (-not $result.try_completed -and -not $result.ContainsKey('failure_phase')) { $result.failure_phase = $result.phase }
    Write-BootstrapStep 'cleanup_before'
    try {
        $reportPath = Join-Path $root 'workspace\evidence\product-report.json'
        if (-not $result.reports.ContainsKey('product') -and [IO.File]::Exists($reportPath)) {
            $result.reports.product = [IO.File]::ReadAllText($reportPath) | ConvertFrom-Json
        }
        Write-BootstrapStep 'ordinary_account_cleanup_before'
        if ($userCreated) {
            $currentUser = Get-LocalUser -Name $userName -ErrorAction Stop
            if ($currentUser.SID.Value -ne $ownerSid) { throw 'Fixture account SID changed; cleanup refused' }
            $installed = Join-Path $env:ProgramFiles 'RuleProxy-Web'
            $deploymentFile = Join-Path $installed 'deployment.json'
            if (Test-Path -LiteralPath $deploymentFile) {
                $deployment = [IO.File]::ReadAllText($deploymentFile) | ConvertFrom-Json
                if ($deployment.owner_sid -ne $ownerSid) { throw 'Product owner changed; cleanup refused' }
                $uninstall = Join-Path $installed 'scripts\windows-uninstall.ps1'
                $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $uninstall + '" -Elevated -OwnerSid ' + $ownerSid
                $cleanupProcess = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -PassThru
                try {
                    if (-not $cleanupProcess.WaitForExit(240000)) {
                        & taskkill.exe /PID $cleanupProcess.Id /T /F | Out-Null
                        throw 'Owned product cleanup exceeded bound'
                    }
                    if ($cleanupProcess.ExitCode -ne 0) { throw 'Owned product cleanup incomplete or needs reboot' }
                } finally { $cleanupProcess.Dispose() }
            }
            $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            $auto = Get-ItemProperty -LiteralPath $winlogon
            if ($auto.AutoAdminLogon -eq '1' -and $auto.DefaultUserName -ne $userName) { throw 'AutoLogon owner changed; cleanup refused' }
            if ($auto.DefaultUserName -eq $userName) {
                if ($auto.DefaultDomainName -and $auto.DefaultDomainName -notin @('.', $env:COMPUTERNAME)) { throw 'AutoLogon domain changed; cleanup refused' }
                Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'
                Remove-ItemProperty -LiteralPath $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
            }
            if ([RuleProxyConsoleSession]::User([uint32]$actorSession) -eq $userName) {
                if (-not [RuleProxyConsoleSession]::WTSLogoffSession([IntPtr]::Zero, [uint32]$actorSession, $false)) { throw 'Fixture session logoff failed' }
                $logoffDeadline = [DateTime]::UtcNow.AddSeconds(30)
                while ([RuleProxyConsoleSession]::User([uint32]$actorSession) -eq $userName) {
                    if ([DateTime]::UtcNow -gt $logoffDeadline) { throw 'Fixture session logoff exceeded bound' }
                    Start-Sleep -Milliseconds 200
                }
            }
            Remove-LocalUser -Name $userName -ErrorAction Stop
        }
        $result.user_cleanup_confirmed = $null -eq (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)
        Write-BootstrapStep 'ordinary_account_cleanup_after'
    } catch { [void](Add-BootstrapError 'cleanup' $_) } finally {
        if (-not $result.user_cleanup_confirmed -or -not $result.try_completed) { $result.status = 'failed' }
        try {
            $result.logs.supervisor = (Read-DiagnosticTail (Join-Path $root 'setup.log')) + [Environment]::NewLine + (Read-DiagnosticTail (Join-Path $root 'bootstrap.log'))
            $result.logs.tests = Read-DiagnosticTail (Join-Path $root 'qualification.log')
        } catch { [void](Add-BootstrapError 'diagnostic_collection' $_) }
        # Keep password for redaction until all result bytes have been sanitized.
        Remove-Item Env:RULEPROXY_TEST_PASSWORD -ErrorAction SilentlyContinue
        Remove-Item Env:RULEPROXY_TEST_USER -ErrorAction SilentlyContinue
        Remove-Item Env:RULEPROXY_TEST_SID -ErrorAction SilentlyContinue
        Remove-Item Env:RULEPROXY_TEST_INTERACTIVE_SESSION -ErrorAction SilentlyContinue
        Write-BootstrapStep 'report_ready'
        $body = Protect-DiagnosticText ($result | ConvertTo-Json -Depth 70 -Compress)
        try { [IO.File]::WriteAllText((Join-Path $root 'bootstrap-result.json'), $body, $utf8) }
        catch {
            [void](Add-BootstrapError 'local_result_write' $_)
            $body = Protect-DiagnosticText ($result | ConvertTo-Json -Depth 70 -Compress)
        }
        $bytes = $utf8.GetBytes($body)
        $passwordText = $null
        if ($null -ne $password) { $password.Dispose(); $password = $null }
        $submitted = $false
        if ($null -ne $configuration -and $configuration.host_url) {
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
                    $submitted = $true
                    break
                } catch { $request.Abort() }
            }
        }
        # This cannot prevent the diagnostic POST.
        if ($submitted) { Unregister-ScheduledTask -TaskName 'RuleProxyProduct-Qualification' -Confirm:$false -ErrorAction SilentlyContinue }
    }
}
