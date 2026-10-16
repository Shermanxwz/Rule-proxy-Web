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
# This separate suite never runs the product GUI/per-application controller.
$result.suite = 'global-capture'
$result.strict_qualified = $false
$result.task_cleanup_confirmed = $false
$result.installation_cleanup_confirmed = $false
$captureUser = 'RuleProxyGlobalCI'
$captureSid = $null
$captureTask = 'RuleProxy-GlobalVM-' + [guid]::NewGuid().ToString('N')
$captureTaskRegistered = $false
$captureUserCreated = $false
$installed = Join-Path $env:ProgramFiles 'RuleProxy-Web'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function Invoke-BoundedScript([string]$Script, [string]$Arguments, [int]$Seconds) {
    $child = Start-Process -FilePath $powershell -ArgumentList ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Script + '" ' + $Arguments) -PassThru -RedirectStandardOutput (Join-Path $root 'installer.stdout.log') -RedirectStandardError (Join-Path $root 'installer.stderr.log')
    try {
        if (-not $child.WaitForExit($Seconds * 1000)) {
            & taskkill.exe /PID $child.Id /T /F | Out-Null
            throw 'Owned installer exceeded its deadline'
        }
        if ($child.ExitCode -ne 0) { throw ('Owned installer failed or requires reboot: ' + $child.ExitCode) }
    } finally { $child.Dispose() }
}
try {
    Write-BootstrapStep 'global_configuration'
    $configuration = [IO.File]::ReadAllText((Join-Path $root 'ruleproxy-vm-config.json')) | ConvertFrom-Json
    if ($configuration.suite -ne 'global-capture') { throw 'Wrong disposable suite' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'SYSTEM bootstrap required' }
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.os = @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR; product_type=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType; native_architecture=$env:PROCESSOR_ARCHITECTURE}
    if ($result.os.product_type -ne 'WinNT' -or $result.os.build -lt 22000 -or $result.os.native_architecture -ne 'AMD64') { throw 'Client Windows 11 x64 required' }
    Write-BootstrapStep 'global_payload'
    $payload = Join-Path $root 'payload.zip'
    $client = New-Object Net.WebClient
    $client.Proxy = $null
    try { $client.DownloadFile(($configuration.host_url + '/payload.zip'), $payload) } finally { $client.Dispose() }
    if ((Get-FileHash $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) { throw 'Payload digest mismatch' }
    $workspace = Join-Path $root 'workspace'
    Expand-Archive -LiteralPath $payload -DestinationPath $workspace
    $packages = @(Get-ChildItem -LiteralPath (Join-Path $workspace 'package') -Filter '*.zip')
    if ($packages.Count -ne 1 -or (Get-FileHash $packages[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.package_sha256) { throw 'Offline package digest mismatch' }
    $stage = Join-Path $root 'bundle'
    Expand-Archive -LiteralPath $packages[0].FullName -DestinationPath $stage
    $bundle = Join-Path $stage 'RuleProxy-Web'
    $manifest = [IO.File]::ReadAllText((Join-Path $bundle 'package-manifest.json')) | ConvertFrom-Json
    foreach ($entry in $manifest.files.PSObject.Properties) {
        if ($entry.Name -match '(^[/\\]|(^|[/\\])\.\.([/\\]|$)|:)') { throw 'Unsafe manifest path' }
        if ((Get-FileHash -LiteralPath (Join-Path $bundle $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw 'Manifest content changed' }
    }
    $result.package = @{manifest_verified=$true; sha256=$configuration.package_sha256; fixed_core_sha256=$manifest.files.'bin/windows-amd64/mihomo.exe'}
    Write-BootstrapStep 'global_admin_owner'
    if (Get-LocalUser -Name $captureUser -ErrorAction SilentlyContinue) { throw 'Capture fixture account already exists' }
    $passwordText = [guid]::NewGuid().ToString('N') + 'Ci!9'
    $password = ConvertTo-SecureString $passwordText -AsPlainText -Force
    $captureAccount = New-LocalUser -Name $captureUser -Password $password -AccountNeverExpires -PasswordNeverExpires
    $captureSid = $captureAccount.SID.Value
    $captureUserCreated = $true
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name -Member $captureUser
    Write-BootstrapStep 'global_install'
    Invoke-BoundedScript (Join-Path $bundle 'scripts\windows-setup.ps1') ('-SourceRoot "' + $bundle + '" -OwnerSid ' + $captureSid + ' -Elevated -NoLaunch') 300
    $deployment = [IO.File]::ReadAllText((Join-Path $installed 'deployment.json')) | ConvertFrom-Json
    if ($deployment.owner_sid -ne $captureSid) { throw 'Installed owner differs from capture fixture' }
    $hashes = @{}
    foreach ($entry in $configuration.source_identity.source_sha256.PSObject.Properties) {
        $checkoutHash = (Get-FileHash -LiteralPath (Join-Path $workspace $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
        $bundleHash = (Get-FileHash -LiteralPath (Join-Path $bundle $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
        $installedHash = (Get-FileHash -LiteralPath (Join-Path $installed $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($checkoutHash -ne $entry.Value -or $bundleHash -ne $entry.Value -or $installedHash -ne $entry.Value) { throw 'Source, package or installed implementation differs' }
        $hashes[$entry.Name] = $installedHash
    }
    $harness = Join-Path $workspace '.github\check_windows_global_capture.py'
    $harnessHash = (Get-FileHash -LiteralPath $harness -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($harnessHash -ne $configuration.source_identity.harness_sha256) { throw 'Capture harness differs' }
    $result.source_identity = @{tested_source_commit=$configuration.source_identity.tested_source_commit; source_sha256=$hashes; harness_sha256=$harnessHash}
    $ownerConfiguration = @{owner_sid=$captureSid; installed=$installed; harness=$harness; root=$root}
    [IO.File]::WriteAllText((Join-Path $root 'owner-config.json'), ($ownerConfiguration | ConvertTo-Json -Compress), $utf8)
    $ownerScript = @'
$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyProductBootstrap'
$cfg = [IO.File]::ReadAllText((Join-Path $root 'owner-config.json')) | ConvertFrom-Json
$detail = @{exit_code=1; owner=@{sid=''; elevated=$false; sid_matches_installation=$false}}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $detail.owner.sid = $identity.User.Value
    $detail.owner.elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $detail.owner.sid_matches_installation = $detail.owner.sid -eq $cfg.owner_sid
    if (-not $detail.owner.elevated -or -not $detail.owner.sid_matches_installation) { throw 'Highest owner token required' }
    & (Join-Path $cfg.installed 'python\python.exe') -I -S -B $cfg.harness --ack-disposable-windows --installed-root $cfg.installed --output (Join-Path $root 'capture-summary.json') *> (Join-Path $root 'capture.log')
    $detail.exit_code = $LASTEXITCODE
} catch { $detail.error_type = $_.Exception.GetType().FullName }
finally {
    $temporary = Join-Path $root 'capture-owner-result.tmp'
    [IO.File]::WriteAllText($temporary, ($detail | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination (Join-Path $root 'capture-owner-result.json') -Force
}
exit $detail.exit_code
'@
    [IO.File]::WriteAllText((Join-Path $root 'capture-owner.ps1'), $ownerScript, $utf8)
    $action = New-ScheduledTaskAction -Execute $powershell -Argument '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\RuleProxyProductBootstrap\capture-owner.ps1'
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 6) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $captureTask -Action $action -Settings $settings -User ($env:COMPUTERNAME + '\' + $captureUser) -Password $passwordText -RunLevel Highest -Force | Out-Null
    $captureTaskRegistered = $true
    Start-ScheduledTask -TaskName $captureTask
    Write-BootstrapStep 'global_capture_running'
    $captureDeadline = [DateTime]::UtcNow.AddSeconds(240)
    $ownerResult = Join-Path $root 'capture-owner-result.json'
    while (-not [IO.File]::Exists($ownerResult)) {
        if ([DateTime]::UtcNow -gt $captureDeadline) { throw 'Capture owner exceeded deadline' }
        Start-Sleep -Milliseconds 250
    }
    $detail = [IO.File]::ReadAllText($ownerResult) | ConvertFrom-Json
    $result.exit_code = [int]$detail.exit_code
    $result.owner = $detail.owner
    $result.reports.global_capture = [IO.File]::ReadAllText((Join-Path $root 'capture-summary.json')) | ConvertFrom-Json
    if ($result.exit_code -ne 0 -or $result.reports.global_capture.passed -ne $true -or $result.reports.global_capture.recovery.recovered -ne $true) { throw 'Capture or recovery incomplete' }
    $result.try_completed = $true
    $result.status = 'passed'
    $result.Remove('error_type'); $result.Remove('error_code')
} catch {
    $result.catch_entered = $true
    $result.failure_phase = $result.phase
    [void](Add-BootstrapError $result.phase $_)
} finally {
    Write-BootstrapStep 'global_cleanup'
    try {
        if ($captureTaskRegistered) {
            Stop-ScheduledTask -TaskName $captureTask -ErrorAction Stop
            $stopDeadline = [DateTime]::UtcNow.AddSeconds(20)
            while ((Get-ScheduledTask -TaskName $captureTask).State -eq 'Running') {
                if ([DateTime]::UtcNow -gt $stopDeadline) { throw 'Capture task cleanup unconfirmed' }
                Start-Sleep -Milliseconds 200
            }
            Unregister-ScheduledTask -TaskName $captureTask -Confirm:$false -ErrorAction Stop
        }
        $result.task_cleanup_confirmed = $true
    } catch { [void](Add-BootstrapError 'capture_task_cleanup' $_) }
    try {
        $deploymentPath = Join-Path $installed 'deployment.json'
        if (Test-Path -LiteralPath $deploymentPath) {
            $deployment = [IO.File]::ReadAllText($deploymentPath) | ConvertFrom-Json
            if (-not $captureSid -or $deployment.owner_sid -ne $captureSid) { throw 'Installed cleanup owner changed' }
            Invoke-BoundedScript (Join-Path $installed 'scripts\windows-uninstall.ps1') ('-OwnerSid ' + $captureSid + ' -Elevated') 120
        }
        $result.installation_cleanup_confirmed = -not (Test-Path -LiteralPath $deploymentPath)
    } catch { [void](Add-BootstrapError 'installation_cleanup' $_) }
    try {
        if (-not $result.task_cleanup_confirmed -or -not $result.installation_cleanup_confirmed) { throw 'Fixture cleanup requires stopped task and restored installation' }
        if ($captureUserCreated) {
            $account = Get-LocalUser -Name $captureUser -ErrorAction Stop
            if ($account.SID.Value -ne $captureSid) { throw 'Capture account SID changed' }
            Remove-LocalUser -Name $captureUser -ErrorAction Stop
        }
        $account = Get-LocalUser -Name $userName -ErrorAction Stop
        if ($account.SID.Value -ne $ownerSid) { throw 'Interactive fixture SID changed' }
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $auto = Get-ItemProperty -LiteralPath $winlogon
        if ($auto.DefaultUserName -ne $userName -or ($auto.DefaultDomainName -and $auto.DefaultDomainName -notin @('.', $env:COMPUTERNAME))) { throw 'AutoLogon fixture owner changed' }
        Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'
        Remove-ItemProperty -LiteralPath $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
        if ([RuleProxyConsoleSession]::User([uint32]$actorSession) -eq $userName) {
            if (-not [RuleProxyConsoleSession]::WTSLogoffSession([IntPtr]::Zero, [uint32]$actorSession, $false)) { throw 'Fixture logoff failed' }
            $logoffDeadline = [DateTime]::UtcNow.AddSeconds(30)
            while ([RuleProxyConsoleSession]::User([uint32]$actorSession) -eq $userName) {
                if ([DateTime]::UtcNow -gt $logoffDeadline) { throw 'Fixture logoff exceeded deadline' }
                Start-Sleep -Milliseconds 200
            }
        }
        Remove-LocalUser -Name $userName -ErrorAction Stop
        $result.user_cleanup_confirmed = ($null -eq (Get-LocalUser -Name $captureUser -ErrorAction SilentlyContinue)) -and ($null -eq (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue))
    } catch { [void](Add-BootstrapError 'account_cleanup' $_) }
    if (-not $result.try_completed -or -not $result.task_cleanup_confirmed -or -not $result.installation_cleanup_confirmed -or -not $result.user_cleanup_confirmed) { $result.status = 'failed' }
    try {
        $captureSummary = Join-Path $root 'capture-summary.json'
        if (-not $result.reports.ContainsKey('global_capture') -and [IO.File]::Exists($captureSummary)) { $result.reports.global_capture = [IO.File]::ReadAllText($captureSummary) | ConvertFrom-Json }
        $result.logs.tests = Read-DiagnosticTail (Join-Path $root 'capture.log')
        $result.logs.supervisor = Read-DiagnosticTail (Join-Path $root 'bootstrap.log')
    } catch { [void](Add-BootstrapError 'diagnostic_collection' $_) }
    Write-BootstrapStep 'global_report_ready'
    $body = Protect-DiagnosticText ($result | ConvertTo-Json -Depth 70 -Compress)
    [IO.File]::WriteAllText((Join-Path $root 'bootstrap-result.json'), $body, $utf8)
    $bytes = $utf8.GetBytes($body)
    $passwordText = $null
    if ($password) { $password.Dispose(); $password = $null }
    if ($configuration -and $configuration.host_url) {
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            $request = [Net.HttpWebRequest]::Create($configuration.host_url + '/result')
            $request.Method = 'POST'; $request.Proxy = $null; $request.Timeout = 15000; $request.ReadWriteTimeout = 15000
            $request.ContentType = 'application/json'; $request.ContentLength = $bytes.Length
            try {
                $stream = $request.GetRequestStream()
                try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
                $response = $request.GetResponse()
                try { if ([int]$response.StatusCode -ne 200) { throw 'Result rejected' } } finally { $response.Dispose() }
                Unregister-ScheduledTask -TaskName 'RuleProxyProduct-Qualification' -Confirm:$false -ErrorAction SilentlyContinue
                break
            } catch { $request.Abort() }
        }
    }
}
