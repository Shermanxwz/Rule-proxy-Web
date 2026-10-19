# Disposable Windows Server runner control. This is not a product installer.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleZip,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$PythonPath,
    [string]$BrowserPath
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This experiment requires a disposable Windows GitHub Actions runner'
}
if ($env:GITHUB_SHA -notmatch '^[0-9a-fA-F]{40}$') { throw 'A fixed source commit is required' }
$repository = Split-Path $PSScriptRoot -Parent
$nonce = [guid]::NewGuid().ToString('N')
$task = 'RuleProxyPsec-' + $nonce
$launch = Join-Path $env:SystemDrive ('RuleProxyPsecLaunch-' + $nonce)
$work = Join-Path $env:SystemDrive ('RuleProxyPsecWork-' + $nonce)
$target = [IO.Path]::GetFullPath($Output)
$utf8 = New-Object Text.UTF8Encoding($false)
$registered = $false
$createdLaunch = $false
$failure = $null
$state = [ordered]@{
    schema_version = 1; scope = 'Windows Server hosted-runner functional control'
    source_commit = $env:GITHUB_SHA.ToLowerInvariant(); windows_11_verified = $false
    privacy_qualified = $false; product_acceptance = $false
    completed = $false; functionality_passed = $false; cleanup_unconfirmed = $true
}
New-Item -ItemType Directory -Path $target -Force | Out-Null

# The bootstrap owns its Popen handle for the entire bounded controller run.
# No output stream or process selected by a numeric PID is exported or killed.
$bootstrap = @'
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import zipfile

MAX_REPORT = 128 * 1024
CONTROLLER_TIMEOUT = 660


def error_type(exc):
    return {"type": type(exc).__name__, "winerror": getattr(exc, "winerror", None),
            "errno": getattr(exc, "errno", None)}


def prepare_runtime(config):
    sys.path.insert(0, config["repository"])
    import install_runtime
    data = install_runtime._g_bundle_bytes(Path(config["bundle"]), allow_env_cache=False)
    runtime = Path(config["launch"]) / "fixed-runtime"
    runtime.mkdir()
    install_runtime._extract_g_bundle(data, runtime)
    # The general installer consumes this member without retaining it. This
    # experiment needs the byte-exact manifest for its independent fixed pin.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        (runtime / "build-manifest.json").write_bytes(archive.read("build-manifest.json"))
    return runtime


def read_report(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_REPORT + 1)
    if len(raw) > MAX_REPORT:
        raise ValueError("report bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("report type")
    return value


def run_controller(config, runtime):
    result = {"controller_exit_code": None, "timed_out": False, "completed": False,
              "cleanup_unconfirmed": True, "functionality_passed": False,
              "windows_11_verified": False, "privacy_qualified": False, "product_acceptance": False}
    report_path = Path(config["launch"]) / "smoke-report.json"
    arguments = [sys.executable, "-I", "-S", "-B",
                 str(Path(config["repository"]) / ".github" / "windows_psec_compartment_smoke.py"),
                 "--disposable-ci", "--executor", str(runtime / "wxc-exec.exe"),
                 "--manifest", str(runtime / "build-manifest.json"),
                 "--work", config["work"], "--report", str(report_path), "--browser", config["browser"]]
    # Scheduled tasks do not inherit the caller's GitHub environment. Forward
    # only validated source provenance and ordinary Windows runtime variables.
    names = ("SystemRoot", "WINDIR", "COMSPEC", "SystemDrive", "PATH", "PATHEXT", "TEMP", "TMP",
             "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "ALLUSERSPROFILE",
             "USERPROFILE", "USERNAME", "USERDOMAIN", "LOCALAPPDATA", "APPDATA",
             "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS")
    environment = {name: os.environ[name] for name in names if name in os.environ}
    environment["GITHUB_SHA"] = config["source_commit"]
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=environment)
    try:
        try:
            result["controller_exit_code"] = process.wait(timeout=CONTROLLER_TIMEOUT)
            result["completed"] = True
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            process.kill()  # Windows Popen retains the original process handle.
            result["controller_exit_code"] = process.wait(timeout=15)
        if report_path.is_file():
            report = read_report(report_path)
            result["report_present"] = True
            checks = report.get("checks", {})
            baseline = report.get("baseline", {}).get("checks", {})
            clean = (all(checks.get(name) is True for name in
                         ("account_cleanup", "fixture_cleanup", "outer_job_empty", "case_cleanup"))
                     and all(baseline.get(name) is True for name in ("outer_job_empty", "case_cleanup")))
            result["cleanup_unconfirmed"] = result["timed_out"] or not clean
            result["functionality_passed"] = (result["completed"] and result["controller_exit_code"] == 0
                                                and report.get("functionality_passed") is True
                                                and not result["cleanup_unconfirmed"])
    except Exception as exc:
        result["error"] = error_type(exc)
        result["cleanup_unconfirmed"] = True
    finally:
        if process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=15)
            except Exception as exc:
                result["termination_error"] = error_type(exc)
            result["cleanup_unconfirmed"] = True
    return result


def main():
    config = read_report(sys.argv[1])
    result = {"schema_version": 1, "scope": "Windows Server hosted-runner functional control",
              "source_commit": config.get("source_commit"), "completed": False,
              "cleanup_unconfirmed": True, "functionality_passed": False,
              "windows_11_verified": False, "privacy_qualified": False, "product_acceptance": False}
    try:
        if os.name != "nt" or struct.calcsize("P") != 8:
            raise RuntimeError("requires native x64 Windows Python")
        if not re.fullmatch(r"[0-9a-f]{40}", config.get("source_commit", "")):
            raise ValueError("source provenance")
        runtime = prepare_runtime(config)
        result.update(run_controller(config, runtime))
    except Exception as exc:
        result["error"] = error_type(exc)
    Path(config["launch"], "bootstrap-report.json").write_text(json.dumps(result), encoding="ascii")
    return 0 if result["functionality_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
'@

try {
    if (-not $PythonPath) { $PythonPath = (Get-Command python -CommandType Application).Source }
    $PythonPath = (Get-Item -LiteralPath $PythonPath).FullName
    $bundle = (Get-Item -LiteralPath $BundleZip).FullName
    if (-not $BrowserPath) {
        foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
            if ($base) {
                $candidate = Join-Path $base 'Microsoft\Edge\Application\msedge.exe'
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $BrowserPath = $candidate; break }
            }
        }
    }
    $BrowserPath = (Get-Item -LiteralPath $BrowserPath).FullName
    if (Test-Path -LiteralPath $launch) { throw 'Unique bootstrap directory already exists' }
    New-Item -ItemType Directory -Path $launch | Out-Null
    $createdLaunch = $true
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $launch -AclObject $acl
    $config = [ordered]@{ repository = $repository; bundle = $bundle; launch = $launch; work = $work
        browser = $BrowserPath; source_commit = $state.source_commit }
    $configPath = Join-Path $launch 'config.json'
    $bootstrapPath = Join-Path $launch 'bootstrap.py'
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json), $utf8)
    [IO.File]::WriteAllText($bootstrapPath, $bootstrap, $utf8)
    # Both paths consist of our fixed root and GUID; no shell is involved.
    $arguments = '-I -S -B "' + $bootstrapPath + '" "' + $configPath + '"'
    $action = New-ScheduledTaskAction -Execute $PythonPath -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 720)
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $scheduler.GetFolder('\').GetTask($task).SetSecurityDescriptor('D:P(A;;GA;;;SY)(A;;GA;;;BA)', 0)
    $started = [DateTime]::Now
    Start-ScheduledTask -TaskName $task
    $deadline = [DateTime]::UtcNow.AddSeconds(750)
    do {
        Start-Sleep -Seconds 2
        $info = Get-ScheduledTaskInfo -TaskName $task
        if ($info.LastRunTime -ge $started.AddSeconds(-2) -and (Get-ScheduledTask -TaskName $task).State -ne 'Running') {
            $state.completed = $true
            break
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $state.completed) { throw 'Own scheduled task timed out' }
    $bootstrapReport = Join-Path $launch 'bootstrap-report.json'
    if (-not (Test-Path -LiteralPath $bootstrapReport -PathType Leaf)) { throw 'Bootstrap report missing' }
    if ((Get-Item -LiteralPath $bootstrapReport).Length -gt 131072) { throw 'Bootstrap report exceeded bound' }
    $observed = Get-Content -LiteralPath $bootstrapReport -Raw | ConvertFrom-Json
    $state.cleanup_unconfirmed = $observed.cleanup_unconfirmed -ne $false
    $state.functionality_passed = $observed.functionality_passed -eq $true -and $info.LastTaskResult -eq 0
    if ($observed.functionality_passed -ne $true -or $info.LastTaskResult -ne 0) {
        throw 'Server functionality control did not pass; inspect structured reports'
    }
} catch {
    $failure = $_
    $state.error = @{ type = $_.Exception.GetType().Name; hresult = $_.Exception.HResult }
} finally {
    $canRemoveLaunch = -not $registered
    if ($registered) {
        try {
            Stop-ScheduledTask -TaskName $task -ErrorAction Stop
            $stopDeadline = [DateTime]::UtcNow.AddSeconds(10)
            while ((Get-ScheduledTask -TaskName $task).State -eq 'Running' -and [DateTime]::UtcNow -lt $stopDeadline) {
                Start-Sleep -Milliseconds 250
            }
            if ((Get-ScheduledTask -TaskName $task).State -eq 'Running') { throw 'Own task stop unconfirmed' }
            $canRemoveLaunch = $true
            $info = Get-ScheduledTaskInfo -TaskName $task
            $state.last_task_result = $info.LastTaskResult
            Unregister-ScheduledTask -TaskName $task -Confirm:$false
            $state.task_removed = $true
        } catch {
            $state.task_removed = $false
            $state.cleanup_unconfirmed = $true
            $state.task_cleanup_error = @{ type = $_.Exception.GetType().Name; hresult = $_.Exception.HResult }
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if ($createdLaunch) {
        try {
            foreach ($name in @('smoke-report.json', 'bootstrap-report.json')) {
                $source = Join-Path $launch $name
                if (Test-Path -LiteralPath $source -PathType Leaf) {
                    if ((Get-Item -LiteralPath $source).Length -gt 131072) { throw 'Structured report exceeded bound' }
                    $null = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json
                    Copy-Item -LiteralPath $source -Destination (Join-Path $target $name)
                }
            }
        } catch {
            $state.report_copy_error = @{ type = $_.Exception.GetType().Name; hresult = $_.Exception.HResult }
            if ($null -eq $failure) { $failure = $_ }
        } finally {
            if ($canRemoveLaunch) {
                try {
                    Remove-Item -LiteralPath $launch -Recurse -Force
                    $state.bootstrap_removed = $true
                } catch {
                    $state.bootstrap_removed = $false
                    $state.cleanup_unconfirmed = $true
                    $state.bootstrap_cleanup_error = @{ type = $_.Exception.GetType().Name; hresult = $_.Exception.HResult }
                    if ($null -eq $failure) { $failure = $_ }
                }
            } else {
                # Preserve protected inputs if termination could not be proved.
                # The disposable runner's destruction is not product cleanup.
                $state.bootstrap_removed = $false
                $state.cleanup_unconfirmed = $true
            }
        }
    }
    if ($null -ne $failure) { $state.functionality_passed = $false }
    [IO.File]::WriteAllText((Join-Path $target 'task.json'), ($state | ConvertTo-Json -Depth 5), $utf8)
}
if ($null -ne $failure) { throw 'Server PSEC control failed; inspect the structured JSON reports' }
