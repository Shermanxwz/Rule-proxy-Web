"""Execute installer continuations without UAC, services or the real desktop."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from ruleproxy import shortcuts, windows_proxy_service


ROOT = Path(__file__).resolve().parent.parent


class ExistingDeploymentVerificationCodeTests(unittest.TestCase):
    def test_actual_verifier_requires_owner_receipt_all_files_and_service_validation(self):
        source = (ROOT / 'scripts/windows-setup.ps1').read_text()
        code = re.search(r"\$verificationCode = @'\n(.*?)\n'@", source, re.S).group(1)
        for mode in ('valid', 'other-owner', 'missing-receipt', 'changed-files', 'unsafe-service'):
            with self.subTest(mode=mode):
                metadata = {'owner_sid': 'expected-owner', 'files': {'package-manifest.json': 'digest'}}
                if mode == 'other-owner':
                    metadata['owner_sid'] = 'other-owner'
                elif mode == 'missing-receipt':
                    metadata['files'] = {}
                control = Mock()
                if mode == 'unsafe-service':
                    control.verify.side_effect = OSError('unsafe service')
                with patch.object(sys, 'argv', ['probe', str(ROOT), 'expected-owner']), \
                        patch.object(windows_proxy_service, 'load_deployment', return_value=metadata) as load, \
                        patch.object(windows_proxy_service, 'ServiceControl', return_value=control):
                    if mode == 'changed-files':
                        load.side_effect = OSError('changed file or ACL')
                    if mode == 'valid':
                        exec(compile(code, '<installer-deployment-verifier>', 'exec'), {})
                        control.verify.assert_called_once_with(metadata)
                    else:
                        with self.assertRaises((OSError, ValueError)):
                            exec(compile(code, '<installer-deployment-verifier>', 'exec'), {})
                        if mode != 'unsafe-service':
                            control.verify.assert_not_called()
                    load.assert_called_once_with(ROOT)


@unittest.skipUnless(os.name == 'nt', 'requires native Windows PowerShell and shortcut COM')
class WindowsSetupCompletionTests(unittest.TestCase):
    def test_component_reuse_requires_every_prerequisite_and_installed_receipt_pin(self):
        script = r'''
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RULEPROXY_SETUP_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Installer PowerShell parse failed' }
foreach ($name in @('Test-ReusableComponents','Test-ExistingDeployment')) {
    $definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    Invoke-Expression $definition.Extent.Text
}
$fixtureRoot = $env:RULEPROXY_SETUP_TEST_ROOT
function Invoke-FakePython {
    if (($args[0..2] -join ' ') -ne '-I -S -c' -or $args[3] -notmatch 'load_deployment' -or
        $args[4] -ne $fixtureRoot -or $args[5] -ne 'expected-owner') { throw 'Private verifier command changed' }
    $global:LASTEXITCODE = $script:nativeVerifierCode
}
Set-Alias -Name (Join-Path $fixtureRoot 'python\python.exe') -Value Invoke-FakePython
foreach ($code in @(0,17,$null)) {
    $script:nativeVerifierCode = $code
    $expected = $null -ne $code -and $code -eq 0
    if ((Test-ExistingDeployment $fixtureRoot $fixtureRoot 'expected-owner') -ne $expected) { throw 'Native verifier exit code was hidden by function scope' }
}
$receipt = Join-Path $fixtureRoot 'package-manifest.json'
$manifest = [pscustomobject]@{schema_version=1;platform='windows-amd64';backend='proxifyre';installers=[pscustomobject]@{}}
foreach ($key in @('vc_redist','ndis_msi','proxifyre_msi','proxifyre_setup')) {
    $manifest.installers | Add-Member NoteProperty $key ([pscustomobject]@{sha256=('1'*64)})
}
function Assert-Protected {
    param([string]$Path)
    if ($Path -ne $receipt) { throw 'Receipt did not come from the installed root' }
    if ($script:rejectAcl) { throw 'Unprotected installed receipt' }
}
function Test-ExistingDeployment {
    param([string]$ExistingRoot,[string]$Stage,[string]$ExpectedOwner)
    if ($ExistingRoot -ne $fixtureRoot -or $Stage -ne 'unused stage' -or $ExpectedOwner -ne 'expected-owner') { throw 'Deployment verifier arguments changed' }
    $script:verifyCalls++
    return $script:verifyResult
}
function Invoke-ReuseCheck {
    param([bool]$Owned=$true,[bool]$Bundle=$true,[bool]$Runtime=$true,[bool]$Driver=$true)
    Test-ReusableComponents $Owned $Bundle $Runtime $Driver $fixtureRoot 'unused stage' $manifest 'expected-owner'
}
$json = $manifest | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText($receipt,$json)
$script:verifyResult = $true; $script:verifyCalls = 0; $script:rejectAcl = $false
if (-not (Invoke-ReuseCheck) -or $script:verifyCalls -ne 1) { throw 'Complete identical components were not revalidated and reused' }
foreach ($missing in @('Owned','Bundle','Runtime','Driver')) {
    $script:verifyCalls = 0
    $arguments = @{}; $arguments[$missing] = $false
    if ((Invoke-ReuseCheck @arguments) -or $script:verifyCalls) { throw ('Missing prerequisite was reused: ' + $missing) }
}
foreach ($changed in @('vc_redist','ndis_msi','proxifyre_msi','proxifyre_setup')) {
    $previous = $json | ConvertFrom-Json
    $previous.installers.$changed.sha256 = '2'*64
    [IO.File]::WriteAllText($receipt,($previous | ConvertTo-Json -Depth 6))
    $script:verifyCalls = 0
    if ((Invoke-ReuseCheck) -or $script:verifyCalls) { throw ('Changed installer pin was reused: ' + $changed) }
}
foreach ($invalid in @('missing','malformed','acl','deployment')) {
    [IO.File]::WriteAllText($receipt,$json)
    $script:rejectAcl = $invalid -eq 'acl'; $script:verifyResult = $invalid -ne 'deployment'
    if ($invalid -eq 'missing') { Remove-Item -LiteralPath $receipt }
    if ($invalid -eq 'malformed') { [IO.File]::WriteAllText($receipt,'not-json') }
    if (Invoke-ReuseCheck) { throw ('Unverified installed components were reused: ' + $invalid) }
}
'''
        with tempfile.TemporaryDirectory(prefix='ruleproxy-component-reuse-') as temporary:
            fixture_root = Path(temporary).resolve()
            runner = fixture_root / 'check.ps1'
            runner.write_text(script, encoding='ascii')
            environment = {key: value for key, value in os.environ.items() if key.casefold() != 'psmodulepath'}
            environment.update(RULEPROXY_SETUP_TEST_SCRIPT=str(ROOT / 'scripts/windows-setup.ps1'),
                               RULEPROXY_SETUP_TEST_ROOT=str(fixture_root))
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(runner)], env=environment, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_owner_continuation_handles_both_tokens_and_preserves_foreign_shortcuts(self):
        script = r'''
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RULEPROXY_SETUP_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Installer PowerShell parse failed' }
foreach ($name in @('Get-SetupExitCode','Test-OwnerPanel','Complete-OwnerSetup')) {
    $definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if (-not $definition) { throw ('Missing installer function: ' + $name) }
    Invoke-Expression $definition.Extent.Text
}
foreach ($expected in @(0,17)) {
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-Command',('exit ' + $expected)) -Wait -PassThru
    if ((Get-SetupExitCode $process 'native child') -ne $expected) { throw 'Native child exit code changed' }
}
$missing = [pscustomobject]@{ExitCode=$null}
$missing | Add-Member ScriptMethod WaitForExit {}
$missing | Add-Member ScriptMethod Refresh {}
foreach ($process in @($missing,$null)) {
    $rejected = $false
    try { Get-SetupExitCode $process 'injected missing result' | Out-Null }
    catch { $rejected = $_.Exception.Message -match 'No (exit code|process result) was returned' }
    if (-not $rejected) { throw 'Missing child result was accepted as success' }
}

$fixtureRoot = $env:RULEPROXY_SETUP_TEST_INSTALLED_ROOT
# Match the fixed Program Files target while retaining Unicode desktop paths.
# Write fixtures with the production Unicode API: WScript.Shell cannot create
# non-ACP targets on an English-locale host. The real completion still reads
# existing links itself, so its ownership/preservation checks remain exercised.
Add-Type -TypeDefinition $env:RULEPROXY_SETUP_TEST_LINK_TYPES
[RuleProxyLinks.Links]::Create((Join-Path $fixtureRoot 'Start-Windows.lnk'),
    (Join-Path $fixtureRoot 'python\pythonw.exe'), '-I -S "Run-RuleProxy.py" --open-browser',
    $fixtureRoot, 'Panel fixture', '')

# Execute the actual outer UAC continuation, replacing only its final process
# exit with return so all cases can run in one test host. Redirect its completion
# function into a private fixture rather than Environment.GetFolderPath(Desktop).
Set-Item Function:\Invoke-FixtureCompletion (Get-Item Function:\Complete-OwnerSetup).ScriptBlock
function Complete-OwnerSetup {
    param([string]$InstalledRoot,[string]$Desktop,[switch]$NoLaunch)
    $script:completionCalls++
    Invoke-FixtureCompletion -InstalledRoot $fixtureRoot -Desktop $fixtureDesktop -NoLaunch:$NoLaunch
}
function Start-Process {
    param([string]$FilePath,$ArgumentList,[string]$WorkingDirectory,[string]$Verb,[switch]$Wait,[switch]$PassThru,[switch]$NoNewWindow)
    if ($Verb -eq 'RunAs') {
        if ($ArgumentList -notmatch ' -Elevated -NoLaunch$') { throw 'UAC child could create another account desktop or launch its panel' }
        $process = [pscustomobject]@{ExitCode=0}
        $process | Add-Member ScriptMethod WaitForExit {}
        $process | Add-Member ScriptMethod Refresh {}
        return $process
    }
    if ($NoNewWindow) {
        if ($FilePath -ne (Join-Path $fixtureRoot 'python\python.exe') -or $WorkingDirectory -ne $fixtureRoot -or
            ($ArgumentList[0..2] -join ' ') -ne '-I -S -c' -or $ArgumentList[3] -notmatch 'panel_state\(8879') {
            throw 'Panel verifier did not use the fixed private interpreter and local endpoint'
        }
        $script:probes++
        $process = [pscustomobject]@{ExitCode=$script:probeCode}
        $process | Add-Member ScriptMethod WaitForExit { param($timeout) return (-not $script:probeTimeout) }
        $process | Add-Member ScriptMethod Refresh {}
        $process | Add-Member ScriptMethod Kill { $script:probeKilled = $true }
        $process | Add-Member ScriptMethod Dispose { $script:probeDisposed = $true }
        return $process
    }
    $script:launches += [pscustomobject]@{file=$FilePath; argv=@($ArgumentList); directory=$WorkingDirectory}
}
$outer = $ast.Find({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.Contains('$childCode = Get-SetupExitCode')},$true)
if (-not $outer) { throw 'Owner UAC continuation is missing' }
$continuation = $outer.Extent.Text -replace '(?m)^    exit 0\r?$','    return'
$SourceRoot = $fixtureRoot; $OwnerSid = 'S-1-5-21-100-200-300-1001'; $Elevated = $false
foreach ($case in @('ordinary','administrator','no-launch','foreign','owned','directory')) {
    $fixtureDesktop = Join-Path $env:RULEPROXY_SETUP_TEST_ROOT $case
    New-Item -ItemType Directory -Path $fixtureDesktop | Out-Null
    $desktopLink = Join-Path $fixtureDesktop 'RuleProxy Web.lnk'
    $before = $null
    if ($case -in @('foreign','owned')) {
        $target = if ($case -eq 'foreign') { $env:ComSpec } else { Join-Path $fixtureRoot 'old.exe' }
        [RuleProxyLinks.Links]::Create($desktopLink, $target, '', $fixtureRoot, 'Existing fixture', '')
        $before = (Get-FileHash -LiteralPath $desktopLink).Hash
    } elseif ($case -eq 'directory') { New-Item -ItemType Directory -Path $desktopLink | Out-Null }
    $isAdmin = $case -ne 'ordinary'; $NoLaunch = $case -eq 'no-launch'
    $script:completionCalls = 0; $script:launches = @(); $script:probes = 0
    $script:probeCode = 0; $script:probeTimeout = $false; $script:probeDisposed = $false
    & ([scriptblock]::Create($continuation))
    if ($script:completionCalls -ne 1) { throw ('Owner completion skipped: ' + $case) }
    if ($NoLaunch) {
        if ($script:launches.Count -or $script:probes -or (Test-Path -LiteralPath $desktopLink)) { throw 'NoLaunch changed the desktop or launched a process' }
        continue
    }
    if ($script:launches.Count -ne 1) { throw ('Background panel launch missing: ' + $case) }
    if ($script:probes -ne 1 -or -not $script:probeDisposed) { throw 'Successful panel launch was not verified and its probe closed' }
    $launch = $script:launches[0]
    if ($launch.file -ne (Join-Path $fixtureRoot 'python\pythonw.exe') -or $launch.directory -ne $fixtureRoot -or $launch.argv[-1] -ne '--no-browser') { throw 'Panel launch did not stay quiet and local' }
    if ($case -eq 'directory') {
        if (-not (Test-Path -LiteralPath $desktopLink -PathType Container)) { throw 'Foreign directory was overwritten' }
    } elseif ($case -eq 'foreign') {
        if ((Get-FileHash -LiteralPath $desktopLink).Hash -ne $before) { throw 'Foreign shortcut was overwritten' }
    } elseif ((Get-FileHash -LiteralPath $desktopLink).Hash -ne (Get-FileHash -LiteralPath (Join-Path $fixtureRoot 'Start-Windows.lnk')).Hash) {
        $com = New-Object -ComObject WScript.Shell
        $inspected = $null
        $comparison = [ordered]@{expected_root=$fixtureRoot; actual_target=$null; desktop_link=$desktopLink}
        try {
            $inspected = $com.CreateShortcut($desktopLink)
            $comparison.actual_target = $inspected.TargetPath
        } catch {
            $comparison['read_error'] = $_.Exception.Message
        } finally {
            if ($inspected) { [Runtime.InteropServices.Marshal]::ReleaseComObject($inspected) | Out-Null }
            [Runtime.InteropServices.Marshal]::ReleaseComObject($com) | Out-Null
        }
        $comparison = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($comparison | ConvertTo-Json -Compress)))
        throw ('Owned desktop launcher was not copied: ' + $case + '; synthetic_path_comparison_base64=' + $comparison)
    }
}
foreach ($failure in @('exit-one','missing-code','timeout')) {
    $fixtureDesktop = Join-Path $env:RULEPROXY_SETUP_TEST_ROOT $failure
    New-Item -ItemType Directory -Path $fixtureDesktop | Out-Null
    $script:probeCode = if ($failure -eq 'missing-code') { $null } else { 1 }
    $script:probeTimeout = $failure -eq 'timeout'
    $script:probeKilled = $false; $script:probeDisposed = $false; $script:failureMessage = $null
    $messages = & {
        try { Invoke-FixtureCompletion -InstalledRoot $fixtureRoot -Desktop $fixtureDesktop }
        catch { $script:failureMessage = $_.Exception.Message }
    } 6>&1 | Out-String
    if ($script:failureMessage -notmatch 'installation completed, but the Web panel failed to start' -or
        $script:failureMessage -notmatch 'RuleProxyWebSafe.+panel.log') { throw ('Panel failure was hidden: ' + $failure) }
    if ($messages.Contains('Installation complete. Web panel:')) { throw 'Unhealthy panel reported installation success' }
    if (-not $script:probeDisposed -or ($script:probeTimeout -and -not $script:probeKilled)) { throw 'Timed-out verifier was not cleaned up' }
    if (-not (Test-Path -LiteralPath (Join-Path $fixtureRoot 'Start-Windows.lnk'))) { throw 'Panel failure removed installed files' }
}
'''
        with tempfile.TemporaryDirectory(prefix='ruleproxy-completion-') as temporary:
            # Windows TEMP may use RUNNER~1, while ShellLink returns the long
            # path. Use the canonical form that Program Files uses in setup.
            fixture_root = Path(temporary).resolve()
            directory = fixture_root / '应用 setup space'
            directory.mkdir()
            installed = (fixture_root / 'installed').resolve()
            (installed / 'python').mkdir(parents=True)
            for name in ('python/python.exe', 'python/pythonw.exe', 'old.exe'):
                shutil.copyfile(sys.executable, installed / name)
            runner = directory / 'check.ps1'
            runner.write_text(script, encoding='ascii')
            environment = {key: value for key, value in os.environ.items() if key.casefold() != 'psmodulepath'}
            environment.update(RULEPROXY_SETUP_TEST_SCRIPT=str(ROOT / 'scripts/windows-setup.ps1'),
                               RULEPROXY_SETUP_TEST_ROOT=str(directory),
                               RULEPROXY_SETUP_TEST_INSTALLED_ROOT=str(installed),
                               RULEPROXY_SETUP_TEST_LINK_TYPES=shortcuts._SHELL_LINK_TYPES)
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(runner)], env=environment, text=True, capture_output=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failed_uac_child_cannot_report_success_or_run_owner_completion(self):
        script = r'''
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RULEPROXY_SETUP_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Installer PowerShell parse failed' }
$definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-SetupExitCode'},$true)
Invoke-Expression $definition.Extent.Text
function Complete-OwnerSetup { throw 'Owner completion must not run after a failed installation' }
function Start-Process {
    param($FilePath,$ArgumentList,$Verb,[switch]$Wait,[switch]$PassThru)
    $code = if ($env:RULEPROXY_SETUP_TEST_CODE -eq 'null') { $null } else { [int]$env:RULEPROXY_SETUP_TEST_CODE }
    $process = [pscustomobject]@{ExitCode=$code}
    $process | Add-Member ScriptMethod WaitForExit {}
    $process | Add-Member ScriptMethod Refresh {}
    return $process
}
$SourceRoot = $env:TEMP; $OwnerSid = 'S-1-5-21-100-200-300-1001'
$isAdmin = $true; $Elevated = $false; $NoLaunch = $false
$outer = $ast.Find({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.Contains('$childCode = Get-SetupExitCode')},$true)
if (-not $outer) { throw 'Owner UAC continuation is missing' }
& ([scriptblock]::Create($outer.Extent.Text))
'''
        with tempfile.TemporaryDirectory(prefix='ruleproxy-child-result-') as temporary:
            runner = Path(temporary) / 'check.ps1'
            runner.write_text(script, encoding='ascii')
            environment = {key: value for key, value in os.environ.items() if key.casefold() != 'psmodulepath'}
            environment['RULEPROXY_SETUP_TEST_SCRIPT'] = str(ROOT / 'scripts/windows-setup.ps1')
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            for code, expected in [('17', 17), ('null', 1)]:
                with self.subTest(code=code):
                    environment['RULEPROXY_SETUP_TEST_CODE'] = code
                    result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                             '-File', str(runner)], env=environment, text=True, capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    self.assertNotIn('Owner completion must not run', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
