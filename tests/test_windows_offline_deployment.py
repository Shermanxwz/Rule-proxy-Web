"""Offline payload identity and product-runtime separation from diagnostic MXC."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from ruleproxy import windows_proxy_pins as pins

SPEC = importlib.util.spec_from_file_location('offline_runtime_installer', Path(__file__).resolve().parent.parent / 'install_runtime.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class WindowsOfflineDeploymentTests(unittest.TestCase):
    def test_official_burn_layout_requires_exact_local_payload_bytes(self):
        import xml.etree.ElementTree as ET
        namespace = 'http://wixtoolset.org/schemas/v4/2008/Burn'
        root = ET.Element('{' + namespace + '}BurnManifest')
        assets = {}
        payloads = {'VisualCppRuntime': ('vc_redist', b'Microsoft VC payload'),
                    'WindowsPacketFilter': ('ndis_msi', b'official driver payload')}
        for name, (key, data) in payloads.items():
            filename = key + '.bin'
            assets[key] = {'name': filename, 'size': len(data), 'url': 'https://example.invalid/' + filename,
                           'sha256': hashlib.sha256(data).hexdigest()}
            ET.SubElement(root, '{' + namespace + '}Payload', Id=name, FilePath=filename, SourcePath=filename,
                          FileSize=str(len(data)), DownloadUrl=assets[key]['url'], Packaging='external',
                          Hash=hashlib.sha512(data).hexdigest().upper())
        ET.SubElement(root, '{' + namespace + '}Registration', Code=pins.BURN_REGISTRATION)
        manifest = ET.tostring(root)
        with tempfile.TemporaryDirectory() as directory, patch.object(pins, 'ASSETS', assets), \
                patch.object(pins, 'BURN_MANIFEST_SHA256', hashlib.sha256(manifest).hexdigest()):
            target = Path(directory)
            for name, (key, data) in payloads.items():
                (target / assets[key]['name']).write_bytes(data)
            result = pins.validate_burn_layout(target, manifest=manifest)
            self.assertEqual(set(result['external_payloads']), set(payloads))
            (target / assets['vc_redist']['name']).write_bytes(b'altered')
            with self.assertRaisesRegex(ValueError, 'digest'):
                pins.validate_burn_layout(target, manifest=manifest)
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                pins.validate_burn_layout(target, manifest=manifest + b' ')

    @unittest.skipUnless(os.name == 'nt', 'requires native Windows ACL APIs')
    def test_windows_protect_tree_keeps_admin_access_and_users_read_only(self):
        # Execute the actual installer function without the installer entrypoint.
        # This reproduces copying children under a protected parent, then
        # protecting the populated tree, including a read-only payload file.
        script = r"""
$ErrorActionPreference = 'Stop'
# A pwsh 7 caller can export its incompatible PSModulePath to this WinPS 5.1
# child. Load only the native host's shipped modules, with explicit errors.
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module -Name Microsoft.PowerShell.Security -ErrorAction Stop
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction Stop
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 77 }
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RULEPROXY_SETUP_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Installer PowerShell parse failed' }
$definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Protect-Tree'},$true)
if (-not $definition) { throw 'Installer ACL function missing' }
Invoke-Expression $definition.Extent.Text
$root = $env:RULEPROXY_SETUP_TEST_ROOT
New-Item -ItemType Directory -Path $root | Out-Null
Protect-Tree $root
New-Item -ItemType Directory -Path (Join-Path $root 'bin\windows-amd64') -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $root 'CHANGELOG.md'),'checked payload')
$license = Join-Path $root 'bin\windows-amd64\MIHOMO-LICENSE'
[IO.File]::WriteAllText($license,'checked license')
[IO.File]::SetAttributes($license,[IO.FileAttributes]::ReadOnly)
Protect-Tree $root
Protect-Tree $root
foreach ($item in @((Get-Item -LiteralPath $root)) + @(Get-ChildItem -LiteralPath $root -Recurse -Force)) {
    $acl = Get-Acl -LiteralPath $item.FullName
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'ACL owner or inheritance incorrect' }
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and (([long]$ace.FileSystemRights -band 0x500D0156) -ne 0)) { throw 'Non-admin write grant found' }
    }
}
if ([IO.File]::ReadAllText((Join-Path $root 'CHANGELOG.md')) -ne 'checked payload') { throw 'Admin read failed' }
[IO.File]::WriteAllText((Join-Path $root 'CHANGELOG.md'),'admin can still write')
Remove-Item -LiteralPath $root -Recurse -Force
if (Test-Path -LiteralPath $root) { throw 'Admin cleanup failed' }
# Execute the real installer exit handling with a process double: only the
# official Burn chain may map ERROR_FAIL_REBOOT_REQUIRED to a pending reboot.
$invoke = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Installer'},$true)
Invoke-Expression $invoke.Extent.Text
function Start-Process {
    param([string]$FilePath,[string]$ArgumentList,[switch]$Wait,[switch]$PassThru)
    $process = [pscustomobject]@{ExitCode=3017}
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($timeout) return $true }
    return $process
}
if ((Invoke-Installer 'unused.exe' '' 'official test' -OfficialBurn) -ne 3010) { throw 'Burn reboot mapping failed' }
$rejected = $false
try { Invoke-Installer 'unused.exe' '' 'ordinary installer' | Out-Null }
catch { $rejected = $_.Exception.Message -match 'exit 3017' }
if (-not $rejected) { throw 'Non-Burn 3017 was incorrectly accepted' }
"""
        temporary = Path(tempfile.mkdtemp(prefix='ruleproxy-acl-'))
        try:
            source = Path(__file__).resolve().parent.parent / 'scripts/windows-setup.ps1'
            runner = temporary / 'check.ps1'
            runner.write_text(script, encoding='ascii')
            environment = {key: value for key, value in os.environ.items() if key.casefold() != 'psmodulepath'}
            environment.update(RULEPROXY_SETUP_TEST_SCRIPT=str(source),
                               RULEPROXY_SETUP_TEST_ROOT=str(temporary / 'protected'))
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(runner)], env=environment, text=True, capture_output=True, timeout=45)
            if result.returncode == 77:
                self.skipTest('native ACL owner test requires an elevated administrator token')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def test_installer_failure_handler_always_attempts_program_rollback(self):
        source = (Path(__file__).resolve().parent.parent / 'scripts/windows-setup.ps1').read_text()
        handler = source.split('} catch {\n    $originalFailure = $_', 1)[1]
        self.assertIn('Restore-ProgramInstallation', handler)
        self.assertIn('throw $originalFailure', handler)
        self.assertNotIn('if ($swapped)', handler)

    @unittest.skipUnless(os.name == 'nt', 'requires native Windows PowerShell fault injection')
    def test_windows_failed_program_swap_restores_old_root_without_deleting_foreign_target(self):
        # Run the actual rollback function AND outer catch from the installer.
        # Only service operations and the new-directory rename are fault doubles;
        # directory moves, hashes, protected ACLs, recovery and deletion are real.
        script = r"""
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 77 }
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RULEPROXY_SETUP_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Installer PowerShell parse failed' }
foreach ($name in @('Protect-Tree','Assert-Protected','Restore-ProgramInstallation')) {
    $definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if (-not $definition) { throw ('Missing installer function: ' + $name) }
    Invoke-Expression $definition.Extent.Text
}
$main = $ast.Find({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and $node.Body.Extent.Text.Contains('$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)')},$true)
if (-not $main) { throw 'Installer outer failure handler missing' }
$failureBody = @'
try {
    if ($case -ne 'first') {
        Move-Item -LiteralPath $root -Destination $backup
        $oldRootMoved = $true
    }
    if ($case -eq 'foreign') {
        New-Item -ItemType Directory -Path $root | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'foreign.txt'),'leave this alone')
    }
    Move-Item -LiteralPath $stage -Destination $root
    $swapped = $true
    throw [IO.IOException]::new('injected failure after swap')
} catch
'@ + $main.CatchClauses[0].Body.Extent.Text
function Get-Service { param([string]$Name,[string]$ErrorAction) return [pscustomobject]@{Name=$Name} }
function Stop-Service { param([string]$Name,[string]$ErrorAction) $script:stops++ }
function Start-Service { param([string]$Name,[string]$ErrorAction) $script:starts++ }
function Write-SetupDiagnostic { param($Failure) }
function Write-State { param([string]$Phase,[bool]$PfOwned) }
function Move-Item {
    param([string]$LiteralPath,[string]$Destination,[string]$ErrorAction)
    if ($LiteralPath -eq $stage -and $case -in @('rename','foreign')) {
        throw [IO.IOException]::new('injected stage rename failure')
    }
    Microsoft.PowerShell.Management\Move-Item @PSBoundParameters
}
foreach ($case in @('rename','after','foreign','first')) {
    $directory = Join-Path $env:RULEPROXY_SETUP_TEST_ROOT $case
    $root = Join-Path $directory 'installed'; $stage = Join-Path $directory 'stage'; $backup = Join-Path $directory 'previous'
    $serviceName = 'RuleProxyControl'; $restoreControlService = $case -ne 'first'
    $swapped = $false; $oldRootMoved = $false; $pfOwned = $true; $setupPhase = 'program_swap'
    $script:starts = 0; $script:stops = 0
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $directory 'user-state.txt'),'keep user state')
    [IO.File]::WriteAllText((Join-Path $stage 'deployment.json'),'new deployment')
    [IO.File]::WriteAllText((Join-Path $stage 'new.txt'),'new code')
    Protect-Tree $stage
    $newDeploymentHash = (Get-FileHash -LiteralPath (Join-Path $stage 'deployment.json') -Algorithm SHA256).Hash
    if ($case -ne 'first') {
        New-Item -ItemType Directory -Path $root | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'deployment.json'),'old deployment')
        [IO.File]::WriteAllText((Join-Path $root 'old.txt'),'old code')
        Protect-Tree $root
        $oldDeploymentHash = (Get-FileHash -LiteralPath (Join-Path $root 'deployment.json') -Algorithm SHA256).Hash
    }
    $observed = $null
    try { & ([scriptblock]::Create($failureBody)) } catch { $observed = $_.Exception.Message }
    if ($observed -notmatch '^injected (stage rename failure|failure after swap)$') { throw ('Original failure was masked: ' + $observed) }
    if ([IO.File]::ReadAllText((Join-Path $directory 'user-state.txt')) -ne 'keep user state') { throw 'User state changed' }
    if ($case -in @('rename','after')) {
        if ([IO.File]::ReadAllText((Join-Path $root 'old.txt')) -ne 'old code' -or (Test-Path $backup)) { throw 'Old installation was not immediately restored' }
        if ($script:starts -ne 1 -or $script:stops -ne 1) { throw 'Original service was not restarted' }
    } elseif ($case -eq 'foreign') {
        if ([IO.File]::ReadAllText((Join-Path $root 'foreign.txt')) -ne 'leave this alone' -or -not (Test-Path (Join-Path $backup 'old.txt'))) { throw 'Foreign target or retained backup changed' }
        if ($script:starts -ne 0 -or $script:stops -ne 0) { throw 'Foreign target was adopted' }
    } else {
        if ([IO.File]::ReadAllText((Join-Path $root 'new.txt')) -ne 'new code' -or $script:starts -ne 0 -or $script:stops -ne 1) { throw 'First-install repair files or service state were lost' }
    }
}
"""
        with tempfile.TemporaryDirectory(prefix='ruleproxy-swap-') as directory:
            root = Path(directory)
            runner = root / 'check.ps1'
            runner.write_text(script, encoding='ascii')
            environment = {key: value for key, value in os.environ.items() if key.casefold() != 'psmodulepath'}
            environment.update(RULEPROXY_SETUP_TEST_SCRIPT=str(Path(__file__).resolve().parent.parent / 'scripts/windows-setup.ps1'),
                               RULEPROXY_SETUP_TEST_ROOT=str(root / 'cases'))
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(runner)], env=environment, text=True, capture_output=True, timeout=45)
            if result.returncode == 77:
                self.skipTest('native rollback ACL test requires an elevated administrator token')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_owned_proxifyre_residue_can_be_removed_after_msi_for_fresh_reinstall(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'ProxiFyre'
            (root / 'logs/archive').mkdir(parents=True)
            (root / 'ProxiFyre.exe').write_bytes(b'official executable')
            (root / 'app-config.sample.json').write_bytes(b'official sample')
            static = {name: pins.digest(root / name) for name in ('ProxiFyre.exe','app-config.sample.json')}
            for name in ('app-config.json','app-config.json.bak','logs/logfile.txt','logs/archive/logfile_0.txt'):
                (root / name).write_bytes(b'owned runtime state')
            self.assertEqual(len(pins.proxifyre_removal_plan(root, static)), 6)
            # MSI removes static payload, deliberately retaining runtime files.
            for name in static:
                (root / name).unlink()
            for name in pins.proxifyre_removal_plan(root, static):
                (root / name).unlink()
            (root / 'logs/archive').rmdir()
            (root / 'logs').rmdir()
            root.rmdir()
            self.assertFalse(root.exists())

    def test_proxifyre_removal_rejects_unknown_or_changed_content_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'ProxiFyre.exe'
            executable.write_bytes(b'official')
            static = {'ProxiFyre.exe': pins.digest(executable)}
            unknown = root / 'someone-elses-file.txt'
            unknown.write_bytes(b'leave this intact')
            with self.assertRaisesRegex(ValueError, 'Unknown'):
                pins.proxifyre_removal_plan(root, static)
            self.assertEqual(unknown.read_bytes(), b'leave this intact')
            unknown.unlink()
            executable.write_bytes(b'changed by another deployment')
            with self.assertRaisesRegex(ValueError, 'Changed'):
                pins.proxifyre_removal_plan(root, static)
            self.assertEqual(executable.read_bytes(), b'changed by another deployment')

    def test_proxifyre_removal_rejects_linked_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'owned'
            root.mkdir()
            target = Path(directory) / 'foreign'
            target.mkdir()
            try:
                (root / 'logs').symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(str(exc))
            with self.assertRaisesRegex(ValueError, 'Linked'):
                pins.proxifyre_removal_plan(root, {'ProxiFyre.exe': '0'*64})
            self.assertTrue(target.is_dir())

    def test_private_pipe_identity_is_stable_and_rejects_non_user_sid(self):
        sid = 'S-1-5-21-100-200-300-1001'
        self.assertEqual(pins.pipe_name(sid), pins.PIPE_PREFIX + hashlib.sha256(sid.encode('ascii')).hexdigest()[:16])
        for value in ('S-1-5-18', 'S-1-5-32-544', sid + '\\anything', ''):
            with self.assertRaises(ValueError):
                pins.pipe_name(value)

    def test_cached_asset_tampering_is_rejected_without_network_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'fixed.bin').write_bytes(b'changed')
            asset = {'name': 'fixed.bin', 'url': 'https://example.invalid/fixed.bin',
                     'sha256': hashlib.sha256(b'correct').hexdigest()}
            with patch.object(pins.urllib.request, 'urlopen') as network, self.assertRaises(ValueError):
                pins.fetch_asset(asset, root)
            network.assert_not_called()

    def test_product_runtime_installs_only_mihomo_and_rejects_tampered_binary(self):
        body = io.BytesIO()
        with zipfile.ZipFile(body, 'w') as archive:
            archive.writestr('mihomo-windows-amd64.exe', b'checked-mihomo')
        def download(asset, _cache):
            return body.getvalue() if asset['name'].endswith('.zip') else b'GPL license'
        with tempfile.TemporaryDirectory() as directory, patch.object(pins, 'fetch_asset', side_effect=download):
            root = Path(directory)
            target = installer.install_windows_proxy(root)
            self.assertTrue(installer.installed_windows_proxy(root))
            self.assertEqual(set(path.name for path in target.iterdir()), {'mihomo.exe', 'MIHOMO-LICENSE', 'runtime.json'})
            record = json.loads((target / 'runtime.json').read_text())
            self.assertNotIn('mxc', record)
            self.assertEqual(record['windows_backend']['name'], 'proxifyre')
            (target / 'mihomo.exe').write_bytes(b'changed')
            self.assertFalse(installer.installed_windows_proxy(root))

    def test_failed_product_download_preserves_the_previous_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'bin/windows-amd64'
            target.mkdir(parents=True)
            (target / 'mihomo.exe').write_bytes(b'old-runtime')
            with patch.object(pins, 'fetch_asset', side_effect=ValueError('mismatch')), self.assertRaises(ValueError):
                installer.install_windows_proxy(root)
            self.assertEqual((target / 'mihomo.exe').read_bytes(), b'old-runtime')

    def test_windows_cli_default_never_requests_mxc(self):
        with patch.object(installer, 'install_windows_proxy') as product, patch.object(installer, 'install') as diagnostic:
            self.assertEqual(installer.main(['--platform', 'windows-amd64']), 0)
        product.assert_called_once_with()
        diagnostic.assert_not_called()


if __name__ == '__main__':
    unittest.main()
