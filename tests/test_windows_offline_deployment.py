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
    @unittest.skipUnless(os.name == 'nt', 'requires native Windows ACL APIs')
    def test_windows_protect_tree_keeps_admin_access_and_users_read_only(self):
        # Execute the actual installer function without the installer entrypoint.
        # This reproduces copying children under a protected parent, then
        # protecting the populated tree, including a read-only payload file.
        script = r"""
$ErrorActionPreference = 'Stop'
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
"""
        temporary = Path(tempfile.mkdtemp(prefix='ruleproxy-acl-'))
        try:
            source = Path(__file__).resolve().parent.parent / 'scripts/windows-setup.ps1'
            runner = temporary / 'check.ps1'
            runner.write_text(script, encoding='ascii')
            environment = dict(os.environ, RULEPROXY_SETUP_TEST_SCRIPT=str(source),
                               RULEPROXY_SETUP_TEST_ROOT=str(temporary / 'protected'))
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(runner)], env=environment, text=True, capture_output=True, timeout=45)
            if result.returncode == 77:
                self.skipTest('native ACL owner test requires an elevated administrator token')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

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
