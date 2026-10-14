"""Validate the VM-only update worker without installing or restarting Windows."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / '.github/windows-vm-update.ps1'
POWERSHELL = shutil.which('powershell.exe') or shutil.which('pwsh')


class WindowsVMUpdateSourceTests(unittest.TestCase):
    def test_source_is_vm_only_and_does_not_change_host_network_or_bypass_servicing(self):
        source = SCRIPT.read_text(encoding='utf-8')
        self.assertIn("C:\\RuleProxyCIUpdates", source)
        self.assertIn("RuleProxyCI-InstallOfficialUpdate", source)
        self.assertNotIn('/IgnoreCheck', source)
        self.assertNotIn('/Unsigned', source)
        self.assertNotIn('Restart-Computer -Force', source)
        for command in ('Set-Net', 'New-NetFirewallRule', 'Set-DnsClient', 'Stop-Process', 'taskkill'):
            self.assertNotIn(command, source)


@unittest.skipUnless(POWERSHELL, 'PowerShell is required for the real manifest validator')
class WindowsVMUpdateManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / 'packages').mkdir()
        data = b'public deterministic test MSU bytes; never installed'
        filename = 'windows11.0-kb5127648-x64_fixture.msu'
        (self.directory / 'packages' / filename).write_bytes(data)
        self.manifest = {'target_build': 26300, 'target_ubr': 9711,
                         'target_package': filename,
                         'packages': [{'filename': filename, 'sha256': hashlib.sha256(data).hexdigest()}]}

    def validate(self, expected, *, hide_hash_cmdlet=False):
        (self.directory / 'update-manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        runner = self.directory / 'validate.ps1'
        # Dot sourcing only defines helpers: the SYSTEM entry point is guarded.
        prelude = "function Get-FileHash { throw 'hash_cmdlet_unavailable' }\n" if hide_hash_cmdlet else ''
        runner.write_text("$ErrorActionPreference='Stop'\n. " + quote(SCRIPT) + '\n' + prelude +
                          "\ntry { $null = Read-UpdateManifest " + quote(self.directory) +
                          "; Write-Output 'valid' } catch { Write-Output $_.Exception.Message }\n", encoding='utf-8-sig')
        result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-File', str(runner)],
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), expected)

    def test_real_validator_accepts_exact_target_and_all_verified_packages(self):
        self.validate('valid', hide_hash_cmdlet=True)

    def test_real_validator_rejects_tampered_package(self):
        self.manifest['packages'][0]['sha256'] = '0' * 64
        self.validate('update_package_hash_mismatch')

    def test_real_validator_rejects_path_escape_before_opening_another_file(self):
        self.manifest['packages'][0]['filename'] = '..\\escape.msu'
        self.validate('update_invalid_package_entry')

    def test_real_validator_rejects_unverified_target_package(self):
        self.manifest['target_package'] = 'unlisted.msu'
        self.validate('update_target_not_verified')

    def test_real_validator_rejects_duplicate_case_insensitive_paths(self):
        duplicate = dict(self.manifest['packages'][0])
        duplicate['filename'] = duplicate['filename'].upper().replace('.MSU', '.msu')
        self.manifest['packages'].append(duplicate)
        self.validate('update_duplicate_filename')

    def test_real_validator_rejects_different_OS_target(self):
        self.manifest['target_build'] = 26200
        self.validate('update_manifest_unexpected_target')

    def test_real_validator_rejects_unlisted_MSU_before_servicing_can_discover_it(self):
        (self.directory / 'packages' / 'unlisted.msu').write_bytes(b'unverified checkpoint')
        self.validate('update_unlisted_package')

    def test_real_validator_rejects_an_extra_subdirectory_in_package_search_path(self):
        (self.directory / 'packages' / 'nested').mkdir()
        self.validate('update_unlisted_package')
