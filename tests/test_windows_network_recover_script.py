"""Offline recovery tests: source contracts plus executable PowerShell behavior.

Native WFP/NRPT mutation is restricted to disposable GitHub Windows runners.
Linux can exercise the parser, C# compiler and mocked OS boundaries with pwsh.
"""
import os
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts/windows-network-recover.ps1'


def powershell():
    if os.name == 'nt':
        return str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
    return os.environ.get('RULEPROXY_TEST_PWSH') or shutil.which('pwsh')


class RecoveryContracts(unittest.TestCase):
    def test_no_guessed_xml_or_blanket_resets(self):
        source = SCRIPT.read_text(encoding='utf-8-sig')
        self.assertNotIn('netsh.exe', source)
        for unsafe in ('netsh winsock reset', 'netsh advfirewall reset',
                       'Remove-NetAdapter', 'Remove-NetFirewallRule', 'Invoke-Expression'):
            self.assertNotIn(unsafe, source)
        self.assertIn('DeleteChecked', source)
        self.assertIn('FwpmFilterEnum0', source)

    def test_guid_fixture_matches_product(self):
        from ruleproxy import windows_global_guard
        expected = uuid.uuid5(windows_global_guard._NAMESPACE, 'a' * 64 + '/provider')
        self.assertIn(str(expected), (ROOT / '.github/test_network_recovery.ps1').read_text())

    def test_bom_and_offline_launcher(self):
        self.assertTrue(SCRIPT.read_bytes().startswith(b'\xef\xbb\xbf'))
        launcher = (ROOT / 'Recover-Windows-Network.cmd').read_text()
        self.assertIn('-Apply', launcher)
        self.assertIn('-Verb RunAs', launcher)
        self.assertNotIn('-ResetDeadLoopbackProxy', launcher)
        self.assertNotIn('DownloadString', launcher)

    @unittest.skipUnless(powershell(), 'PowerShell not installed')
    def test_parser_native_interop_compile_and_behavior(self):
        result = subprocess.run(
            [powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
             '-File', str(ROOT / '.github/test_network_recovery.ps1'), '-ScriptPath', str(SCRIPT)],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('recovery behavioral assertions', result.stdout)
        result = subprocess.run(
            [powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
             '-File', str(ROOT / '.github/test_network_recovery_native.ps1'),
             '-ScriptPath', str(SCRIPT), '-CompileOnly'],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('native fixture interop compiles', result.stdout)

    @unittest.skipUnless(os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true',
                         'real WFP/NRPT changes: disposable GitHub Windows only')
    def test_native_owned_and_foreign_fixture(self):
        result = subprocess.run(
            [powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
             '-File', str(ROOT / '.github/test_network_recovery_native.ps1'), '-ScriptPath', str(SCRIPT)],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS: native owned/foreign WFP and NRPT recovery', result.stdout)


if __name__ == '__main__':
    unittest.main()
