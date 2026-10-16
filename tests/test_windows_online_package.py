"""Online releases carry the complete pinned bootstrap source, without binaries/state."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('ruleproxy_online_package_test', ROOT / '.github/build_windows_online_package.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class WindowsOnlinePackageTests(unittest.TestCase):
    def test_complete_bootstrap_layout_and_exact_source_bytes_without_downloads(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(builder.offline, 'download', side_effect=AssertionError('online packaging must not download')), \
                mock.patch.object(builder.offline, 'stage', side_effect=AssertionError('must not bundle offline assets')):
            target = Path(directory) / 'source'
            metadata = builder.stage(target)
            expected = set(builder.offline.project_files()) | set(builder.EXTRA_SOURCES)
            self.assertEqual(set(metadata['files']), expected)
            self.assertEqual(len(expected), 41)
            self.assertEqual({p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()},
                             expected | {'INSTALL-WINDOWS.txt', 'release-source.json'})
            for name in expected:
                original = (ROOT / name).read_bytes()
                if name.endswith('.cmd'):
                    original = original.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
                    self.assertNotIn(b'\n', (target / name).read_bytes().replace(b'\r\n', b''))
                self.assertEqual((target / name).read_bytes(), original, name)
                self.assertEqual(hashlib.sha256(original).hexdigest(), metadata['files'][name])
            for name in ('ruleproxy/windows_proxy_burn_manifest.xml', 'ruleproxy/windows_proxy_pins.py',
                         'ruleproxy/windows_runtime_pins.py', 'Setup-Windows.cmd', 'Start-Windows.cmd'):
                self.assertIn(name, expected)
            for key, name in zip(builder.offline.LICENSE_KEYS, builder.offline.BUNDLED_LICENSE_SOURCES):
                self.assertIn(name, expected)
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(),
                                 builder.offline.pins.ASSETS[key]['sha256'])
            # The shipped embedded interpreter runs this exact -I -S entrypoint;
            # verify its import closure without site packages or fetching assets.
            result = subprocess.run([sys.executable, '-I', '-S', '-B', str(target / '.github/build_windows_package.py'), '--help'],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--stage-only', result.stdout)

    def test_metadata_and_instructions_state_online_and_incomplete_native_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            metadata = builder.stage(target)
            self.assertEqual(metadata['kind'], 'online-source-bootstrap')
            self.assertIs(metadata['third_party_binaries_bundled'], False)
            self.assertIs(metadata['offline_package_manifest_included'], False)
            self.assertNotIn('commit', metadata)
            self.assertNotIn('timestamp', metadata)
            self.assertEqual(json.loads((target / 'release-source.json').read_text()), metadata)
            instructions = (target / 'INSTALL-WINDOWS.txt').read_bytes()
            self.assertEqual(hashlib.sha256(instructions).hexdigest(), metadata['generated_files']['INSTALL-WINDOWS.txt'])
            text = instructions.decode('utf-8')
            for marker in ('首次安装需要联网', '无需预装全局 Python', 'UAC', '3010', '重启', '自行导入 YAML', '完整验收尚未通过'):
                self.assertIn(marker, text)

    def test_source_provider_cannot_smuggle_binaries_yaml_manifest_or_state(self):
        for name in ('web/third-party.exe', 'ruleproxy/driver.dll', 'ruleproxy/driver.sys', 'web/installer.msi',
                     'ruleproxy/private.yaml', 'web/profile.yml', 'package-manifest.json', '.windows-cache/secrets.py',
                     'ruleproxy/licenses/UNREVIEWED-LICENSE'):
            with self.subTest(name=name), mock.patch.object(builder.offline, 'project_files', return_value=[name]), \
                    self.assertRaises(ValueError):
                builder.project_files()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'private.yaml').write_text('private configuration')
            with self.assertRaisesRegex(ValueError, 'empty directory'):
                builder.stage(target)
            self.assertEqual((target / 'private.yaml').read_text(), 'private configuration')

    def test_two_builds_have_identical_zip_hashes_and_fixed_archive_metadata(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch('builtins.print'):
            first, second = Path(directory) / 'first', Path(directory) / 'second'
            self.assertEqual(builder.main([str(first)]), 0)
            self.assertEqual(builder.main([str(second)]), 0)
            name = 'RuleProxy-Web-0.3.0-windows-x64-online-setup.zip'
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            checksum, checksum_name = (first / 'SHA256SUMS.txt').read_text().split()
            self.assertEqual(checksum_name, name)
            self.assertEqual(hashlib.sha256((first / name).read_bytes()).hexdigest(), checksum)
            with zipfile.ZipFile(first / name) as archive:
                for entry in archive.infolist():
                    self.assertTrue(entry.filename.startswith('RuleProxy-Web/'))
                    self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                    self.assertEqual(entry.external_attr >> 16, 0o100644)
                    self.assertNotIn('.windows-cache', entry.filename)
                    self.assertFalse(entry.filename.lower().endswith(('.exe', '.msi', '.dll', '.sys', '.pyd', '.yaml', '.yml')))
                    self.assertNotEqual(Path(entry.filename).name, 'package-manifest.json')


if __name__ == '__main__':
    unittest.main()
