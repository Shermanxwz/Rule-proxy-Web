"""Discovery filters bundle maintenance executables without launching them."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy import launcher


class WindowsDiscoveryHelperTests(unittest.TestCase):
    def test_maintenance_names_include_whitespace_and_exact_elevation_helper(self):
        for name in (
            'Uninstall Antigravity.exe', 'UNINSTALL ANTIGRAVITY.EXE',
            'Uninstall\tAntigravity.exe', 'uninstall.exe', 'uninstaller.exe',
            'uninstall-antigravity.exe', 'uninstall_antigravity.exe',
            'uninstall.antigravity.exe', 'unins000.exe', 'setup.exe',
            'updater.exe', 'crashpad-handler.exe', 'elevate.exe', 'ELEVATE.EXE',
        ):
            with self.subTest(name=name):
                self.assertTrue(launcher._is_excluded_program(Path('app') / name, 'antigravity'))

    def test_legitimate_names_are_not_substring_filtered(self):
        for name in ('Antigravity.exe', 'Editor.exe', 'My Editor.exe',
                     'ElevateStudio.exe', 'elevate-client.exe',
                     'uninstallable.exe', 'SetupStudio.exe', 'UpdaterStudio.exe'):
            with self.subTest(name=name):
                self.assertFalse(launcher._is_excluded_program(Path('app') / name, 'Application'))

    def test_bundle_scan_keeps_main_and_other_apps_without_launching(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program_files = root / 'Program Files'
            local = root / 'local'
            bundle = local / 'Programs' / 'antigravity'
            main = bundle / 'Antigravity.exe'
            uninstall = bundle / 'Uninstall Antigravity.exe'
            elevate = bundle / 'resources' / 'elevate.exe'
            editor = program_files / 'Editor' / 'Editor.exe'
            second_main = program_files / 'antigravity' / 'Antigravity.exe'
            for executable in (main, uninstall, elevate, editor, second_main):
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_bytes(b'MZ fixture, never executed')
            marker = bundle / 'resources' / 'app' / 'main.js'
            marker.parent.mkdir()
            marker.write_text('// Electron marker', encoding='utf-8')
            environment = {'PROGRAMFILES': str(program_files),
                           'PROGRAMFILES(X86)': str(root / 'x86'),
                           'LOCALAPPDATA': str(local)}
            with patch.dict(os.environ, environment), \
                    patch.object(launcher, '_win_registry_apps', return_value=[('Registered main', main)]), \
                    patch.object(launcher, '_win_store_apps', return_value=[]), \
                    patch('subprocess.Popen', side_effect=AssertionError('Discovery must not launch')):
                found = launcher._windows_discover()
            paths = [app['path'] for app in found]
            self.assertCountEqual(paths, [str(p.resolve()) for p in (main, editor, second_main)])
            self.assertEqual(paths.count(str(main.resolve())), 1, 'Registry and scan must deduplicate by path')
            selected = next(app for app in found if app['path'] == str(main.resolve()))
            self.assertEqual(selected['adapter'], 'chromium')
            self.assertEqual(selected['args'], [])
            self.assertTrue(uninstall.exists(), 'Filtering must not delete installation files')
            self.assertTrue(elevate.exists())


if __name__ == '__main__':
    unittest.main()
