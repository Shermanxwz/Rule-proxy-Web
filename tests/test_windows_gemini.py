"""Gemini's launcher rejects browser proxy flags and starts versioned images."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ruleproxy import launcher
from ruleproxy.manager import Manager
from ruleproxy.windows_gemini import is_gemini, routing_paths


class GeminiCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'Google' / 'Gemini'
        self.version = self.root / 'app-1.17.0'
        self.version.mkdir(parents=True)
        self.entry = self.root / 'Gemini.exe'
        self.helper = self.root / 'GeminiAppLauncher.exe'
        self.main = self.version / 'Gemini.exe'
        self.version_helper = self.version / 'GeminiAppLauncher.exe'
        for path in (self.entry, self.helper, self.main, self.version_helper):
            path.write_bytes(b'MZ fixture')
            path.chmod(0o755)
        env = patch.dict(os.environ, {'LOCALAPPDATA': str(self.base),
                                     'PROGRAMFILES': str(self.base / 'empty'),
                                     'PROGRAMFILES(X86)': str(self.base / 'empty-x86')})
        env.start()
        self.addCleanup(env.stop)

    def test_discovery_finds_gemini_without_starting_it(self):
        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch.object(launcher, '_win_registry_apps', return_value=[]), \
                patch.object(launcher, '_win_store_apps', return_value=[]), \
                patch('subprocess.Popen', side_effect=AssertionError('must not launch')):
            found = launcher._windows_discover()
        gemini = next(app for app in found if app['label'] == 'Gemini')
        self.assertEqual(gemini['path'], str(self.entry.resolve()))
        self.assertEqual(gemini['adapter'], 'environment')

    def test_existing_chromium_entry_starts_without_forbidden_switches(self):
        app = {'id': 'gemini', 'label': 'Gemini', 'path': str(self.entry),
               'adapter': 'chromium', 'args': [], 'use_original_data': True}
        with patch.object(launcher.sys, 'platform', 'win32'):
            command, env, _ = launcher.prepare_app(app, 10809, self.base / 'profiles',
                                                   transparent=True, native_proxy=True)
        self.assertEqual(command, [str(self.entry.resolve())])
        self.assertEqual(env['HTTPS_PROXY'], 'http://127.0.0.1:10809')

    def test_policy_includes_stable_and_versioned_images(self):
        manager = Manager(self.base / 'state', 18879)
        self.addCleanup(manager.close)
        manager.settings['apps'] = [{'id': 'gemini', 'label': 'Gemini',
                                    'path': str(self.entry), 'adapter': 'chromium',
                                    'enabled': True, 'args': []}]
        self.assertEqual(set(manager._selected_windows_paths()),
                         {str(p.resolve()) for p in (self.entry, self.helper, self.main, self.version_helper)})
        newer = self.root / 'app-1.18.0' / 'Gemini.exe'
        newer.parent.mkdir()
        newer.touch()
        self.assertIn(str(newer.resolve()), manager._selected_windows_paths())

    def test_other_apps_named_gemini_are_not_special_cased(self):
        other = self.base / 'Elsewhere' / 'Gemini.exe'
        other.parent.mkdir()
        other.touch()
        self.assertFalse(is_gemini(other))
        self.assertEqual(routing_paths(other), [])

    def test_missing_version_never_silently_selects_only_launcher(self):
        self.main.unlink()
        with self.assertRaisesRegex(ValueError, '无法找到 Gemini'):
            routing_paths(self.entry)


if __name__ == '__main__':
    unittest.main()
