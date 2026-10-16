"""Store candidates use the ordinary executable selection and routing flow."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy import launcher


class WindowsStoreDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.programs = self.root / 'Program Files'
        self.store = self.programs / 'WindowsApps'
        self.chatgpt = self.store / 'OpenAI.ChatGPT_1.2.3_x64__publisher' / 'app' / 'ChatGPT.exe'
        self.chatgpt.parent.mkdir(parents=True)
        self.chatgpt.write_bytes(b'MZ fixture, never executed')
        self.chatgpt.chmod(0o755)
        self.editor = self.programs / 'Editor' / 'Editor.exe'
        self.editor.parent.mkdir()
        self.editor.write_bytes(b'MZ fixture, never executed')
        self.environment = patch.dict(os.environ, {
            'PROGRAMFILES': str(self.programs),
            'PROGRAMFILES(X86)': str(self.root / 'empty-x86'),
            'LOCALAPPDATA': str(self.root / 'local'),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def candidate(self):
        return {'label': 'ChatGPT', 'path': str(self.chatgpt),
                'package_family_name': 'OpenAI.ChatGPT_publisher', 'application_id': 'ChatGPT'}

    def test_registered_store_executable_is_listed_without_walking_windowsapps_or_starting_apps(self):
        original = Path.iterdir

        def guarded_walk(path):
            if path == self.store:
                raise AssertionError('Must query package registration, not walk WindowsApps')
            return original(path)

        with patch.object(launcher, '_win_store_apps', return_value=[self.candidate()]), \
                patch.object(launcher, '_win_registry_apps', return_value=[]), \
                patch.object(Path, 'iterdir', guarded_walk), \
                patch('subprocess.Popen', side_effect=AssertionError('Discovery must not launch a candidate')):
            found = launcher._windows_discover()
        selected = next(app for app in found if app['label'] == 'ChatGPT')
        self.assertEqual(selected['path'], str(self.chatgpt.resolve()))
        self.assertEqual(selected['source'], 'windows-store')
        self.assertEqual(selected['adapter'], 'chromium')
        self.assertEqual(selected['args'], [])
        normalized = launcher.validate_app(selected)
        self.assertEqual(normalized['path'], str(self.chatgpt.resolve()))
        self.assertNotIn('source', normalized)
        self.assertNotIn('package_family_name', normalized)

    def test_store_and_registry_results_are_deduplicated_with_the_store_display_name(self):
        with patch.object(launcher, '_win_store_apps', return_value=[self.candidate()]), \
                patch.object(launcher, '_win_registry_apps', return_value=[('Old name', self.chatgpt)]):
            found = launcher._windows_discover()
        entries = [app for app in found if app['path'] == str(self.chatgpt.resolve())]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['label'], 'ChatGPT')
        self.assertEqual(entries[0]['source'], 'windows-store')

    def test_unavailable_package_service_does_not_hide_ordinary_applications(self):
        with patch('ruleproxy.windows_store_apps.discover_store_apps', side_effect=OSError('Appx unavailable')), \
                patch.object(launcher, '_win_registry_apps', return_value=[]):
            found = launcher._windows_discover()
        entry = next(app for app in found if app['path'] == str(self.editor.resolve()))
        self.assertNotIn('source', entry)

    def test_missing_store_version_has_an_actionable_error_while_normal_errors_remain(self):
        self.chatgpt.unlink()
        app = {'label': 'ChatGPT', 'path': str(self.chatgpt), 'adapter': 'chromium'}
        with patch.object(launcher.sys, 'platform', 'win32'):
            with self.assertRaisesRegex(ValueError, '刷新应用列表.*重新添加'):
                launcher.validate_app(app)
            with self.assertRaisesRegex(ValueError, '找不到这个程序'):
                launcher.validate_app({**app, 'path': str(self.editor.parent / 'missing.exe')})
        with patch.object(launcher.sys, 'platform', 'linux'):
            with self.assertRaisesRegex(ValueError, '找不到这个程序'):
                launcher.validate_app(app)


if __name__ == '__main__':
    unittest.main()
