"""Shared-data selection persists and never blocks core cleanup on filesystem checks."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from ruleproxy.manager import Manager


class AppProfileSettingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        program = self.root / 'chrome'
        program.write_bytes(b'fake executable')
        program.chmod(0o700)
        self.manager = Manager(self.root / 'state', 18879)
        self.addCleanup(self.manager.close)
        self.manager.add_app({'label': 'Browser', 'path': str(program), 'adapter': 'chromium'})
        self.ident = self.manager.settings['apps'][0]['id']

    def tearDown(self):
        self.manager.active.clear()
        self.manager.core = None

    def test_choice_survives_restart_without_importing_or_copying_data(self):
        with patch.object(sys, 'platform', 'win32'):
            self.manager.set_app_profile(self.ident, True)
        self.assertTrue(self.manager.app(self.ident)['use_original_data'])
        self.assertFalse((self.manager.directory / 'profiles').exists())
        restored = Manager(self.manager.directory, 19879)
        try:
            self.assertTrue(restored.app(self.ident)['use_original_data'])
            with patch.object(sys, 'platform', 'win32'):
                restored.set_app_profile(self.ident, False)
            saved = json.loads((self.manager.directory / 'settings.json').read_text())
            self.assertIs(saved['apps'][0]['use_original_data'], False)
        finally:
            restored.close()

    def test_rejects_nonboolean_or_unknown_app(self):
        for value in (None, 'true', 1, [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '布尔值'):
                self.manager.set_app_profile(self.ident, value)
        with self.assertRaisesRegex(ValueError, '不存在'):
            self.manager.set_app_profile('missing', True)
        self.assertNotIn('use_original_data', self.manager.app(self.ident))

    def test_running_application_must_be_closed_before_changing_data(self):
        process = Mock(poll=Mock(return_value=None))
        self.manager.active[self.ident] = (process, None)
        with self.assertRaisesRegex(ValueError, '先关闭'):
            self.manager.set_app_profile(self.ident, True)
        process.terminate.assert_not_called()
        self.assertNotIn('use_original_data', self.manager.app(self.ident))

    def test_linux_checks_release_manager_lock_and_refuse_conflicting_actions(self):
        acquired = threading.Event()

        def other_thread():
            with self.manager.lock:
                acquired.set()

        def check(_app):
            worker = threading.Thread(target=other_thread)
            worker.start()
            self.assertTrue(acquired.wait(2), 'filesystem checks must not prevent core cleanup')
            worker.join(timeout=2)
            self.assertIn(self.ident, self.manager._profile_preparing)
            with self.assertRaisesRegex(ValueError, '正在检查'):
                self.manager.launch(self.ident)
            with self.assertRaisesRegex(ValueError, '正在准备'):
                self.manager.change_app(self.ident, delete=True)
            return self.root / 'original'

        with patch.object(sys, 'platform', 'linux'), \
                patch('ruleproxy.app_profile_data.original_profile_source', side_effect=check):
            self.manager.set_app_profile(self.ident, True)
        self.assertEqual(self.manager._profile_preparing, set())
        self.assertTrue(self.manager.app(self.ident)['use_original_data'])

    def test_failed_source_check_preserves_previous_choice_and_settings(self):
        before = (self.manager.directory / 'settings.json').read_bytes()
        with patch.object(sys, 'platform', 'linux'), \
                patch('ruleproxy.app_profile_data.original_profile_source', side_effect=ValueError('profile is busy')):
            with self.assertRaisesRegex(ValueError, 'busy'):
                self.manager.set_app_profile(self.ident, True)
        self.assertEqual((self.manager.directory / 'settings.json').read_bytes(), before)
        self.assertNotIn('use_original_data', self.manager.app(self.ident))
        self.assertEqual(self.manager._profile_preparing, set())

    def test_failed_settings_write_restores_choice(self):
        with patch.object(sys, 'platform', 'win32'), \
                patch.object(self.manager, '_save', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(OSError, 'disk full'):
                self.manager.set_app_profile(self.ident, True)
        self.assertNotIn('use_original_data', self.manager.app(self.ident))
        self.assertEqual(self.manager._profile_preparing, set())

    def test_linux_launch_keeps_workspace_separate_and_passes_real_profile(self):
        self.manager.app(self.ident)['use_original_data'] = True
        self.manager.core = Mock(poll=Mock(return_value=None))
        source = self.root / 'original'
        process = Mock(pid=12345, poll=Mock(return_value=None))
        resource = Mock()
        with patch.object(sys, 'platform', 'linux'), \
                patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch('ruleproxy.manager.prepare_app', return_value=(['browser'], {}, '')), \
                patch('ruleproxy.manager.app_profile_directory', return_value=source), \
                patch('ruleproxy.linux_runtime.downloads_folder', return_value=None), \
                patch('ruleproxy.linux_runtime.launch', return_value=(process, resource)) as launch:
            result = self.manager.launch(self.ident)
        self.assertEqual(launch.call_args.args[2], self.manager.directory / 'profiles' / self.ident)
        self.assertEqual(launch.call_args.kwargs, {'original_profile': source, 'profile_adapter': 'chromium'})
        self.assertIn('直接共用', result['detail'])
        self.assertFalse(source.exists())


if __name__ == '__main__':
    unittest.main()
