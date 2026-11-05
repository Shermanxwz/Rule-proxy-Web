"""Full production Manager import with mocked OS/backend boundaries; no native calls."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

BASE = Path(__file__).with_name('test_manager_system_proxy_compat.py')
spec = importlib.util.spec_from_file_location('_ipc_manager_fixture', BASE)
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)


class ManagerIPCTests(unittest.TestCase):
    def setUp(self):
        self.m, self.ns = fixture_module.fixture(actual_import=True)
        self.m.directory = Path('not-read-or-written')
        self.m.settings['antigravity_ipc_compat'] = False
        self.backend = self.m._windows_backend
        package = ModuleType('ruleproxy')
        package.__path__ = []
        self.recognize = Mock(side_effect=lambda path: path == 'Antigravity.exe')
        context = patch.dict(sys.modules, {
            'ruleproxy': package,
            'ruleproxy.windows_antigravity': SimpleNamespace(is_antigravity=self.recognize),
        })
        context.start()
        self.addCleanup(context.stop)

    def running(self, selected=True):
        self.m.core = Mock(pid=101, poll=Mock(return_value=None))
        self.m.settings['apps'] = [{'path': 'Antigravity.exe', 'enabled': selected}]
        self.m.settings['antigravity_ipc_compat'] = True

    def test_default_does_not_touch_new_broker_operation(self):
        self.running()
        self.m.settings['antigravity_ipc_compat'] = False
        self.m._sync_windows_policy()
        self.backend.antigravity_ipc.assert_not_called()
        self.backend.app_guard_apply.assert_called_once_with(10809)

    def test_enable_is_saved_without_native_actions(self):
        self.m.set_antigravity_ipc_compat(True)
        self.assertIs(self.m.settings['antigravity_ipc_compat'], True)
        self.m._save.assert_called_once_with()
        self.backend.assert_not_called()
        self.assertFalse(self.m.uses_system_proxy)

    def test_explicit_disable_clears_broker_fault_before_saving(self):
        self.m.settings['antigravity_ipc_compat'] = True
        self.m.set_antigravity_ipc_compat(False)
        self.backend.antigravity_ipc.assert_called_once_with(False)
        self.assertIs(self.m.settings['antigravity_ipc_compat'], False)
        self.m._save.assert_called_once_with()

    def test_failed_revoke_keeps_setting_retryable(self):
        self.m.settings['antigravity_ipc_compat'] = True
        self.backend.antigravity_ipc.side_effect = RuntimeError('close failed')
        with self.assertRaises(RuntimeError):
            self.m.set_antigravity_ipc_compat(False)
        self.assertIs(self.m.settings['antigravity_ipc_compat'], True)
        self.m._save.assert_not_called()

    def test_disable_save_failure_restores_setting_not_old_lease(self):
        self.m.settings['antigravity_ipc_compat'] = True
        self.m._save.side_effect = OSError('save failed')
        with self.assertRaises(OSError):
            self.m.set_antigravity_ipc_compat(False)
        self.backend.antigravity_ipc.assert_called_once_with(False)
        self.assertIs(self.m.settings['antigravity_ipc_compat'], True)

    def test_strict_boolean(self):
        for value in (1, 0, None, 'true', [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.m.set_antigravity_ipc_compat(value)
        self.m._save.assert_not_called()

    def test_identical_setting_is_noop(self):
        self.m.set_antigravity_ipc_compat(False)
        self.m._save.assert_not_called()

    def test_save_failure_rolls_back(self):
        self.m._save.side_effect = OSError('fixture')
        with self.assertRaises(OSError):
            self.m.set_antigravity_ipc_compat(True)
        self.assertIs(self.m.settings['antigravity_ipc_compat'], False)

    def test_stopped_and_recovery_gates(self):
        for attribute, value in (('core', Mock()), ('active', {'app': Mock()}),
                                 ('_profile_preparing', {'app'}), ('quitting', True),
                                 ('_global_fault', True), ('_restore_pending', True),
                                 ('_proxy_watchdog', Mock())):
            with self.subTest(attribute=attribute):
                previous = getattr(self.m, attribute)
                setattr(self.m, attribute, value)
                try:
                    with self.assertRaises(ValueError):
                        self.m.set_antigravity_ipc_compat(True)
                finally:
                    setattr(self.m, attribute, previous)
        self.m.closed.set()
        with self.assertRaises(ValueError):
            self.m.set_antigravity_ipc_compat(True)
        self.m._save.assert_not_called()

    def test_platform_and_mode_gates(self):
        for platform, mode in (('linux', 'applications'), ('win32', 'global')):
            self.ns['sys'].platform = platform
            self.m.settings['capture_mode'] = mode
            with self.assertRaises(ValueError):
                self.m.set_antigravity_ipc_compat(True)
        self.m._save.assert_not_called()

    def test_guard_precedes_intent_and_only_bool_crosses_boundary(self):
        self.running()
        self.m._sync_windows_policy()
        self.assertEqual([call[0] for call in self.backend.mock_calls],
                         ['apply', 'app_guard_apply', 'antigravity_ipc'])
        self.backend.antigravity_ipc.assert_called_once_with(True)

    def test_failed_guard_never_grants_ipc(self):
        self.running()
        self.backend.app_guard_apply.side_effect = RuntimeError('guard failed')
        with self.assertRaises(RuntimeError):
            self.m._sync_windows_policy()
        self.backend.antigravity_ipc.assert_not_called()

    def test_disabled_or_unselected_app_revokes_intent(self):
        self.running(selected=False)
        self.m._sync_windows_policy()
        self.backend.antigravity_ipc.assert_called_once_with(False)

    def test_other_application_does_not_gain_ipc_intent(self):
        self.running()
        self.m.settings['apps'][0]['path'] = 'other.exe'
        self.m._sync_windows_policy()
        self.backend.antigravity_ipc.assert_called_once_with(False)

    def test_no_guard_means_no_ipc_exception(self):
        self.running()
        self.m.settings['windows_app_guard'] = False
        self.m._sync_windows_policy()
        self.backend.app_guard_apply.assert_not_called()
        self.backend.antigravity_ipc.assert_called_once_with(False)

    def test_empty_paths_stop_broker(self):
        self.running()
        self.m._selected_windows_paths.return_value = []
        self.m._sync_windows_policy()
        self.backend.stop.assert_called_once_with()
        self.backend.antigravity_ipc.assert_not_called()

    def test_global_mode_does_not_send_ipc(self):
        self.running()
        self.m.settings['capture_mode'] = 'global'
        self.m._sync_windows_policy()
        self.backend.antigravity_ipc.assert_not_called()
        self.backend.apply.assert_not_called()

    def test_repeated_sync_preserves_broker_idempotent_intent(self):
        self.running()
        self.m._sync_windows_policy()
        self.m._sync_windows_policy()
        self.assertEqual(self.backend.antigravity_ipc.call_count, 2)
        self.backend.stop.assert_not_called()

    def test_saved_type_validation(self):
        for value in (True, False, 1, 'true', None, []):
            with self.subTest(value=value):
                self.m.settings['antigravity_ipc_compat'] = False
                self.ns['read_saved_text'].return_value = json.dumps({'antigravity_ipc_compat': value})
                self.m._restore_settings()
                self.assertIs(self.m.settings['antigravity_ipc_compat'], value if type(value) is bool else False)

    def test_state_lock_covers_nonrunning_core_and_recovery(self):
        self.assertIs(self.m.state()['antigravity_ipc_compat_locked'], False)
        self.m.core = Mock(poll=Mock(return_value=1))
        self.assertIs(self.m.state()['running'], False)
        self.assertIs(self.m.state()['antigravity_ipc_compat_locked'], True)
        self.m.core = None
        for attribute in ('_restore_pending', '_global_fault', '_proxy_watchdog'):
            with self.subTest(attribute=attribute):
                old = getattr(self.m, attribute)
                setattr(self.m, attribute, True)
                try:
                    self.assertIs(self.m.state()['antigravity_ipc_compat_locked'], True)
                finally:
                    setattr(self.m, attribute, old)

    def test_state_exposes_intent_not_connectivity(self):
        self.assertIs(self.m.state()['antigravity_ipc_compat'], False)
        self.m.settings['antigravity_ipc_compat'] = True
        self.assertIs(self.m.state()['antigravity_ipc_compat'], True)
        self.assertIs(self.m.state()['running'], False)


if __name__ == '__main__':
    unittest.main()
