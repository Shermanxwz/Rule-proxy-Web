"""Automatic, application-scoped local IPC through real Manager methods, offline."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, call, patch

BASE = Path(__file__).with_name('test_manager_system_proxy_compat.py')
spec = importlib.util.spec_from_file_location('_ipc_manager_fixture', BASE)
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)


class ManagerIPCTests(unittest.TestCase):
    def setUp(self):
        self.m, self.ns = fixture_module.fixture(actual_import=True)
        self.m.directory = Path('not-read-or-written')
        self.backend = self.m._windows_backend
        # Exercise real grouping rather than letting a path mock invent intent.
        del self.m._selected_windows_paths
        self.m._bind_store_app = Mock()
        package = ModuleType('ruleproxy')
        package.__path__ = []
        self.recognize = Mock(side_effect=lambda path: path == 'Antigravity.exe')
        self.agy_paths = Mock(return_value=['Antigravity.exe', 'language_server.exe'])
        self.gemini_paths = Mock(return_value=['Gemini.exe', 'gemini_helper.exe'])
        self.family = Mock(return_value=SimpleNamespace(entry_path='Current.exe',
                                                       paths=('Current.exe', 'StoreHelper.exe')))
        context = patch.dict(sys.modules, {
            'ruleproxy': package,
            'ruleproxy.windows_antigravity': SimpleNamespace(is_antigravity=self.recognize,
                                                            routing_paths=self.agy_paths),
            'ruleproxy.windows_gemini': SimpleNamespace(is_gemini=lambda path: path == 'Gemini.exe',
                                                       routing_paths=self.gemini_paths),
            'ruleproxy.windows_app_family': SimpleNamespace(resolve_store_family=self.family),
        })
        context.start()
        self.addCleanup(context.stop)

    def running(self, selected=True, path='Antigravity.exe', related=()):
        self.m.core = Mock(pid=101, poll=Mock(return_value=None))
        self.m.settings['apps'] = [{'id': 'app', 'path': path, 'enabled': selected,
                                    'related_paths': list(related)}]

    def test_guard_precedes_automatic_groups_without_preference(self):
        self.running()
        self.m._sync_windows_policy()
        paths = ['Antigravity.exe', 'language_server.exe']
        self.assertEqual(self.backend.mock_calls, [call.apply(paths, 10809, 101),
                                                   call.app_guard_apply(10809), call.local_ipc([paths])])
        self.assertEqual(self.m._windows_paths, paths)
        self.assertEqual(self.m._windows_ipc_groups, [paths])
        self.assertNotIn('antigravity_ipc_compat', self.m.settings)
        self.m._save.assert_not_called()
        self.assertFalse(self.m.uses_system_proxy)

    def test_failed_capture_never_applies_guard_or_grants_ipc(self):
        self.running()
        self.backend.apply.side_effect = RuntimeError('capture failed')
        with self.assertRaisesRegex(RuntimeError, 'capture failed'):
            self.m._sync_windows_policy()
        self.backend.app_guard_apply.assert_not_called()
        self.backend.local_ipc.assert_not_called()

    def test_failed_guard_never_grants_ipc(self):
        self.running()
        self.backend.app_guard_apply.side_effect = RuntimeError('guard failed')
        with self.assertRaisesRegex(RuntimeError, 'guard failed'):
            self.m._sync_windows_policy()
        self.backend.local_ipc.assert_not_called()
        self.backend.antigravity_ipc.assert_not_called()

    def test_failed_local_ipc_propagates_without_revoking_guard(self):
        self.running()
        self.backend.local_ipc.side_effect = RuntimeError('IPC verification failed')
        with self.assertRaisesRegex(RuntimeError, 'IPC verification failed'):
            self.m._sync_windows_policy()
        self.backend.app_guard_apply.assert_called_once_with(10809)
        self.backend.app_guard_revoke.assert_not_called()
        self.backend.stop.assert_not_called()
        self.backend.antigravity_ipc.assert_not_called()
        self.m._save.assert_not_called()

    def test_other_application_automatically_gets_its_own_group(self):
        self.running(path='Other.exe', related=['OtherHelper.exe'])
        self.m._sync_windows_policy()
        self.backend.apply.assert_called_once_with(['Other.exe', 'OtherHelper.exe'], 10809, 101)
        self.backend.local_ipc.assert_called_once_with([['Other.exe', 'OtherHelper.exe']])
        self.agy_paths.assert_not_called()
        self.backend.antigravity_ipc.assert_not_called()

    def test_group_boundaries_do_not_merge_distinct_applications(self):
        self.running(path='Editor.exe', related=['EditorHelper.exe', 'Shared.exe', 'EditorHelper.exe'])
        self.m.settings['apps'].extend([
            {'id': 'other', 'path': 'Chat.exe', 'enabled': True, 'related_paths': ['Shared.exe']},
            {'id': 'disabled', 'path': 'Disabled.exe', 'enabled': False, 'related_paths': ['Secret.exe']},
        ])
        self.m._sync_windows_policy()
        self.backend.apply.assert_called_once_with(
            ['Editor.exe', 'EditorHelper.exe', 'Shared.exe', 'Chat.exe'], 10809, 101)
        self.backend.local_ipc.assert_called_once_with([
            ['Editor.exe', 'EditorHelper.exe', 'Shared.exe'], ['Chat.exe', 'Shared.exe']])

    def test_special_app_helpers_stay_with_their_selected_application(self):
        self.running(related=['CustomHelper.exe'])
        self.m.settings['apps'].append({'id': 'gemini', 'path': 'Gemini.exe', 'enabled': True})
        self.m._sync_windows_policy()
        self.backend.local_ipc.assert_called_once_with([
            ['Antigravity.exe', 'language_server.exe', 'CustomHelper.exe'],
            ['Gemini.exe', 'gemini_helper.exe'],
        ])

    def test_store_family_paths_form_one_application_group(self):
        self.running(path='Old.exe', related=['Related.exe'])
        binding = {'package_family_name': 'Vendor.Product_publisher', 'application_id': 'Main'}
        self.m.settings['apps'][0]['store_binding'] = binding
        self.m._sync_windows_policy()
        self.family.assert_called_once_with(binding)
        self.assertEqual(self.m.settings['apps'][0]['path'], 'Current.exe')
        self.backend.local_ipc.assert_called_once_with([['Current.exe', 'StoreHelper.exe', 'Related.exe']])

    def test_failed_group_resolution_does_not_publish_partial_policy(self):
        self.running(path='Editor.exe')
        self.m._windows_ipc_groups = [['Previous.exe']]
        self.m.settings['apps'].append({'id': 'store', 'path': 'Store.exe', 'enabled': True,
                                       'store_binding': {'package_family_name': 'Vendor.Product_publisher',
                                                         'application_id': 'Main'}})
        self.family.side_effect = ValueError('ambiguous package')
        with self.assertRaisesRegex(ValueError, 'ambiguous package'):
            self.m._sync_windows_policy()
        self.assertEqual(self.m._windows_ipc_groups, [['Previous.exe']])
        self.assertEqual(self.backend.mock_calls, [])

    def test_no_guard_means_no_ipc_exception(self):
        self.running()
        self.m.settings['windows_app_guard'] = False
        self.m._sync_windows_policy()
        self.backend.apply.assert_called_once()
        self.backend.app_guard_apply.assert_not_called()
        self.backend.local_ipc.assert_not_called()
        self.backend.antigravity_ipc.assert_not_called()

    def test_unselected_last_app_clears_groups_and_stops_broker(self):
        self.running(selected=False)
        self.m._windows_ipc_groups = [['Old.exe']]
        self.m._sync_windows_policy()
        self.backend.stop.assert_called_once_with()
        self.backend.apply.assert_not_called()
        self.backend.local_ipc.assert_not_called()
        self.backend.antigravity_ipc.assert_not_called()
        self.assertEqual(self.m._windows_ipc_groups, [])
        self.assertEqual(self.m._windows_paths, [])

    def test_stopped_dead_core_nonwindows_and_global_do_not_send_ipc(self):
        for platform, mode, core_state in (('win32', 'global', 'live'),
                                           ('linux', 'applications', 'live'),
                                           ('win32', 'applications', 'missing'),
                                           ('win32', 'applications', 'dead')):
            with self.subTest(platform=platform, mode=mode, core_state=core_state):
                self.running()
                self.ns['sys'].platform = platform
                self.m.settings['capture_mode'] = mode
                if core_state == 'missing':
                    self.m.core = None
                elif core_state == 'dead':
                    self.m.core.poll.return_value = 1
                self.m._sync_windows_policy()
                self.assertEqual(self.backend.mock_calls, [])
                self.recognize.assert_not_called()

    def test_repeated_sync_preserves_broker_idempotent_intent(self):
        self.running()
        self.m._sync_windows_policy()
        self.m._sync_windows_policy()
        groups = [['Antigravity.exe', 'language_server.exe']]
        self.assertEqual(self.backend.local_ipc.call_args_list, [call(groups), call(groups)])
        self.backend.stop.assert_not_called()
        self.backend.antigravity_ipc.assert_not_called()

    def test_legacy_switch_is_ignored_and_marked_for_backup(self):
        for value in (True, False, 1, 'true', None, []):
            with self.subTest(value=value):
                self.m._settings_need_backup = False
                self.ns['read_saved_text'].return_value = json.dumps({'antigravity_ipc_compat': value})
                self.m._restore_settings()
                self.assertNotIn('antigravity_ipc_compat', self.m.settings)
                self.assertTrue(self.m._settings_need_backup)
                self.assertEqual(self.m.capture_mode, 'applications')
        self.assertEqual(self.backend.mock_calls, [])
        self.m._save.assert_not_called()

    def test_injected_legacy_switch_never_controls_automatic_ipc(self):
        self.running(path='Other.exe')
        for value in (False, True, None, 'false'):
            with self.subTest(value=value):
                self.m.settings['antigravity_ipc_compat'] = value
                self.backend.reset_mock()
                self.m._sync_windows_policy()
                self.backend.local_ipc.assert_called_once_with([['Other.exe']])
                self.backend.antigravity_ipc.assert_not_called()
                self.assertFalse(self.m.uses_system_proxy)

    def test_removed_setter_is_absent(self):
        self.assertFalse(hasattr(type(self.m), 'set_antigravity_ipc_compat'))

    def test_state_exposes_automatic_scope_not_legacy_preference_or_success(self):
        self.m.settings['antigravity_ipc_compat'] = True
        for platform, mode, automatic in (('win32', 'applications', True),
                                           ('win32', 'global', False),
                                           ('linux', 'applications', False)):
            for guard in (True, False):
                with self.subTest(platform=platform, mode=mode, guard=guard):
                    self.ns['sys'].platform = platform
                    self.m.settings.update(capture_mode=mode, windows_app_guard=guard)
                    self.m._global_fault = True
                    state = self.m.state()
                    self.assertIs(state['local_ipc_automatic'], automatic)
                    self.assertFalse(state['running'])
                    self.assertNotIn('antigravity_ipc_compat', state)
                    self.assertNotIn('antigravity_ipc_compat_locked', state)
                    self.assertNotIn('local_ipc', state['protection'])
        self.assertEqual(self.backend.mock_calls, [])

    def test_enable_guard_for_live_paths_applies_guard_before_groups(self):
        self.running(path='Other.exe')
        self.m.settings['windows_app_guard'] = False
        self.m._sync_windows_policy()
        self.backend.reset_mock()
        self.m.set_app_guard(True)
        self.assertEqual(self.backend.mock_calls, [call.app_guard_apply(10809), call.local_ipc([['Other.exe']])])
        self.m._save.assert_called_once_with()
        self.assertEqual(self.m.capture_mode, 'applications')

    def test_enable_guard_failure_never_sends_groups(self):
        self.running(path='Other.exe')
        self.m._windows_paths = ['Other.exe']
        self.m._windows_ipc_groups = [['Other.exe']]
        self.backend.app_guard_apply.side_effect = RuntimeError('guard failed')
        with self.assertRaisesRegex(RuntimeError, 'guard failed'):
            self.m.set_app_guard(True)
        self.backend.local_ipc.assert_not_called()

    def test_disable_guard_only_revokes_guard_not_scope_or_legacy_switches(self):
        self.running()
        self.m.set_app_guard(False)
        self.assertEqual(self.backend.mock_calls, [call.app_guard_revoke()])
        self.assertEqual(self.m.capture_mode, 'applications')
        self.assertNotIn('antigravity_ipc_compat', self.m.settings)
        self.assertNotIn('system_proxy_compat', self.m.settings)

    def test_guard_preference_outside_live_application_scope_does_not_send_groups(self):
        for platform, mode, live, paths in (('win32', 'global', True, ['Other.exe']),
                                            ('linux', 'applications', True, ['Other.exe']),
                                            ('win32', 'applications', False, ['Other.exe']),
                                            ('win32', 'applications', True, [])):
            with self.subTest(platform=platform, mode=mode, live=live, paths=paths):
                self.running(path='Other.exe')
                self.ns['sys'].platform = platform
                self.m.settings['capture_mode'] = mode
                self.m._windows_paths = paths
                self.m._windows_ipc_groups = [['Other.exe']] if paths else []
                if not live:
                    self.m.core = None
                self.m.set_app_guard(True)
                self.assertEqual(self.backend.mock_calls, [])
                self.assertEqual(self.m.capture_mode, mode)


if __name__ == '__main__':
    unittest.main()
