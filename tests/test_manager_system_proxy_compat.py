"""Offline AST and full-import Manager contracts; all external boundaries mocked.
No native imports, processes, registry, WFP, constructor or watcher threads run.
"""
import ast
import importlib.util
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace, ModuleType
import unittest
import uuid
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'ruleproxy' / 'manager.py'


def fixture(actual_import=False):
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Manager')
    wanted = {'capture_mode', 'uses_system_proxy', '_bind_store_app',
              '_restore_settings', '_save', 'state', 'start', 'stop', '_watch',
              '_sync_windows_policy', 'launch', '_proxy_watchdog_healthy', '_require_proxy_ready',
              '_start_antigravity_recovery', '_antigravity_recovery_check'}
    cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    ns = dict(__name__='ruleproxy.compat_test', __package__='ruleproxy',
              sys=SimpleNamespace(platform='win32'), os=SimpleNamespace(name='nt'),
              socket=Mock(), subprocess=Mock(CREATE_NEW_PROCESS_GROUP=512, CREATE_NO_WINDOW=0x08000000),
              time=SimpleNamespace(monotonic=lambda: 100, sleep=Mock()), json=json, uuid=uuid,
              MAX_SETTINGS_BYTES=100000, MAX_APPS=128,
              CAPTURE_MODES=('applications', 'global'), __version__='test',
              read_saved_text=Mock(return_value=None), write_private=Mock(),
              stop_process=Mock(), close_resource=Mock(),
              traceback=SimpleNamespace(print_exc=Mock()), prepare_app=Mock(), Path=Path)
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(SOURCE), 'exec'), ns)
    if actual_import:
        package = ModuleType('ruleproxy')
        package.__path__ = [str(SOURCE.parent)]
        package.__version__ = 'test'
        package.autostart = Mock()
        dependencies = {
            'ruleproxy': package,
            'ruleproxy.config': SimpleNamespace(CAPTURE_MODES=('applications', 'global'),
                                               MAX_SOURCE_BYTES=100000, compile_config=Mock()),
            'ruleproxy.launcher': SimpleNamespace(app_identity=Mock(), app_profile_directory=Mock(), discover_apps=Mock(),
                                                 validate_app=Mock(), prepare_app=Mock()),
            'ruleproxy.shortcuts': SimpleNamespace(create_shortcut_files=Mock(), remove_shortcut_files=Mock()),
        }
        spec = importlib.util.spec_from_file_location('ruleproxy.manager', SOURCE)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, dependencies):
            spec.loader.exec_module(module)
        # Import the COMPLETE production class, then replace external boundaries.
        # No constructor, worker threads or native calls are run.
        overrides = {key: value for key, value in ns.items()
                     if key not in {'Manager', '__name__', '__package__', '__builtins__'}}
        module.__dict__.update(overrides)
        ns = module.__dict__
    m = ns['Manager'].__new__(ns['Manager'])
    m.lock = threading.RLock()
    m.closed = threading.Event()
    m.quitting = False
    m.core = m.core_log = m._core_job = m._proxy_watchdog = None
    m._proxy_watchdog_armed = False
    m.active = {}
    m._antigravity_recovery = {}
    m._profile_preparing = set()
    m._global_fault = m._restore_pending = False
    m._restore_retry_at = 0
    m._windows_paths = []
    m._windows_ipc_groups = []
    m._windows_family_paths = {}
    m._windows_backend = Mock()
    m._windows_backend.snapshot.return_value = {'state': 'running'}
    m.settings = dict(capture_mode='applications', windows_app_guard=True,
                      apps=[], core_path='', runtime_path='')
    m.error = ''
    m._save = Mock()
    m._recover_global = Mock()
    m._release_legacy_tun = Mock()
    m.protection = Mock(return_value={'supported': True})
    m._selected_windows_paths = Mock(return_value=['fixture.exe'])
    m.windows_backend = Mock(return_value=m._windows_backend)
    m._compile = Mock(return_value=SimpleNamespace(text='mock', selected_node='', nodes=[], primary_group='', warnings=[]))
    m.compiled = m._compile.return_value
    m.source = 'mock'
    m.core_path = Mock(return_value=Path('never-executed.exe'))
    m._controller = Mock()
    m.mixed_port, m.controller_port, m.panel_port = 10809, 19097, 18879
    m.storage_warnings = []
    m._settings_need_backup = False
    m.token = 'mock'
    m.available_apps = Mock(return_value=([], False))
    m.files_dir = Mock(return_value='mock')
    m.autostart_status = Mock(return_value={})
    return m, ns


class CompatTests(unittest.TestCase):
    def setUp(self):
        self.m, self.ns = fixture(getattr(self, 'actual_import', False))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.m.directory = Path(directory)
        self.proxy = SimpleNamespace(enable=Mock(), restore=Mock())
        self.watchdog = Mock(nonce='0123456789abcdef0123456789abcdef', process=Mock(poll=Mock(return_value=None)))
        self.watch = Mock(return_value=self.watchdog)
        # Replace package and imported leaf modules entirely: native code is never loaded.
        package = ModuleType('ruleproxy')
        package.system_proxy = self.proxy
        self.launcher = Mock()
        self.stack.enter_context(patch.dict(sys.modules, {
            'ruleproxy': package, 'ruleproxy.system_proxy': self.proxy,
            'ruleproxy.system_proxy_watchdog': SimpleNamespace(start=self.watch),
            'ruleproxy.windows_core_process': SimpleNamespace(CoreJob=Mock()),
            'ruleproxy.windows_app_process': SimpleNamespace(launch=self.launcher),
            'ruleproxy.windows_gemini_native_proxy': SimpleNamespace(prepare=Mock(return_value=None),
                                                                   recover_pending=Mock()),
            'ruleproxy.windows_antigravity': SimpleNamespace(is_antigravity=Mock(return_value=False)),
        }))
        self.process = Mock(pid=123, poll=Mock(return_value=None))
        self.ns['subprocess'].run.return_value.returncode = 0
        self.ns['subprocess'].Popen.return_value = self.process
        self.addCleanup(self.cleanup_log)

    def cleanup_log(self):
        if self.m.core_log is not None:
            self.m.core_log.close()

    def test_default_and_platform_mode_matrix(self):
        self.assertFalse(self.m.uses_system_proxy)
        for platform in ('win32', 'linux', 'darwin'):
            for mode in ('applications', 'global'):
                for legacy in (True, False, 'true', None):
                    with self.subTest(platform=platform, mode=mode, legacy=legacy):
                        self.ns['sys'].platform = platform
                        self.m.settings.update(capture_mode=mode, system_proxy_compat=legacy)
                        self.assertIs(self.m.uses_system_proxy, mode == 'global')
                        state = self.m.state()
                        self.assertIs(state['uses_system_proxy'], mode == 'global')
                        self.assertEqual(state['system_proxy_scope'], 'current_user' if mode == 'global' else None)
                        self.assertNotIn('system_proxy_compat', state)
                        self.assertNotIn('system_proxy_compat_locked', state)

    def test_removed_setter_is_not_part_of_manager(self):
        self.assertFalse(hasattr(type(self.m), 'set_system_proxy_compat'))

    def test_restore_ignores_legacy_options_without_widening_scope(self):
        cases = [({}, False)]
        for key in ('system_proxy_compat', 'antigravity_ipc_compat'):
            cases.extend(({key: value}, True) for value in (True, False, 0, 1, 'true', None, [], {}))
        cases.append(({'system_proxy_compat': True, 'antigravity_ipc_compat': True}, True))
        for data, backup in cases:
            for mode in (None, 'applications', 'global'):
                with self.subTest(data=data, mode=mode):
                    saved = {**data, **({'capture_mode': mode} if mode else {})}
                    self.m.settings['capture_mode'] = 'applications'
                    self.m._settings_need_backup = False
                    self.m.storage_warnings.clear()
                    self.ns['read_saved_text'].return_value = json.dumps(saved)
                    self.m._restore_settings()
                    self.assertEqual(self.m.capture_mode, mode or 'applications')
                    self.assertIs(self.m.uses_system_proxy, mode == 'global')
                    self.assertEqual(self.m._settings_need_backup, backup)
                    for key in ('system_proxy_compat', 'antigravity_ipc_compat'):
                        self.assertNotIn(key, self.m.settings)
                    if data.get('system_proxy_compat') is True:
                        self.assertTrue(any('全局（系统代理）' in message for message in self.m.storage_warnings))
        self.m._save.assert_not_called()
        self.proxy.enable.assert_not_called()
        self.m._windows_backend.assert_not_called()

    def test_legacy_settings_are_backed_up_before_first_clean_save(self):
        original = json.dumps({'system_proxy_compat': True, 'antigravity_ipc_compat': False,
                               'capture_mode': 'applications', 'windows_app_guard': False})
        path = self.m.directory / 'settings.json'
        path.write_text(original, encoding='utf-8')
        self.ns['read_saved_text'].return_value = original
        self.m._restore_settings()
        self.assertEqual(path.read_text(encoding='utf-8'), original)
        self.assertFalse(self.m.settings['windows_app_guard'])
        self.ns['write_private'].side_effect = lambda destination, text: destination.write_text(text, encoding='utf-8')
        type(self.m)._save(self.m)
        backups = list(self.m.directory.glob('settings.recovery-*.json'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(encoding='utf-8'), original)
        saved = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(saved['capture_mode'], 'applications')
        self.assertFalse(saved['windows_app_guard'])
        self.assertNotIn('system_proxy_compat', saved)
        self.assertNotIn('antigravity_ipc_compat', saved)
        self.assertFalse(self.m._settings_need_backup)
        type(self.m)._save(self.m)
        self.assertEqual(list(self.m.directory.glob('settings.recovery-*.json')), backups)

    def test_failed_clean_save_restores_original_legacy_settings_for_retry(self):
        path = self.m.directory / 'settings.json'
        original = '{"system_proxy_compat": true}'
        path.write_text(original, encoding='utf-8')
        self.ns['read_saved_text'].return_value = original
        self.m._restore_settings()
        self.ns['write_private'].side_effect = OSError('save failed')
        with self.assertRaisesRegex(OSError, 'save failed'):
            type(self.m)._save(self.m)
        self.assertEqual(path.read_text(encoding='utf-8'), original)
        self.assertEqual(list(self.m.directory.glob('settings.recovery-*.json')), [])
        self.assertTrue(self.m._settings_need_backup)
        self.assertEqual(self.m.capture_mode, 'applications')

    def test_global_watchdog_enable_arm_order_has_no_application_policy(self):
        self.m.settings['capture_mode'] = 'global'
        order = []
        self.m._windows_backend.apply.side_effect = lambda *a: order.append('capture')
        self.m._windows_backend.app_guard_apply.side_effect = lambda *a: order.append('guard')
        self.watch.side_effect = lambda *a: order.append('watchdog') or self.watchdog
        self.proxy.enable.side_effect = lambda *a, **kw: order.append('enable')
        self.watchdog.arm.side_effect = lambda: order.append('arm')
        self.m.start()
        self.assertEqual(order, ['watchdog', 'enable', 'arm'])
        self.m._selected_windows_paths.assert_not_called()
        self.m._windows_backend.apply.assert_not_called()
        self.m._windows_backend.app_guard_apply.assert_not_called()
        self.m._windows_backend.local_ipc.assert_not_called()
        self.assertEqual(self.m._windows_paths, [])
        self.proxy.enable.assert_called_once_with(self.m.directory, 10809, watchdog_session='0123456789abcdef0123456789abcdef')
        self.assertTrue(self.m.state()['system_proxy_managed'])
        self.assertEqual(self.m.state()['system_proxy_scope'], 'current_user')

    def test_default_start_no_system_proxy_and_global_unchanged(self):
        self.m.start()
        self.watch.assert_not_called()
        self.proxy.enable.assert_not_called()
        self.cleanup_log()
        self.m.core_log = self.m.core = None
        self.m.settings['capture_mode'] = 'global'
        self.m._windows_backend.reset_mock()
        self.m.start()
        self.watch.assert_called_once()
        self.m._windows_backend.apply.assert_not_called()
        self.m._windows_backend.app_guard_apply.assert_not_called()

    def test_start_failures_restore_and_retain_guard(self):
        for failing in ('guard', 'watchdog', 'enable', 'arm'):
            with self.subTest(failing=failing):
                targets = {'guard': self.m._windows_backend.app_guard_apply,
                           'watchdog': self.watch, 'enable': self.proxy.enable,
                           'arm': self.watchdog.arm}
                for target in targets.values():
                    target.reset_mock(side_effect=True)
                targets[failing].side_effect = OSError(failing)
                self.m.settings['capture_mode'] = 'applications' if failing == 'guard' else 'global'
                self.m._windows_backend.stop.reset_mock()
                with self.assertRaises(OSError):
                    self.m.start()
                self.proxy.restore.assert_called()
                self.m._windows_backend.stop.assert_called_once_with(retain_app_guard=True)
                self.assertIsNone(self.m.core)
                self.assertTrue(self.m.settings['windows_app_guard'])

    def test_failed_restore_keeps_live_core_and_watchdog_for_retry(self):
        self.m.settings['capture_mode'] = 'global'
        self.watchdog.arm.side_effect = OSError('arm')
        self.proxy.restore.side_effect = OSError('restore')
        with self.assertRaises(ValueError):
            self.m.start()
        self.assertIs(self.m.core, self.process)
        self.assertIs(self.m._proxy_watchdog, self.watchdog)
        self.assertTrue(self.m._restore_pending)
        self.assertFalse(self.m.state()['system_proxy_managed'])
        self.ns['stop_process'].assert_not_called()
        self.proxy.restore.side_effect = None
        self.m.stop(retain_app_guard=True)
        self.assertFalse(self.m._restore_pending)
        self.assertIsNone(self.m.core)
        self.assertIsNone(self.m._proxy_watchdog)

    def test_faulted_start_and_launch_preserve_original_error(self):
        self.m.settings['capture_mode'] = 'global'
        self.watchdog.arm.side_effect = OSError('arm failed')
        self.proxy.restore.side_effect = OSError('restore denied')
        with self.assertRaises(ValueError):
            self.m.start()
        original = self.m.error
        for action in (self.m.start, lambda: self.m.launch('app')):
            with self.assertRaises(ValueError) as raised:
                action()
            self.assertEqual(str(raised.exception), original)
            self.assertEqual(self.m.error, original)
        self.assertFalse(self.m._proxy_watchdog_armed)
        self.launcher.assert_not_called()
        self.assertEqual(self.ns['subprocess'].Popen.call_count, 1)

    def test_watchdog_dead_unarmed_missing_and_poll_error(self):
        self.m.settings['capture_mode'] = 'global'
        for failure in ('dead', 'unarmed', 'missing', 'poll-error'):
            with self.subTest(failure=failure):
                self.watchdog.process.poll.side_effect = None
                self.watchdog.process.poll.return_value = None
                self.m.start()
                if failure == 'dead':
                    self.watchdog.process.poll.return_value = 1
                elif failure == 'unarmed':
                    self.m._proxy_watchdog_armed = False
                elif failure == 'missing':
                    self.m._proxy_watchdog = None
                else:
                    self.watchdog.process.poll.side_effect = OSError('poll')
                self.assertFalse(self.m.state()['system_proxy_managed'])
                for action in (self.m.start, lambda: self.m.launch('app')):
                    with self.assertRaises(ValueError):
                        action()
                self.m.closed = Mock(wait=Mock(side_effect=[False, True]))
                self.m._watch()
                self.assertIsNone(self.m.core)
                self.assertFalse(self.m._proxy_watchdog_armed)
                self.m._windows_backend.stop.assert_called_with(retain_app_guard=True)
                self.m.closed = threading.Event()
        self.assertEqual(self.proxy.restore.call_count, 4)

    def test_dead_watchdog_restore_failure_retains_core_and_error(self):
        self.m.settings['capture_mode'] = 'global'
        self.m.start()
        self.watchdog.process.poll.side_effect = OSError('poll failed')
        self.proxy.restore.side_effect = OSError('specific restore failure')
        self.m.closed = Mock(wait=Mock(side_effect=[False, True]), is_set=Mock(return_value=False))
        self.m._watch()
        self.assertTrue(self.m._restore_pending)
        self.assertTrue(self.m._global_fault)
        self.assertIs(self.m.core, self.process)
        self.assertFalse(self.m._proxy_watchdog_armed)
        self.assertFalse(self.m.state()['system_proxy_managed'])
        self.assertIn('specific restore failure', self.m.error)
        original = self.m.error
        for action in (self.m.start, lambda: self.m.launch('app')):
            with self.assertRaises(ValueError) as raised:
                action()
            self.assertEqual(str(raised.exception), original)
        self.m._windows_backend.stop.assert_called_with(retain_app_guard=True)
        self.watchdog.close.assert_not_called()
        self.ns['stop_process'].assert_not_called()
        self.proxy.restore.side_effect = None
        self.m.stop(retain_app_guard=True)
        self.assertFalse(self.m._restore_pending)
        self.assertFalse(self.m._global_fault)
        self.assertIsNone(self.m._proxy_watchdog)
        self.assertFalse(self.m._proxy_watchdog_armed)

    def test_application_scoped_live_core_does_not_need_watchdog(self):
        self.m.start()
        self.m.start()
        self.assertFalse(self.m.state()['system_proxy_managed'])
        self.assertEqual(self.ns['subprocess'].Popen.call_count, 1)
        self.m.app = Mock(return_value=dict(id='app', path='fixture.exe', adapter='environment', enabled=True))
        self.ns['prepare_app'].return_value = (['fixture.exe'], {}, '')
        self.launcher.return_value = Mock(pid=456)
        self.m.launch('app')
        self.assertFalse(self.ns['prepare_app'].call_args.kwargs['system_proxy'])

    def test_stop_restores_before_watchdog_backend_and_core(self):
        self.m.settings['capture_mode'] = 'global'
        self.m.start()
        order = []
        self.proxy.restore.side_effect = lambda *a: order.append('restore')
        self.watchdog.close.side_effect = lambda: order.append('watchdog')
        self.m._windows_backend.stop.side_effect = lambda **kw: order.append(('backend', kw))
        self.ns['stop_process'].side_effect = lambda *a: order.append('core')
        self.m.stop(retain_app_guard=True)
        self.assertEqual(order, ['restore', 'watchdog', ('backend', {'retain_app_guard': True}), 'core'])

    def test_global_launch_passes_system_proxy_without_application_rules(self):
        self.m.settings['capture_mode'] = 'global'
        self.m.start()
        app = dict(id='app', path='fixture.exe', adapter='environment', enabled=True)
        self.m.app = Mock(return_value=app)
        self.ns['prepare_app'].return_value = (['fixture.exe'], {}, '')
        self.launcher.return_value = Mock(pid=456)
        self.m.launch('app')
        self.assertTrue(self.ns['prepare_app'].call_args.kwargs['system_proxy'])
        self.m._windows_backend.apply.assert_not_called()
        self.m._windows_backend.app_guard_apply.assert_not_called()
        self.m._windows_backend.local_ipc.assert_not_called()
        self.m._selected_windows_paths.assert_not_called()
        self.assertEqual(self.m._windows_paths, [])

    def test_application_backend_failure_watch_restores_with_guard_retained(self):
        self.m.start()
        self.m._windows_backend.snapshot.return_value = {'state': 'down'}
        self.m.closed = Mock(wait=Mock(side_effect=[False, True]))
        self.m._watch()
        self.proxy.restore.assert_called_once()
        self.m._windows_backend.stop.assert_called_once_with(retain_app_guard=True)

    def test_global_watch_does_not_probe_an_unused_application_backend(self):
        self.m.settings['capture_mode'] = 'global'
        self.m.start()
        self.m._windows_backend.snapshot.return_value = {'state': 'down'}
        self.m.closed = Mock(wait=Mock(side_effect=[False, True]))
        self.m._watch()
        self.m._windows_backend.snapshot.assert_not_called()
        self.m._windows_backend.stop.assert_not_called()
        self.proxy.restore.assert_not_called()
        self.assertIs(self.m.core, self.process)
        self.assertTrue(self.m.state()['system_proxy_managed'])

    def test_watch_retries_pending_restore_without_revoking_guard(self):
        self.m.settings['capture_mode'] = 'global'
        self.m.start()
        self.m._restore_pending = True
        self.m._restore_retry_at = 0
        self.m.closed = Mock(wait=Mock(side_effect=[False, True]))
        self.m._watch()
        self.proxy.restore.assert_called_once()
        self.m._windows_backend.stop.assert_called_once_with(retain_app_guard=True)
        self.assertFalse(self.m._restore_pending)

    def test_global_mode_does_not_enable_disabled_guard(self):
        self.m.settings.update(capture_mode='global', windows_app_guard=False)
        self.m.start()
        self.m._windows_backend.apply.assert_not_called()
        self.m._windows_backend.app_guard_apply.assert_not_called()
        self.m._windows_backend.local_ipc.assert_not_called()
        self.assertFalse(self.m.settings['windows_app_guard'])

    def test_constructor_defaults_have_no_deprecated_preferences(self):
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Manager')
        constructor = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
        assignments = [node for node in ast.walk(constructor) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Attribute) and target.attr == 'settings'
                               for target in node.targets)]
        self.assertEqual(len(assignments), 1)
        defaults = ast.literal_eval(assignments[0].value)
        self.assertEqual(defaults['capture_mode'], 'applications')
        self.assertFalse(defaults['windows_app_guard'])
        self.assertNotIn('system_proxy_compat', defaults)
        self.assertNotIn('antigravity_ipc_compat', defaults)

    def test_dead_core_watch_restores_with_guard_retained(self):
        self.m.settings['capture_mode'] = 'global'
        self.m.start()
        self.process.poll.return_value = 1
        self.m.closed = Mock(wait=Mock(side_effect=[False, True]))
        self.m._watch()
        self.proxy.restore.assert_called_once()
        self.m._windows_backend.stop.assert_called_once_with(retain_app_guard=True)


class ImportedManagerCompatTests(CompatTests):
    """Run every contract against the imported production class, not AST slices."""
    actual_import = True


if __name__ == '__main__':
    unittest.main()
