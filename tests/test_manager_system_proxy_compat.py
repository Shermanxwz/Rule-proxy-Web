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
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'ruleproxy' / 'manager.py'


def fixture(actual_import=False):
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Manager')
    wanted = {'capture_mode', 'uses_system_proxy', 'set_system_proxy_compat',
              '_restore_settings', 'state', 'start', 'stop', '_watch',
              '_sync_windows_policy', 'launch', '_proxy_watchdog_healthy', '_require_proxy_ready',
              '_start_antigravity_recovery', '_antigravity_recovery_check'}
    cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    ns = dict(__name__='ruleproxy.compat_test', __package__='ruleproxy',
              sys=SimpleNamespace(platform='win32'), os=SimpleNamespace(name='nt'),
              socket=Mock(), subprocess=Mock(CREATE_NEW_PROCESS_GROUP=512, CREATE_NO_WINDOW=0x08000000),
              time=SimpleNamespace(monotonic=lambda: 100, sleep=Mock()), json=json,
              MAX_SETTINGS_BYTES=100000, MAX_APPS=128,
              CAPTURE_MODES=('applications', 'global'), __version__='test',
              read_saved_text=Mock(return_value=None), write_private=Mock(),
              stop_process=Mock(), close_resource=Mock(),
              traceback=SimpleNamespace(print_exc=Mock()), prepare_app=Mock())
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
            'ruleproxy.launcher': SimpleNamespace(app_profile_directory=Mock(), discover_apps=Mock(),
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
    m._windows_backend = Mock()
    m._windows_backend.snapshot.return_value = {'state': 'running'}
    m.settings = dict(capture_mode='applications', system_proxy_compat=False,
                      windows_app_guard=True, apps=[], core_path='', runtime_path='')
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
        self.m.settings['system_proxy_compat'] = True
        self.assertTrue(self.m.uses_system_proxy)
        self.ns['sys'].platform = 'linux'
        self.assertFalse(self.m.uses_system_proxy)
        self.m.settings['capture_mode'] = 'global'
        for value in (True, False):
            self.m.settings['system_proxy_compat'] = value
            self.assertTrue(self.m.uses_system_proxy)

    def test_setter_saves_boolean_and_rolls_back_failure(self):
        self.m.set_system_proxy_compat(True)
        self.m._save.assert_called_once()
        self.m._save.side_effect = OSError('save')
        with self.assertRaises(OSError):
            self.m.set_system_proxy_compat(False)
        self.assertTrue(self.m.settings['system_proxy_compat'])
        self.assertTrue(self.m.settings['windows_app_guard'])

    def test_setter_rejects_nonboolean_and_busy_states(self):
        for value in (1, 0, 'true', None):
            with self.assertRaises(ValueError):
                self.m.set_system_proxy_compat(value)
        for attribute, value in [('core', self.process), ('active', {'app': object()}),
                                 ('_profile_preparing', {'app'}), ('_restore_pending', True),
                                 ('_global_fault', True), ('_proxy_watchdog', self.watchdog),
                                 ('quitting', True)]:
            old = getattr(self.m, attribute)
            setattr(self.m, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                self.m.set_system_proxy_compat(True)
            setattr(self.m, attribute, old)
        self.m.closed.set()
        with self.assertRaises(ValueError):
            self.m.set_system_proxy_compat(True)
        self.m._save.assert_not_called()

    def test_setter_rejects_global_and_non_windows(self):
        self.m.settings['capture_mode'] = 'global'
        with self.assertRaises(ValueError):
            self.m.set_system_proxy_compat(True)
        self.m.settings['capture_mode'] = 'applications'
        self.ns['sys'].platform = 'linux'
        with self.assertRaises(ValueError):
            self.m.set_system_proxy_compat(True)

    def test_restore_missing_valid_invalid_setting(self):
        for data, expected, invalid in [({}, False, False),
                                       ({'system_proxy_compat': True}, True, False),
                                       ({'system_proxy_compat': 'true'}, False, True)]:
            self.m.settings['system_proxy_compat'] = False
            self.m._settings_need_backup = False
            self.ns['read_saved_text'].return_value = json.dumps(data)
            self.m._restore_settings()
            self.assertEqual(self.m.settings['system_proxy_compat'], expected)
            self.assertEqual(self.m._settings_need_backup, invalid)

    def test_start_policy_and_guard_precede_watchdog_enable_arm(self):
        self.m.settings['system_proxy_compat'] = True
        order = []
        self.m._windows_backend.apply.side_effect = lambda *a: order.append('capture')
        self.m._windows_backend.app_guard_apply.side_effect = lambda *a: order.append('guard')
        self.watch.side_effect = lambda *a: order.append('watchdog') or self.watchdog
        self.proxy.enable.side_effect = lambda *a, **kw: order.append('enable')
        self.watchdog.arm.side_effect = lambda: order.append('arm')
        self.m.start()
        self.assertEqual(order, ['capture', 'guard', 'watchdog', 'enable', 'arm'])
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
                self.m.settings['system_proxy_compat'] = True
                self.m._windows_backend.stop.reset_mock()
                with self.assertRaises(OSError):
                    self.m.start()
                self.proxy.restore.assert_called()
                self.m._windows_backend.stop.assert_called_once_with(retain_app_guard=True)
                self.assertIsNone(self.m.core)
                self.assertTrue(self.m.settings['windows_app_guard'])

    def test_failed_restore_keeps_live_core_and_watchdog_for_retry(self):
        self.m.settings['system_proxy_compat'] = True
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
        self.m.settings['system_proxy_compat'] = True
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
        self.m.settings['system_proxy_compat'] = True
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
        self.m.settings['system_proxy_compat'] = True
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

    def test_noncompat_live_core_does_not_need_watchdog(self):
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
        self.m.settings['system_proxy_compat'] = True
        self.m.start()
        order = []
        self.proxy.restore.side_effect = lambda *a: order.append('restore')
        self.watchdog.close.side_effect = lambda: order.append('watchdog')
        self.m._windows_backend.stop.side_effect = lambda **kw: order.append(('backend', kw))
        self.ns['stop_process'].side_effect = lambda *a: order.append('core')
        self.m.stop(retain_app_guard=True)
        self.assertEqual(order, ['restore', 'watchdog', ('backend', {'retain_app_guard': True}), 'core'])

    def test_launch_passes_system_proxy_but_keeps_policy(self):
        self.m.settings['system_proxy_compat'] = True
        self.m.start()
        app = dict(id='app', path='fixture.exe', adapter='environment', enabled=True)
        self.m.app = Mock(return_value=app)
        self.ns['prepare_app'].return_value = (['fixture.exe'], {}, '')
        self.launcher.return_value = Mock(pid=456)
        self.m.launch('app')
        self.assertTrue(self.ns['prepare_app'].call_args.kwargs['system_proxy'])
        self.assertEqual(self.m._windows_backend.apply.call_count, 2)
        self.assertEqual(self.m._windows_backend.app_guard_apply.call_count, 2)

    def test_backend_failure_watch_restores_with_guard_retained(self):
        self.m.settings['system_proxy_compat'] = True
        self.m.start()
        self.m._windows_backend.snapshot.return_value = {'state': 'down'}
        self.m.closed = Mock(wait=Mock(side_effect=[False, True]))
        self.m._watch()
        self.proxy.restore.assert_called_once()
        self.m._windows_backend.stop.assert_called_once_with(retain_app_guard=True)

    def test_watch_retries_pending_restore_without_revoking_guard(self):
        self.m.settings['system_proxy_compat'] = True
        self.m.start()
        self.m._restore_pending = True
        self.m._restore_retry_at = 0
        self.m.closed = Mock(wait=Mock(side_effect=[False, True]))
        self.m._watch()
        self.proxy.restore.assert_called_once()
        self.m._windows_backend.stop.assert_called_once_with(retain_app_guard=True)
        self.assertFalse(self.m._restore_pending)

    def test_compat_does_not_enable_disabled_guard(self):
        self.m.settings.update(system_proxy_compat=True, windows_app_guard=False)
        self.m.start()
        self.m._windows_backend.apply.assert_called_once()
        self.m._windows_backend.app_guard_apply.assert_not_called()
        self.assertFalse(self.m.settings['windows_app_guard'])

    def test_constructor_default_is_explicit_false(self):
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        defaults = [node for node in ast.walk(tree) if isinstance(node, ast.Dict)
                    and any(isinstance(key, ast.Constant) and key.value == 'core_path'
                            for key in node.keys)]
        self.assertTrue(any(any(isinstance(key, ast.Constant) and key.value == 'system_proxy_compat'
                                and isinstance(value, ast.Constant) and value.value is False
                                for key, value in zip(node.keys, node.values)) for node in defaults))

    def test_dead_core_watch_restores_with_guard_retained(self):
        self.m.settings['system_proxy_compat'] = True
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
