"""Real Manager methods with fake OS, broker and task scheduling boundaries."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('_recovery_fixture', Path(__file__).with_name('test_manager_system_proxy_compat.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class ManagerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.m, self.ns = fixture.fixture(actual_import=True)
        self.process, self.core = Mock(poll=Mock(return_value=None)), Mock(poll=Mock(return_value=None))
        self.process.pid = 22
        self.m.core = self.core
        self.app = {'id': 'a', 'path': 'Antigravity.exe', 'enabled': True, 'adapter': 'chromium'}
        self.m.settings['apps'] = [self.app]
        self.m.settings['antigravity_ipc_compat'] = True
        self.m.active['a'] = (self.process, None)
        self.report = {'supported': True, 'status': {'state': 'running', 'app_guard': {'active': True},
                      'antigravity_ipc': {'supported': True, 'enabled': True, 'active': True, 'state': 'active'}}}
        self.m._windows_backend.probe.return_value = self.report
        self.task_factory = Mock()
        context = patch.dict(sys.modules, {
            'ruleproxy.windows_antigravity': SimpleNamespace(is_antigravity=lambda path: path == 'Antigravity.exe'),
            'ruleproxy.windows_antigravity_task': SimpleNamespace(RecoveryTask=self.task_factory),
            'ruleproxy.windows_app_process': SimpleNamespace(launch=Mock(return_value=self.process))})
        context.start()
        self.addCleanup(context.stop)

    def check(self):
        return self.m._antigravity_recovery_check('a', self.process, self.core)

    def test_ready_requires_live_owned_generation_and_broker(self):
        self.assertIs(self.check(), True)
        self.m._windows_backend.probe.assert_called_once()

    def test_waiting_ipc_returns_tristate_none(self):
        self.report['status']['antigravity_ipc'].update(active=False, state='watching')
        self.assertIsNone(self.check())

    def test_core_replaced_before_probe_cancels(self):
        self.m.core = Mock()
        self.assertIs(self.check(), False)
        self.m._windows_backend.probe.assert_not_called()

    def test_app_replaced_during_probe_cancels(self):
        def probe():
            self.m.active['a'] = (Mock(), None)
            return self.report
        self.m._windows_backend.probe.side_effect = probe
        self.assertIs(self.check(), False)

    def test_guard_or_broker_fault_cancels(self):
        for target, key, value in ((self.report, 'supported', False),
                                   (self.report['status'], 'state', 'idle'),
                                   (self.report['status']['app_guard'], 'active', False),
                                   (self.report['status']['antigravity_ipc'], 'enabled', False),
                                   (self.report['status']['antigravity_ipc'], 'state', 'failed')):
            old = target[key]
            target[key] = value
            self.assertIs(self.check(), False)
            target[key] = old

    def test_stopped_or_disabled_lifecycle_cancels(self):
        for key in ('windows_app_guard', 'antigravity_ipc_compat'):
            self.m.settings[key] = False
            self.assertIs(self.check(), False)
            self.m.settings[key] = True
        self.app['enabled'] = False
        self.assertIs(self.check(), False)
        self.app['enabled'] = True
        self.process.poll.return_value = 0
        self.assertIs(self.check(), False)

    def test_new_task_bound_to_current_objects(self):
        self.m._start_antigravity_recovery('a', self.app, self.process)
        self.task_factory.return_value.start.assert_called_once()
        callback = self.task_factory.call_args.args[2]
        self.assertIs(callback(), True)
        self.m.core = Mock()
        self.assertIs(callback(), False)

    def test_noneligible_launch_does_not_schedule(self):
        for setting in ('windows_app_guard', 'antigravity_ipc_compat'):
            self.m.settings[setting] = False
            self.m._start_antigravity_recovery('a', self.app, self.process)
            self.m.settings[setting] = True
        self.m._start_antigravity_recovery('a', {**self.app, 'path': 'Other.exe'}, self.process)
        self.m.settings['capture_mode'] = 'global'
        self.m._start_antigravity_recovery('a', self.app, self.process)
        self.task_factory.assert_not_called()

    def test_stop_cancels_before_terminating_owned_app(self):
        events = []
        task = Mock(cancel=Mock(side_effect=lambda: events.append('cancel')))
        self.m._antigravity_recovery['a'] = task
        self.process.terminate.side_effect = lambda: events.append('terminate')
        self.m.stop_app('a')
        self.assertEqual(events, ['cancel', 'terminate'])
        self.assertNotIn('a', self.m.active)

    def test_repeat_launch_does_not_schedule(self):
        self.m._require_proxy_ready = Mock()
        self.m.launch('a')
        self.task_factory.assert_not_called()

    def test_new_launch_schedules_once_after_registering(self):
        self.m.active.clear()
        self.m._require_proxy_ready = Mock()
        self.m._sync_windows_policy = Mock()
        self.m.directory = Path('unused')
        self.ns['prepare_app'].return_value = (['Antigravity.exe'], {}, '')
        def start():
            self.assertIs(self.m.active['a'][0], self.process)
        self.task_factory.return_value.start.side_effect = start
        self.m.launch('a')
        self.m.launch('a')
        self.task_factory.assert_called_once()

    def test_state_exposes_only_fixed_current_generation_result(self):
        self.m._antigravity_recovery['a'] = SimpleNamespace(process=self.process,
            result={'state': 'recovered', 'reload_attempted': True, 'private': 'not exported'})
        result = self.m.state()['apps'][0]['startup_recovery']
        self.assertEqual(result, {'state': 'recovered', 'reload_attempted': True})
        self.m._antigravity_recovery['a'].process = Mock()
        self.assertNotIn('startup_recovery', self.m.state()['apps'][0])

    def test_thread_start_failure_does_not_fail_owned_launch(self):
        self.task_factory.return_value.start.side_effect = RuntimeError('fixture')
        self.m._start_antigravity_recovery('a', self.app, self.process)
        self.assertNotIn('a', self.m._antigravity_recovery)
        self.assertIs(self.m.active['a'][0], self.process)
        self.task_factory.return_value.cancel.assert_called_once()


if __name__ == '__main__':
    unittest.main()
