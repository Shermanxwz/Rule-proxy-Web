"""Offline Manager -> Runtime -> wire decoder -> Broker fault-retention contracts.
No Manager constructor, real processes, pipes, SCM, settings or WFP objects.
"""
import ast
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load_manager_methods():
    """Compile unchanged real method ASTs without importing UI/YAML dependencies."""
    source = Path(__file__).resolve().parents[1] / 'ruleproxy' / 'manager.py'
    tree = ast.parse(source.read_text(encoding='utf-8'), filename=str(source))
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Manager')
    wanted = {'stop', '_watch', 'windows_backend', 'capture_mode', 'close', 'begin_quit',
              'stop_app', 'start', '_save_app_changes', 'uses_system_proxy',
              '_require_proxy_ready', '_proxy_watchdog_healthy'}
    owner.body = [node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    module = ast.Module(body=[owner], type_ignores=[])
    namespace = {'__name__': 'ruleproxy.manager_retention_test', '__package__': 'ruleproxy',
                 'sys': SimpleNamespace(platform='win32'), 'time': time,
                 'traceback': SimpleNamespace(print_exc=Mock()),
                 'stop_process': Mock(), 'close_resource': Mock()}
    exec(compile(module, str(source), 'exec'), namespace)
    return namespace['Manager']


Manager = load_manager_methods()
from ruleproxy.windows_proxy_policy import ProxyError, decode_request
from ruleproxy.windows_proxy_runtime import Runtime
from test_guard_failure_retention import broker_fixture


SID = 'S-1-5-21-1-2-3-1001'


class OneTick:
    def __init__(self):
        self.calls = 0

    def wait(self, _timeout):
        self.calls += 1
        return self.calls > 1


class Core:
    pid = 102

    def __init__(self, dead=False):
        self.dead = dead

    def poll(self):
        return 1 if self.dead else None


class WireClient:
    """Only transport/authentication is fake; decode and broker dispatch are real."""
    def __init__(self, broker):
        self.broker = broker
        self.ops = []
        self.reject_retained = False
        self.status_error = None

    def request(self, operation, **fields):
        self.ops.append(operation)
        request = decode_request(json.dumps({
            'schema_version': 1, 'request_id': 'a' * 32,
            'op': operation, 'client_pid': 101, **fields,
        }).encode())
        if operation == 'status' and self.status_error:
            raise self.status_error
        if operation == 'stop_retain_guard' and self.reject_retained:
            raise ProxyError('invalid_request', 'old broker rejects operation')
        return self.broker.handle(request, 101, SID)


class ManagerFailureRetentionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Fail immediately if the harness accidentally reaches a native boundary.
        for name in ('ServiceControl', 'ProcessLease', 'PipeAPI', '_dll'):
            self.stack.enter_context(patch('ruleproxy.windows_proxy_service.' + name,
                                          side_effect=AssertionError('native boundary: ' + name)))
        self.stack.enter_context(patch('ruleproxy.windows_global_guard._Engine',
                                      side_effect=AssertionError('native WFP boundary')))
        self.stack.enter_context(patch('ruleproxy.windows_proxy_client.Client',
                                      side_effect=AssertionError('real pipe client')))
        self.restore = Mock()
        fake_proxy = SimpleNamespace(restore=self.restore)
        self.stack.enter_context(patch.dict(sys.modules, {'ruleproxy.system_proxy': fake_proxy}))
        self.stack.enter_context(patch('ruleproxy.system_proxy', fake_proxy, create=True))
        self.stack.enter_context(patch.object(Manager, '_release_legacy_tun', create=True))
        self.stack.enter_context(patch('ruleproxy.windows_proxy_service._log_service_error'))
        self.broker, self.gate, self.control = broker_fixture()
        self.broker.metadata['owner_sid'] = SID
        self.wire = WireClient(self.broker)
        self.runtime = Runtime(Path('isolated-not-read'))
        self.runtime._client = self.wire
        self.runtime._connect = lambda: self.wire
        self.manager = Manager.__new__(Manager)
        self.manager.lock = threading.RLock()
        self.manager.closed = OneTick()
        self.manager.directory = Path('isolated-not-read')
        self.manager.settings = {'capture_mode': 'applications'}
        self.manager.active = {}
        self.manager.core = Core()
        self.manager.core_log = self.manager._core_job = None
        self.manager._proxy_watchdog = None
        self.manager._proxy_watchdog_armed = False
        self.manager._restore_pending = False
        self.manager._restore_retry_at = 0
        self.manager._windows_backend = self.runtime
        self.manager._windows_paths = ['fixture.exe']
        self.manager._global_fault = False
        self.manager.error = ''

    def assert_retained(self):
        self.assertTrue(self.gate.active)
        self.assertEqual(self.gate.purges, 0)
        self.assertIn('stop_retain_guard', self.wire.ops)
        self.assertNotIn('stop', self.wire.ops)

    def test_dead_core_watcher_retains(self):
        self.manager.core.dead = True
        self.broker.core.live = False
        self.manager._watch()
        self.assert_retained()
        self.assertIsNone(self.manager.core)
        self.assertIsNone(self.broker.core)

    def test_backend_down_watcher_retains(self):
        self.control.state = 1
        self.manager._watch()
        self.assert_retained()
        self.assertNotIn('其他同路径实例可能恢复直连', self.manager.error)

    def test_backend_status_error_value_retains(self):
        self.wire.status_error = ProxyError('backend_unavailable', 'injected unavailable')
        self.manager._watch()
        self.assert_retained()

    def test_backend_status_unexpected_exception_retains(self):
        self.wire.status_error = RuntimeError('injected unexpected status error')
        self.manager._watch()
        self.assert_retained()

    def test_restoration_retry_retains(self):
        self.manager._restore_pending = True
        self.manager._watch()
        self.assert_retained()

    def test_broker_first_cleanup_then_manager_retains(self):
        self.manager.core.dead = True
        self.broker.core.live = False
        self.broker.check_lease()
        self.assertEqual(self.gate.purges, 0)
        self.manager._watch()
        self.assert_retained()

    def test_explicit_stop_still_revokes(self):
        self.manager.stop()
        self.assertFalse(self.gate.active)
        self.assertEqual(self.gate.purges, 1)
        self.assertEqual(self.wire.ops, ['stop'])

    def test_old_broker_failure_never_falls_back(self):
        self.manager.core.dead = True
        self.broker.core.live = False
        self.wire.reject_retained = True
        self.manager._watch()
        self.assert_retained()
        self.assertIn('尚未完成', self.manager.error)
        self.assertNotIn('已确认', self.manager.error)

    def test_fault_close_retains(self):
        self.manager.closed = Mock()
        self.manager.launch_owner = Mock()
        self.manager.close(restore_global=False)
        self.assert_retained()
        self.restore.assert_called_once()
        self.manager.closed.set.assert_called_once()
        self.manager.launch_owner.shutdown.assert_called_once_with(wait=True)

    def test_explicit_close_revokes(self):
        self.manager.closed = Mock()
        self.manager.launch_owner = Mock()
        self.manager.close(restore_global=True)
        self.assertEqual(self.gate.purges, 1)
        self.assertEqual(self.wire.ops, ['stop'])

    def test_default_close_revokes(self):
        self.manager.closed = Mock()
        self.manager.launch_owner = Mock()
        self.manager.close()
        self.assertEqual(self.gate.purges, 1)
        self.assertEqual(self.wire.ops, ['stop'])

    def test_begin_quit_is_explicit(self):
        self.manager.quitting = False
        self.manager.begin_quit()
        self.assertTrue(self.manager.quitting)
        self.assertEqual(self.gate.purges, 1)
        self.assertEqual(self.wire.ops, ['stop'])

    def test_stale_core_before_restart_retains(self):
        self.manager.quitting = False
        self.manager.closed = Mock()
        self.manager.closed.is_set.return_value = False
        self.manager.compiled = None
        self.manager.core.dead = True
        self.broker.core.live = False
        with self.assertRaises(ValueError):
            self.manager.start()
        self.assert_retained()

    def test_policy_rollback_failure_retains(self):
        previous = [{'id': 'previous-fixture'}]
        self.manager._selected_windows_paths = Mock(return_value=[])
        self.manager._sync_windows_policy = Mock(side_effect=ValueError('injected policy failure'))
        with self.assertRaises(ValueError):
            self.manager._save_app_changes(previous)
        self.assert_retained()
        self.assertEqual(self.manager.settings['apps'], previous)

    def test_startup_exception_retention_call_structural_only(self):
        # Static coverage only: startup execution requires many unrelated mocks.
        source = Path(__file__).resolve().parents[1] / 'ruleproxy' / 'manager.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Manager')
        start = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == 'start')
        calls = [node for node in ast.walk(start) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'stop'
                 and isinstance(node.func.value, ast.Attribute)
                 and node.func.value.attr == '_windows_backend']
        self.assertEqual(len(calls), 1)
        self.assertTrue(any(keyword.arg == 'retain_app_guard'
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is True for keyword in calls[0].keywords))

    def test_retain_operation_rejects_unknown_fields(self):
        base = {'schema_version': 1, 'request_id': 'b' * 32,
                'op': 'stop_retain_guard', 'client_pid': 101}
        self.assertEqual(decode_request(json.dumps(base).encode()), base)
        with self.assertRaises(ProxyError):
            decode_request(json.dumps({**base, 'retain_app_guard': True}).encode())

    def test_retain_operation_keeps_current_panel_authentication(self):
        request = {'schema_version': 1, 'request_id': 'c' * 32,
                   'op': 'stop_retain_guard', 'client_pid': 103}
        parsed = decode_request(json.dumps(request).encode())
        with self.assertRaises(ProxyError) as error:
            self.broker.handle(parsed, 103, SID)
        self.assertEqual(error.exception.code, 'instance_conflict')
        self.assertEqual(self.gate.purges, 0)
        with self.assertRaises(ProxyError) as error:
            self.broker.handle(parsed, 103, 'S-1-5-21-1-2-3-1002')
        self.assertEqual(error.exception.code, 'access_denied')


if __name__ == '__main__':
    unittest.main()
