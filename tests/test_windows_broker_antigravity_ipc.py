"""Pure mocks: no Windows calls, service launches or application execution."""
import ctypes
import json
import ntpath
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

from ruleproxy import windows_proxy_service as service
from ruleproxy import windows_proxy_policy as policy
from ruleproxy.windows_proxy_runtime import Runtime
import test_windows_proxy_service as fixtures

PAIR = (r'c:\apps\main.exe', r'c:\apps\helper.exe')


class BrokerIPC(unittest.TestCase):
    setUp = fixtures.BrokerTests.setUp
    request = fixtures.BrokerTests.request
    handle = fixtures.BrokerTests.handle

    def ready(self):
        self.handle(paths=list(PAIR))
        self.guard = mock.Mock()
        self.guard.status.return_value = {'supported': True, 'active': True, 'detail': 'proxy only'}
        self.guard.apply.return_value = {'active': True}
        self.guard.purge.return_value = {'active': False}
        self.broker.app_guard_gate = self.guard
        self.broker.app_guard_intent = True
        self.tracker = mock.Mock(records=())
        self.broker.ipc_factory = mock.Mock(return_value=self.tracker)
        self.broker._ipc_pair_from_paths = mock.Mock(return_value=PAIR)
        self.broker._verify_ipc_base = mock.Mock()

    def enable(self):
        return self.handle('antigravity_ipc', enabled=True)

    def test_default_and_old_components(self):
        self.assertFalse(self.broker.snapshot()['antigravity_ipc']['enabled'])
        self.assertFalse(self.handle('antigravity_ipc', enabled=False)['supported'])
        with self.assertRaisesRegex(policy.ProxyError, 'unavailable'):
            self.enable()

    def test_enable_requires_live_guarded_pair(self):
        self.ready()
        for attr, value in [('app_guard_intent', False), ('paths', []), ('port', None), ('engine_owned', False)]:
            before = getattr(self.broker, attr)
            setattr(self.broker, attr, value)
            with self.assertRaises(policy.ProxyError):
                self.enable()
            setattr(self.broker, attr, before)
        self.guard.status.return_value['active'] = False
        with self.assertRaises(policy.ProxyError):
            self.enable()
        self.broker.ipc_factory.assert_not_called()

    def test_wrong_owner_and_panel(self):
        self.ready()
        for pid, sid in [(222, self.sid), (101, self.sid + '1')]:
            with self.assertRaises(policy.ProxyError):
                self.broker.handle(self.request('antigravity_ipc', enabled=True, client_pid=pid), pid, sid)
        self.broker.ipc_factory.assert_not_called()

    def test_repeat_enable_backend_and_guard_keep_epoch(self):
        self.ready()
        first = self.enable()['enabled_after']
        self.enable()
        self.handle(paths=list(PAIR))
        self.handle('app_guard_apply', proxy_port=10809)
        self.assertEqual(self.broker.ipc_enabled_after, first)
        self.broker.ipc_factory.assert_called_once()
        self.tracker.close.assert_not_called()
        self.assertIn('antigravity', self.broker.snapshot()['app_guard']['detail'])
        self.assertFalse(self.broker.snapshot()['strict_isolation'])

    def test_adding_other_paths_keeps_pair_epoch(self):
        self.ready(); self.enable()
        before = self.broker.ipc_enabled_after
        self.handle(paths=list(PAIR) + [r'C:\Apps\extra.exe'])
        self.handle('app_guard_apply', proxy_port=10809)
        self.assertEqual(self.broker.ipc_enabled_after, before)
        self.tracker.close.assert_not_called()
        self.broker.ipc_factory.assert_called_once()

    def test_path_removal_closes_before_new_config(self):
        self.ready(); self.enable()
        self.tracker.close.side_effect = lambda: self.assertEqual(tuple(self.broker.paths), PAIR)
        self.handle(paths=[PAIR[0]])
        self.tracker.close.assert_called_once()
        self.assertIsNone(self.broker.ipc_tracker)

    def test_core_replacement_closes_first(self):
        self.ready(); self.enable()
        self.tracker.close.side_effect = lambda: self.assertEqual(self.broker.core.pid, 102)
        self.handle(paths=list(PAIR), mihomo_pid=103)
        self.tracker.close.assert_called_once()

    def test_proxy_port_replacement_closes_first(self):
        self.ready(); self.enable()
        self.handle(paths=list(PAIR), proxy_port=10810)
        self.tracker.close.assert_called_once()

    def test_guard_revoke_close_before_purge(self):
        self.ready(); self.enable()
        events = []
        self.tracker.close.side_effect = lambda: events.append('ipc')
        self.guard.purge.side_effect = lambda: events.append('base') or {'active': False}
        self.handle('app_guard_revoke')
        self.assertEqual(events, ['ipc', 'base'])

    def test_stop_retain_guard_closes_ipc(self):
        self.ready(); self.enable()
        self.handle('stop_retain_guard')
        self.tracker.close.assert_called_once()
        self.guard.purge.assert_not_called()

    def test_failed_close_blocks_purge_and_can_retry(self):
        self.ready(); self.enable()
        self.tracker.close.side_effect = OSError('close unconfirmed')
        with self.assertRaises(policy.ProxyError):
            self.handle('app_guard_revoke')
        self.guard.purge.assert_not_called()
        self.assertIs(self.broker.ipc_tracker, self.tracker)
        self.assertEqual(self.broker.snapshot()['antigravity_ipc']['error']['code'], 'ipc_cleanup_incomplete')
        with self.assertRaises(policy.ProxyError):
            self.handle('app_guard_apply', proxy_port=10809)
        self.guard.apply.assert_not_called()
        self.tracker.close.side_effect = None
        self.handle('antigravity_ipc', enabled=False)
        self.assertIsNone(self.broker.ipc_tracker)

    def test_failed_close_blocks_stop_and_shutdown_base(self):
        self.ready(); self.enable()
        self.tracker.close.side_effect = OSError('close unconfirmed')
        with self.assertRaises(policy.ProxyError):
            self.broker.stop()
        with self.assertRaises(policy.ProxyError):
            self.broker.shutdown()
        self.guard.purge.assert_not_called()
        self.assertIsNotNone(self.broker.panel)

    def test_peer_refresh_failure_keeps_base_and_specific_error(self):
        self.ready(); self.enable()
        self.tracker.refresh.side_effect = policy.ProxyError('requires_restart', 'existing peer')
        self.broker.check_lease()
        self.guard.purge.assert_not_called()
        self.assertTrue(self.broker.app_guard_intent)
        self.assertEqual(self.broker.snapshot()['antigravity_ipc']['error']['code'], 'requires_restart')
        self.broker.check_lease()
        self.assertEqual(self.broker.snapshot()['antigravity_ipc']['error']['code'], 'requires_restart')

    def test_base_apply_failure_revokes_ipc_only(self):
        self.ready(); self.enable()
        self.guard.apply.side_effect = OSError('base apply failed')
        with self.assertRaises(OSError):
            self.handle('app_guard_apply', proxy_port=10809)
        self.tracker.close.assert_called_once()
        self.guard.purge.assert_not_called()
        self.assertIsNotNone(self.broker.ipc_error)

    def test_pair_validation_failure_never_constructs(self):
        self.ready()
        self.broker._ipc_pair_from_paths.side_effect = policy.ProxyError('ipc_invalid_pair', 'missing helper')
        with self.assertRaises(policy.ProxyError):
            self.enable()
        self.broker.ipc_factory.assert_not_called()


class Protocol(unittest.TestCase):
    def request(self, enabled=True, **extra):
        return json.dumps(dict(schema_version=1, request_id='a'*32, op='antigravity_ipc',
                               client_pid=123, enabled=enabled, **extra)).encode()

    def test_only_strict_bool_and_no_identity_fields(self):
        for value in (True, False):
            self.assertEqual(policy.decode_request(self.request(value))['enabled'], value)
        for value in (0, 1, None, 'true', [], {}):
            with self.assertRaises(policy.ProxyError):
                policy.decode_request(self.request(value))
        for name in ('ports', 'PIDs', 'paths', 'AppIDs'):
            with self.assertRaises(policy.ProxyError):
                policy.decode_request(self.request(**{name: []}))

    def test_runtime_old_and_new_brokers(self):
        runtime = Runtime(Path('.'))
        client = mock.Mock()
        runtime._connect = mock.Mock(return_value=client)
        client.request.return_value = {}
        self.assertFalse(runtime.antigravity_ipc(False)['supported'])
        with self.assertRaises(policy.ProxyError):
            runtime.antigravity_ipc(True)
        client.reset_mock()
        client.request.side_effect = [{'antigravity_ipc': {'supported': True}}, {'enabled': True}]
        self.assertTrue(runtime.antigravity_ipc(True)['enabled'])
        self.assertEqual(client.request.call_args, mock.call('antigravity_ipc', enabled=True))


class NativeBoundaryMocks(unittest.TestCase):
    def test_peer_checks_image_before_owner_and_skips_nonpair(self):
        kernel, advapi = mock.Mock(), mock.Mock()
        kernel.OpenProcess.return_value = 55
        kernel.WaitForSingleObject.return_value = 258
        with mock.patch.object(service, '_dll', side_effect=lambda name: kernel if name == 'kernel32' else advapi), \
             mock.patch.object(service.ProcessLease, 'image_path', return_value=r'C:\Other\other.exe'):
            self.assertIsNone(service._peer_lease(1, 'owner', PAIR))
        advapi.OpenProcessToken.assert_not_called()
        kernel.CloseHandle.assert_called_once_with(55)

    def test_peer_foreign_sid_and_unknown_error(self):
        kernel, advapi = mock.Mock(), mock.Mock()
        kernel.OpenProcess.return_value = 55
        kernel.WaitForSingleObject.return_value = 258
        with mock.patch.object(service, '_dll', side_effect=lambda name: kernel if name == 'kernel32' else advapi), \
             mock.patch.object(service.ProcessLease, 'image_path', return_value=PAIR[0]), \
             mock.patch.object(service, '_token_sid', return_value='foreign'):
            self.assertIsNone(service._peer_lease(1, 'owner', PAIR))
        with mock.patch.object(service, '_dll', side_effect=lambda name: kernel if name == 'kernel32' else advapi), \
             mock.patch.object(service.ProcessLease, 'image_path', side_effect=OSError('query failed')):
            with self.assertRaises(OSError):
                service._peer_lease(1, 'owner', PAIR)

    def test_pending_handle_survives_factory_cleanup_failure(self):
        kernel, advapi = mock.Mock(), mock.Mock()
        kernel.OpenProcess.return_value = 55
        kernel.WaitForSingleObject.return_value = 258
        pending = []
        with mock.patch.object(service, '_dll', side_effect=lambda name: kernel if name == 'kernel32' else advapi), \
             mock.patch.object(service.ProcessLease, 'image_path', return_value=r'C:\Other\other.exe'), \
             mock.patch.object(service._PeerLease, 'close', side_effect=OSError('close failed')):
            with self.assertRaises(OSError):
                service._peer_lease(1, 'owner', PAIR, pending=pending)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].handle, 55)
        pending[0].close()
        self.assertIsNone(pending[0].handle)

    def test_native_assembly_uses_engine_ids_and_fixed_owner_sd(self):
        from ruleproxy import windows_global_guard as wfp
        from ruleproxy import windows_ipc_lease as leases
        broker = service.Broker({'owner_sid': 'S-1-5-21-1-2-3-1000'}, control=mock.Mock())
        broker.app_guard_gate = mock.Mock()
        broker._verify_ipc_base = mock.Mock()
        engine = mock.MagicMock()
        engine.__enter__.return_value = engine
        engine.app_id.side_effect = [b'engine-main', b'engine-helper']
        native = mock.Mock()
        peer = mock.Mock()
        peer.image_path.return_value = PAIR[0]
        peer.creation_time.return_value = 101
        peer.alive.return_value = True
        def rows(family):
            return [{'state': 2, 'local': '127.0.0.1', 'local_port': 5000, 'pid': 17}] if family == service.socket.AF_INET else []
        with mock.patch.object(wfp, '_Engine', return_value=engine), \
             mock.patch.object(wfp, '_descriptor', return_value=b'owner-sd') as descriptor, \
             mock.patch.object(leases, 'LeaseSet', return_value=native), \
             mock.patch.object(leases, 'Endpoint', side_effect=lambda *args: args), \
             mock.patch.object(service, '_peer_lease', return_value=peer), \
             mock.patch.object(service, '_tcp_connections', side_effect=rows):
            tracker = service._new_ipc_tracker(broker, PAIR, 100)
            tracker.refresh()
            descriptor.assert_called_once_with('D:(A;;CC;;;S-1-5-21-1-2-3-1000)')
            native.replace.assert_called_once_with(((b'engine-main', b'engine-helper', b'owner-sd', 5000),))
            broker._verify_ipc_base.assert_called_once_with(PAIR)
            events = []
            native.close.side_effect = lambda: events.append('revoke')
            peer.close.side_effect = lambda: events.append('handle')
            tracker.close()
            self.assertEqual(events, ['revoke', 'handle'])

    def test_exact_base_readback_rejects_wrong_paths_not_just_count(self):
        from ruleproxy import windows_app_guard as app
        from ruleproxy import windows_global_guard as wfp
        guard = app.AppGuard({'root': r'C:\broker', 'owner_sid': 'S-1-5-21-1-2-3-1000'})
        guard._owned_provider = mock.Mock(return_value=True)
        guard._owned_sublayer = mock.Mock(return_value=True)
        guard._scan = mock.Mock(return_value=guard._expected(app._plan([b'other1', b'other2'], 10809)))
        broker = service.Broker({'owner_sid': 'owner'}, control=mock.Mock())
        broker.app_guard_gate, broker.app_guard_intent = guard, True
        broker.paths, broker.port = list(PAIR), 10809
        engine = mock.MagicMock()
        engine.__enter__.return_value = engine
        engine.app_id.side_effect = lambda path: b'main' if str(path) == PAIR[0] else b'helper'
        with mock.patch.object(wfp, '_Engine', return_value=engine):
            with self.assertRaisesRegex(policy.ProxyError, 'coverage'):
                broker._verify_ipc_base(PAIR)
            guard._scan.return_value = guard._expected(app._plan([b'extra', b'main', b'helper'], 10809))
            broker._verify_ipc_base(PAIR)
            guard._scan.return_value = guard._expected(app._plan([b'main', b'helper'], 10810))
            with self.assertRaises(policy.ProxyError):
                broker._verify_ipc_base(PAIR)

    def test_owner_profile_registry_only(self):
        registry = mock.Mock(REG_SZ=1, HKEY_USERS=2, KEY_READ=3)
        registry.OpenKey.return_value = mock.MagicMock()
        registry.QueryValueEx.return_value = (r'C:\Users\owner\AppData\Local', 1)
        sid = 'S-1-5-21-1-2-3-1000'
        with mock.patch.dict(sys.modules, winreg=registry):
            self.assertEqual(service._owner_local_app_data(sid), r'C:\Users\owner\AppData\Local')
            self.assertEqual(registry.OpenKey.call_args.args[0], 2)
            self.assertTrue(registry.OpenKey.call_args.args[1].startswith(sid + '\\'))
            for value, kind in [(r'\\server\share', 1), ('relative', 1), (r'C:\Users\owner', 2)]:
                registry.QueryValueEx.return_value = value, kind
                with self.assertRaises(policy.ProxyError):
                    service._owner_local_app_data(sid)

    def test_trusted_profile_keyword_ignores_system_environment(self):
        from ruleproxy import windows_antigravity as paths
        local = Path.cwd() / 'owner-fixture'
        main = local / 'Programs' / 'antigravity' / 'Antigravity.exe'
        with mock.patch.dict(paths.os.environ, LOCALAPPDATA=str(Path.cwd() / 'system-fixture')), \
             mock.patch.object(paths, '_plain'), \
             mock.patch.object(Path, 'resolve', lambda value, **kw: value):
            self.assertEqual(paths.routing_paths(main), [])
            result = paths.routing_paths(main, local_app_data=str(local))
            self.assertEqual(result[0], str(main))
            self.assertEqual(len(result), 2)

    def test_creation_time_uses_held_handle(self):
        process = service.ProcessLease.__new__(service.ProcessLease)
        process.kernel = mock.Mock()
        process.handle = 9
        def times(handle, created, *_rest):
            self.assertEqual(handle, 9)
            created._obj.dwHighDateTime, created._obj.dwLowDateTime = 2, 3
            return True
        process.kernel.GetProcessTimes.side_effect = times
        self.assertEqual(process.creation_time(), (2 << 32) | 3)


if __name__ == '__main__':
    unittest.main()
