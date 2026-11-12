"""Group broker/runtime/protocol tests with injected identities and WFP."""
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch, MagicMock

from ruleproxy import windows_proxy_policy as policy, windows_proxy_service as service
from ruleproxy.windows_proxy_runtime import Runtime
from ruleproxy.windows_local_ipc import PeerRetired
import test_windows_proxy_service as fixtures

MAIN, HELPER, OTHER = (r'c:\apps\main.exe', r'c:\apps\helper.exe', r'c:\apps\other.exe')


class LocalBrokerTests(unittest.TestCase):
    setUp = fixtures.BrokerTests.setUp
    request = fixtures.BrokerTests.request
    handle = fixtures.BrokerTests.handle

    def ready(self):
        self.handle(paths=[MAIN, HELPER, OTHER])
        self.guard = Mock()
        self.guard.status.return_value = {'supported': True, 'active': True}
        self.guard.apply.return_value = {'active': True}
        self.guard.purge.return_value = {'active': False}
        self.broker.app_guard_gate, self.broker.app_guard_intent = self.guard, True
        self.tracker = Mock(records=(), waiting_restart_count=0)
        self.broker.local_ipc_factory = Mock(return_value=self.tracker)
        self.broker._verify_ipc_base = Mock()

    def enable(self, groups=None):
        return self.handle('local_ipc', groups=[[MAIN, HELPER], [OTHER]] if groups is None else groups)

    def test_single_image_groups_and_idempotence(self):
        self.ready()
        status = self.enable([[MAIN]])
        self.assertEqual(status['state'], 'watching')
        self.assertTrue(status['enabled'])
        self.assertFalse(status['strict_isolation'])
        self.enable([[MAIN]])
        self.broker.local_ipc_factory.assert_called_once()
        self.assertEqual(self.broker.ipc_groups, ((MAIN,),))
        self.tracker.close.assert_not_called()

    def test_groups_must_be_guarded_and_owner_current(self):
        self.ready()
        for groups in ([[r'c:\other\outsider.exe']], [[MAIN, r'c:\other\outsider.exe']]):
            with self.assertRaises(policy.ProxyError):
                self.enable(groups)
        self.broker.local_ipc_factory.assert_not_called()
        for pid, sid in ((222, self.sid), (101, self.sid + '1')):
            with self.assertRaises(policy.ProxyError):
                self.broker.handle(self.request('local_ipc', groups=[[MAIN]], client_pid=pid), pid, sid)
        self.broker.app_guard_intent = False
        with self.assertRaises(policy.ProxyError):
            self.enable()

    def test_missing_component_is_explicit_without_grant(self):
        result = self.enable([[MAIN]])
        self.assertFalse(result['supported'])
        self.assertEqual(result['state'], 'unsupported')
        self.assertIsNone(self.broker.ipc_tracker)

    def test_waiting_old_instance_state_can_coexist_with_active_other_group(self):
        self.ready()
        self.tracker.waiting_restart_count = 2
        self.assertEqual(self.enable()['state'], 'waiting_restart')
        self.tracker.records = (object(),)
        status = self.broker.snapshot()['local_ipc']
        self.assertTrue(status['active'])
        self.assertEqual(status['waiting_restart_count'], 2)
        self.assertEqual(status['endpoint_count'], 1)
        self.assertFalse(self.broker.snapshot()['antigravity_ipc']['active'])

    def test_group_change_revokes_first_and_preserves_existing_path_epochs(self):
        self.ready()
        self.enable([[MAIN]])
        before = self.broker.ipc_path_epochs[MAIN]
        next_tracker = Mock(records=(), waiting_restart_count=0)
        self.broker.local_ipc_factory.return_value = next_tracker
        events = []
        self.tracker.close.side_effect = lambda: events.append('revoke')
        self.broker.local_ipc_factory.side_effect = lambda *args: events.append('create') or next_tracker
        self.enable([[MAIN, HELPER]])
        self.assertEqual(events, ['revoke', 'create'])
        self.assertEqual(self.broker.ipc_path_epochs[MAIN], before)
        self.assertGreaterEqual(self.broker.ipc_path_epochs[HELPER], before)

    def test_failed_revoke_blocks_expansion_and_guard_purge(self):
        self.ready(); self.enable([[MAIN]])
        self.tracker.close.side_effect = OSError('close unconfirmed')
        with self.assertRaises(policy.ProxyError):
            self.enable([[MAIN, HELPER]])
        self.broker.local_ipc_factory.assert_called_once()
        self.assertIs(self.broker.ipc_tracker, self.tracker)
        self.assertEqual(self.broker.snapshot()['local_ipc']['state'], 'failed')
        for op, fields in [('app_guard_revoke', {}), ('app_guard_apply', {'proxy_port': 10809}),
                           ('apply', {})]:
            with self.assertRaises(policy.ProxyError):
                self.handle(op, **fields)
        self.guard.purge.assert_not_called()

    def test_explicit_successful_stop_clears_fault_but_retained_stop_does_not(self):
        self.ready(); self.enable()
        self.tracker.refresh.side_effect = policy.ProxyError('process_changed', 'identity')
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'process_changed')
        self.broker.stop(retain_app_guard=True)
        self.assertIsNotNone(self.broker.ipc_error)
        self.broker.stop()
        self.assertIsNone(self.broker.ipc_error)

    def test_failed_stop_never_clears_fault(self):
        self.ready(); self.enable()
        self.tracker.close.side_effect = OSError('close unconfirmed')
        with self.assertRaises(policy.ProxyError):
            self.broker.stop()
        self.assertEqual(self.broker.ipc_error['code'], 'ipc_cleanup_incomplete')
        self.guard.purge.assert_not_called()

    def test_legacy_sticky_fault_is_visible_to_the_new_status_consumer(self):
        self.ready()
        self.broker.ipc_error = {'code': 'listener_changed', 'message': 'legacy fault'}
        status = self.broker.snapshot()['local_ipc']
        self.assertEqual(status['state'], 'failed')
        self.assertEqual(status['error']['code'], 'listener_changed')
        with self.assertRaises(policy.ProxyError):
            self.enable()
        self.broker.stop()
        self.assertIsNone(self.broker.snapshot()['local_ipc']['error'])

    def test_reconciliation_empty_does_not_acknowledge_fault(self):
        self.ready(); self.enable()
        self.tracker.refresh.side_effect = policy.ProxyError('process_changed', 'identity')
        self.broker.check_lease()
        result = self.enable([])
        self.assertEqual(result['state'], 'failed')
        self.assertIsNotNone(self.broker.ipc_error)

    def test_guard_revoke_closes_dynamic_rules_before_persistent_rules(self):
        self.ready(); self.enable()
        events = []
        self.tracker.close.side_effect = lambda: events.append('dynamic')
        self.guard.purge.side_effect = lambda: events.append('persistent') or {'active': False}
        self.handle('app_guard_revoke')
        self.assertEqual(events, ['dynamic', 'persistent'])

    def test_normal_retirement_rebuilds_only_once_with_original_groups_and_epochs(self):
        self.ready(); self.enable()
        epochs, groups = dict(self.broker.ipc_path_epochs), self.broker.ipc_groups
        replacement = Mock(records=(), waiting_restart_count=0)
        self.broker.local_ipc_factory.return_value = replacement
        self.tracker.refresh.side_effect = PeerRetired('listener_disappeared', 'retired')
        self.broker.check_lease()
        self.broker.local_ipc_factory.assert_called_with(self.broker, groups, epochs)
        replacement.refresh.assert_not_called()
        self.assertEqual(self.broker.ipc_path_epochs, epochs)
        self.assertIsNone(self.broker.ipc_error)

    def test_removing_member_from_path_policy_closes_group_first(self):
        self.ready(); self.enable()
        self.tracker.close.side_effect = lambda: self.assertIn(HELPER, self.broker.paths)
        self.handle(paths=[MAIN, OTHER])
        self.tracker.close.assert_called_once()
        self.assertIsNone(self.broker.ipc_tracker)

    def test_core_or_port_replacement_revokes_before_new_ownership(self):
        for fields in ({'mihomo_pid': 103}, {'proxy_port': 10810}):
            with self.subTest(fields=fields):
                self.ready(); self.enable()
                self.tracker.close.side_effect = lambda: self.assertEqual(self.broker.port, 10809)
                self.handle(paths=[MAIN, HELPER, OTHER], **fields)
                self.tracker.close.assert_called_once()
                self.broker.stop()

    def test_native_assembly_uses_exact_engine_ids_owner_and_group_clients(self):
        from ruleproxy import windows_global_guard as wfp, windows_ipc_lease as leases
        self.ready()
        native = Mock()
        engine = MagicMock()
        engine.__enter__.return_value = engine
        engine.app_id.side_effect = lambda path: str(path).encode()
        process = Mock(alive=Mock(return_value=True), image_path=Mock(return_value=MAIN),
                       creation_time=Mock(return_value=101))
        def rows(family):
            return [dict(state=2, local='127.0.0.1', local_port=5000, pid=17)] if family == service.socket.AF_INET else []
        with patch.object(wfp, '_Engine', return_value=engine), \
             patch.object(wfp, '_descriptor', return_value=b'owner') as descriptor, \
             patch.object(leases, 'LeaseSet', return_value=native), \
             patch.object(leases, 'GroupEndpoint', side_effect=lambda *args: args), \
             patch.object(service, '_peer_lease', return_value=process), \
             patch.object(service, '_tcp_connections', side_effect=rows):
            tracker = service._new_local_ipc_tracker(self.broker, ((MAIN, HELPER), (OTHER,)),
                                                     {MAIN: 100, HELPER: 100, OTHER: 100})
            tracker.refresh()
            descriptor.assert_called_once_with('D:(A;;CC;;;' + self.sid + ')')
            endpoint, = native.replace.call_args.args[0]
            self.assertEqual(endpoint[0], MAIN.encode())
            self.assertEqual(set(endpoint[1]), {MAIN.encode(), HELPER.encode()})
            self.assertNotIn(OTHER.encode(), endpoint[1])
            tracker.close()


class ProtocolRuntimeTests(unittest.TestCase):
    def message(self, groups, **extra):
        return json.dumps(dict(schema_version=1, request_id='a'*32, op='local_ipc',
                               client_pid=123, groups=groups, **extra)).encode()

    def test_protocol_no_ports_pid_or_identity_fields(self):
        for groups in ([], [[MAIN]], [[MAIN, HELPER], [OTHER]]):
            self.assertEqual(policy.decode_request(self.message(groups))['groups'], groups)
        for name in ('ports', 'pids', 'owner_sid', 'AppIDs'):
            with self.assertRaises(policy.ProxyError):
                policy.decode_request(self.message([[MAIN]], **{name: []}))
        for groups in (None, True, {}, [None], [[]], [['relative.exe']], [[MAIN]] * 129):
            with self.assertRaises(policy.ProxyError):
                policy.decode_request(self.message(groups))

    def test_protocol_unique_path_limit(self):
        groups = [[fr'c:\apps\p{index}.exe'] for index in range(129)]
        with self.assertRaises(policy.ProxyError):
            policy.normalize_ipc_groups(groups)

    def test_duplicate_browser_pwa_groups_deduplicate_without_transitive_merge(self):
        self.assertEqual(policy.normalize_ipc_groups([[MAIN], [MAIN.upper()]]), [[MAIN]])
        groups = [[MAIN, HELPER], [HELPER.upper(), MAIN.upper()], [HELPER, OTHER]]
        self.assertEqual(policy.normalize_ipc_groups(groups),
                         sorted([sorted([MAIN, HELPER]), sorted([HELPER, OTHER])]))

    def test_runtime_missing_component_and_new_component(self):
        runtime = Runtime(Path('.'))
        client = Mock()
        runtime._connect = Mock(return_value=client)
        client.request.return_value = {}
        result = runtime.local_ipc([[MAIN]])
        self.assertEqual(result['state'], 'unsupported')
        client.request.assert_called_once_with('status')
        client.reset_mock()
        client.request.side_effect = [{'local_ipc': {'supported': True}}, {'state': 'watching'}]
        self.assertEqual(runtime.local_ipc([[MAIN]])['state'], 'watching')
        self.assertEqual(client.request.call_args.args, ('local_ipc',))
        self.assertEqual(client.request.call_args.kwargs, {'groups': [[MAIN]]})


class AutomaticPeerBoundaryTests(unittest.TestCase):
    def test_access_denied_candidate_is_skipped_only_on_generic_path(self):
        error = PermissionError(13, 'protected listener')
        with patch.object(service, '_peer_lease', side_effect=error):
            self.assertIsNone(service._local_peer_lease(45, 'owner', (MAIN,), pending=[]))
            with self.assertRaises(PermissionError):
                service._peer_lease(45, 'owner', (MAIN,), pending=[])

    def test_winerror_five_is_skipped_but_other_errors_remain_faults(self):
        denied = OSError('denied')
        denied.winerror = 5
        with patch.object(service, '_peer_lease', side_effect=denied):
            self.assertIsNone(service._local_peer_lease(45, 'owner', (MAIN,), pending=[]))
        with patch.object(service, '_peer_lease', side_effect=OSError('unknown native error')):
            with self.assertRaises(OSError):
                service._local_peer_lease(45, 'owner', (MAIN,), pending=[])

    def test_access_denied_with_unreleased_handle_still_faults(self):
        pending, retained = [], object()
        def fail(*args, **kwargs):
            pending.append(retained)
            raise PermissionError(13, 'handle cleanup failed')
        with patch.object(service, '_peer_lease', side_effect=fail):
            with self.assertRaises(PermissionError):
                service._local_peer_lease(45, 'owner', (MAIN,), pending=pending)
        self.assertEqual(pending, [retained])

    def test_protected_unrelated_listener_does_not_block_selected_endpoint(self):
        from ruleproxy.windows_local_ipc import Tracker
        known = Mock(alive=Mock(return_value=True), image_path=Mock(return_value=MAIN),
                     creation_time=Mock(return_value=101), close=Mock())
        def factory(pid, *args, **kwargs):
            if pid == 999:
                raise PermissionError(13, 'protected system process')
            return known
        rows = [dict(state=2, local='127.0.0.1', local_port=5000, pid=10),
                dict(state=2, local='127.0.0.1', local_port=9999, pid=999)]
        apply, revoke = Mock(), Mock()
        with patch.object(service, '_peer_lease', side_effect=factory):
            tracker = Tracker([[MAIN]], 'owner', 100,
                rows_factory=lambda family: rows if family == service.socket.AF_INET else [],
                process_factory=lambda pid, sid: service._local_peer_lease(pid, sid, (MAIN,), pending=[]),
                apply=apply, revoke=revoke)
            records = tracker.refresh()
        self.assertEqual([record.port for record in records], [5000])
        revoke.assert_not_called()
        tracker.close()


if __name__ == '__main__':
    unittest.main()
