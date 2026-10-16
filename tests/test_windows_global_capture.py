"""Pure evidence-parser/safety checks; never opens sockets or changes networking."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('windows_capture_harness',
    Path(__file__).resolve().parents[1] / '.github/check_windows_global_capture.py')
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
MARKER = b'RuleProxyCapture:test:nonce'


def block(kind, body, endian='<'):
    padded = body + b'\0' * (-len(body) % 4)
    size = len(padded) + 12
    return struct.pack(endian + 'II', kind, size) + padded + struct.pack(endian + 'I', size)


def frame(protocol=17, *, marker=MARKER, target=H.DEST4, port=None, flags=2, fragment=0):
    if protocol == 17:
        body = struct.pack('!HHHH', 53000, port or H.UDP_PORT, 8 + len(marker), 0) + marker
    else:
        body = struct.pack('!HHIIBBHHH', 53000, port or H.TCP_PORT, 0, 0, 5 << 4, flags, 0, 0, 0)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 0, fragment, 64,
        protocol, 0, ipaddress.IPv4Address('192.0.2.55').packed, ipaddress.IPv4Address(target).packed)
    return b'\x01' * 12 + b'\x08\x00' + header + body


def capture(frames, *, endian='<', link=1, truncation=0):
    result = block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    result += block(1, struct.pack(endian + 'HHI', link, 0, 65535), endian)
    for data in frames:
        result += block(6, struct.pack(endian + '5I', 0, 0, 1, len(data), len(data) + truncation) + data, endian)
    return result


class CaptureParserTests(unittest.TestCase):
    def parse(self, value):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'packet.pcapng'
            path.write_bytes(value)
            return H.pcapng_counts(path, MARKER)

    def test_full_control_counts_distinct_tcp_syn_udp_nonce_both_endians(self):
        for endian in ('<', '>'):
            with self.subTest(endian=endian):
                result = self.parse(capture([frame(), frame(6), frame(6, flags=18),
                    frame(marker=b'other-session'), frame(target='198.51.100.1')], endian=endian))
                self.assertEqual((result['tcp_syn'], result['udp_marker'], result['packets_parsed']), (1, 1, 5))
                self.assertEqual(len(result['sha256']), 64)

    def test_valid_empty_interface_is_zero_but_absent_interface_rejected(self):
        self.assertEqual(self.parse(capture([]))['packets_parsed'], 0)
        with self.assertRaisesRegex(ValueError, 'missing_capture_interface'):
            self.parse(capture([])[:28])

    def test_truncated_or_wrong_interface_is_not_a_false_zero(self):
        for value in (capture([frame()], truncation=1), capture([frame()], link=101),
                      capture([frame()])[:-1], capture([frame()]) + b'\0'):
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                self.parse(value)

    def test_packet_without_interface_and_unsupported_packet_block_rejected(self):
        shb = capture([])[:28]
        bad = shb + block(6, struct.pack('<5I', 0, 0, 0, 14, 14) + b'\0' * 14)
        for value in (bad, capture([]) + block(3, b'\0' * 4)):
            with self.assertRaises(ValueError):
                self.parse(value)

    def test_watched_fragment_rejected_instead_of_ignored(self):
        with self.assertRaisesRegex(ValueError, 'fragmented_watched_probe'):
            self.parse(capture([frame(fragment=0x2000)]))

    def test_vlan_frame_counted_and_unrelated_ipv6_ignored(self):
        data = frame()
        vlan = data[:12] + b'\x81\x00\x00\x01' + data[12:]
        self.assertEqual(H.ethernet_probe(vlan, MARKER), (0, 1))
        self.assertEqual(H.ethernet_probe(b'\0' * 12 + b'\x86\xdd', MARKER), (0, 0))

    def test_short_watched_ipv4_tcp_udp_fail_closed(self):
        for value in (b'\0' * 3, frame()[:-1], frame(6)[:-3]):
            with self.assertRaises(ValueError):
                H.ethernet_probe(value, MARKER)

    def test_size_bound_reads_at_most_bound_plus_one(self):
        with patch.object(H, 'MAX_CAPTURE', 16):
            with self.assertRaisesRegex(ValueError, 'capture_size_bound'):
                self.parse(capture([]))


class HarnessPlanningTests(unittest.TestCase):
    def test_unique_nic_mac_required_and_nested_json_supported(self):
        data = {'components': [{'Id': 7, 'Type': 'Miniport', 'MacAddress': 'AA-BB-CC-DD-EE-FF', 'Name': 'physical'},
                               {'Id': 8, 'Type': 'Miniport', 'MacAddress': '00-00-00-00-00-01', 'Name': 'tun'}]}
        self.assertEqual(H.component_id(data, 'aa:bb:cc:dd:ee:ff', 'physical'), 7)
        with self.assertRaisesRegex(ValueError, 'physical_mac_required'):
            H.component_id(data, '', 'physical')
        data['components'].append({'Id': 9, 'Type': 'Miniport', 'MacAddress': 'AA-BB-CC-DD-EE-FF'})
        with self.assertRaisesRegex(ValueError, 'physical_component_not_unique'):
            H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'physical')

    def test_description_or_matching_name_alone_never_selects_a_component(self):
        for data in ({'Id': 7, 'Type': 'Miniport', 'Name': 'nic'},
                     {'Id': 7, 'Type': 'Miniport', 'Name': 'nic', 'Mac': '11-22-33-44-55-66'},
                     {'Id': 7, 'Name': 'nic', 'Mac': 'AA-BB-CC-DD-EE-FF'}):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, 'physical_component_not_unique'):
                H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'nic')

    def test_server2025_properties_bind_exact_ifindex_despite_different_driver_name(self):
        # Shape/names from run38914473858 summary; identity values below are
        # synthetic. Old evidence omitted the actual Properties.Value fields.
        data = [{'Name': 'Network Adapters', 'Components': [
            {'Id': 40, 'Name': 'Microsoft NetVsc Nic #3', 'Type': 'Miniport',
             'Properties': [{'Name': 'MAC Address', 'Value': 'AA-BB-CC-DD-EE-FF'},
                            {'Name': 'ifIndex', 'Value': '14'},
                            {'Name': 'Ndis Object', 'Value': 'private-pointer'}],
             'Counters': [{'Name': 'Upper'}] * 500},
            {'Id': 18, 'Name': 'TCPIP', 'Type': 'Protocol',
             'Properties': [{'Name': 'Miniport ifIndex', 'Value': '14'}]}]}]
        self.assertEqual(H.component_id(data, 'AA-BB-CC-DD-EE-FF',
            'Microsoft Hyper-V Network Adapter #3', 14), 40)
        evidence = H.component_diagnostics(data, 'AA-BB-CC-DD-EE-FF', 'different', 14)
        self.assertEqual(evidence['component_count'], 2)
        self.assertEqual(evidence['rows'][0]['fields']['id'], 40)
        self.assertEqual(evidence['rows'][0]['properties'][0]['value'], 'AA-BB-CC-DD-EE-FF')
        self.assertEqual(evidence['rows'][0]['properties'][1]['value'], '14')
        self.assertNotIn('private-pointer', json.dumps(evidence))
        # Exact live interface index suffices when pktmon exposes no MAC.
        del data[0]['Components'][0]['Properties'][0]
        self.assertEqual(H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'different', 14), 40)

    def test_properties_identity_conflict_ambiguity_and_unknown_schema_refused(self):
        good = {'Id': 40, 'Name': 'ignored', 'Type': 'Miniport', 'Properties': [
            {'Name': 'MAC Address', 'Value': 'AA-BB-CC-DD-EE-FF'}, {'Name': 'ifIndex', 'Value': 14}]}
        import copy
        cases = []
        for key, value in (('MAC Address', '11-22-33-44-55-66'), ('ifIndex', 15),
                           ('ifIndex', True), ('ifIndex', '0xe'), ('MAC Address', 'AA-BB-CC-DD-EE-FF garbage')):
            item = copy.deepcopy(good)
            next(prop for prop in item['Properties'] if prop['Name'] == key)['Value'] = value
            cases.append(item)
        conflict = copy.deepcopy(good)
        conflict['Properties'].append({'Name': 'ifIndex', 'Value': 99})
        cases += [conflict, {**good, 'Properties': {}}, {**good, 'Properties': [{'Name': 'ifIndex'}]},
                  {**good, 'ifIndex': 99}, {**good, 'Type': 'Filter'}, {**good, 'Type': 'unknown'},
                  {**good, 'Id': '40'}, {**good, 'ComponentId': 41}]
        for item in cases:
            with self.subTest(item=item), self.assertRaises(ValueError):
                H.component_id([item], 'AA-BB-CC-DD-EE-FF', 'ignored', 14)
        for data in ([good, good], [good, {**good, 'Id': 41}]):
            with self.assertRaisesRegex(ValueError, 'physical_component_not_unique'):
                H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'ignored', 14)
        with self.assertRaisesRegex(ValueError, 'physical_index_required'):
            H.component_id(good, 'AA-BB-CC-DD-EE-FF', 'ignored', True)

    def test_mac_without_live_index_binding_cannot_replace_expected_interface(self):
        data = {'Id': 7, 'Type': 'Miniport', 'Mac': 'AA-BB-CC-DD-EE-FF'}
        with self.assertRaisesRegex(ValueError, 'physical_component_not_unique'):
            H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'physical', 14)

    def test_nic_identity_diagnostics_survive_counters_and_component_row_bound(self):
        data = [{'Id': item + 100, 'Type': 'Protocol', 'Name': 'other',
                 'Counters': [{'Name': 'counter'}] * 100} for item in range(120)]
        data.append({'Id': 40, 'Type': 'Miniport', 'Name': 'driver name', 'Properties': [
            {'Name': 'MAC Address', 'Value': 'AA-BB-CC-DD-EE-FF'}, {'Name': 'ifIndex', 'Value': '14'}]})
        value = H.component_diagnostics(data, 'AA-BB-CC-DD-EE-FF', 'adapter name', 14)
        self.assertTrue(value['rows_bound_reached'])
        self.assertFalse(value['traversal_incomplete'])
        self.assertEqual(value['component_count'], 121)
        self.assertEqual(value['rows'][0]['fields']['id'], 40)
        self.assertEqual(value['rows'][0]['properties'][1]['value'], '14')
        self.assertEqual(H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'adapter name', 14), 40)

    def test_tun_receipt_reports_actual_guid_luid_index_and_guard_check_without_mutation(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from ruleproxy import windows_global_guard as guard
        expected = '5c7d2762-671d-c5cd-02f3-f6d58670a9f5'
        api = SimpleNamespace(**{name: Mock() for name in ('ConvertInterfaceAliasToLuid',
            'ConvertInterfaceLuidToGuid', 'ConvertInterfaceLuidToIndex')})
        def alias(name, pointer):
            self.assertEqual(name, 'RuleProxyTun')
            pointer._obj.value = 42
            return 0
        def identity(_luid, pointer):
            value = guard._GUID.of(expected)
            H.ctypes.memmove(pointer, H.ctypes.byref(value), H.ctypes.sizeof(value))
            return 0
        def index(_luid, pointer):
            pointer._obj.value = 27
            return 0
        api.ConvertInterfaceAliasToLuid.side_effect = alias
        api.ConvertInterfaceLuidToGuid.side_effect = identity
        api.ConvertInterfaceLuidToIndex.side_effect = index
        with patch.object(H.ctypes, 'WinDLL', return_value=api, create=True), \
             patch.object(guard, '_tun_luid', return_value=42):
            value = H.tun_identity_receipt({'guard': {'tun_ready': True}})
        self.assertEqual(value['interface_guid'], expected)
        self.assertEqual((value['luid'], value['interface_index']), (42, 27))
        self.assertTrue(value['identity_matches'])
        self.assertTrue(value['start_guard_tun_ready'])
        self.assertFalse(value['native_qualified'])
        with patch.object(H.ctypes, 'WinDLL', return_value=api, create=True), \
             patch.object(guard, '_tun_luid', return_value=99):
            self.assertFalse(H.tun_identity_receipt({'guard': {}})['identity_matches'])
        api.ConvertInterfaceAliasToLuid.side_effect = lambda *_: 1168
        with patch.object(H.ctypes, 'WinDLL', return_value=api, create=True), \
             self.assertRaisesRegex(OSError, 'tun_identity_readback_failed'):
            H.tun_identity_receipt({'guard': {}})

    def test_budget_caps_operations_and_rejects_new_work_but_recovery_has_own_limit(self):
        with patch.object(H.time, 'monotonic', return_value=100):
            budget = H.ExperimentBudget()
        with patch.object(H, '_ACTIVE_BUDGET', budget), patch.object(H.time, 'monotonic', return_value=230):
            self.assertEqual(H.operation_timeout(20), 5)
            with self.assertRaisesRegex(RuntimeError, 'time_budget_insufficient'):
                budget.require(90)
        with patch.object(H, '_ACTIVE_BUDGET', budget), patch.object(H.time, 'monotonic', return_value=235):
            with self.assertRaisesRegex(RuntimeError, 'time_budget_exhausted'):
                H.operation_timeout(20)
        with patch.object(H, '_ACTIVE_BUDGET', None):
            self.assertEqual(H.operation_timeout(25), 25)
        self.assertLess(H.EXPERIMENT_BUDGET_SECONDS, H.RECOVERY_DEADLINE_SECONDS)
        self.assertEqual(H.RECOVERY_DEADLINE_SECONDS, 180)

    def test_fixture_accepted_by_real_production_compiler_without_private_ip_exception(self):
        from ruleproxy.config import compile_config
        source = H.fixture_source(41367)
        compiled = compile_config(source, secret='unit', capture_mode='global').config
        self.assertEqual(compiled['proxies'][0]['server'], H.FIXTURE_SERVER)
        self.assertEqual(compiled['proxies'][0]['port'], 41367)
        self.assertTrue(compiled['proxies'][0]['udp'])
        with self.assertRaises(ValueError):
            compile_config(source.replace(H.FIXTURE_SERVER, '127.0.0.1'), secret='unit', capture_mode='global')

    def test_bind_failure_never_counts_as_physical_probe_or_calls_connect_send(self):
        from unittest.mock import MagicMock
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.bind.side_effect = OSError(10049, 'address unavailable')
        with patch.object(H.socket, 'socket', return_value=connection):
            result = H.actor({'marker': 'RuleProxyCapture:unit', 'host': H.DEST4, 'family': 4,
                'tcp_port': H.TCP_PORT, 'udp_port': H.UDP_PORT, 'source': '192.0.2.1', 'echo': False})
        self.assertFalse(H.valid_physical_attempt(result))
        for kind in ('tcp', 'udp'):
            self.assertFalse(result[kind]['executed'])
            self.assertEqual(result[kind]['stage'], 'bind')
        connection.connect.assert_not_called()
        connection.sendto.assert_not_called()

    def test_only_target_attempts_with_wfp_or_transport_evidence_are_valid(self):
        for stage, error, accepted in (('bind', 10013, False), ('socket', 10013, False),
            ('connect', 10013, True), ('send', 10013, True), ('connect', 10060, True),
            ('connect', 10049, False), ('send', 10047, False), ('connect', 10051, False)):
            result = {kind: {'stage': stage, 'error': error, 'executed': True, 'socket_ok': False}
                      for kind in ('tcp', 'udp')}
            with self.subTest(stage=stage, error=error):
                self.assertEqual(H.valid_physical_attempt(result), accepted)

    def test_recovery_stops_only_exact_owned_capture_and_confirms_idle(self):
        with tempfile.TemporaryDirectory() as work:
            state = Path(work) / 'state.json'
            base = str(Path(work) / 'wire-owned')
            H.write_json(state, {'capture': {'base': base, 'stopped': False}})
            active = 'Logger name: PktMon\nLog file: ' + base + '_0001.etl\n'
            with patch.object(H, 'pktmon', side_effect=[active, 'ok', 'Packet Monitor is not running.']) as packet:
                self.assertTrue(H.restore_capture(state)['stopped'])
            self.assertEqual(packet.call_args_list[1].args, ('stop',))
            self.assertTrue(H.read_json(state)['capture']['stopped'])

    def test_recovery_never_stops_foreign_or_unverifiable_capture(self):
        with tempfile.TemporaryDirectory() as work:
            state = Path(work) / 'state.json'
            H.write_json(state, {'capture': {'base': str(Path(work) / 'wire-owned'), 'stopped': False}})
            for active in ('Log file: C:\\foreign.etl', 'unknown localized status'):
                with patch.object(H, 'pktmon', return_value=active) as packet, self.assertRaisesRegex(RuntimeError, 'ownership_unconfirmed'):
                    H.restore_capture(state)
                packet.assert_called_once_with('status')
            active = 'Log file: ' + str(Path(work) / 'wire-owned') + '.etl\n'
            with patch.object(H, 'pktmon', side_effect=[active, 'stop unsuccessful', active]), self.assertRaisesRegex(RuntimeError, 'stop_unconfirmed'):
                H.restore_capture(state)
            self.assertFalse(H.read_json(state)['capture']['stopped'])

    def test_scope_diagnostic_reports_exact_safety_fields_without_relaxing_rejection(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        from unittest.mock import Mock
        from ruleproxy import windows_global_guard as guard
        owned = H.scoped_guard({'root': '/protected', 'owner_sid': 'S-1-5-21-1-2-3-1001'}, 'unit-scope')
        value = guard._Filter()
        key = guard._GUID.of(owned.provider)
        value.key = guard._GUID.of(owned._rule_key(6, 'block'))
        value.display = guard._Display('scope', owned.marker)
        value.provider = H.ctypes.pointer(key)
        value.layer = guard._GUID.of(guard._LAYERS[6])
        value.sublayer = guard._GUID.of(owned.sublayer)
        value.flags, value.count = 97, 1
        @contextmanager
        def get(kind, identity, structure):
            yield value if str(identity) == value.key.text() else None
        engine = SimpleNamespace(get=get)
        with self.assertRaisesRegex(guard.ProxyError, 'scope_filter_readback') as caught:
            owned._filters(engine)
        diagnostic = json.loads(str(caught.exception).split(':', 1)[1])
        self.assertEqual(len(diagnostic), 1)
        row = diagnostic[0]
        self.assertEqual(row['flags'], 97)
        self.assertEqual(row['expected_flags'], 1)
        self.assertTrue(all(row[field] for field in ('marker_matches', 'provider_matches',
            'sublayer_matches', 'layer_matches')))
        self.assertEqual(row['condition_count'], 1)
        self.assertNotIn('/protected', str(caught.exception))
        self.assertNotIn('app', row)

    def test_component_diagnostic_exposes_id_type_and_nested_schema_without_guessing(self):
        data = {'Components': [{'Component ID': '17', 'MACAddress': 'AA-BB-CC-DD-EE-FF',
                'Description': 'physical', 'Type': 'Miniport'}]}
        evidence = H.component_diagnostics(data, 'AA-BB-CC-DD-EE-FF', 'physical')
        self.assertEqual(evidence['exact_mac_match_count'], 1)
        self.assertEqual(evidence['exact_description_match_count'], 1)
        row = evidence['rows'][0]
        self.assertEqual(row['fields']['componentid'], '17')
        self.assertEqual(row['field_types']['componentid'], 'str')
        self.assertEqual(row['fields']['type'], 'Miniport')
        self.assertIn('Components', row['json_path'])
        with self.assertRaisesRegex(ValueError, 'physical_component_id_invalid'):
            H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'physical')

    def test_component_diagnostic_bounds_and_redacts_paths_without_losing_ambiguity(self):
        data = [{'Id': i + 1, 'Type': 'Miniport', 'Mac': 'AA-BB-CC-DD-EE-FF', 'Name': 'C:\\private\\file.exe'}
                for i in range(120)]
        value = H.component_diagnostics(data, 'AA-BB-CC-DD-EE-FF', 'physical')
        self.assertEqual(value['exact_mac_match_count'], 120)
        self.assertEqual(len(value['rows']), 96)
        self.assertTrue(value['rows_bound_reached'])
        self.assertNotIn('private', json.dumps(value))
        with self.assertRaises(ValueError):
            H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'physical')

    def test_read_only_component_snapshot_reports_zero_selection_and_preserves_schema(self):
        nic = {'index': 6, 'mac': 'AA-BB-CC-DD-EE-FF', 'description': 'physical',
               'source': '192.0.2.1', 'gateway': '192.0.2.2', 'alias': 'Ethernet'}
        data = {'Components': [{'Id': '7', 'Type': 'Miniport', 'ifIndex': 6, 'Mac': nic['mac'], 'Name': nic['description']}]}
        with patch.object(H, 'ps', return_value=json.dumps(nic)), \
             patch.object(H, 'pktmon', return_value=json.dumps(data)) as packet:
            actual, selected, evidence = H.nic_components()
        self.assertEqual(actual, nic)
        self.assertIsNone(selected)
        self.assertEqual(evidence['selection_error'], 'physical_component_id_invalid')
        self.assertEqual(evidence['exact_mac_match_count'], 1)
        self.assertNotIn('source', evidence['nic'])
        packet.assert_called_once_with('list', '--json')

    def test_failed_open_process_only_missing_pid_can_count_as_gone(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        for error in (5, 87):
            api = SimpleNamespace(**{name: Mock() for name in ('OpenProcess', 'CloseHandle',
                'QueryFullProcessImageNameW', 'GetProcessTimes', 'TerminateProcess', 'WaitForSingleObject')})
            api.OpenProcess.return_value = 0
            with patch.object(H.ctypes, 'WinDLL', return_value=api, create=True), \
                 patch.object(H.ctypes, 'get_last_error', return_value=error, create=True), \
                 patch.object(H.ctypes, 'WinError', side_effect=lambda value: OSError(value, 'native_error'), create=True):
                if error == 87:
                    H.terminate_owned({'pid': 17}, Path('/fixed/mihomo.exe'))
                else:
                    with self.assertRaises(OSError):
                        H.terminate_owned({'pid': 17}, Path('/fixed/mihomo.exe'))
            api.TerminateProcess.assert_not_called()

    def test_missing_or_wrong_owned_process_identity_cannot_claim_core_kill(self):
        with patch.object(H, 'pid_identity', return_value=None), self.assertRaisesRegex(RuntimeError, 'identity_unconfirmed'):
            H.require_owned_identity(42, Path('/protected/mihomo.exe'))
        with patch.object(H, 'pid_identity', return_value={'image': '/other/python.exe'}), self.assertRaisesRegex(RuntimeError, 'identity_unconfirmed'):
            H.require_owned_identity(42, Path('/protected/mihomo.exe'))

    def test_current_host_cannot_run_network_experiment(self):
        from types import SimpleNamespace
        with patch.object(H.os, 'name', 'posix'), self.assertRaisesRegex(RuntimeError, 'explicit_disposable_windows_ack_required'):
            H.run(SimpleNamespace(ack_disposable_windows=True))

    def test_dns_restore_failure_keeps_guard_and_does_not_restart_service(self):
        from ruleproxy import windows_proxy_service as service
        from ruleproxy import windows_global_dns as dns
        from ruleproxy import windows_global_guard as guard
        from unittest.mock import Mock
        for failure in ({'supported': True, 'active': True}, {'supported': False, 'active': False}):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as work:
                state = Path(work) / 'state.json'
                H.write_json(state, {'root': work, 'nonce': 'unit', 'route_created': False})
                lease = Mock()
                lease.normal_stop.return_value = failure
                previous_path = list(sys.path)
                try:
                    with patch.object(service, 'load_deployment', return_value={'root': work}), \
                         patch.object(service, 'protected_path'), \
                         patch.object(H, 'service_state') as control, \
                         patch.object(H, 'scoped_guard') as scope, \
                         patch.object(guard, 'Guard') as full, \
                         patch.object(dns, 'DnsLease', return_value=lease):
                        result = H._recover_locked(state)
                    self.assertFalse(result['recovered'])
                    self.assertIn('owned_dns_restore_unconfirmed', result['errors'][0])
                    control.assert_called_once_with({'root': work}, False)
                    scope.assert_not_called()
                    full.assert_not_called()
                finally:
                    sys.path[:] = previous_path

    def test_dns_preflight_requires_exact_loopback_answer_and_no_system_proxy(self):
        import urllib.request
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'Status': 0,
            'Answer': [{'type': 1, 'data': '127.0.0.1'}]}).encode()
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(urllib.request, 'build_opener', return_value=opener):
            value = H.fixture_dns_preflight()
        self.assertTrue(value['only_ipv4_answer_loopback'])
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 5)
        response.__enter__.return_value.read.return_value = b'{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}'
        with patch.object(urllib.request, 'build_opener', return_value=opener), self.assertRaisesRegex(RuntimeError, 'fixture_dns_loopback_control_missing'):
            H.fixture_dns_preflight()


@unittest.skipUnless(os.name == 'nt', 'native in-memory Windows ACL constructor')
class NativeAclConstructorTests(unittest.TestCase):
    def test_acl_contains_real_system_admin_sid_objects_without_account_name_lookup(self):
        # Construct and inspect only: no filesystem ACL/network mutation.
        script = H.private_acl_script() + ("$result=@($acl.GetAccessRules($true,$true,"
            "[Security.Principal.SecurityIdentifier])|ForEach-Object {"
            "@{sid=$_.IdentityReference.Value;rights=[int]$_.FileSystemRights;"
            "inheritance=[int]$_.InheritanceFlags;type=[int]$_.AccessControlType}})|ConvertTo-Json -Compress")
        rules = json.loads(H.ps(script))
        self.assertEqual({item['sid'] for item in rules}, {'S-1-5-18', 'S-1-5-32-544'})
        self.assertTrue(all(item['rights'] == 2032127 and item['inheritance'] == 3 and item['type'] == 0
                            for item in rules))


if __name__ == '__main__':
    unittest.main()
