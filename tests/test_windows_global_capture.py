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


def filter_listing(*names):
    """Stand-in for `pktmon filter list`: only the substrings the harness checks."""
    return ''.join(name + ' ' + H.DEST4 + '\n' for name in names)


def loss_evidence():
    return {'buffer_info': {'events_lost': 0, 'buffers_lost': 0}, 'restore': {'stopped': True,
        'cli_metadata': {'stop': {'final_events_lost': 0, 'log_parent_is_private_run_directory': True,
                                 'log_matches_owned_prefix': True}}}}


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

    def test_server2025_sriov_vf_and_netvsc_shared_mac_use_live_ifindex(self):
        # run38936420411: Mellanox VF Id3/index3 and NetVsc Id40/index14
        # legitimately share a MAC. Values below preserve that relationship.
        mac = 'AA-BB-CC-DD-EE-FF'
        vf = {'Id': 3, 'Type': 'Miniport', 'Name': 'Mellanox ConnectX-4 Lx Virtual Ethernet Adapter',
              'Properties': [{'Name': 'MAC Address', 'Value': mac}, {'Name': 'ifIndex', 'Value': 3}]}
        netvsc = {'Id': 40, 'Type': 'Miniport', 'Name': 'Microsoft NetVsc Nic #3',
                  'Properties': [{'Name': 'MAC Address', 'Value': mac}, {'Name': 'ifIndex', 'Value': 14}]}
        logical = {'Id': 40, 'Type': 'NetVsc', 'Name': netvsc['Name'],
                   'Properties': [{'Name': 'Nic ifIndex', 'Value': 3},
                                  {'Name': 'MAC Address', 'Value': mac}, {'Name': 'ifIndex', 'Value': 14}]}
        for components in ([vf, logical, netvsc], [netvsc, logical, vf]):
            with self.subTest(order=[item['Type'] for item in components]):
                self.assertEqual(H.component_id([{'Components': components}], mac, 'different adapter name', 14), 40)
                self.assertEqual(H.component_id([{'Components': components}], mac, 'different adapter name', 3), 3)
                self.assertEqual(H.capture_component_ids([{'Components': components}], mac,
                    'different adapter name', 14, 40), [3, 40])
        self.assertEqual(H.capture_component_ids([netvsc], mac, 'single VM NIC', 14, 40), [40])
        for other in ({**vf, 'Id': 40}, {**vf, 'Properties': [{'Name': 'MAC Address', 'Value': mac}]},
                      {**vf, 'Id': '3'}):
            with self.subTest(other=other), self.assertRaises(ValueError):
                H.capture_component_ids([netvsc, other], mac, 'different adapter name', 14, 40)
        too_many = [netvsc] + [{'Id': index, 'Type': 'Miniport', 'Properties': [
            {'Name': 'MAC Address', 'Value': mac}, {'Name': 'ifIndex', 'Value': index}]} for index in range(1, 5)]
        with self.assertRaisesRegex(ValueError, 'capture_component_set_bound'):
            H.capture_component_ids(too_many, mac, 'different adapter name', 14, 40)
        # MAC alone cannot distinguish the two actual miniports.
        with self.assertRaisesRegex(ValueError, 'physical_component_not_unique'):
            H.component_id([vf, netvsc], mac, 'different adapter name')
        # Conflicting MAC on the exact live interface remains a hard refusal.
        netvsc['Properties'][0]['Value'] = '11-22-33-44-55-66'
        with self.assertRaisesRegex(ValueError, 'component_identity_conflict'):
            H.component_id([vf, netvsc], mac, 'different adapter name', 14)

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
            self.assertEqual(packet.call_args_list[0].args, ('status',))
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

    def test_capture_filter_install_replaces_filters_and_records_confirmed_destination(self):
        evidence = {}
        with patch.object(H, 'pktmon', side_effect=['stale listing', '', '', filter_listing(H.CAPTURE_FILTER)]) as packet:
            H.install_capture_filter(evidence)
        self.assertEqual([call.args for call in packet.call_args_list], [('filter', 'list'), ('filter', 'remove'),
            ('filter', 'add', H.CAPTURE_FILTER, '-i', H.DEST4), ('filter', 'list')])
        self.assertEqual(evidence['filter_before'], 'stale listing')
        self.assertEqual(evidence['filter'], {'name': H.CAPTURE_FILTER, 'ip': H.DEST4, 'confirmed': True})

    def test_capture_filter_install_tolerates_failed_remove_when_no_filter_exists(self):
        evidence = {}
        with patch.object(H, 'pktmon', side_effect=['', RuntimeError('pktmon_operation_failed:none'), '',
                          filter_listing(H.CAPTURE_FILTER)]) as packet:
            H.install_capture_filter(evidence)
        self.assertEqual(packet.call_args_list[2].args, ('filter', 'add', H.CAPTURE_FILTER, '-i', H.DEST4))
        self.assertTrue(evidence['filter']['confirmed'])

    def test_capture_filter_install_refuses_listing_without_both_name_and_destination(self):
        for listing in ('', H.CAPTURE_FILTER + '\n', H.DEST4 + '\n'):
            evidence = {}
            with self.subTest(listing=listing), patch.object(H, 'pktmon', side_effect=['', '', '', listing]), \
                 self.assertRaisesRegex(RuntimeError, 'capture_filter_unconfirmed'):
                H.install_capture_filter(evidence)
            self.assertNotIn('filter', evidence)

    def test_capture_filter_removal_tolerates_failed_remove_only_when_name_is_gone(self):
        with patch.object(H, 'pktmon', side_effect=[RuntimeError('pktmon_operation_failed:none'), filter_listing()]) as packet:
            self.assertTrue(H.remove_capture_filter())
        self.assertEqual([call.args for call in packet.call_args_list], [('filter', 'remove'), ('filter', 'list')])
        with patch.object(H, 'pktmon', side_effect=['', filter_listing(H.CAPTURE_FILTER)]), \
             self.assertRaisesRegex(RuntimeError, 'capture_filter_remove_unconfirmed'):
            H.remove_capture_filter()

    def test_capture_filter_install_tolerates_failing_empty_listing_before_install(self):
        evidence = {}
        with patch.object(H, 'pktmon', side_effect=[RuntimeError('pktmon_operation_failed:There are no packet filters.'),
                          '', '', filter_listing(H.CAPTURE_FILTER)]):
            H.install_capture_filter(evidence)
        self.assertTrue(evidence['filter_before'].startswith('listing_failed:'))
        self.assertTrue(evidence['filter']['confirmed'])

    def test_capture_filter_removal_reads_failing_listing_output_for_remaining_name(self):
        with patch.object(H, 'pktmon', side_effect=['', RuntimeError('pktmon_operation_failed:no filters')]):
            self.assertTrue(H.remove_capture_filter())
        with patch.object(H, 'pktmon', side_effect=['', RuntimeError('pktmon_operation_failed:' + H.CAPTURE_FILTER)]), \
             self.assertRaisesRegex(RuntimeError, 'capture_filter_remove_unconfirmed'):
            H.remove_capture_filter()

    def test_restore_removes_lease_named_filter_even_when_capture_never_started(self):
        with tempfile.TemporaryDirectory() as work:
            state = Path(work) / 'state.json'
            H.write_json(state, {'capture': {'base': str(Path(work) / 'wire-never'), 'stopped': False,
                                             'filter': H.CAPTURE_FILTER}})
            with patch.object(H, 'pktmon', side_effect=['Packet Monitor is not running.', '', '']) as packet:
                result = H.restore_capture(state)
            self.assertEqual([call.args for call in packet.call_args_list],
                             [('status',), ('filter', 'remove'), ('filter', 'list')])
            self.assertIs(result['cli_metadata']['filter_removed'], True)
            self.assertTrue(H.read_json(state)['capture']['stopped'])

    def test_restore_stops_owned_capture_before_removing_named_filter(self):
        with tempfile.TemporaryDirectory() as work:
            state = Path(work) / 'state.json'
            base = str(Path(work) / 'wire-owned')
            H.write_json(state, {'capture': {'base': base, 'stopped': False, 'filter': H.CAPTURE_FILTER}})
            active = 'Logger name: PktMon\nLog file: ' + base + '_0001.etl\n'
            with patch.object(H, 'pktmon', side_effect=[active, 'ok', 'Packet Monitor is not running.', '',
                                                        filter_listing()]) as packet:
                self.assertIs(H.restore_capture(state)['cli_metadata']['filter_removed'], True)
            self.assertEqual([call.args for call in packet.call_args_list],
                             [('status',), ('stop',), ('status',), ('filter', 'remove'), ('filter', 'list')])

    def test_restore_without_filter_lease_never_calls_filter_commands(self):
        with tempfile.TemporaryDirectory() as work:
            state = Path(work) / 'state.json'
            H.write_json(state, {'capture': {'base': str(Path(work) / 'wire-never'), 'stopped': False}})
            with patch.object(H, 'pktmon', side_effect=['Packet Monitor is not running.']) as packet:
                result = H.restore_capture(state)
            self.assertNotIn('filter_removed', result['cli_metadata'])
            self.assertEqual([call.args for call in packet.call_args_list], [('status',)])

    def test_capture_metadata_exports_only_owned_basename_sizes_and_reported_loss_counts(self):
        base = Path('C:/ProgramData/private-run/wire-before')
        output = ('Log file: C:\\ProgramData\\private-run\\wire-before1.etl\n'
            'Logging mode: Multi-file\nMaximum file size: 16 MB\nEvents lost: 12\nBuffers lost: 0\n'
            'Unrecognized: C:\\secret\\payload\nNode: https://private.invalid/token\n')
        value = H.capture_cli_metadata(output, base)
        self.assertTrue(value['log_parent_is_private_run_directory'])
        self.assertTrue(value['log_matches_owned_prefix'])
        self.assertEqual(value['log_basename'], 'wire-before1.etl')
        self.assertEqual(value['maximum_file_size'], '16 MB')
        self.assertEqual(value['events_lost'], 12)
        self.assertTrue(value['loss_counters_reported'])
        self.assertNotIn('private-run', json.dumps(value))
        self.assertNotIn('secret', json.dumps(value))
        self.assertNotIn('invalid', json.dumps(value))
        missing = H.capture_cli_metadata('Packet Monitor is not running.', base)
        self.assertTrue(missing['idle_reported'])
        self.assertFalse(missing['loss_counters_reported'])
        self.assertNotIn('events_lost', missing)
        foreign = H.capture_cli_metadata('Log file: C:\\foreign\\wire-before1.etl', base)
        self.assertFalse(foreign['log_parent_is_private_run_directory'])
        self.assertFalse(foreign['log_matches_owned_prefix'])
        stopped = H.capture_cli_metadata('Log file: C:\\ProgramData\\private-run\\wire-before2.etl (No events lost)', base)
        self.assertEqual(stopped['final_events_lost'], 0)
        self.assertEqual(stopped['log_basename'], 'wire-before2.etl')
        self.assertTrue(stopped['log_matches_owned_prefix'])
        unknown = H.capture_cli_metadata('Log file: C:\\ProgramData\\private-run\\wire-before2.etl (Some events lost)', base)
        self.assertNotIn('final_events_lost', unknown)

    def test_loss_receipt_requires_final_owned_zero_and_never_treats_unknown_as_zero(self):
        import copy
        good = loss_evidence()
        self.assertTrue(H.capture_loss_verified(good))
        cases = [None, {}, {'buffer_info': good['buffer_info']}]
        for section, key, value in (('buffer_info', 'events_lost', 1), ('buffer_info', 'buffers_lost', 1),
                                   ('buffer_info', 'events_lost', False), ('stop', 'final_events_lost', None),
                                   ('stop', 'log_matches_owned_prefix', False)):
            bad = copy.deepcopy(good)
            target = bad['buffer_info'] if section == 'buffer_info' else bad['restore']['cli_metadata']['stop']
            target[key] = value
            cases.append(bad)
        bad = copy.deepcopy(good)
        bad['restore']['cli_metadata']['status_before'] = {'events_lost': 1}
        cases.append(bad)
        for bad in cases:
            with self.subTest(bad=bad):
                self.assertFalse(H.capture_loss_verified(bad))

    def test_missing_physical_positive_can_continue_loss_free_experiment_but_never_pass_controls(self):
        before = {'tcp_syn': 0, 'udp_marker': 0, 'capture_loss_verified': True,
                  'capture_diagnostics': loss_evidence()}
        after = {**before, 'tcp_syn': 1, 'udp_marker': 1}
        report = {'phases': {'outside_before': before, 'outside_after': after}}
        self.assertFalse(H.record_physical_control(report, 'before'))
        self.assertIn('physical_positive_before_missing', report['evidence_gaps'])
        self.assertTrue(H.record_physical_control(report, 'after'))
        self.assertFalse(report['physical_positive_before_valid'] and report['physical_positive_after_valid'])
        before['capture_diagnostics'] = {}
        with self.assertRaisesRegex(RuntimeError, 'capture_loss_unverified'):
            H.record_physical_control(report, 'before')

    def test_capture_inventory_only_reports_capture_files_and_actual_sizes_inside_private_work(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'state.json').write_text('private state')
            (work / 'capture.py').write_text('private script')
            (work / 'carrier-private.log').write_text('private log contents')
            (work / 'wire-before1.etl').write_bytes(b'123456789')
            (work / 'wire-before.etl.0001').write_bytes(b'12')
            inventory = H.capture_inventory(work, work / 'wire-before')
        self.assertEqual(inventory['capture_file_count'], 2)
        self.assertEqual(inventory['matching_etl_count'], 1)
        self.assertEqual(inventory['matching_etl_bytes'], 9)
        self.assertEqual({item['basename'] for item in inventory['files']}, {'wire-before1.etl', 'wire-before.etl.0001'})
        self.assertFalse(inventory['etl_logical_event_bytes_verified'])
        self.assertNotIn(directory, json.dumps(inventory))
        self.assertNotIn('contents', json.dumps(inventory))
        self.assertNotIn('state.json', json.dumps(inventory))

    def test_capture_failure_distinguishes_missing_count_size_and_still_restores(self):
        for count, size, code in ((0, 1, 'capture_files_missing'),
                                 (5, 1, 'capture_file_count_exceeded'),
                                 (1, 9, 'capture_total_bytes_exceeded')):
            with self.subTest(count=count, size=size), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                H.write_json(work / 'state.json', {})
                def actor(_marker):
                    for index in range(count):
                        (work / ('wire-before' + str(index + 1) + '.etl')).write_bytes(b'x' * size)
                    return {'probe_executed': True}
                # Filter list, remove, add and confirm run before the original start and buffer-info calls.
                with patch.object(H, 'pktmon', side_effect=['', '', '', filter_listing(H.CAPTURE_FILTER),
                         'Logging mode: Multi-file\nMaximum file size: 16 MB',
                         RuntimeError('unsupported optional flag with private output')]), \
                     patch.object(H, 'restore_capture', return_value={'stopped': True}) as restore, \
                     patch.object(H.time, 'sleep'), patch.object(H, 'MAX_CAPTURE', 8), \
                     self.assertRaisesRegex(H.CaptureEvidenceError, code) as caught:
                    H.capture_probe(work, 40, 'before', actor)
                restore.assert_called_once_with(work / 'state.json')
                evidence = caught.exception.evidence
                self.assertEqual(evidence['phase'], 'before')
                self.assertEqual(evidence['inventory_after_flush_wait']['matching_etl_count'], count)
                self.assertEqual(evidence['inventory_after_flush_wait']['matching_etl_bytes'], count * size)
                self.assertTrue(evidence['restore']['stopped'])
                self.assertEqual(evidence['buffer_info'], {'available': False, 'error_type': 'RuntimeError'})
                self.assertNotIn('private output', json.dumps(evidence))
                self.assertNotIn(directory, json.dumps(evidence))

    def test_component_aggregation_requires_every_conversion_and_zero_on_each_declared_path(self):
        import copy
        empty = {'tcp_syn': 0, 'udp_marker': 0, 'packets_parsed': 0,
                 'captures': [{'sha256': '0' * 64, 'bytes': 188}]}
        values = {'3': copy.deepcopy(empty), '40': copy.deepcopy(empty)}
        result = H.aggregate_capture_components([3, 40], values, 1)
        result.update(capture_loss_verified=True, capture_diagnostics=loss_evidence())
        self.assertTrue(H.protected_components_clear(result, [3, 40]))
        self.assertEqual(result['packets_parsed'], 0)
        values['3']['tcp_syn'] = values['3']['udp_marker'] = 1
        values['3']['packets_parsed'] = 2
        result = H.aggregate_capture_components([3, 40], values, 1)
        result.update(capture_loss_verified=True, capture_diagnostics=loss_evidence())
        self.assertEqual((result['tcp_syn'], result['udp_marker']), (1, 1))
        self.assertFalse(H.protected_components_clear(result, [3, 40]))
        cases = [{'3': copy.deepcopy(empty)}, {**values, '99': copy.deepcopy(empty)},
                 {**values, '40': {**empty, 'captures': []}}, {**values, '40': {**empty, 'udp_marker': -1}}]
        for incomplete in cases:
            with self.subTest(incomplete=incomplete), self.assertRaisesRegex(ValueError, 'conversion_incomplete'):
                H.aggregate_capture_components([3, 40], incomplete, 1)
            self.assertFalse(H.protected_components_clear({'declared_components': [3, 40],
                'components': incomplete}, [3, 40]))
        for declared in ([3, 3], [], [True, 40], list(range(1, 6))):
            with self.assertRaisesRegex(ValueError, 'capture_component_set_invalid'):
                H.aggregate_capture_components(declared, values, 1)

    def test_capture_converts_all_frozen_components_and_missing_conversion_cannot_pass(self):
        for omit_second in (False, True):
            with self.subTest(omit_second=omit_second), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                H.write_json(work / 'state.json', {})
                marker = None
                def actor(value):
                    nonlocal marker
                    marker = value.encode('ascii')
                    (work / 'wire-before1.etl').write_bytes(b'etl fixture')
                    return {'tcp': {'executed': True}, 'udp': {'executed': True}}
                def packet(*arguments):
                    if arguments[0] == 'start':
                        self.assertEqual(arguments[arguments.index('--comp') + 1], '3,40')
                    elif arguments[0] == 'etl2pcap':
                        identity = arguments[arguments.index('--component-id') + 1]
                        output = arguments[arguments.index('--out') + 1]
                        if identity == 3:
                            output.write_bytes(capture([frame(6), frame(marker=marker)]))
                        elif not omit_second:
                            output.write_bytes(capture([]))
                    elif arguments[:2] == ('filter', 'list'):
                        return filter_listing(H.CAPTURE_FILTER)
                    elif arguments[0] == 'status':
                        return 'Events lost: 0\nBuffers lost: 0'
                    return ''
                with patch.object(H, 'pktmon', side_effect=packet), \
                     patch.object(H, 'restore_capture', return_value=loss_evidence()['restore']), patch.object(H.time, 'sleep'):
                    if omit_second:
                        with self.assertRaises(H.CaptureEvidenceError) as caught:
                            H.capture_probe(work, [3, 40], 'before', actor)
                        self.assertEqual(caught.exception.evidence['conversion_component'], 40)
                        self.assertEqual(caught.exception.evidence['component_results']['40']['captures'], [])
                    else:
                        result = H.capture_probe(work, [3, 40], 'before', actor)
                        self.assertEqual(result['declared_components'], [3, 40])
                        self.assertEqual(result['components']['3']['tcp_syn'], 1)
                        self.assertEqual(result['components']['3']['udp_marker'], 1)
                        self.assertEqual(result['components']['40']['packets_parsed'], 0)
                        self.assertEqual(len(result['captures']), 2)

    def test_capture_filter_is_leased_then_installed_before_start(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            H.write_json(work / 'state.json', {})
            calls, leases = [], []
            def actor(_marker):
                (work / 'wire-before1.etl').write_bytes(b'etl fixture')
                return {'tcp': {'executed': True}, 'udp': {'executed': True}}
            def packet(*arguments):
                calls.append(arguments)
                if arguments == ('filter', 'add', H.CAPTURE_FILTER, '-i', H.DEST4):
                    leases.append(H.read_json(work / 'state.json')['capture'])
                elif arguments[:2] == ('filter', 'list'):
                    return filter_listing(H.CAPTURE_FILTER)
                elif arguments[0] == 'etl2pcap':
                    arguments[arguments.index('--out') + 1].write_bytes(capture([]))
                elif arguments[0] == 'status':
                    return 'Events lost: 0\nBuffers lost: 0'
                return ''
            with patch.object(H, 'pktmon', side_effect=packet), \
                 patch.object(H, 'restore_capture', return_value=loss_evidence()['restore']), patch.object(H.time, 'sleep'):
                result = H.capture_probe(work, 40, 'before', actor)
        self.assertEqual(calls[:4], [('filter', 'list'), ('filter', 'remove'),
                                     ('filter', 'add', H.CAPTURE_FILTER, '-i', H.DEST4), ('filter', 'list')])
        self.assertEqual(calls[4][:2], ('start', '--capture'))
        self.assertEqual(leases, [{'base': str(work / 'wire-before'), 'stopped': False, 'filter': H.CAPTURE_FILTER}])
        self.assertTrue(result['capture_loss_verified'])

    def test_capture_start_failure_still_removes_installed_filter_through_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            H.write_json(work / 'state.json', {})
            installed = []
            def packet(*arguments):
                if arguments[:2] == ('filter', 'add'):
                    installed.append(arguments[2])
                elif arguments[:2] == ('filter', 'remove'):
                    installed.clear()
                elif arguments[:2] == ('filter', 'list'):
                    return filter_listing(*installed)
                elif arguments[0] == 'start':
                    raise RuntimeError('pktmon_operation_failed:start refused')
                elif arguments[0] == 'status':
                    return 'Packet Monitor is not running.'
                return ''
            with patch.object(H, 'pktmon', side_effect=packet), \
                 self.assertRaisesRegex(H.CaptureEvidenceError, 'pktmon_operation_failed') as caught:
                H.capture_probe(work, 40, 'before', lambda _marker: {'probe_executed': True})
            self.assertEqual(installed, [])
            self.assertIs(caught.exception.evidence['restore']['cli_metadata']['filter_removed'], True)
            self.assertTrue(H.read_json(work / 'state.json')['capture']['stopped'])

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
                'Description': 'physical', 'Type': 'Miniport', 'SecondaryId': 700}]}
        evidence = H.component_diagnostics(data, 'AA-BB-CC-DD-EE-FF', 'physical')
        self.assertEqual(evidence['exact_mac_match_count'], 1)
        self.assertEqual(evidence['exact_description_match_count'], 1)
        row = evidence['rows'][0]
        self.assertEqual(row['fields']['componentid'], '17')
        self.assertEqual(row['field_types']['componentid'], 'str')
        self.assertEqual(row['fields']['type'], 'Miniport')
        self.assertEqual(row['fields']['secondaryid'], 700)
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

    def test_startup_smoke_uses_real_start_lifecycle_without_capture_and_cannot_claim_full_acceptance(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        from unittest.mock import Mock, create_autospec
        from ruleproxy import windows_proxy_service as service
        from ruleproxy import windows_app_process as app_process
        from ruleproxy import windows_global_runtime as runtime
        from ruleproxy import windows_global_guard as guard
        from ruleproxy import windows_global_dns as dns
        from ruleproxy import windows_proxy_client as client
        for failure in (None, 'echo', 'receiver', 'recovery', 'dns', 'dns_ok'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root = Path(directory)
                (root / 'ruleproxy').mkdir()
                (root / 'ruleproxy/windows_global_guard.py').write_text('fixed guard fixture')
                (root / 'RuleProxy-Web').mkdir()
                sid = 'S-1-5-21-1-2-3-1001'
                metadata = {'root': str(root), 'owner_sid': sid, 'files': {'bin/windows-amd64/mihomo.exe': '0' * 64}}
                idle_guard = {'supported': True, 'active': False, 'persistent': False}
                idle_dns = {'supported': True, 'active': False, 'fresh': True}
                held_guard = {'supported': True, 'active': True, 'persistent': True}
                held_dns = {'supported': True, 'active': True, 'fresh': True, 'effective': True}
                instance = Mock()
                instance.status.return_value = {'supported': True, 'running': False}
                instance.start.return_value = {'running': True, 'pid': 17, 'guard': {'tun_ready': True}}
                guard_instance, dns_instance = Mock(), Mock()
                guard_instance.status.side_effect = [idle_guard, held_guard, idle_guard]
                dns_instance.status.side_effect = [idle_dns, held_dns, idle_dns]
                counts = {key: 1 for key in ('tcp4', 'tcp6', 'udp4', 'udp6')}
                if failure == 'receiver':
                    counts['udp6'] = 0
                fixture = SimpleNamespace(port=41367, counts=counts, close=Mock())
                environment = SimpleNamespace(**{**vars(os), 'name': 'nt', 'environ': {**os.environ, 'ProgramData': directory}})
                stack.enter_context(patch.object(H, 'os', environment))
                stack.enter_context(patch.object(H.sys, 'getwindowsversion', return_value=(10, 0, 26100), create=True))
                stack.enter_context(patch.object(service, 'load_deployment', return_value=metadata))
                stack.enter_context(patch.object(service, 'protected_path'))
                api = create_autospec(app_process._KernelAPI, instance=True)
                api.is_elevated.return_value = True
                stack.enter_context(patch.object(app_process, '_get_api', return_value=api))
                stack.enter_context(patch.object(client, 'current_user_sid', return_value=sid))
                stack.enter_context(patch.object(runtime, 'Runtime', return_value=instance))
                stack.enter_context(patch.object(guard, 'Guard', return_value=guard_instance))
                stack.enter_context(patch.object(dns, 'DnsLease', return_value=dns_instance))
                packet = stack.enter_context(patch.object(H, 'pktmon', side_effect=AssertionError('startup must not capture')))
                powershell = stack.enter_context(patch.object(H, 'ps', return_value='ok'))
                stack.enter_context(patch.object(H, 'task', return_value='independent-watchdog'))
                stack.enter_context(patch.object(H, 'EchoNode', return_value=fixture))
                stack.enter_context(patch.object(H, 'fixture_dns_preflight', return_value={'verified': True}))
                relay = Mock()
                relay.close.return_value = {'active': 0, 'closed': True}
                def prepare(work, _state, _fixture, report, _budget, _names):
                    H.write_json(work / 'carrier-owned.json', {'pid': 18, 'creation': 24, 'image': 'fixed'})
                    report['dns_fixture_sha256'] = 'ea4e180ea6f02912341aa81041fdc71e663bb6095aeefaa9b5fe1733ea57ca7d'
                    return {'relay': relay}
                stack.enter_context(patch.object(H, 'prepare_dns_smoke', side_effect=prepare))
                def dns_queries(_context, report, _budget):
                    if failure == 'dns':
                        raise RuntimeError('dns_disabled_control_not_observed')
                    report['dns_smoke_passed'] = True
                stack.enter_context(patch.object(H, 'run_dns_smoke', side_effect=dns_queries))
                stack.enter_context(patch.object(H, 'tun_identity_receipt', return_value={'identity_matches': True, 'start_guard_tun_ready': True}))
                stack.enter_context(patch.object(H, 'require_owned_identity', return_value={'pid': 17, 'creation': 23, 'image': 'fixed'}))
                terminated = stack.enter_context(patch.object(H, 'terminate_owned'))
                stack.enter_context(patch.object(H.shutil, 'copytree'))
                stack.enter_context(patch.object(H, 'recover', return_value={'recovered': failure != 'recovery'}))
                def echo(value):
                    return {kind: {'received_echo': not (failure == 'echo' and value['family'] == 6 and kind == 'udp'),
                                   'socket_ok': True} for kind in ('tcp', 'udp')}
                actors = stack.enter_context(patch.object(H, 'actor', side_effect=echo))
                stack.enter_context(patch.object(H, 'print', create=True))
                previous_path = list(sys.path)
                try:
                    result = H.run(SimpleNamespace(ack_disposable_windows=True, installed_root=root,
                        output=root / 'summary.json', read_only_components=False, startup_smoke_only=True,
                        dns_smoke=failure in ('dns', 'dns_ok')))
                finally:
                    sys.path[:] = previous_path
                value = H.read_json(root / 'summary.json')
                self.assertEqual(result, 0 if failure in (None, 'dns_ok') else 1)
                self.assertEqual(value['mode'], 'disposable_windows_tun_startup_smoke')
                self.assertEqual(value['startup_smoke_passed'], failure in (None, 'dns_ok'))
                for key in ('passed', 'strict_qualified', 'physical_qualified', 'ipv4_physical_scope_passed',
                            'dns_qualified', 'ipv6_public_egress_qualified', 'rdp_qualified', 'packet_fail_closed_proven'):
                    self.assertIs(value[key], False)
                self.assertTrue(value['core_started'])
                self.assertTrue(value['explicit_global_stop'])
                self.assertEqual(actors.call_count, 2)
                self.assertIs(instance.start.call_args.kwargs['require_strict'], False)
                instance.stop.assert_called_once_with()
                if failure in ('dns', 'dns_ok'):
                    self.assertEqual([call.args[0]['pid'] for call in terminated.call_args_list], [18, 17])
                    self.assertEqual(value['dns_smoke_passed'], failure == 'dns_ok')
                    self.assertTrue(value['dns_carrier_closed_before_core_death'])
                    relay.close.assert_called_once_with()
                else:
                    terminated.assert_called_once()
                packet.assert_not_called()
                scripts = str(powershell.call_args_list)
                self.assertNotRegex(scripts, r'(?:New|Set|Remove|Enable|Disable)-Net')
                self.assertNotIn('203.0.113.77/32', scripts)
                self.assertIn('native_ipv6_before_core', value)
                self.assertIn('native_ipv6_after_start', value)

    def test_native_ipv6_diagnostics_are_read_only_bounded_and_return_only_compact_summary(self):
        summary = {'available': True, 'global_unicast_ipv6_count': 0,
                   'non_tun_global_unicast_ipv6_count': 0, 'tun_present': False,
                   'default_routes': [], 'interfaces': [], 'disabled_components': {'present': False, 'dword': None}}
        with patch.object(H, 'ps', return_value=json.dumps(summary)) as powershell:
            self.assertEqual(H.native_ipv6_diagnostics(), summary)
        script = powershell.call_args.args[0]
        self.assertEqual(powershell.call_args.kwargs['timeout'], 8)
        self.assertIn('Get-NetIPAddress', script)
        self.assertIn('Get-NetIPInterface', script)
        self.assertIn('Get-NetRoute', script)
        self.assertIn("$present=(@($registry.GetValueNames()) -contains 'DisabledComponents')", script)
        self.assertNotRegex(script, r'(?:New|Set|Remove|Enable|Disable)-Net|Set-Item|\.SetValue\(')
        self.assertNotIn('IPAddress=[', script)
        with patch.object(H, 'ps', side_effect=RuntimeError('private host details')):
            failed = H.native_ipv6_diagnostics()
        self.assertFalse(failed['available'])
        self.assertNotIn('private', json.dumps(failed))

    def test_dns_smoke_requires_unique_queries_causal_disable_and_restored_node_traffic(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        class FixtureError(ValueError):
            def __init__(self, code):
                super().__init__(code)
                self.code = code
        for failure in (None, 'reuse_positive', 'no_rejected_attempt', 'disabled_query_succeeded',
                        'restored_no_traffic', 'restored_no_fresh_admission', 'restored_only_pre_disable_bytes', 'bad_response'):
            with self.subTest(failure=failure):
                state = {'enabled': True, 'accepted': 0, 'rejected': 0, 'active': 1,
                         'bytes_to_resolver': 0, 'bytes_to_client': 0}
                if failure == 'reuse_positive':
                    state['accepted'] = 3
                relay = Mock()
                relay.snapshot.side_effect = lambda: dict(state)
                def disable():
                    state.update(enabled=False, active=0)
                    if failure == 'restored_only_pre_disable_bytes':
                        state['bytes_to_resolver'] += 100
                        state['bytes_to_client'] += 200
                    return dict(state)
                relay.disable.side_effect = disable
                relay.enable.side_effect = lambda: state.update(enabled=True)
                names, raw_calls, system_calls = [], [], []
                def name(_expected):
                    result = 'rp-' + format(len(names) + 1, '016x') + '.1.2.3.4.sslip.io.'
                    names.append(result)
                    return result
                def query(query_name, expected_ip):
                    if not state['enabled']:
                        if failure == 'no_rejected_attempt':
                            raise H.subprocess.TimeoutExpired('fixed DNS child', 3)
                        state['rejected'] += 1
                        if failure != 'disabled_query_succeeded':
                            raise FixtureError('system_dns_child_failed')
                    if not (failure == 'restored_no_traffic' and len(system_calls) == 3):
                        if not (failure == 'reuse_positive' and len(system_calls) < 3
                                or failure == 'restored_no_fresh_admission' and len(system_calls) == 3):
                            state['accepted'] += 1
                        if not (failure == 'restored_only_pre_disable_bytes' and len(system_calls) == 3):
                            state['bytes_to_resolver'] += 100
                            state['bytes_to_client'] += 200
                    return {'validated': failure != 'bad_response', 'query_name': query_name, 'addresses': [expected_ip]}
                def system(query_name, expected_ip, **kwargs):
                    system_calls.append((query_name, kwargs['timeout']))
                    return query(query_name, expected_ip)
                def raw(peer, **kwargs):
                    raw_calls.append((peer, kwargs['protocol'], kwargs['timeout']))
                    return query(kwargs['name'], kwargs['expected_ip'])
                module = SimpleNamespace(query_name=name, system_dns_query=system, raw_dns_query=raw, FixtureError=FixtureError)
                report = {'dns_smoke_passed': False, 'dns_qualified': False, 'strict_qualified': False}
                if failure in (None, 'reuse_positive'):
                    H.run_dns_smoke({'module': module, 'relay': relay}, report, Mock())
                    self.assertTrue(report['dns_smoke_passed'])
                    self.assertEqual(len(names), len(set(names)))
                    self.assertEqual(len(names), 7)
                    self.assertEqual(set((peer, protocol) for peer, protocol, _ in raw_calls),
                        {(peer, protocol) for peer in ('198.18.0.2', 'fdfe:dcba:8879::2') for protocol in ('udp', 'tcp')})
                    self.assertEqual([timeout for _, timeout in system_calls], [3, 3, 3])
                    if failure == 'reuse_positive':
                        self.assertEqual(report['dns_smoke']['before']['accepted'], 3)
                        self.assertEqual(report['dns_smoke']['positive']['accepted'], 3)
                        self.assertEqual(report['dns_smoke']['restored']['accepted'], 4)
                else:
                    with self.assertRaises((RuntimeError, FixtureError)):
                        H.run_dns_smoke({'module': module, 'relay': relay}, report, Mock())
                    self.assertFalse(report['dns_smoke_passed'])
                self.assertIs(report['dns_qualified'], False)
                self.assertIs(report['strict_qualified'], False)

    def test_echo_node_only_admits_fixed_doh_connect_after_carrier_success_callback(self):
        import threading
        from unittest.mock import MagicMock, Mock
        for host in ('1.1.1.1', '9.9.9.9'):
            with self.subTest(host=host):
                connection = MagicMock()
                connection.recv.side_effect = [b'\x05\x01', b'\x00', b'\x05\x01\x00', b'\x01',
                                               ipaddress.IPv4Address(host).packed, struct.pack('!H', 443)]
                fixture = H.EchoNode.__new__(H.EchoNode)
                fixture.lock, fixture.clients = threading.Lock(), {connection}
                fixture.doh_relay = Mock()
                fixture.doh_relay.handle.side_effect = lambda stream, _host, _port, on_ready: on_ready(stream)
                fixture.serve(connection)
                if host == '1.1.1.1':
                    self.assertEqual(fixture.doh_relay.handle.call_args.args, (connection, host, 443))
                    self.assertEqual(connection.sendall.call_args_list[-1].args[0][:3], b'\x05\x00\x00')
                else:
                    fixture.doh_relay.handle.assert_not_called()
                    self.assertEqual(connection.sendall.call_args_list[-1].args[0][:3], b'\x05\x02\x00')
                self.assertFalse(fixture.clients)

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
    def test_native_ipv6_classifier_includes_ula_and_documentation_but_excludes_local_addresses(self):
        # Execute the exact production PowerShell classifier with synthetic
        # literals only. No host network query or registry access occurs.
        with patch.object(H, 'ps', return_value='{}') as powershell:
            H.native_ipv6_diagnostics()
        script = powershell.call_args.args[0].split('$addresses=', 1)[0]
        script += "$result=@('fdfe:dcba:8879::1','2001:db8::88','fe80::1','::1','ff02::1','::','::ffff:192.0.2.1','::ffff:127.0.0.1')|ForEach-Object {Is-Unicast6 $_}|ConvertTo-Json -Compress"
        self.assertEqual(json.loads(H.ps(script, timeout=8)), [True, True, False, False, False, False, False, False])

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
