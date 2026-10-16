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
        data = {'components': [{'Id': 7, 'MacAddress': 'AA-BB-CC-DD-EE-FF', 'Name': 'physical'},
                               {'Id': 8, 'MacAddress': '00-00-00-00-00-01', 'Name': 'tun'}]}
        self.assertEqual(H.component_id(data, 'aa:bb:cc:dd:ee:ff', 'physical'), 7)
        with self.assertRaisesRegex(ValueError, 'physical_mac_required'):
            H.component_id(data, '', 'physical')
        data['components'].append({'Id': 9, 'MacAddress': 'AA-BB-CC-DD-EE-FF'})
        with self.assertRaisesRegex(ValueError, 'physical_component_not_unique'):
            H.component_id(data, 'AA-BB-CC-DD-EE-FF', 'physical')

    def test_description_fallback_only_when_component_has_no_mac(self):
        self.assertEqual(H.component_id({'Id': 7, 'Name': 'nic'}, 'AA-BB-CC-DD-EE-FF', 'nic'), 7)
        with self.assertRaisesRegex(ValueError, 'physical_component_not_unique'):
            H.component_id({'Id': 7, 'Name': 'nic', 'Mac': '11-22-33-44-55-66'}, 'AA-BB-CC-DD-EE-FF', 'nic')

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
        value.flags, value.count = 65, 1
        @contextmanager
        def get(kind, identity, structure):
            yield value if str(identity) == value.key.text() else None
        engine = SimpleNamespace(get=get)
        with self.assertRaisesRegex(guard.ProxyError, 'scope_filter_readback') as caught:
            owned._filters(engine)
        diagnostic = json.loads(str(caught.exception).split(':', 1)[1])
        self.assertEqual(len(diagnostic), 1)
        row = diagnostic[0]
        self.assertEqual(row['flags'], 65)
        self.assertEqual(row['expected_flags'], 1)
        self.assertTrue(all(row[field] for field in ('marker_matches', 'provider_matches',
            'sublayer_matches', 'layer_matches')))
        self.assertEqual(row['condition_count'], 1)
        self.assertNotIn('/protected', str(caught.exception))
        self.assertNotIn('app', row)

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
