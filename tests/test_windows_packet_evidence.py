"""Construct real Ethernet/IP/UDP frames, without claiming PSEC blocking."""
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('ruleproxy_packet_evidence', ROOT / '.github/windows_packet_evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
MAC = bytes.fromhex('525400123456')
OTHER_MAC = bytes.fromhex('525400abcdef')
DNS = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09ruleproxy\x07invalid\x00\x00\x01\x00\x01'


def checksum(data):
    if len(data) & 1:
        data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def manifest(*families):
    probes = []
    for family in families or ('ipv4',):
        for index, role in enumerate(evidence.ROLES):
            marker = struct.pack('!H', index + 0x5200) + DNS[2:]
            probes.append({'id': family + '-' + role, 'group': family, 'role': role,
                           'family': family, 'protocol': 'udp', 'source_mac': '52:54:00:12:34:56',
                           'source_ip': '10.0.2.15' if family == 'ipv4' else 'fec0::15',
                           'destination': '1.1.1.1' if family == 'ipv4' else '2606:4700:4700::1111',
                           'port': 53, 'payload_hex': marker.hex()})
    return {'schema_version': 1, 'probes': probes}


def frame(probe, *, mac=MAC, vlan=(), protocol=17, fragment=0, extension=None, payload=None, port=None):
    source = ipaddress.ip_address(probe['source_ip']).packed
    destination = ipaddress.ip_address(probe['destination']).packed
    payload = bytes.fromhex(probe['payload_hex']) if payload is None else payload
    port = probe['port'] if port is None else port
    body = struct.pack('!HHHH', 45123, port, len(payload) + 8, 0) + payload if protocol == 17 else payload
    if protocol == 17 and probe['family'] == 'ipv6':
        pseudo = source + destination + struct.pack('!I3xB', len(body), 17)
        body = body[:6] + struct.pack('!H', checksum(pseudo + body) or 0xffff) + body[8:]
    if probe['family'] == 'ipv4':
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 21, fragment,
                             64, protocol, 0, source, destination)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        ethertype = 0x0800
    else:
        if extension is not None:
            body = bytes((protocol, 0)) + b'\x00' * 6 + body
            protocol = extension
        header = struct.pack('!IHBB16s16s', 6 << 28, len(body), protocol, 64, source, destination)
        ethertype = 0x86dd
    ethernet = OTHER_MAC + mac
    for index, tag in enumerate(vlan):
        ethernet += struct.pack('!HH', tag, index + 1)
    ethernet += struct.pack('!H', ethertype)
    return ethernet + header + body


def pcap(packets, *, endian='<', nanos=False, linktype=1, snaplen=65536):
    magic = 0xa1b23c4d if nanos else 0xa1b2c3d4
    result = struct.pack(endian + 'IHHiiII', magic, 2, 4, 0, 0, snaplen, linktype)
    for index, packet in enumerate(packets):
        result += struct.pack(endian + 'IIII', 1000 + index, 123, len(packet), len(packet)) + packet
    return result


def controls(value):
    before = [frame(p) for p in value['probes'] if p['role'] == 'outside_before']
    after = [frame(p) for p in value['probes'] if p['role'] == 'outside_after']
    return before, after


class WindowsPacketEvidenceTests(unittest.TestCase):
    def test_real_ipv4_ipv6_controls_work_in_all_classic_pcap_byte_orders_and_time_units(self):
        value = manifest('ipv4', 'ipv6')
        before, after = controls(value)
        for endian in ('<', '>'):
            for nanos in (False, True):
                with self.subTest(endian=endian, nanos=nanos):
                    capture = pcap(before + after, endian=endian, nanos=nanos)
                    result = evidence.analyze_bytes(capture, value)
                    self.assertEqual(result['status'], 'complete')
                    self.assertTrue(result['absence_observed'])
                    self.assertFalse(result['kernel_denial_proven'])
                    self.assertFalse(result['acceptance_passed'])
                    self.assertEqual(result['capture_sha256'], hashlib.sha256(capture).hexdigest())
                    self.assertEqual([p['count'] for p in result['counts']], [1, 0, 0, 1] * 2)

    def test_delivered_contained_datagram_is_counted_and_cannot_be_absence(self):
        value = manifest()
        before, after = controls(value)
        packets = before + [frame(value['probes'][1]), frame(value['probes'][2])] + after
        result = evidence.analyze_bytes(pcap(packets), value)
        self.assertEqual(result['status'], 'complete')
        self.assertFalse(result['absence_observed'])
        self.assertEqual([p['count'] for p in result['counts']], [1, 1, 1, 1])

    def test_vlan_tagged_controls_and_contained_marker_are_matched(self):
        value = manifest('ipv6')
        packets = [frame(value['probes'][i], vlan=(0x88a8, 0x8100)) for i in (0, 1, 3)]
        result = evidence.analyze_bytes(pcap(packets), value)
        self.assertEqual([p['count'] for p in result['counts']], [1, 1, 0, 1])
        self.assertFalse(result['absence_observed'])

    def test_rx_source_mac_other_port_or_payload_cannot_match_guest_egress(self):
        value = manifest()
        before, after = controls(value)
        parent = value['probes'][1]
        packets = before + [frame(parent, mac=OTHER_MAC),
                            frame(parent, port=54), frame(parent, payload=b'unrelated fixed datagram')] + after
        result = evidence.analyze_bytes(pcap(packets), value)
        self.assertTrue(result['absence_observed'])
        self.assertEqual([p['count'] for p in result['counts']], [1, 0, 0, 1])

    def test_source_ip_change_cannot_turn_exact_contained_marker_into_zero_proof(self):
        value = manifest('ipv6')
        before, after = controls(value)
        changed_ip = dict(value['probes'][1], source_ip='fec0::1234')
        result = evidence.analyze_bytes(pcap(before + [frame(changed_ip)] + after), value)
        self.assertEqual(result['unknown_reasons'], {'probe_marker_unexpected_source_ip': 1})
        self.assertFalse(result['absence_observed'])
        self.assertIsNone(result['contained_markers_absent'])

    def test_summary_never_contains_http_body_marker_addresses_or_capture_path(self):
        value = manifest()
        before, after = controls(value)
        private = b'GET /HTTP_CAPABILITY_DO_NOT_EXPORT HTTP/1.1\r\nCookie: PRIVATE_DO_NOT_EXPORT\r\n\r\n'
        result = evidence.analyze_bytes(pcap(before + [frame(value['probes'][1], protocol=6, payload=private)] + after), value)
        text = json.dumps(result)
        for secret in ('HTTP_CAPABILITY_DO_NOT_EXPORT', 'PRIVATE_DO_NOT_EXPORT', '1.1.1.1', '10.0.2.15',
                       '52:54:00:12:34:56', value['probes'][0]['payload_hex']):
            self.assertNotIn(secret, text)
        self.assertTrue(result['absence_observed'])

    def test_missing_positive_control_and_reversed_control_window_are_incomplete(self):
        value = manifest()
        before, after = controls(value)
        for packets in (before, after, after + before):
            result = evidence.analyze_bytes(pcap(packets), value)
            self.assertEqual(result['status'], 'incomplete')
            self.assertIsNone(result['contained_markers_absent'])
            self.assertFalse(result['absence_observed'])

    def test_control_minimum_is_enforced_and_contained_markers_must_be_in_window(self):
        value = manifest()
        before, after = controls(value)
        value['probes'][0]['minimum_count'] = 2
        self.assertEqual(evidence.analyze_bytes(pcap(before + after), value)['status'], 'incomplete')
        value['probes'][0]['minimum_count'] = 1
        packets = [frame(value['probes'][1])] + before + after
        self.assertEqual(evidence.analyze_bytes(pcap(packets), value)['status'], 'incomplete')

    def test_matching_ipv4_fragments_are_unknown_not_zero_pass(self):
        value = manifest()
        before, after = controls(value)
        for fragment in (0x2000, 1):
            result = evidence.analyze_bytes(pcap(before + [frame(value['probes'][1], fragment=fragment)] + after), value)
            self.assertEqual(result['unknown_reasons'], {'unparsed_ipv4_udp_fragment': 1})
            self.assertFalse(result['absence_observed'])
            self.assertIsNone(result['contained_markers_absent'])
            self.assertIsNone(result['groups'][0]['contained_markers_absent'])

    def test_matching_ipv6_extension_is_unknown_even_if_visible_payload_is_a_marker(self):
        value = manifest('ipv6')
        before, after = controls(value)
        result = evidence.analyze_bytes(pcap(before + [frame(value['probes'][1], extension=0)] + after), value)
        self.assertEqual(result['unknown_reasons'], {'unparsed_ipv6_next_header': 1})
        self.assertFalse(result['absence_observed'])
        self.assertIsNone(result['contained_markers_absent'])

    def test_matching_ipv4_ipsec_or_tunnel_cannot_hide_udp_as_zero_proof(self):
        value = manifest()
        before, after = controls(value)
        for protocol in (4, 41, 47, 50, 51):
            with self.subTest(protocol=protocol):
                outer = dict(value['probes'][1], source_ip='10.0.2.123')
                result = evidence.analyze_bytes(pcap(before + [frame(outer, protocol=protocol)] + after), value)
                self.assertEqual(result['unknown_reasons'], {'unparsed_ipv4_encapsulation': 1})
                self.assertFalse(result['absence_observed'])
        # A tunnel can change both source IP and outer address family.
        ipv6 = manifest('ipv6')
        before, after = controls(ipv6)
        result = evidence.analyze_bytes(pcap(before + [frame(value['probes'][1], protocol=41)] + after), ipv6)
        self.assertEqual(result['unknown_records'], 1)
        self.assertFalse(result['absence_observed'])

    def test_complete_unrelated_non_udp_header_does_not_require_reading_its_body(self):
        value = manifest('ipv6')
        before, after = controls(value)
        result = evidence.analyze_bytes(pcap(before + [frame(value['probes'][1], protocol=6, payload=b'private')] + after), value)
        self.assertEqual(result['unknown_records'], 0)
        self.assertTrue(result['absence_observed'])

    def test_truncated_pcap_headers_packets_and_snaplen_truncation_are_rejected(self):
        value = manifest()
        capture = pcap([frame(value['probes'][0])])
        cases = [capture[:23], capture[:30], capture[:-1]]
        changed = bytearray(capture)
        struct.pack_into('<I', changed, 36, len(capture) - 40 + 1)  # Original length differs.
        cases.append(bytes(changed))
        for data in cases:
            with self.assertRaises(evidence.EvidenceError):
                evidence.analyze_bytes(data, value)

    def test_unsupported_linktype_bad_magic_fraction_and_udp_length_are_rejected(self):
        value = manifest()
        packet = frame(value['probes'][0])
        good = pcap([packet])
        fraction = bytearray(good)
        struct.pack_into('<I', fraction, 28, 1_000_000)
        udp = bytearray(packet)
        struct.pack_into('!H', udp, 14 + 20 + 4, 9)
        cases = [pcap([packet], linktype=113), b'\x0a\x0d\x0d\x0a' + good[4:], bytes(fraction), pcap([bytes(udp)])]
        for data in cases:
            with self.assertRaises(evidence.EvidenceError):
                evidence.analyze_bytes(data, value)

    def test_manifest_rejects_missing_roles_ambiguous_markers_wrong_family_and_protocol(self):
        good = manifest()
        cases = []
        missing = copy.deepcopy(good); missing['probes'].pop(); cases.append(missing)
        duplicate = copy.deepcopy(good); duplicate['probes'][1]['payload_hex'] = duplicate['probes'][0]['payload_hex']; cases.append(duplicate)
        family = copy.deepcopy(good); family['probes'][0]['source_ip'] = '::1'; cases.append(family)
        protocol = copy.deepcopy(good); protocol['probes'][0]['protocol'] = 'tcp'; cases.append(protocol)
        tuple_mismatch = copy.deepcopy(good); tuple_mismatch['probes'][0]['port'] = 54; cases.append(tuple_mismatch)
        for value in cases:
            with self.assertRaises(evidence.EvidenceError):
                evidence.analyze_bytes(pcap([]), value)

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'Private POSIX QEMU captures only')
    def test_private_file_required_and_symlink_is_not_followed(self):
        value = manifest()
        before, after = controls(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.pcap'
            path.write_bytes(pcap(before + after))
            path.chmod(0o600)
            self.assertTrue(evidence.analyze_capture(path, value)['absence_observed'])
            path.chmod(0o644)
            with self.assertRaisesRegex(evidence.EvidenceError, 'capture_not_private_regular_file'):
                evidence.analyze_capture(path, value)
            path.chmod(0o600)
            link = Path(directory) / 'alias.pcap'
            link.symlink_to(path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'capture_open_failed'):
                evidence.analyze_capture(link, value)

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'Private POSIX QEMU captures only')
    def test_cli_sanitizes_failure_instead_of_serializing_bad_capture_or_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'PRIVATE_PATH_DO_NOT_EXPORT.pcap'
            capture.write_bytes(b'PRIVATE_PACKET_DO_NOT_EXPORT')
            capture.chmod(0o600)
            source = root / 'manifest.json'; source.write_text(json.dumps(manifest()))
            report = root / 'summary.json'
            with mock.patch('builtins.print'):
                code = evidence.main(['--pcap', str(capture), '--manifest', str(source), '--report', str(report)])
            self.assertEqual(code, 1)
            data = report.read_text()
            self.assertNotIn('PRIVATE_PATH_DO_NOT_EXPORT', data)
            self.assertNotIn('PRIVATE_PACKET_DO_NOT_EXPORT', data)
            self.assertFalse(json.loads(data)['absence_observed'])

    def test_report_cannot_overwrite_capture_or_manifest_even_when_capture_is_bad(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'raw.pcap'; capture.write_bytes(b'original raw evidence')
            source = root / 'manifest.json'; source.write_text(json.dumps(manifest()))
            for report in (capture, source):
                with self.subTest(report=report.name), mock.patch('sys.stderr'), self.assertRaises(SystemExit):
                    evidence.main(['--pcap', str(capture), '--manifest', str(source), '--report', str(report)])
            self.assertEqual(capture.read_bytes(), b'original raw evidence')
            self.assertEqual(json.loads(source.read_text()), manifest())

    @unittest.skipUnless(os.name == 'posix', 'POSIX QEMU capture privacy check')
    def test_failed_capture_analysis_cannot_overwrite_a_hardlinked_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = b'raw capture evidence that must remain intact'
            capture = root / 'raw.pcap'; capture.write_bytes(original); capture.chmod(0o600)
            report = root / 'summary.json'
            os.link(capture, root / 'summary.json.tmp')
            source = root / 'manifest.json'; source.write_text(json.dumps(manifest()))
            with mock.patch('builtins.print'):
                code = evidence.main(['--pcap', str(capture), '--manifest', str(source), '--report', str(report)])
            self.assertEqual(code, 1)
            self.assertEqual(capture.read_bytes(), original)
            self.assertEqual((root / 'summary.json.tmp').read_bytes(), original)
            self.assertEqual(json.loads(report.read_text())['error'], 'capture_not_private_regular_file')


if __name__ == '__main__':
    unittest.main()
