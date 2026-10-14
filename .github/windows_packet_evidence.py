"""Summarize private QEMU Ethernet PCAPs without exposing their packet bodies.

This tool observes fixed UDP probe markers on the captured VM NIC. Absence is
not a kernel-denial claim or product acceptance. The caller must finish QEMU,
reject its dump/write errors, and prove that both contained senders ran between
the outside controls. Raw PCAPs stay private and must never be artifacts.

Manifest: schema_version=1, probes=[{id, group, role, family, protocol:'udp',
source_mac, source_ip, destination, port, payload_hex, minimum_count?}]. Each
group contains exactly outside_before, parent, child, outside_after, with a
common source/destination tuple and four distinct nonempty fixed markers.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile

MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_FRAME_BYTES = 1024 * 1024
MAX_RECORDS = 5_000_000
MAX_MANIFEST_BYTES = 128 * 1024
ROLES = ('outside_before', 'parent', 'child', 'outside_after')
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
MAGICS = {b'\xd4\xc3\xb2\xa1': ('<', 1_000_000), b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
          b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000), b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000)}


class EvidenceError(ValueError):
    """Fixed error codes only: never include path, address or raw packet data."""


def prepare_manifest(value):
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or not isinstance(value.get('probes'), list)
            or not 1 <= len(value['probes']) <= 64):
        raise EvidenceError('invalid_manifest')
    probes, groups, ids, wires = [], {}, set(), set()
    required = {'id', 'group', 'role', 'family', 'protocol', 'source_mac', 'source_ip',
                'destination', 'port', 'payload_hex'}
    for item in value['probes']:
        if not isinstance(item, dict) or not required <= item.keys() or item.keys() - required - {'minimum_count'}:
            raise EvidenceError('invalid_probe_fields')
        if any(not isinstance(item[k], str) or not IDENTIFIER.fullmatch(item[k]) for k in ('id', 'group')):
            raise EvidenceError('invalid_probe_identifier')
        if item['id'] in ids or item['role'] not in ROLES or item['family'] not in ('ipv4', 'ipv6') or item['protocol'] != 'udp':
            raise EvidenceError('invalid_probe_role_or_identity')
        ids.add(item['id'])
        if not isinstance(item['source_mac'], str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', item['source_mac']):
            raise EvidenceError('invalid_source_mac')
        mac = bytes.fromhex(item['source_mac'].replace(':', ''))
        if not any(mac) or mac[0] & 1:
            raise EvidenceError('invalid_source_mac')
        try:
            if any(not isinstance(item[k], str) or '%' in item[k] for k in ('source_ip', 'destination')):
                raise ValueError()
            source, destination = ipaddress.ip_address(item['source_ip']), ipaddress.ip_address(item['destination'])
        except ValueError as exc:
            raise EvidenceError('invalid_ip_literal') from exc
        version = 4 if item['family'] == 'ipv4' else 6
        if (source.version != version or destination.version != version or source.is_unspecified
                or source.is_multicast or (version == 6 and (source.ipv4_mapped or destination.ipv4_mapped))):
            raise EvidenceError('invalid_ip_family_or_source')
        if type(item['port']) is not int or not 1 <= item['port'] <= 65535:
            raise EvidenceError('invalid_destination_port')
        marker = item['payload_hex']
        if not isinstance(marker, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,512}', marker):
            raise EvidenceError('invalid_payload_marker')
        marker = bytes.fromhex(marker)
        minimum = item.get('minimum_count', 1)
        if type(minimum) is not int or not 1 <= minimum <= 1000:
            raise EvidenceError('invalid_control_minimum')
        base = (mac, version, source.packed, destination.packed, item['port'])
        wire = base + (marker,)
        if wire in wires:
            raise EvidenceError('ambiguous_probe_marker')
        wires.add(wire)
        probe = dict(id=item['id'], group=item['group'], role=item['role'], base=base,
                     payload=marker, minimum=minimum, count=0, first=None, last=None)
        probes.append(probe)
        groups.setdefault(item['group'], []).append(probe)
    for group in groups.values():
        if len(group) != 4 or {p['role'] for p in group} != set(ROLES):
            raise EvidenceError('missing_or_duplicate_group_roles')
        if len({p['base'] for p in group}) != 1 or len({p['payload'] for p in group}) != 4:
            raise EvidenceError('group_controls_do_not_match_sender_tuple')
    canonical = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return probes, groups, hashlib.sha256(canonical).hexdigest()


class Reader:
    def __init__(self, stream):
        self.stream, self.digest, self.total = stream, hashlib.sha256(), 0

    def read(self, length, *, allow_eof=False):
        data = self.stream.read(length)
        self.total += len(data)
        if self.total > MAX_CAPTURE_BYTES:
            raise EvidenceError('capture_size_limit')
        self.digest.update(data)
        if not data and allow_eof:
            return None
        if len(data) != length:
            raise EvidenceError('incomplete_capture_record')
        return data


def udp_frame(frame, probes):
    """Return a UDP tuple/payload or a fixed unknown code, never read TCP bodies."""
    if len(frame) < 14:
        raise EvidenceError('malformed_ethernet_header')
    mac = frame[6:12]
    offset, ethertype, vlan_count = 14, struct.unpack_from('!H', frame, 12)[0], 0
    while ethertype in (0x8100, 0x88a8, 0x9100):
        vlan_count += 1
        if len(frame) < offset + 4:
            raise EvidenceError('malformed_vlan_header')
        if vlan_count > 4:
            return None, 'unsupported_vlan_stack' if any(p['base'][0] == mac for p in probes) else None
        ethertype = struct.unpack_from('!H', frame, offset + 2)[0]
        offset += 4
    if ethertype not in (0x0800, 0x86DD):
        return None, None
    if ethertype == 0x0800:
        if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
            raise EvidenceError('malformed_ipv4_header')
        ihl = (frame[offset] & 15) * 4
        length = struct.unpack_from('!H', frame, offset + 2)[0]
        if ihl < 20 or ihl > 60 or length < ihl or len(frame) < offset + length:
            raise EvidenceError('malformed_ipv4_length')
        protocol, source, destination = frame[offset + 9], frame[offset + 12:offset + 16], frame[offset + 16:offset + 20]
        # Opaque packets can carry a different outer IP. The watched VM MAC
        # still makes their hidden contents relevant to an absence claim.
        identity = any(p['base'][0] == mac for p in probes)
        fragment = struct.unpack_from('!H', frame, offset + 6)[0]
        if fragment & 0x8000:
            raise EvidenceError('malformed_ipv4_fragment_flags')
        options = frame[offset + 20:offset + ihl]
        index, source_routed = 0, False
        while index < len(options):
            option = options[index]
            if option == 0:
                break
            if option == 1:
                index += 1
                continue
            if index + 2 > len(options) or options[index + 1] < 2 or index + options[index + 1] > len(options):
                raise EvidenceError('malformed_ipv4_options')
            source_routed |= option in (131, 137)
            index += options[index + 1]
        if protocol != 17:
            # IP-in-IP, GRE and IPsec can hide a fixed UDP marker. Preserve
            # uncertainty rather than treating an opaque sender packet as zero.
            return None, ('unparsed_ipv4_encapsulation' if identity and protocol in (4, 41, 47, 50, 51)
                          else None)
        if identity and source_routed:
            return None, 'unparsed_ipv4_source_route'
        target = any(p['base'][:2] == (mac, 4) and p['base'][3] == destination for p in probes)
        if fragment & 0x3FFF:
            return None, 'unparsed_ipv4_udp_fragment' if target else None
        version, start, end = 4, offset + ihl, offset + length
    else:
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
            raise EvidenceError('malformed_ipv6_header')
        length, protocol = struct.unpack_from('!H', frame, offset + 4)[0], frame[offset + 6]
        if len(frame) < offset + 40 + length:
            raise EvidenceError('malformed_ipv6_length')
        source, destination = frame[offset + 8:offset + 24], frame[offset + 24:offset + 40]
        identity = any(p['base'][0] == mac for p in probes)
        if protocol in (6, 58, 59):  # TCP, ICMPv6 or no next header: no UDP marker.
            return None, None
        if protocol != 17:
            # Routing headers could change the apparent destination. Do not
            # treat unsupported extensions/encryption from this source as zero.
            return None, 'unparsed_ipv6_next_header' if identity else None
        version, start, end = 6, offset + 40, offset + 40 + length
    if end - start < 8:
        raise EvidenceError('malformed_udp_header')
    source_port, destination_port, length, _checksum = struct.unpack_from('!HHHH', frame, start)
    if length < 8 or length != end - start:
        raise EvidenceError('malformed_udp_length')
    base = (mac, version, source, destination, destination_port)
    if not any(p['base'] == base for p in probes):
        # A temporary address change must not hide the exact contained marker.
        # Only inspect UDP to a selected destination; no unrelated HTTP bodies.
        candidates = [p for p in probes if p['base'][0:2] == (mac, version)
                      and p['base'][3:5] == (destination, destination_port)]
        if any(p['payload'] == frame[start + 8:end] for p in candidates):
            return None, 'probe_marker_unexpected_source_ip'
        return None, None
    # Checksums can be partial before NIC offload; matching is exact tuple,
    # complete IP/UDP lengths and complete marker bytes, not checksum inference.
    return (base, frame[start + 8:end]), None


def analyze_stream(stream, manifest):
    probes, groups, manifest_hash = prepare_manifest(manifest)
    reader = Reader(stream)
    header = reader.read(24)
    if header[:4] not in MAGICS:
        raise EvidenceError('unsupported_capture_format')
    endian, fraction_limit = MAGICS[header[:4]]
    major, minor, _zone, _accuracy, snaplen, linktype = struct.unpack(endian + 'HHiiII', header[4:])
    if (major, minor) != (2, 4) or linktype != 1 or not 14 <= snaplen <= MAX_FRAME_BYTES:
        raise EvidenceError('unsupported_capture_header')
    unknown, records = {}, 0
    while True:
        record = reader.read(16, allow_eof=True)
        if record is None:
            break
        records += 1
        if records > MAX_RECORDS:
            raise EvidenceError('capture_record_limit')
        _seconds, fraction, captured, original = struct.unpack(endian + 'IIII', record)
        if fraction >= fraction_limit or captured != original or not 14 <= captured <= snaplen:
            raise EvidenceError('truncated_or_invalid_capture_packet')
        match, reason = udp_frame(reader.read(captured), probes)
        if reason:
            unknown[reason] = unknown.get(reason, 0) + 1
        if match:
            base, marker = match
            for probe in probes:
                if probe['base'] == base and probe['payload'] == marker:
                    probe['count'] += 1
                    probe['first'] = records if probe['first'] is None else probe['first']
                    probe['last'] = records
    controls_complete, contained_absent, windows_ordered = True, True, True
    group_results = []
    for name, group in groups.items():
        roles = {p['role']: p for p in group}
        before, after = roles['outside_before'], roles['outside_after']
        controls = all(roles[r]['count'] >= roles[r]['minimum'] for r in ('outside_before', 'outside_after'))
        ordered = controls and before['last'] < after['first']
        # If a contained marker was delivered, it must lie within the controls
        # to make this interval interpretable. It still invalidates absence.
        if ordered:
            ordered = all(p['count'] == 0 or (before['last'] < p['first'] <= p['last'] < after['first'])
                          for p in (roles['parent'], roles['child']))
        absent = roles['parent']['count'] == roles['child']['count'] == 0
        controls_complete &= controls
        windows_ordered &= bool(ordered)
        contained_absent &= absent
        group_results.append({'id': name, 'positive_controls_complete': controls,
                              'control_window_ordered': bool(ordered),
                              'contained_markers_absent': absent if not unknown and controls and ordered else None})
    complete = not unknown and controls_complete and windows_ordered
    return {'schema_version': 1, 'status': 'complete' if complete else 'incomplete',
            'scope': 'captured_qemu_vm_nic_egress', 'acceptance_passed': False,
            'kernel_denial_proven': False, 'capture_format_complete': True,
            'capture_sha256': reader.digest.hexdigest(), 'capture_bytes': reader.total,
            'manifest_sha256': manifest_hash, 'packet_records': records,
            'positive_controls_complete': controls_complete, 'control_windows_ordered': windows_ordered,
            'unknown_records': sum(unknown.values()), 'unknown_reasons': unknown,
            'contained_markers_absent': contained_absent if complete else None,
            'absence_observed': complete and contained_absent,
            'groups': group_results,
            'counts': [{'id': p['id'], 'group': p['group'], 'role': p['role'], 'count': p['count'],
                        'payload_sha256': hashlib.sha256(p['payload']).hexdigest()} for p in probes]}


def analyze_bytes(data, manifest):
    """Pure format/marker analysis for constructed-packet tests; no file claim."""
    return analyze_stream(io.BytesIO(data), manifest)


def analyze_capture(path, manifest):
    # This evidence tool runs on the Linux QEMU host. Windows mode bits do not
    # prove NTFS privacy, so refuse that file-level claim on other platforms.
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        raise EvidenceError('capture_private_mode_not_supported')
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_size > MAX_CAPTURE_BYTES):
            raise EvidenceError('capture_not_private_regular_file')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            result = analyze_stream(stream, manifest)
            after = os.fstat(stream.fileno())
        if (before.st_size != result['capture_bytes'] or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise EvidenceError('capture_changed_during_read')
        return result
    except OSError as exc:
        raise EvidenceError('capture_open_failed') from exc
    finally:
        if fd is not None:
            os.close(fd)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(arguments)
    temporary = args.report.with_suffix(args.report.suffix + '.tmp')
    inputs = {args.pcap.resolve(), args.manifest.resolve()}
    if args.report.resolve() in inputs or temporary.resolve() in inputs:
        parser.error('report paths must differ from capture and manifest')
    try:
        with args.manifest.open('rb') as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise EvidenceError('manifest_size_limit')
        result = analyze_capture(args.pcap, json.loads(raw))
        code = 0 if result['status'] == 'complete' else 1
    except (EvidenceError, ValueError, OSError):
        exc = sys.exc_info()[1]
        reason = str(exc) if isinstance(exc, EvidenceError) else 'invalid_or_unreadable_manifest'
        result = {'schema_version': 1, 'status': 'incomplete', 'acceptance_passed': False,
                  'kernel_denial_proven': False, 'capture_format_complete': False, 'absence_observed': False,
                  'error': reason}
        code = 1
    # The report contains only counters, fixed codes and hashes, never addresses,
    # original markers, paths, packet bodies or raw PCAP references.
    # Exclusive temporary creation avoids following a pre-existing .tmp link
    # or modifying an input inode through a hard-linked output placeholder.
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='ascii', dir=args.report.parent,
                                         prefix='.packet-summary-', delete=False) as output:
            pending = Path(output.name)
            output.write(json.dumps(result, ensure_ascii=True, indent=2) + '\n')
        os.replace(pending, args.report)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    print(json.dumps({'status': result['status'], 'absence_observed': result['absence_observed']}, ensure_ascii=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
