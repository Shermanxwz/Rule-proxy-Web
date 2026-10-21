"""Pure, inactive runner-TCP capture contract; no capture/transport/actor actions.

Expected binding and completion facts MUST come from a future trusted controller.
This module does not authenticate their origin. Matches are captured tuple bytes,
not actor attribution or valid packet delivery (checksums are not validated).
No QPC-to-PCAP conversion, payload retention, network access, or acceptance change.
Format: libpcap pcap-savefile(5), RFC 791, RFC 9293. Classic Ethernet only.
"""
import hashlib
import json
import re
import struct

MAX_MANIFEST = 65536
MAX_PCAP = 64 * 1024 * 1024
MAX_RECORDS = 262144
MAX_SNAPLEN = 262144  # Actual producer header; not a promise to decode jumbo frames.
MAX_FRAME = 65536
BINDING_KEYS = {'run_nonce', 'case_nonce', 'actor_sha256', 'executor_sha256',
                'actor_source_sha256', 'identity_source_sha256', 'source_commit',
                'actor_report_sha256', 'ordinary_report_sha256', 'build', 'ubr'}
ENDPOINT_KEYS = {'vm_mac', 'destination_ipv4', 'destination_port'}
CAPTURE_KEYS = {'sha256', 'bytes', 'header_before_cases', 'shutdown_after_terminal',
                'fifo_eof', 'stderr_eof', 'dump_error', 'overflow', 'truncated',
                'fsynced', 'fd_closed', 'qemu_exited_orderly', 'qemu_killed',
                'sink_status', 'sink_exit_code'}
POSITIVE_CAPTURE = {'header_before_cases', 'shutdown_after_terminal', 'fifo_eof',
                    'stderr_eof', 'fsynced', 'fd_closed', 'qemu_exited_orderly'}
NEGATIVE_CAPTURE = {'dump_error', 'overflow', 'truncated', 'qemu_killed'}


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _hex(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def _object(value, keys):
    return type(value) is dict and set(value) == keys


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('manifest')
        value[key] = item
    return value


def validate_manifest(raw, expected):
    """Return private validated structure plus collision flag; never log result.

    The expected digest binds ALL flow rows, not merely self-declared hashes.
    A collision is retained separately so positive tuple observations survive,
    but it always prevents an absence conclusion.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_MANIFEST:
        raise ValueError('manifest')
    if not _object(expected, {'binding', 'endpoint', 'manifest_sha256', 'connect_controls_verified'}):
        raise ValueError('binding')
    if type(expected['connect_controls_verified']) is not bool:
        raise ValueError('binding')
    if not _hex(expected['manifest_sha256'], 64) or hashlib.sha256(raw).hexdigest() != expected['manifest_sha256']:
        raise ValueError('binding')
    try:
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('manifest')))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('manifest') from None
    if not _object(value, {'schema_version', 'binding', 'endpoint', 'selected', 'ordinary'}) or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('manifest')
    binding = value['binding']
    if not _object(binding, BINDING_KEYS):
        raise ValueError('manifest')
    for key in BINDING_KEYS - {'build', 'ubr'}:
        size = 32 if key.endswith('nonce') else 40 if key == 'source_commit' else 64
        if not _hex(binding[key], size):
            raise ValueError('manifest')
    if type(binding['build']) is not int or binding['build'] != 26300 or type(binding['ubr']) is not int or binding['ubr'] != 9457:
        raise ValueError('manifest')
    endpoint = value['endpoint']
    if not _object(endpoint, ENDPOINT_KEYS) or not _hex(endpoint['vm_mac'], 12) or endpoint['destination_ipv4'] != '10.0.2.2' or not _integer(endpoint['destination_port'], 1025, 65535):
        raise ValueError('manifest')
    mac = bytes.fromhex(endpoint['vm_mac'])
    if mac == b'\0' * 6 or mac[0] & 1:
        raise ValueError('manifest')
    if (not _object(expected['binding'], BINDING_KEYS) or not _object(expected['endpoint'], ENDPOINT_KEYS)
            or any(type(binding[key]) is not type(expected['binding'][key]) for key in BINDING_KEYS)
            or any(type(endpoint[key]) is not type(expected['endpoint'][key]) for key in ENDPOINT_KEYS)
            or binding != expected['binding'] or endpoint != expected['endpoint']):
        raise ValueError('binding')
    selected, ordinary = value['selected'], value['ordinary']
    if type(selected) is not list or len(selected) != 3 or type(ordinary) is not list or not 3 <= len(ordinary) <= 42:
        raise ValueError('manifest')
    for index, row in enumerate(selected):
        if not _object(row, {'index', 'source_port'}) or type(row['index']) is not int or row['index'] != index or not _integer(row['source_port'], 1, 65535):
            raise ValueError('manifest')
    # Existing actor lifecycle: final after connection is the terminal witness.
    # Samples span the QPC window; they are NOT all asserted to be inside it.
    phases = ['before'] + ['sample'] * (len(ordinary) - 2) + ['after']
    for index, (row, phase) in enumerate(zip(ordinary, phases)):
        if (not _object(row, {'phase', 'index', 'source_port', 'connect_succeeded', 'nonce_verified'})
                or row['phase'] != phase or type(row['index']) is not int or row['index'] != index
                or not _integer(row['source_port'], 1, 65535)
                or row['connect_succeeded'] is not True or row['nonce_verified'] is not True):
            raise ValueError('manifest')
    ports = [row['source_port'] for row in selected + ordinary]
    return value, len(set(ports)) != len(ports)


def decode_pcap(data, endpoint, selected_ports, ordinary_ports):
    """Private bounded decoder result; fixed target inputs must already validate.

    ARP and IPv6 are deliberately outside this IPv4 TCP claim. Unknown guest
    encapsulation prevents absence. Retransmitted frames are not port collisions.
    Earlier tuple observations survive a later malformed/truncated record.
    A capture-digest mismatch also retains only a byte observation, never a
    run-attributed packet; manifest binding mismatch does not decode a scope.
    """
    result = {'selected_seen': set(), 'ordinary_first': {}, 'unknown_packets': 0,
              'records': 0, 'reasons': set()}
    def bad(reason):
        result['reasons'].add(reason)
    if type(data) is not bytes or len(data) > MAX_PCAP:
        bad('capture_bound'); return result
    if len(data) < 24:
        bad('header'); return result
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
               b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
    if data[:4] not in formats:
        bad('header'); return result
    endian, scale = formats[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack_from(endian + 'HHIIII', data, 4)
    if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_SNAPLEN or linktype != 1:
        bad('header'); return result
    source_mac = bytes.fromhex(endpoint['vm_mac'])
    destination = b'\x0a\x00\x02\x02'
    view = memoryview(data)
    offset = 24
    while offset < len(data):
        if result['records'] >= MAX_RECORDS:
            bad('record_bound'); break
        if len(data) - offset < 16:
            bad('truncated'); break
        _, fraction, captured, original = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        if fraction >= scale or captured > snaplen or captured > original:
            bad('record'); break
        if captured != original:
            bad('truncated')
        if captured > MAX_FRAME:
            bad('frame_bound'); break
        if len(data) - offset < captured:
            bad('truncated'); break
        frame = view[offset:offset + captured]
        offset += captured
        result['records'] += 1
        if len(frame) < 14:
            bad('ethernet'); continue
        if frame[6:12] != source_mac:
            continue
        ether_type = int.from_bytes(frame[12:14], 'big')
        if ether_type in (0x0806, 0x86dd):
            continue
        if ether_type != 0x0800:
            bad('encapsulation'); continue
        ip = frame[14:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            bad('ipv4'); continue
        ihl = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], 'big')
        if ihl < 20 or total < ihl or total > len(ip):
            bad('ipv4'); continue
        if ip[16:20] != destination or ip[9] != 6:
            continue
        fragments = int.from_bytes(ip[6:8], 'big')
        if fragments & 0x3fff:
            bad('fragment'); continue
        if fragments & 0x8000:
            bad('ipv4'); continue
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            bad('tcp'); continue
        header = (tcp[12] >> 4) * 4
        if header < 20 or header > len(tcp):
            bad('tcp'); continue
        source_port, destination_port = struct.unpack_from('!HH', tcp)
        if destination_port != endpoint['destination_port']:
            continue
        if source_port in selected_ports:
            result['selected_seen'].add(source_port)
        if source_port in ordinary_ports:
            if tcp[13] & 0x02 and not tcp[13] & 0x15:
                result['ordinary_first'].setdefault(source_port, result['records'])
        elif source_port not in selected_ports:
            result['unknown_packets'] += 1
            bad('unknown_flow')
    if not result['records']:
        bad('empty')
    return result


def evaluate(data, manifest_bytes, expected, capture):
    """Return closed diagnostics only. No isolation or actor-leak pass exists."""
    public = {'schema_version': 1, 'status': 'inconclusive',
              'manifest_valid': False, 'binding_contract_matched': False,
              'ports_unique': False, 'connect_controls_contract': False, 'capture_complete_contract': False,
              'decoder_complete': False, 'ordinary_syn_controls': False,
              'tuple_packet_observed': None, 'selected_ports_observed': 0,
              'unknown_flow_packets': 0, 'records': 0, 'reasons': [],
              'actor_attribution_established': False, 'isolation_acceptance': False,
              'checksums_validated': False, 'qpc_timestamp_mapping_used': False}
    try:
        manifest, collision = validate_manifest(manifest_bytes, expected)
    except ValueError as error:
        public['reasons'] = ['binding' if str(error) == 'binding' else 'manifest']
        return public
    public['manifest_valid'] = True
    public['binding_contract_matched'] = True
    public['ports_unique'] = not collision
    public['connect_controls_contract'] = expected['connect_controls_verified']
    decoded = decode_pcap(data, manifest['endpoint'],
                          {r['source_port'] for r in manifest['selected']},
                          {r['source_port'] for r in manifest['ordinary']})
    reasons = decoded['reasons']
    public['decoder_complete'] = not reasons
    public['tuple_packet_observed'] = bool(decoded['selected_seen'])
    public['selected_ports_observed'] = len(decoded['selected_seen'])
    public['unknown_flow_packets'] = decoded['unknown_packets']
    public['records'] = decoded['records']
    if collision:
        reasons.add('port_collision')
    if not expected['connect_controls_verified']:
        reasons.add('connect_controls')
    capture_ok = (_object(capture, CAPTURE_KEYS)
                  and type(data) is bytes and len(data) <= MAX_PCAP and _hex(capture.get('sha256'), 64)
                  and capture['sha256'] == hashlib.sha256(data).hexdigest()
                  and _integer(capture.get('bytes'), 24, MAX_PCAP) and capture['bytes'] == len(data)
                  and all(capture[key] is True for key in POSITIVE_CAPTURE)
                  and all(capture[key] is False for key in NEGATIVE_CAPTURE)
                  and type(capture['sink_status']) is str and capture['sink_status'] == 'complete'
                  and type(capture['sink_exit_code']) is int and capture['sink_exit_code'] == 0)
    public['capture_complete_contract'] = capture_ok
    if not capture_ok:
        reasons.add('capture_lifecycle')
    indices = [decoded['ordinary_first'].get(row['source_port']) for row in manifest['ordinary']]
    controls = (all(type(index) is int for index in indices)
                and indices[-1] > max(indices[:-1]))
    public['ordinary_syn_controls'] = controls
    if not controls:
        reasons.add('ordinary_syn')
    if public['tuple_packet_observed'] and not reasons:
        public['status'] = 'tuple_packet_observed'
    elif not reasons:
        public['status'] = 'no_selected_tuple_observed'
    public['reasons'] = sorted(reasons)
    return public
