"""Independent ABI2 input packing. Pure bytes only; no OS or DLL access.

Inputs originate from the guarded owner's admitted generation, retained file
leases and predeclared current-primary baseline. Native output is never used
to revise those expectations. This module does not authorize an actual run.
"""
import re
import struct
import uuid

MAX_QPC = (1 << 63) - 1
MAX_HANDLE = (1 << 64) - 2
CMM_GUID = 'b4626452-3359-4b34-9a97-dd85e4b79f2c'


def require(condition, label):
    if not condition:
        raise ValueError('cmm_input_' + label)


def integer(value, lower=0, upper=(1 << 32) - 1):
    return type(value) is int and lower <= value <= upper


def sid_bytes(value):
    require(type(value) is str and re.fullmatch(r'S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){0,15}', value), 'SID_text')
    parts = [int(item) for item in value.split('-')[2:]]
    authority, sub = parts[0], parts[1:]
    require(authority < 1 << 48 and all(item < 1 << 32 for item in sub), 'SID_range')
    return bytes((1, len(sub))) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', item) for item in sub)


def digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) and value != '0' * 64, 'digest')
    return bytes.fromhex(value)


def utf16(value, limit, *, dos=False):
    require(type(value) is str and 0 < len(value) < limit and '\0' not in value, 'text_extent')
    require(all(32 <= ord(ch) < 127 for ch in value) if dos else all(ord(ch) >= 32 for ch in value), 'text_chars')
    if dos:
        require(re.fullmatch(r'[A-Za-z]:\\[^/:?*"<>|]+', value) is not None
                and '..' not in value.split('\\'), 'DOS_path')
    else:
        require(value.startswith('\\Device\\HarddiskVolume') and '/' not in value
                and '..' not in value.split('\\'), 'NT_path')
    raw = value.encode('utf-16-le')
    require(len(raw) == len(value) * 2, 'UTF16_scalar')
    return raw + b'\0\0'


def identity_bytes(primary):
    keys = {'sid', 'session_id', 'token_type', 'impersonation_level', 'appcontainer',
            'appcontainer_sid', 'integrity_rid', 'elevated', 'ui_access', 'capabilities',
            'token_id', 'authentication_id'}
    require(type(primary) is dict and set(primary) == keys, 'identity_keys')
    require(primary['token_type'] == 1 and type(primary['token_type']) is int
            and primary['impersonation_level'] is None and primary['appcontainer'] is True
            and primary['integrity_rid'] == 4096 and type(primary['integrity_rid']) is int
            and primary['elevated'] is False and primary['ui_access'] is False
            and primary['capabilities'] == [] and type(primary['capabilities']) is list
            and integer(primary['session_id'])
            and integer(primary['token_id'], 1, (1 << 64) - 1)
            and integer(primary['authentication_id'], 1, (1 << 64) - 1), 'zero_primary')
    user = sid_bytes(primary['sid'])
    ac = sid_bytes(primary['appcontainer_sid'])
    require(primary['appcontainer_sid'].startswith('S-1-15-2-'), 'AC_SID')
    raw = bytearray(256)
    struct.pack_into('<IIII', raw, 0, 256, 2, len(user), len(ac))
    raw[16:16 + len(user)] = user
    raw[84:84 + len(ac)] = ac
    struct.pack_into('<IIIIIIIIQQ', raw, 152, primary['session_id'], 1, 0xffffffff,
                     4096, 1, 0, 0, 0, primary['token_id'], primary['authentication_id'])
    return bytes(raw)


def security_bytes(security, parent_sid):
    require(type(security) is dict and set(security) == {'process', 'thread'}, 'SD_keys')
    sid_bytes(parent_sid)
    masks = ('GA', '0x1fffff')
    admitted = {'D:P(A;;' + system + ';;;SY)(A;;' + parent + ';;;' + parent_sid + ')'
                for system in masks for parent in masks}
    raw = bytearray(1024)
    struct.pack_into('<II', raw, 0, 1024, 2)
    for index, key in enumerate(('process', 'thread')):
        value = security[key]
        require(type(value) is str and value in admitted and 0 < len(value) <= 247, 'private_SD')
        encoded = value.encode('utf-16-le') + b'\0\0'
        struct.pack_into('<I', raw, 8 + 4 * index, len(value))
        start = 16 + 496 * index
        raw[start:start + len(encoded)] = encoded
    return bytes(raw)


def pe_bytes(shape, *, dll):
    keys = {'machine', 'timestamp', 'entry_rva', 'image_bytes', 'header_bytes', 'subsystem', 'is_dll'}
    require(type(shape) is dict and set(shape) == keys
            and all(integer(shape[key]) for key in keys - {'is_dll'})
            and type(shape['is_dll']) is bool and shape['is_dll'] is dll
            and shape['machine'] == 0x8664
            and 0 < shape['entry_rva'] < shape['image_bytes'] <= 64 * 1024 * 1024
            and 512 <= shape['header_bytes'] <= 4096, 'PE_shape')
    return struct.pack('<IIIIIIII', 32, shape['machine'], shape['timestamp'],
                       shape['entry_rva'], shape['image_bytes'], shape['header_bytes'],
                       shape['subsystem'], int(dll))


def file_id_bytes(fact):
    require(type(fact) is dict and set(fact) == {'nt_path', 'volume_serial', 'file_id'}, 'file_fact')
    utf16(fact['nt_path'], 1024)
    require(integer(fact['volume_serial'], 0, (1 << 64) - 1)
            and type(fact['file_id']) is str and re.fullmatch('[0-9a-f]{32}', fact['file_id']), 'file_id')
    raw = struct.pack('<Q', fact['volume_serial']) + bytes.fromhex(fact['file_id'])
    require(any(raw), 'file_id_zero')
    return raw


def epoch(config, window):
    require(type(window) is dict and set(window) == {'start', 'end'}, 'window_keys')
    f, start, deadline = (config[key] for key in ('frequency', 'start_qpc', 'root_deadline_qpc'))
    require(integer(f, 1, MAX_QPC // 120) and integer(start, 1, MAX_QPC - 120 * f)
            and deadline == start + 120 * f and type(deadline) is int
            and integer(window['start'], start, deadline - 35 * f - 1)
            and type(window['end']) is int
            and window['end'] == min(window['start'] + 8 * f, deadline - 35 * f), 'original_epoch')
    return f, start, deadline, window['start'], window['end']


def marker_bytes(config, window, generation, signals):
    values = epoch(config, window)
    require(type(generation) is dict and set(generation) == {'pid', 'created'}
            and integer(generation['pid'], 1) and integer(generation['created'], 1, MAX_QPC), 'generation')
    require(type(signals) is list and len(signals) == 2 and len(set(signals)) == 2
            and all(integer(item, 1, MAX_HANDLE) for item in signals), 'signals')
    raw = bytearray(320)
    struct.pack_into('<4sHH', raw, 0, b'CMM2', 2, 320)
    require(type(config['run']) is str and re.fullmatch('[0-9a-f]{32}', config['run'])
            and config['run'] != '0' * 32, 'nonce')
    raw[8:24] = bytes.fromhex(config['run'])
    raw[24:56] = digest(config['config_sha256'])
    raw[56:88] = digest(config['source_sha256'])
    raw[88:120] = digest(config['marker_sha256'])
    struct.pack_into('<QQQQQ', raw, 120, *values)
    struct.pack_into('<I', raw, 160, generation['pid'])
    struct.pack_into('<QQQII', raw, 168, generation['created'], *signals, 128, 2)
    return bytes(raw)


def plan_bytes(config, window, generation, handles, pointers, paths, target, marker, payload_guid):
    """Pack one ABI2 plan; pointers are owner-held buffer addresses, not proof."""
    values = epoch(config, window)
    require(type(generation) is dict and set(generation) == {'pid', 'created'}
            and integer(generation['pid'], 1) and integer(generation['created'], 1, MAX_QPC), 'generation')
    handle_names = ('process', 'thread', 'primary_token', 'inner_job', 'outer_job',
                    'entered_event', 'body_event', 'target_lease', 'marker_lease')
    pointer_names = ('target_path', 'marker_nt_path', 'marker_ascii_path', 'expected_identity', 'expected_security')
    require(type(handles) is dict and set(handles) == set(handle_names)
            and all(integer(handles[key], 1, MAX_HANDLE) for key in handle_names)
            and len(set(handles.values())) == 9, 'borrowed_handles')
    require(type(pointers) is dict and set(pointers) == set(pointer_names)
            and all(integer(pointers[key], 0x10000, (1 << 47) - 4096) for key in pointer_names)
            and len(set(pointers.values())) == 5, 'input_pointers')
    require(type(paths) is dict and set(paths) == {'target', 'marker_nt', 'marker_ascii'}, 'path_keys')
    utf16(paths['target'], 260, dos=True)
    utf16(paths['marker_nt'], 1024)
    require(type(paths['marker_ascii']) is str and 0 < len(paths['marker_ascii']) <= 1023
            and all(32 <= ord(ch) <= 126 for ch in paths['marker_ascii'])
            and '\0' not in paths['marker_ascii'], 'marker_ASCII')
    require(type(config['run']) is str and re.fullmatch('[0-9a-f]{32}', config['run'])
            and config['run'] != '0' * 32, 'nonce')
    raw = bytearray(512)
    struct.pack_into('<IIQQQQQI', raw, 0, 512, 2, *values, generation['pid'])
    struct.pack_into('<Q', raw, 56, generation['created'])
    struct.pack_into('<9Q', raw, 64, *(handles[key] for key in handle_names))
    raw[136:152] = bytes.fromhex(config['run'])
    for offset, key in ((152, 'config_sha256'), (184, 'source_sha256'), (216, 'target_sha256'), (248, 'marker_sha256')):
        raw[offset:offset + 32] = digest(config[key])
    for offset, key, count in ((280, 'target_path', len(paths['target'])),
                               (296, 'marker_nt_path', len(paths['marker_nt'])),
                               (312, 'marker_ascii_path', len(paths['marker_ascii'])),
                               (328, 'expected_identity', 256), (344, 'expected_security', 1024)):
        struct.pack_into('<QI', raw, offset, pointers[key], count)
    for offset, value, dll in ((360, target, False), (384, marker, True)):
        require(type(value) is dict and set(value) == {'fact', 'bytes', 'pe'}
                and integer(value['bytes'], 1, 8 * 1024 * 1024), 'retained_file')
        raw[offset:offset + 24] = file_id_bytes(value['fact'])
        raw[408 + 32 * int(dll):440 + 32 * int(dll)] = pe_bytes(value['pe'], dll=dll)
        struct.pack_into('<Q', raw, 488 + 8 * int(dll), value['bytes'])
    require(marker['fact']['nt_path'] == paths['marker_nt'], 'marker_NT_binding')
    require(type(payload_guid) is str and payload_guid == CMM_GUID, 'GUID')
    guid = uuid.UUID(payload_guid)
    require(guid.int != 0, 'GUID_zero')
    raw[472:488] = guid.bytes_le
    return bytes(raw)
