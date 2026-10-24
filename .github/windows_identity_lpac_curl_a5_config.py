"""Pure A5 Config2048 encoder. No file, clock, loader, process or API access.

Caller supplies observed facts and the complete child-table HANDLE_LIST6.
Bytes alone grant no identity, inheritance, Resume, network or cleanup authority.
"""
import struct

ACTUAL_READY = False
INTERFACE_VERSION = 1
PAYLOAD_GUID = 'a5193b72-5ad3-4f4b-ae3a-706564727073'
PAYLOAD_GUID_BYTES = bytes.fromhex('723b19a5d35a4b4fae3a706564727073')
CONFIG_BYTES = 2048
TRACE_BYTES = 557312
SHIM_BASENAME = 'windows_identity_lpac_curl_a5_http_shim.dll'
REQUEST_TOTAL, RESPONSE_TOTAL = 8193, 12289
REQUEST_HEADER, RESPONSE_HEADER = 128, 113
REQUEST_BODY, RESPONSE_BODY = 8065, 12176
MAX_QPC = (1 << 63) - 1
INVALID_HANDLE = (1 << 64) - 1
FIELDS = frozenset((
    'run', 'source_sha256', 'config_sha256', 'target_sha256', 'shim_sha256',
    'frequency', 'root_start', 'root_deadline', 'work_deadline', 'window_start',
    'window_end', 'target_pid', 'target_creation', 'trace_nonce', 'private_path',
    'system_ws2_path', 'case', 'port', 'virtual_local_port', 'inherited_handles'))


def need(condition, label):
    if not condition:
        raise ValueError(label)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def hexadecimal(value, size):
    need(type(value) is str and len(value) == size * 2
         and all(c in '0123456789abcdef' for c in value), 'a5_hex')
    raw = bytes.fromhex(value)
    need(any(raw), 'a5_zero_commitment')
    return raw


def path_ascii(value, basename, limit):
    need(type(value) is str and 3 < len(value) < limit, 'a5_path_size')
    need(value[0].isascii() and value[0].isalpha() and value[1:3] == ':\\', 'a5_path_root')
    need(all(32 <= ord(c) <= 126 for c in value)
         and not any(c in value for c in '/?*"<>|') and ':' not in value[2:], 'a5_path_literal')
    parts = value[3:].split('\\')
    need(all(p and p not in ('.', '..') and not p.endswith(('.', ' ')) for p in parts)
         and parts[-1] == basename, 'a5_path_component')
    return value.encode('ascii')


def fixed_headers(case, port):
    """Root-calibrated profile1; complete header/body totals, no learned input."""
    hexadecimal(case, 16)
    need(integer(port, 49153, 65535), 'a5_port')
    request = (f'POST /ruleproxy-a2/{case} HTTP/1.1\r\n'
               f'Host: 127.0.0.1:{port}\r\nContent-Length: 8065\r\n'
               'Connection: close\r\n\r\n').encode('ascii')
    response = ('HTTP/1.1 200 OK\r\nContent-Length: 12176\r\n'
                f'Connection: close\r\nX-RuleProxy-Case: {case}\r\n\r\n').encode('ascii')
    need(len(request) == REQUEST_HEADER and len(response) == RESPONSE_HEADER, 'a5_profile_header')
    return request, response


def pack_config(values):
    need(type(values) is dict and set(values) == FIELDS, 'a5_config_keys')
    f = values['frequency']; start = values['root_start']
    need(integer(f, 1, MAX_QPC // 120) and integer(start, 1, MAX_QPC - 120 * f), 'a5_root_clock')
    need(type(values['root_deadline']) is int and values['root_deadline'] == start + 120 * f
         and type(values['work_deadline']) is int and values['work_deadline'] == start + 85 * f, 'a5_original_epoch')
    s = values['window_start']; e = values['window_end']
    need(integer(s, start, values['work_deadline'] - 1) and s <= MAX_QPC - 8 * f
         and type(e) is int and e == min(s + 8 * f, values['work_deadline']) and s < e, 'a5_original_window')
    need(integer(values['target_pid'], 1, (1 << 32) - 1)
         and integer(values['target_creation'], 1, INVALID_HANDLE), 'a5_generation')
    handles = values['inherited_handles']
    need(type(handles) in (list, tuple) and len(handles) == 6
         and all(integer(h, 1, INVALID_HANDLE - 1) for h in handles)
         and len(set(handles)) == 6, 'a5_child_HANDLE_LIST6')
    # All six numbers belong to the selected child table, never the parent's
    # later-reused table. Order: trace, response_read, request_write, 3 stdio.
    run = hexadecimal(values['run'], 16)
    case = hexadecimal(values['case'], 16)
    nonce = hexadecimal(values['trace_nonce'], 16)
    need(len({run, case, nonce}) == 3, 'a5_distinct_cases')
    fixed_headers(values['case'], values['port'])
    need(integer(values['virtual_local_port'], 49153, 65535)
         and values['virtual_local_port'] != values['port'], 'a5_virtual_local_port')
    private = path_ascii(values['private_path'], SHIM_BASENAME, 1024)
    system = path_ascii(values['system_ws2_path'], 'WS2_32.dll', 260).decode('ascii').encode('utf-16-le')
    raw = bytearray(CONFIG_BYTES)
    struct.pack_into('<4sHH', raw, 0, b'A5P1', 1, CONFIG_BYTES)
    raw[8:24] = run
    for offset, name in ((24, 'source_sha256'), (56, 'config_sha256'),
                         (88, 'target_sha256'), (120, 'shim_sha256')):
        raw[offset:offset+32] = hexadecimal(values[name], 32)
    struct.pack_into('<6QIIQQ', raw, 152, f, start, values['root_deadline'], values['work_deadline'],
                     s, e, values['target_pid'], 0, values['target_creation'], handles[0])
    struct.pack_into('<4I', raw, 224, TRACE_BYTES, 256, len(private), len(system) // 2)
    raw[240:256] = nonce
    raw[256:256+len(private)] = private
    raw[1280:1280+len(system)] = system
    struct.pack_into('<QQ16sHHIIHHII', raw, 1800, handles[1], handles[2], case,
                     values['port'], 1, REQUEST_TOTAL, RESPONSE_TOTAL,
                     REQUEST_HEADER, RESPONSE_HEADER, REQUEST_BODY, RESPONSE_BODY)
    struct.pack_into('<HH', raw, 1856, values['virtual_local_port'], 0)
    return bytes(raw)
