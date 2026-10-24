"""Pure byte decoder for the new A4 startup diagnostic.

Private decoded facts may contain captured arguments or identities. Only review()
is intended as a safe projection. This module never opens files or invokes an OS
adapter, and an inner diagnostic can never qualify outer execution or cleanup.
The ABI03 trace tables are filled only from the author's final source contract.
"""
import struct
import hashlib

ACTUAL_READY = False
CONFIG_BYTES = 2048
HEADER_BYTES = 256
ROW_BYTES = 2176
CAPACITY = 256
TRACE_BYTES = HEADER_BYTES + CAPACITY * ROW_BYTES
GUID = '8b743b1e-2850-4c82-a350-fda8439e3ab1'
GUID_BYTES_LE = bytes.fromhex('1e3b748b5028824ca350fda8439e3ab1')
I64_MAX = (1 << 63) - 1
U64_MAX = (1 << 64) - 1


class ReaderError(ValueError):
    """Fixed codes only; exception text must not contain private raw values."""


def _need(value, code):
    if not value:
        raise ReaderError(code)


def _raw(value, size, code):
    _need(type(value) is bytes and len(value) == size, code)
    return value


def _zero(value):
    return not any(value)


def _u16(value, offset):
    return struct.unpack_from('<H', value, offset)[0]


def _u32(value, offset):
    return struct.unpack_from('<I', value, offset)[0]


def _u64(value, offset):
    return struct.unpack_from('<Q', value, offset)[0]


def _i32(value, offset):
    return struct.unpack_from('<i', value, offset)[0]


def _i64(value, offset):
    return struct.unpack_from('<q', value, offset)[0]


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _ascii_owned(value, units, capacity, code):
    _need(0 < units < capacity and len(value) == capacity, code)
    _need(value[units] == 0 and _zero(value[units + 1:]), code)
    content = value[:units]
    _need(all(32 <= b <= 126 for b in content), code)
    return content.decode('ascii')


def _wide_owned(value, units, capacity, code):
    _need(0 < units < capacity and len(value) == capacity * 2, code)
    content = value[:units * 2]
    _need(value[units * 2:units * 2 + 2] == b'\0\0' and
          _zero(value[(units + 1) * 2:]), code)
    try:
        text = content.decode('utf-16-le', 'strict')
    except UnicodeError:
        raise ReaderError(code) from None
    _need('\0' not in text, code)
    return text


def _config(raw2048):
    b = _raw(raw2048, CONFIG_BYTES, 'config_extent')
    _need(b[:4] == b'A4P1' and _u16(b, 4) == 1 and _u16(b, 6) == CONFIG_BYTES,
          'config_header')
    _need(_u32(b, 204) == 0 and _zero(b[1800:]), 'config_reserved')
    _need(_u32(b, 224) == TRACE_BYTES and _u32(b, 228) == CAPACITY, 'config_trace_extent')
    run, source, config, target, shim = b[8:24], b[24:56], b[56:88], b[88:120], b[120:152]
    nonce = b[240:256]
    _need(all(not _zero(v) for v in (run, source, config, target, shim, nonce)),
          'config_commitments')
    f, root_start, root_end, work_end, start, end = struct.unpack_from('<6Q', b, 152)
    _need(0 < f <= I64_MAX // 120 and 0 <= root_start <= start < end <= work_end <= root_end <= I64_MAX,
          'config_clock_domain')
    _need(root_end == root_start + 120 * f and work_end == root_start + 85 * f and
          end == min(start + 8 * f, work_end), 'config_original_bounds')
    pid, creation, handle = _u32(b, 200), _u64(b, 208), _u64(b, 216)
    _need(0 < pid < 0xffffffff and 0 < creation < U64_MAX and 0 < handle < U64_MAX,
          'config_generation_handle')
    private_units, system_units = _u32(b, 232), _u32(b, 236)
    private = _ascii_owned(b[256:1280], private_units, 1024, 'config_private_path')
    system = _wide_owned(b[1280:1800], system_units, 260, 'config_system_path')
    _need(len(private) >= 4 and private[0].isascii() and private[0].isalpha() and
          private[1:3] == ':\\' and all(c not in '/:?*"<>|' for c in private[3:]),
          'config_private_path')
    parts = private[3:].split('\\')
    _need(all(p and p not in ('.', '..') and p[-1] not in '. ' for p in parts) and
          parts[-1] == 'windows_identity_lpac_curl_ws2_shim.dll', 'config_private_path')
    _need(len(system) >= 4 and system[1:3] == ':\\' and
          all(32 <= ord(c) <= 126 and c != '/' and (c != ':' or i == 1)
              for i, c in enumerate(system)) and
          system.rsplit('\\', 1)[-1].lower() == 'ws2_32.dll', 'config_system_path')
    return dict(raw=b, sha256=_sha(b), run=run, source_sha256=source,
                config_sha256=config, target_sha256=target, shim_sha256=shim,
                frequency=f, root_start=root_start, root_deadline=root_end,
                work_deadline=work_end, window_start=start, window_end=end,
                target_pid=pid, target_creation=creation, trace_handle=handle,
                trace_nonce=nonce, private_path=private,
                private_path_bytes=private_units, system_ws2_path=system,
                system_ws2_chars=system_units)


WS2_EXPORTS = (
    ('accept', 1), ('bind', 2), ('closesocket', 3), ('connect', 4),
    ('getpeername', 5), ('getsockname', 6), ('getsockopt', 7), ('htonl', 8),
    ('htons', 9), ('ioctlsocket', 10), ('listen', 13), ('ntohs', 15),
    ('recv', 16), ('recvfrom', 17), ('select', 18), ('send', 19),
    ('sendto', 20), ('setsockopt', 21), ('shutdown', 22), ('socket', 23),
    ('WSACloseEvent', 45), ('WSACreateEvent', 50), ('gethostname', 57),
    ('WSAEnumNetworkEvents', 64), ('WSAEventSelect', 67), ('WSAIoctl', 78),
    ('WSAResetEvent', 95), ('WSAGetLastError', 111), ('WSASetLastError', 112),
    ('WSAStartup', 115), ('WSACleanup', 116), ('WSAWaitForMultipleEvents', 124),
    ('__WSAFDIsSet', 151), ('freeaddrinfo', 191), ('getaddrinfo', 192))
GATEWAY_EXPORTS = (('GetProcAddress', 200), ('GetModuleHandleW', 201),
                   ('LoadLibraryExW', 202), ('FreeLibrary', 203))
EXPORTS = WS2_EXPORTS + GATEWAY_EXPORTS + (('GetModuleFileNameA', 204),)
EXPORT_NAMES = dict((ordinal, name) for name, ordinal in EXPORTS)
MODULE_NAMES = {0: 'unknown', 1: 'main_image', 2: 'private_shim',
                3: 'kernel32', 4: 'kernelbase', 5: 'ntdll'}
RESOLUTION_NAMES = {0: 'unsupported', 1: 'private_export',
                    2: 'system_filename', 3: 'ntdll_version'}


def _module_name(captured, config):
    """Classify owned UTF16 bytes, never reread arg0 or any caller memory."""
    if captured is None:
        return 1
    if len(captured) % 2:
        return 0
    units = struct.unpack('<' + 'H' * (len(captured) // 2), captured)
    if not units or any(v > 127 for v in units):
        return 0
    name = ''.join(chr(v) for v in units).lower()
    if name in ('ws2_32.dll', 'windows_identity_lpac_curl_ws2_shim.dll',
                'api-ms-win-core-libraryloader-l1-2-0.dll',
                config['private_path'].lower(), config['system_ws2_path'].lower()):
        return 2
    for kind, names in ((3, ('kernel32', 'kernel32.dll')),
                        (4, ('kernelbase', 'kernelbase.dll')),
                        (5, ('ntdll', 'ntdll.dll'))):
        if name in names:
            return kind
    return 0


def _resolve(module, captured, ordinal=0):
    if module == 2:
        for name, number in WS2_EXPORTS:
            if captured is None and ordinal == number or captured == name.encode('ascii') and not ordinal:
                return 1, number
    if ordinal or captured is None:
        return 0, 0
    if module in (2, 3, 4):
        for name, number in GATEWAY_EXPORTS:
            if captured == name.encode('ascii'):
                return 1, number
        if captured == b'GetModuleFileNameA':
            return 2, 204
    if module == 5 and captured == b'RtlVerifyVersionInfo':
        return 3, 0
    return 0, 0


def _startup_data():
    data = bytearray(408)
    struct.pack_into('<HH', data, 0, 0x0202, 0x0202)
    description = b'Private startup diagnostic; transport unsupported\0'
    status = b'Diagnostic only\0'
    data[16:16 + len(description)] = description
    data[273:273 + len(status)] = status
    return bytes(data)


def _capture_payload(row, flags):
    """Decode committed owned copies; never dereference a recorded pointer."""
    kind, count = _u32(row, 64), _u32(row, 68)
    payload = row[96:2144]
    _need(0 <= kind <= 9 and count <= 2048 and _zero(payload[count:]), 'capture_extent')
    complete_claimed, fault = bool(flags & 256), bool(flags & 16)
    complete = complete_claimed and not fault
    captured = payload[:count]
    content = None
    if kind == 0:
        _need(count == 0 and not (flags & (64 | 128)), 'capture_none')
    elif kind == 1:
        _need(count % 2 == 0 and count <= 2048 and not (flags & (64 | 128)), 'capture_wide')
        if complete:
            _need(count >= 2 and captured[-2:] == b'\0\0', 'capture_wide_terminator')
            units = struct.unpack('<' + 'H' * (count // 2), captured)
            _need(all(units[:-1]), 'capture_wide_embedded_null')
            content = captured[:-2]
        else:
            _need(fault, 'capture_wide_incomplete')
    elif kind == 2:
        _need(count <= 65 and not (flags & (64 | 128)), 'capture_ascii')
        if complete:
            _need(count >= 1 and captured[-1:] == b'\0' and b'\0' not in captured[:-1],
                  'capture_ascii_terminator')
            content = captured[:-1]
        else:
            _need(fault, 'capture_ascii_incomplete')
    elif kind == 3:
        _need(count == 0 and (fault or complete and bool(flags & 64) and not (flags & 128)),
              'capture_ordinal')
    elif kind == 4:
        _need(count == 0 and (fault or complete and bool(flags & 128) and not (flags & 64)),
              'capture_null')
    elif kind == 5:
        _need(not (flags & (64 | 128)) and count <= 408, 'capture_WSADATA')
        if complete:
            _need(count == 408 and captured == _startup_data(), 'capture_WSADATA_committed')
        else:
            _need(fault, 'capture_WSADATA_incomplete')
    else:
        _need(not (flags & (64 | 128)), 'capture_internal_flags')
        exact = {6: 2048, 7: 456, 8: 72}.get(kind)
        if complete:
            _need(exact is None or count == exact, 'capture_internal_size')
        else:
            _need(fault, 'capture_internal_incomplete')
    return dict(input_kind=kind, captured_bytes=count, owned_bytes=captured,
                captured_sha256=_sha(captured), content=content,
                complete=complete, capture_complete_claimed=complete_claimed,
                input_fault=fault)


def _row_storage(raw2176):
    """Storage decoding only; fixed opcode/flag validation follows final ABI03."""
    b = _raw(raw2176, ROW_BYTES, 'row_extent')
    return {
        'size': _u32(b, 0), 'operation': _u32(b, 4),
        'sequence': _u64(b, 8), 'entered_qpc': _u64(b, 16),
        'returned_qpc': _u64(b, 24), 'raw_return': _i64(b, 32),
        'error': _i32(b, 40), 'flags': _u32(b, 44),
        'arg0': _u64(b, 48), 'arg1': _u64(b, 56),
        'input_kind': _u32(b, 64), 'captured_bytes': _u32(b, 68),
        'module_kind': _u32(b, 72), 'resolution_kind': _u32(b, 76),
        'resolved_ordinal': _u32(b, 80), 'thread_id': _u32(b, 84),
        'arg2': _u64(b, 88),
        'sdk': {'raw_return': _i64(b, 2144), 'error': _i32(b, 2152),
                'flags': _u32(b, 2156), 'entered_qpc': _u64(b, 2160),
                'returned_qpc': _u64(b, 2168)},
        'raw': b, 'sha256': _sha(b)
    }


INTERNAL_OPERATIONS = {
    300: ('QueryPerformanceFrequency', 8), 301: ('bounded_scan_summary', 72),
    302: ('selected_payload_framing', 456), 303: ('selected_configuration', 2048),
    304: ('GetCurrentProcessId', 0), 305: ('GetProcessTimes', 32),
    306: ('GetHandleInformation_before', 4), 307: ('SetHandleInformation_clear', 0),
    308: ('GetHandleInformation_after', 4), 309: ('MapViewOfFile', 0),
    310: ('CloseHandle_trace', 0), 311: ('GetModuleFileNameW_self', 2048),
    312: ('GetModuleHandleW_kernel32', 0), 313: ('GetModuleFileNameW_kernel32', 2048),
    314: ('GetModuleHandleW_kernelbase', 0), 315: ('GetModuleFileNameW_kernelbase', 2048),
    316: ('GetModuleHandleW_ntdll', 0), 317: ('GetModuleFileNameW_ntdll', 2048),
    318: ('GetProcAddress_filename', 0), 319: ('GetProcAddress_version', 0),
    320: ('GetModuleFileNameW_after_acquire', 2048), 321: ('GetModuleHandleW_main', 0),
    322: ('GetSystemDirectoryW', 520)}
SCHEMA_METADATA = {
    'schema_version': 1, 'payload_guid': GUID,
    'ABI': {'name': 'lpac-curl-A4-startup-config-trace-abi-03.json', 'bytes': 14766,
            'sha256': '6c3eb52d716124c3638530e0a9a78df2130e50cbdc1e471f9cd9845653dc2b0d'},
    'signature_manifest': {'name': 'lpac-curl-A4-startup-shim-signatures-01.json', 'bytes': 15299,
                           'sha256': '02b5f4a24433f7725e1f2d1f423da75c431d5427ce51b1ce170f9d531de600d2'},
    'implementation_source_freeze': {'name': 'lpac-curl-A4-startup-diagnostic-source-freeze-08.json',
                                      'bytes': 5302,
                                      'sha256': 'f4cea9322ed95137dd774c84b74b66005b3f4e2de9b92fa9a74890d7d3204968'},
    'sizes': [2048, 256, 2176, 256, 557312],
    'internal_operations': [[k, *v] for k, v in INTERNAL_OPERATIONS.items()],
    'SDK_flags': [1, 2, 4, 8, 16, 32],
    'delivery_flags': [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048],
    'header_state_flags': [1, 2, 4, 8, 16, 32, 64]}


def _same_typed(a, b):
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return set(a) == set(b) and all(_same_typed(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(_same_typed(x, y) for x, y in zip(a, b))
    return a == b


def _schema(schema_metadata):
    _need(_same_typed(schema_metadata, SCHEMA_METADATA), 'schema_mismatch')


def validate_config(raw2048, *, schema_metadata):
    _schema(schema_metadata)
    return _config(raw2048)


def _clock_pair(entered, returned, entered_flag, returned_flag, clock_bad, config):
    if returned_flag:
        _need(entered_flag, 'return_without_entry')
    # Post-clock failure must retain a returned API result even with endpoint0.
    if not entered_flag:
        _need(not returned_flag and entered == returned == 0 or clock_bad,
              'unentered_clock_fields')
    elif returned_flag and not clock_bad:
        _need(0 < entered <= returned <= I64_MAX, 'clock_pair_order')
    elif entered and returned:
        _need(entered <= returned <= I64_MAX, 'clock_pair_order')
    return bool(entered_flag and returned_flag and not clock_bad and
                config['window_start'] <= entered <= returned < config['window_end'])


def _sdk(row, config):
    s = row['sdk']
    f = s['flags']
    _need(f & ~63 == 0, 'SDK_unknown_flags')
    if not f:
        _need(s['raw_return'] == s['error'] == s['entered_qpc'] == s['returned_qpc'] == 0,
              'SDK_absent_fields')
        return dict(s, entered=False, returned=False, exception=False,
                    error_captured=False, timely=False, absent=True)
    entered, returned = bool(f & 1), bool(f & 2)
    # Native07+ leaves the entire SDK record zero on non-close admission
    # failure. Clock-only attempts belong to the outer delivery record.
    _need(entered, 'SDK_nonzero_without_entry')
    _need(not returned or entered, 'SDK_return_without_entry')
    _need(not (f & 4) or returned, 'SDK_error_without_return')
    if returned:
        _need(f & 4 and not f & 8, 'SDK_return_receipt')
    _need(returned or s['returned_qpc'] == 0, 'SDK_unreturned_return_clock')
    timely = _clock_pair(s['entered_qpc'], s['returned_qpc'], entered, returned,
                         bool(f & (8 | 16 | 32)), config)
    return dict(s, entered=entered, returned=returned, exception=bool(f & 8),
                error_captured=bool(f & 4), timely=timely, absent=False)


def _row(raw2176, slot, config):
    row = _row_storage(raw2176)
    _need(row['size'] == ROW_BYTES, 'row_size')
    _need(row['sequence'] == 2 * slot + 2, 'row_commit_sequence')
    op, flags = row['operation'], row['flags']
    _need((op in EXPORT_NAMES and op != 204) or op in INTERNAL_OPERATIONS, 'row_operation')
    _need(flags & ~4095 == 0, 'delivery_unknown_flags')
    _need(bool(flags & 2048) == (op in INTERNAL_OPERATIONS), 'internal_flag')
    _need(row['module_kind'] in MODULE_NAMES and row['resolution_kind'] in RESOLUTION_NAMES,
          'classification_enum')
    _need(row['thread_id'] != 0, 'row_thread')
    entered, returned = bool(flags & 1), bool(flags & 2)
    _need(not (flags & 4) or returned, 'delivery_error_without_return')
    timely = _clock_pair(row['entered_qpc'], row['returned_qpc'], entered, returned,
                         bool(flags & (512 | 1024)), config)
    captured = _capture_payload(raw2176, flags)
    sdk = _sdk(row, config)
    primary_interval = None
    if op in (202, 203) and sdk['entered']:
        # Preserve every raw SDK return and resource obligation even when the
        # containing export's clocks are unknown or causally inconsistent.
        primary_interval = bool(entered and returned and sdk['returned'] and
            0 < row['entered_qpc'] <= sdk['entered_qpc'] <=
            sdk['returned_qpc'] <= row['returned_qpc'] <= I64_MAX)
    if not sdk['absent']:
        _need(op in (202, 203) or op in INTERNAL_OPERATIONS and op not in (301, 302, 303),
              'unexpected_SDK_call')
    if op in INTERNAL_OPERATIONS and op not in (301, 302, 303):
        _need(row['raw_return'] == sdk['raw_return'] and row['error'] == sdk['error'] and
              row['entered_qpc'] == sdk['entered_qpc'] and row['returned_qpc'] == sdk['returned_qpc'],
              'internal_raw_SDK_mismatch')
        _need(returned == sdk['returned'], 'internal_return_flag')
        expected_bytes = INTERNAL_OPERATIONS[op][1]
        if sdk['entered'] and expected_bytes:
            _need(captured['input_kind'] == 9 and
                  (captured['captured_bytes'] == expected_bytes or captured['input_fault']),
                  'SDK_output_extent')
        elif not captured['input_fault']:
            _need(captured['input_kind'] == 0 and captured['captured_bytes'] == 0,
                  'unexpected_SDK_output')
    if op in (301, 302, 303):
        _need(sdk['absent'] and captured['input_kind'] == {301: 8, 302: 7, 303: 6}[op] and
              captured['complete'] and row['raw_return'] == 1 and entered and returned,
              'summary_shape')
    if op in (300, 301, 302, 303, 304, 305, 321, 322):
        _need(row['arg0'] == row['arg1'] == row['arg2'] == 0, 'fixed_internal_args')
    if op in (306, 307, 308, 309, 310):
        _need(row['arg0'] == config['trace_handle'] and row['arg1'] == row['arg2'] == 0,
              'trace_handle_binding')
    row.update(capture=captured, SDK=sdk, entered=entered, returned=returned,
               error_valid=bool(flags & 4), timely=timely,
               unsupported=bool(flags & 8), diagnostic_failure=bool(flags & 32),
               primary_SDK_within_delivery=primary_interval,
               operation_name=EXPORT_NAMES.get(op, INTERNAL_OPERATIONS.get(op, ('',))[0]),
               internal=bool(flags & 2048))
    return row


def _header(b, c):
    _need(b[:4] == b'A4T1' and _u16(b, 4) == 1 and _u16(b, 6) == HEADER_BYTES,
          'trace_header')
    _need(struct.unpack_from('<3I', b, 8) == (TRACE_BYTES, CAPACITY, ROW_BYTES),
          'trace_extent')
    _need(_u32(b, 148) == 0 and _zero(b[248:256]), 'trace_reserved')
    claimed, overflow, fault = struct.unpack_from('<3I', b, 20)
    sequence, unsupported, refs, state = struct.unpack_from('<QQII', b, 208)
    _need(claimed <= CAPACITY and overflow in (0, 1) and fault in (0, 1) and
          sequence <= 2 * CAPACITY and refs <= 64 and state & ~127 == 0 and
          unsupported < (1 << len(EXPORTS)), 'trace_bounds')
    _need(b[32:48] == c['run'] and b[48:80] == c['config_sha256'] and
          b[80:112] == c['source_sha256'] and b[112:144] == c['shim_sha256'] and
          b[232:248] == c['trace_nonce'], 'trace_commitments')
    _need(_u32(b, 144) == c['target_pid'] and _u64(b, 152) == c['target_creation'],
          'trace_generation')
    expected = (c['frequency'], c['root_start'], c['root_deadline'], c['work_deadline'],
                c['window_start'], c['window_end'])
    _need(struct.unpack_from('<6Q', b, 160) == expected, 'trace_original_epoch')
    return dict(claimed=claimed, overflow=bool(overflow), input_fault=bool(fault),
                sequence=sequence, unsupported_mask=unsupported,
                startup_refs=refs, state_flags=state)


def _expected_framing():
    b = bytearray(456)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 60, 64)
    b[64:68] = b'PE\0\0'
    struct.pack_into('<H', b, 70, 1)
    struct.pack_into('<HHH', b, 84, 240, 0x2000, 0x20b)
    b[328:336] = b'.detour\0'
    struct.pack_into('<II', b, 340, 368, 2136)
    struct.pack_into('<4I', b, 368, 64, 0x00727444, 64, 2136)
    struct.pack_into('<II', b, 432, 2072, 0)
    b[440:456] = GUID_BYTES_LE
    return bytes(b)


BOOTSTRAP_ORDER = (300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310,
                   322, 311, 312, 313, 314, 315, 316, 317, 321, 318, 319)


def _SDK_success(row):
    sdk, op = row['SDK'], row['operation']
    if not sdk['returned'] or sdk['exception']:
        return False
    value = sdk['raw_return']
    if op in (311, 313, 315, 317, 320):
        return 0 < value < 1024
    if op == 322:
        return 0 < value < 260
    if op in (202, 309, 312, 314, 316, 318, 319, 321):
        return 0 < value < U64_MAX
    return value != 0


def _SDK_path(row, c):
    s = row['SDK']
    if not (_SDK_success(row) and row['capture']['complete']):
        return None
    count, payload = s['raw_return'], row['capture']['owned_bytes']
    _need(len(payload) in (520, 2048), 'SDK_path_buffer')
    text = _wide_owned(payload, count, len(payload) // 2, 'SDK_path_output')
    _need(all(32 <= ord(v) <= 126 for v in text), 'SDK_path_ASCII')
    return text


def _bootstrap(rows, c):
    failures = []
    by_op = {}
    for row in rows:
        if row['internal']:
            by_op.setdefault(row['operation'], []).append(row)
    for op in BOOTSTRAP_ORDER:
        if len(by_op.get(op, ())) != 1:
            failures.append('bootstrap_missing_or_duplicate')
    if failures:
        return dict(complete=False, failures=failures, self_module=None,
                    scanner=None, known_modules={})
    first_rows = rows[:len(BOOTSTRAP_ORDER)]
    if tuple(v['operation'] for v in first_rows) != BOOTSTRAP_ORDER:
        failures.append('bootstrap_order')
    one = dict((op, by_op[op][0]) for op in BOOTSTRAP_ORDER)
    for op, row in one.items():
        if op not in (301, 302, 303) and not (_SDK_success(row) and row['SDK']['timely'] and
                                             not row['capture']['input_fault']):
            failures.append('bootstrap_SDK_not_qualified')
    if any(failures):
        # Even a failed bootstrap may contain authoritative successful closes.
        # Resource derivation below still processes every committed SDK fact.
        return dict(complete=False, failures=failures, self_module=None,
                    scanner=None, known_modules={})
    def zero_args(row):
        _need(row['arg0'] == row['arg1'] == row['arg2'] == 0, 'bootstrap_fixed_args')
    for op in (300, 301, 302, 303, 304, 305, 321, 322):
        zero_args(one[op])
    _need(_u64(one[300]['capture']['owned_bytes'], 0) == c['frequency'], 'actual_frequency')
    _need(one[304]['SDK']['raw_return'] == c['target_pid'], 'actual_process_id')
    _need(_u64(one[305]['capture']['owned_bytes'], 0) == c['target_creation'], 'actual_creation')
    for op in (306, 307, 308, 309, 310):
        _need(one[op]['arg0'] == c['trace_handle'] and one[op]['arg1'] == one[op]['arg2'] == 0,
              'trace_handle_binding')
    _need(_u32(one[306]['capture']['owned_bytes'], 0) == 1 and
          _u32(one[308]['capture']['owned_bytes'], 0) == 0, 'trace_handle_flags')
    map_value = one[309]['SDK']['raw_return']
    _need(map_value >= 0x10000 and map_value < (1 << 47) and map_value % 8 == 0,
          'map_view_address')
    summary = one[301]['capture']['owned_bytes']
    values = struct.unpack('<5Q8I', summary)
    keys = ('first', 'last', 'allocation', 'payload', 'framing_bytes', 'regions', 'candidates',
            'records', 'found', 'region_cap', 'candidate_cap', 'record_cap', 'reserved')
    scan = dict(zip(keys, values))
    _need(scan['found'] == 1 and scan['reserved'] == 0 and
          (scan['region_cap'], scan['candidate_cap'], scan['record_cap']) == (4096, 256, 64) and
          1 <= scan['regions'] <= 4096 and 1 <= scan['candidates'] <= 256 and
          1 <= scan['records'] <= 64, 'scan_summary_bounds')
    _need(0x10000 <= scan['allocation'] < (1 << 47) - 2504 and
          scan['payload'] == scan['allocation'] + 456 and scan['framing_bytes'] == 2504,
          'scan_selected_extent')
    _need(scan['first'] <= scan['last'] and scan['last'] - scan['first'] <= c['frequency'],
          'scan_local_bound')
    for op in (301, 302, 303):
        _need(one[op]['entered_qpc'] == scan['first'] and one[op]['returned_qpc'] == scan['last'],
              'scan_summary_clock_binding')
    _need(one[302]['capture']['owned_bytes'] == _expected_framing(), 'selected_framing')
    _need(one[303]['capture']['owned_bytes'] == c['raw'], 'selected_config')
    system_dir = _SDK_path(one[322], c)
    _need(system_dir is not None and (system_dir + '\\WS2_32.dll').lower() == c['system_ws2_path'].lower(),
          'actual_system_directory')
    self_module = one[311]['arg0']
    _need(0 < self_module < U64_MAX and _SDK_path(one[311], c).lower() == c['private_path'].lower(),
          'actual_private_module')
    modules = {2: self_module}
    for kind, hop, nop, leaf in ((3, 312, 313, 'kernel32.dll'),
                                  (4, 314, 315, 'kernelbase.dll'),
                                  (5, 316, 317, 'ntdll.dll')):
        h = one[hop]['SDK']['raw_return']
        _need(one[hop]['arg0'] != 0 and one[hop]['arg1'] == one[hop]['arg2'] == 0 and
              one[nop]['arg0'] == h and one[nop]['arg1'] == one[nop]['arg2'] == 0,
              'borrowed_module_binding')
        _need(_SDK_path(one[nop], c).lower() == (system_dir + '\\' + leaf).lower(),
              'borrowed_module_path')
        modules[kind] = h
    modules[1] = one[321]['SDK']['raw_return']
    _need(len(set(modules.values())) == len(modules), 'live_module_alias')
    for op, kind in ((318, 3), (319, 5)):
        _need(one[op]['arg0'] == modules[kind] and one[op]['arg1'] != 0 and one[op]['arg2'] == 0,
              'fixed_system_procedure_binding')
    return dict(complete=True, failures=[], self_module=self_module, scanner=scan,
                known_modules=modules)


def _classifications(rows, c, bootstrap):
    facts, reasons, derived_unsupported = [], [], 0
    used_name_proofs = set()
    modules = bootstrap['known_modules']
    ordinal_bits = dict((ordinal, i) for i, (_, ordinal) in enumerate(EXPORTS))
    unsupported_WS2 = set(n for _, n in WS2_EXPORTS) - {111, 112, 115, 116}
    for row in rows:
        op, capture = row['operation'], row['capture']
        if row['internal']:
            continue
        item = dict(operation=op, owned_input_reclassified=False)
        if op in unsupported_WS2:
            derived_unsupported |= 1 << ordinal_bits[op]
            reasons.append('unsupported_export_observed')
        if row['unsupported']:
            derived_unsupported |= 1 << ordinal_bits[op]
        if op in (200, 201, 202, 203) and row['returned'] and not row['raw_return']:
            # The producer rejects every failed closed-gateway delivery,
            # independently of a separately known acquisition/release return.
            derived_unsupported |= 1 << ordinal_bits[op]
            reasons.append('closed_gateway_failed_delivery')
        if row['primary_SDK_within_delivery'] is False:
            reasons.append('primary_SDK_outside_delivery_or_unknown_interval')
        if op in (201, 202) and capture['complete']:
            _need(capture['input_kind'] in (1, 4), 'module_input_kind')
            module = (1 if op == 201 else 0) if capture['input_kind'] == 4 else _module_name(capture['content'], c)
            _need(module == row['module_kind'], 'owned_module_classification')
            if capture['input_kind'] == 4:
                _need(row['arg0'] == 0, 'NULL_module_pointer')
            else:
                _need(row['arg0'] != 0, 'module_pointer_present')
            item.update(owned_input_reclassified=True, derived_module_kind=module)
            if op == 202 and row['SDK']['entered']:
                _need(module == 2 and row['arg1'] == 0 and row['arg2'] in (0, 0x800),
                      'SDK_load_closed_input')
            if module == 0 or op == 202 and (module != 2 or row['arg1'] or row['arg2'] not in (0, 0x800)):
                derived_unsupported |= 1 << ordinal_bits[op]
                reasons.append('unsupported_loader_input')
            if op == 201 and row['returned'] and row['raw_return']:
                if module in modules:
                    _need(row['raw_return'] == modules[module], 'borrowed_delivery_module')
                else:
                    reasons.append('borrowed_delivery_binding_unknown')
        elif op == 200 and capture['complete']:
            _need(capture['input_kind'] in (2, 3, 4), 'procedure_input_kind')
            if capture['input_kind'] == 3:
                _need(1 <= row['arg1'] <= 65535, 'procedure_ordinal')
                symbol, ordinal = None, row['arg1']
            elif capture['input_kind'] == 4:
                _need(row['arg1'] == 0, 'NULL_procedure_pointer')
                symbol, ordinal = None, 0
            else:
                _need(row['arg1'] > 65535, 'procedure_pointer_present')
                symbol, ordinal = capture['content'], 0
            if modules:
                module = next((kind for kind, value in modules.items() if value == row['arg0']), 0)
                _need(module == row['module_kind'], 'actual_module_classification')
            else:
                module = row['module_kind']
                reasons.append('procedure_module_binding_unknown')
            resolution, resolved = _resolve(module, symbol, ordinal)
            _need((resolution, resolved) == (row['resolution_kind'], row['resolved_ordinal']),
                  'owned_procedure_resolution')
            item.update(owned_input_reclassified=True, derived_module_kind=module,
                        derived_resolution_kind=resolution, derived_resolved_ordinal=resolved)
            if resolution == 0:
                derived_unsupported |= 1 << ordinal_bits[op]
                reasons.append('unsupported_procedure_observed')
        if op not in (202, 203):
            _need(row['SDK']['absent'], 'duplicate_or_unapproved_export_SDK')
        if op == 202 and row['returned'] and row['raw_return']:
            _need(row['SDK']['returned'] and row['SDK']['raw_return'] == row['raw_return'],
                  'load_delivery_not_SDK_acquisition')
            # Production holds the reference lock through its unique fresh
            # module-name call. Bind by same-thread claim order, then verify
            # clocks; selecting only timely rows would hide a bad/extra proof.
            following = min((v['sequence'] for v in rows if not v['internal']
                and v['thread_id'] == row['thread_id']
                and v['sequence'] > row['sequence']), default=2 * CAPACITY + 2)
            names = [v for v in rows if v['operation'] == 320
                and v['thread_id'] == row['thread_id']
                and row['sequence'] < v['sequence'] < following
                and v['arg0'] == row['SDK']['raw_return']]
            proof_ok = False
            if len(names) == 1:
                proof = names[0]
                path = _SDK_path(proof, c)
                proof_ok = bool(proof['timely'] and proof['SDK']['timely']
                    and proof['arg1'] == proof['arg2'] == 0
                    and path is not None and path.lower() == c['private_path'].lower()
                    and row['SDK']['returned_qpc'] <= proof['SDK']['entered_qpc']
                    <= proof['SDK']['returned_qpc'] <= row['returned_qpc'])
                used_name_proofs.add(proof['sequence'])
            item['load_module_name_proof_complete'] = proof_ok
            if not proof_ok:
                reasons.append('nonnull_load_name_proof_missing_duplicate_or_unqualified')
        if op == 203 and row['returned'] and row['raw_return']:
            _need(row['SDK']['returned'] and row['SDK']['raw_return'] != 0,
                  'release_delivery_not_SDK_success')
        facts.append(item)
    if any(v['operation'] == 320 and v['sequence'] not in used_name_proofs for v in rows):
        # NULL delivery never requires a name proof, and all its SDK facts are
        # retained. An extra/unassigned proof can only make the inner partial.
        reasons.append('unassigned_module_name_proof')
    return facts, reasons, derived_unsupported


def _resources(rows, header, bootstrap, stable, concurrent):
    acquisitions, releases, trace_closes, views = [], [], [], []
    unknown, reasons = not stable or concurrent, []
    starts = cleanups = unreturned_loads = 0
    startup_prefix, prefix_min, prefix_max = 0, 0, 0
    prefix_valid = True
    startup_unknown = not stable or concurrent
    for row in rows:
        op, sdk = row['operation'], row['SDK']
        if op == 202:
            if sdk['entered'] and not sdk['returned']:
                unreturned_loads += 1
                unknown = True
                reasons.append('SDK_load_unreturned')
            if sdk['returned'] and sdk['raw_return']:
                value = sdk['raw_return']
                known = 0 < value < U64_MAX
                acquisitions.append(dict(slot=row['sequence'] // 2 - 1, module=value,
                                         identity_bound=known and value == bootstrap['self_module'],
                                         consumed=False, released=False))
                if not known or value != bootstrap['self_module']:
                    unknown = True
                    reasons.append('acquired_module_identity_unknown')
        elif op == 203 and not sdk['absent'] and sdk['entered']:
            module = row['arg0']
            ticket = next((v for v in acquisitions if v['module'] == module and not v['consumed']), None)
            if ticket is None:
                unknown = True
                reasons.append('release_without_known_acquisition')
            else:
                ticket['consumed'] = True
                if sdk['returned'] and sdk['raw_return'] != 0:
                    ticket['released'] = True
                else:
                    unknown = True
                    reasons.append('release_outcome_unknown')
            releases.append(dict(sdk_returned=sdk['returned'], sdk_raw_return=sdk['raw_return'],
                                 delivery_returned=row['returned'], delivery_raw_return=row['raw_return']))
        elif op == 309:
            if sdk['returned'] and sdk['raw_return']:
                views.append(sdk['raw_return'])
            elif sdk['entered'] and not sdk['returned']:
                unknown = True
                reasons.append('map_outcome_unknown')
        elif op == 310:
            trace_closes.append(sdk['returned'] and sdk['raw_return'] != 0 and not sdk['exception'])
            if not trace_closes[-1]:
                unknown = True
                reasons.append('trace_close_unknown')
        elif op in (115, 116):
            if not row['returned']:
                startup_unknown = True
            elif row['raw_return'] == 0:
                if op == 115:
                    starts += 1
                    startup_prefix += 1
                    prefix_max = max(prefix_max, startup_prefix)
                    if not 0 < startup_prefix <= 64:
                        prefix_valid = False
                        startup_unknown = True
                        reasons.append('startup_prefix_capacity_or_unresolved')
                    if row['arg0'] != 0x0202 or row['capture']['input_kind'] != 5 or not row['capture']['complete']:
                        startup_unknown = True
                else:
                    cleanups += 1
                    startup_prefix -= 1
                    prefix_min = min(prefix_min, startup_prefix)
                    if startup_prefix < 0:
                        prefix_valid = False
                        startup_unknown = True
                        reasons.append('cleanup_prefix_underflow_or_unresolved')
    if len(trace_closes) != 1 or len(views) != 1:
        unknown = True
        reasons.append('mapping_or_once_close_incomplete')
    if header['state_flags'] & (16 | 32 | 64):
        unknown = True
    if header['overflow'] or header['input_fault'] or header['state_flags'] & (8 | 32 | 64):
        startup_unknown = True
    startup_delta = starts - cleanups
    if startup_delta < 0 or startup_delta != header['startup_refs']:
        startup_unknown = True
        reasons.append('startup_counter_unknown')
    possible = sum(not v['released'] for v in acquisitions) + unreturned_loads
    outstanding = sum(not v['released'] and v['identity_bound'] for v in acquisitions)
    if possible:
        reasons.append('known_or_possible_module_references_outstanding')
    if startup_delta != 0:
        reasons.append('startup_references_outstanding')
    return dict(acquisitions=acquisitions, SDK_acquisition_count=len(acquisitions),
                releases=releases, SDK_release_count=len(releases),
                unreturned_load_count=unreturned_loads,
                known_module_reference_lower_bound=outstanding,
                possible_module_reference_obligations=possible,
                module_reference_state_unknown=unknown,
                module_references_known_balanced=not unknown and possible == 0,
                trace_close_count=len(trace_closes),
                trace_handle_close_confirmed=len(trace_closes) == 1 and trace_closes[0],
                retained_view_count=len(views), view_explicitly_unmapped=False,
                view_reclamation_after_target_exit_proven=False,
                startup_success_count=starts, cleanup_success_count=cleanups,
                startup_delta=startup_delta, header_startup_refs=header['startup_refs'],
                startup_prefix_valid=prefix_valid,
                startup_claimed_prefix_min=prefix_min,
                startup_claimed_prefix_max=prefix_max,
                startup_reference_state_unknown=startup_unknown,
                startup_references_known_balanced=not startup_unknown and startup_delta == 0,
                all_resources_closed_or_empty=False, reasons=reasons)


def decode_trace(raw557312, *, expected_config2048, schema_metadata):
    _schema(schema_metadata)
    c = _config(expected_config2048)
    b = _raw(raw557312, TRACE_BYTES, 'trace_extent')
    if _zero(b):
        return dict(status='unbound', header_bound=False, trace_sha256=_sha(b),
                    config=c, header=None, rows=[], uncommitted_rows=[],
                    unused_nonzero_rows=[], stable=False, bootstrap=None,
                    diagnostic_candidate_complete=False,
                    resources={'all_resources_closed_or_empty': False,
                               'module_reference_state_unknown': True,
                               'startup_reference_state_unknown': True},
                    reasons=['no_bound_trace_not_empty_proof'])
    h = _header(b, c)
    rows, uncommitted, unused = [], [], []
    for slot in range(CAPACITY):
        rawrow = b[HEADER_BYTES + slot * ROW_BYTES:HEADER_BYTES + (slot + 1) * ROW_BYTES]
        if slot >= h['claimed']:
            if not _zero(rawrow):
                unused.append(dict(slot=slot, sha256=_sha(rawrow), raw=rawrow))
            continue
        if _u64(rawrow, 8) != 2 * slot + 2:
            # No typed return/close authority is inferred from a torn record.
            uncommitted.append(dict(slot=slot, sha256=_sha(rawrow), raw=rawrow,
                                    storage=_row_storage(rawrow)))
            continue
        rows.append(_row(rawrow, slot, c))
    stable = not uncommitted and not unused and h['sequence'] == 2 * len(rows)
    bootstrap = _bootstrap(rows, c)
    classifications, reasons, derived_unsupported = _classifications(rows, c, bootstrap)
    concurrent = any(a['thread_id'] != v['thread_id'] and a['entered_qpc'] and v['entered_qpc'] and
                     max(a['entered_qpc'], v['entered_qpc']) < min(a['returned_qpc'], v['returned_qpc'])
                     for i, a in enumerate(rows) for v in rows[i + 1:])
    resources = _resources(rows, h, bootstrap, stable, concurrent)
    if not stable:
        reasons.append('torn_or_nonzero_unused_storage')
    if concurrent:
        reasons.append('concurrent_calls_balance_not_certified')
    if not bootstrap['complete']:
        reasons.extend(bootstrap['failures'])
    if h['overflow'] or h['input_fault'] or h['state_flags'] or h['unsupported_mask'] or derived_unsupported:
        reasons.append('sticky_failure_or_unsupported')
    if derived_unsupported & ~h['unsupported_mask']:
        reasons.append('unsupported_header_missing_observed_bit')
    if any(not row['returned'] or not row['timely'] or row['diagnostic_failure'] or
           row['capture']['input_fault'] or not row['SDK']['absent'] and not row['SDK']['timely']
           for row in rows):
        reasons.append('unreturned_late_or_unqualified_call')
    reasons.extend(resources['reasons'])
    if resources['startup_success_count'] == 0:
        reasons.append('no_successful_private_startup_observed')
    complete = bool(stable and rows and bootstrap['complete'] and not reasons and
                    resources['module_references_known_balanced'] and
                    resources['startup_references_known_balanced'] and
                    resources['startup_success_count'] > 0 and
                    resources['trace_handle_close_confirmed'])
    return dict(status='diagnostic-candidate' if complete else 'partial',
                header_bound=True, trace_sha256=_sha(b), config=c, header=h,
                rows=rows, uncommitted_rows=uncommitted, unused_nonzero_rows=unused,
                stable=stable, bootstrap=bootstrap, classifications=classifications,
                derived_unsupported_mask=derived_unsupported,
                concurrent_calls_observed=concurrent, resources=resources,
                diagnostic_candidate_complete=complete, reasons=sorted(set(reasons)))


FIXED_FALSE_CLAIMS = {
    'network_qualified': False, 'DNS_qualified': False, 'proxy_qualified': False,
    'Linux_equivalence': False, 'product_acceptance': False,
    'selected_version_positive': False, 'application_compatibility': False,
    'actual_OS_TLS_verified': False, 'physical_Resume_qualified': False,
    'external_cleanup_qualified': False, 'natural_exit_qualified': False,
    'target_identity_and_Jobs_qualified': False, 'loader_accepted': False,
    'hostile_child_trace_authenticity': False, 'hostile_same_sid_boundary': False,
    'parent_payload_readonly_verified': False, 'all_dynamic_calls_mediated': False,
    'per_VirtualQuery_raw_verified': False, 'whole_address_space_no_duplicates': False}


def review(raw557312, *, expected_config2048, schema_metadata):
    """Closed safe projection. No names, paths, PIDs, handles or raw ticks."""
    d = decode_trace(raw557312, expected_config2048=expected_config2048,
                     schema_metadata=schema_metadata)
    c = d['config']
    result = dict(schema_version=1, stage='independent-A4-startup-trace-byte-review',
                  status=d['status'], config_sha256=_sha(expected_config2048),
                  trace_sha256=d['trace_sha256'], source_sha256=c['source_sha256'].hex(),
                  header_bound=d['header_bound'], stable=d['stable'],
                  diagnostic_candidate_complete=d['diagnostic_candidate_complete'],
                  fixed_false_claims=dict(FIXED_FALSE_CLAIMS), reasons=d['reasons'],
                  row_count=len(d['rows']), uncommitted_row_count=len(d['uncommitted_rows']),
                  nonzero_unused_row_count=len(d['unused_nonzero_rows']))
    if not d['header_bound']:
        result.update(resources_unknown=True, all_resources_closed_or_empty=False)
        return result
    h, resources, bootstrap = d['header'], d['resources'], d['bootstrap']
    result['header'] = {k: h[k] for k in ('claimed', 'overflow', 'input_fault', 'sequence',
                                         'unsupported_mask', 'startup_refs', 'state_flags')}
    result['bootstrap_complete'] = bootstrap['complete']
    result['concurrent_calls_observed'] = d['concurrent_calls_observed']
    result['resources'] = {k: resources[k] for k in (
        'SDK_acquisition_count', 'SDK_release_count', 'known_module_reference_lower_bound',
        'unreturned_load_count',
        'possible_module_reference_obligations',
        'module_reference_state_unknown', 'module_references_known_balanced',
        'trace_close_count', 'trace_handle_close_confirmed', 'retained_view_count',
        'view_explicitly_unmapped', 'view_reclamation_after_target_exit_proven',
        'startup_success_count', 'cleanup_success_count', 'startup_delta', 'header_startup_refs',
        'startup_reference_state_unknown', 'startup_references_known_balanced',
        'all_resources_closed_or_empty')}
    result['calls'] = []
    for row in d['rows']:
        sdk = row['SDK']
        item = dict(operation=row['operation'], operation_name=row['operation_name'],
                    internal=row['internal'], entered=row['entered'], returned=row['returned'],
                    timely=row['timely'], unsupported=row['unsupported'],
                    diagnostic_failure=row['diagnostic_failure'],
                    delivery_nonzero=bool(row['raw_return']) if row['returned'] else None,
                    delivery_error=row['error'] if row['error_valid'] else None,
                    input_kind=row['input_kind'], captured_bytes=row['captured_bytes'],
                    captured_sha256=row['capture']['captured_sha256'],
                    capture_complete=row['capture']['complete'], input_fault=row['capture']['input_fault'],
                    SDK=dict(entered=sdk['entered'], returned=sdk['returned'],
                             exception=sdk['exception'], timely=sdk['timely'],
                             error=sdk['error'] if sdk['error_captured'] else None,
                             raw_return_storage_nonzero=bool(sdk['raw_return']),
                             return_nonzero=bool(sdk['raw_return']) if sdk['returned'] else None))
        if row['operation'] in (115, 116) and row['returned']:
            item['direct_startup_or_cleanup_result'] = row['raw_return']
        if row['operation'] == 192 and row['returned']:
            item['direct_resolver_stub_result'] = row['raw_return']
        if row['operation'] == 111 and row['returned']:
            known_error = row['raw_return'] in (0, 10014, 10045, 10067, 10092, 10093)
            item['private_error_getter_result'] = row['raw_return'] if known_error else None
            item['unclassified_private_error_value_present'] = not known_error
        result['calls'].append(item)
    scan = bootstrap['scanner']
    result['scanner'] = None if scan is None else {
        k: scan[k] for k in ('regions', 'candidates', 'records', 'found',
                             'region_cap', 'candidate_cap', 'record_cap', 'framing_bytes')}
    result['scanner_claim_boundary'] = 'bounded summary and selected framing only; first-match selection'
    result['trace_is_not_hostile_authenticity_proof'] = True
    return result
