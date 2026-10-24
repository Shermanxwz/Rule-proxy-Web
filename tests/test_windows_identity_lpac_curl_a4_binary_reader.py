"""Synthetic byte fixtures only. Author has not executed these tests."""
from pathlib import Path
import importlib.util
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'a4_binary_reader_under_test',
    ROOT / '.github/windows_identity_lpac_curl_a4_binary_reader.py')
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


def config_fixture():
    b = bytearray(2048)
    b[:4] = b'A4P1'
    struct.pack_into('<HH', b, 4, 1, 2048)
    b[8:24] = bytes(range(1, 17))
    b[24:56], b[56:88] = b's' * 32, b'c' * 32
    b[88:120], b[120:152] = b't' * 32, b'h' * 32
    struct.pack_into('<6Q', b, 152, 1000, 100000, 220000, 185000, 110000, 118000)
    struct.pack_into('<IIQQ', b, 200, 1024, 0, 123456, 0x100)
    private = b'C:\\owned\\windows_identity_lpac_curl_ws2_shim.dll'
    system = 'C:\\Windows\\System32\\WS2_32.dll'.encode('utf-16-le')
    struct.pack_into('<4I', b, 224, 557312, 256, len(private), len(system) // 2)
    b[240:256] = b'n' * 16
    b[256:256 + len(private)] = private
    b[1280:1280 + len(system)] = system
    return bytes(b)


def wide_buffer(text, count):
    b = text.encode('utf-16-le') + b'\0\0'
    return b + bytes(count - len(b))


def framing_fixture():
    b = bytearray(456)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 60, 64)
    b[64:68] = b'PE\0\0'
    struct.pack_into('<HHHH', b, 68, 0, 1, 0, 0)
    struct.pack_into('<HHH', b, 84, 240, 0x2000, 0x20b)
    b[328:336] = b'.detour\0'
    struct.pack_into('<II', b, 340, 368, 2136)
    struct.pack_into('<4I', b, 368, 64, 0x00727444, 64, 2136)
    struct.pack_into('<II', b, 432, 2072, 0)
    b[440:456] = bytes.fromhex('1e3b748b5028824ca350fda8439e3ab1')
    return bytes(b)


def startup_data_fixture():
    b = bytearray(408)
    struct.pack_into('<HH', b, 0, 0x0202, 0x0202)
    for offset, text in ((16, b'Private startup diagnostic; transport unsupported\0'),
                         (273, b'Diagnostic only\0')):
        b[offset:offset + len(text)] = text
    return bytes(b)


def row_fixture(op, slot, tick, *, value=1, args=(0, 0, 0), payload=b'', kind=0,
                module=0, resolution=0, ordinal=0, sdk=True):
    b = bytearray(2176)
    internal = op >= 300
    flags = 1 | 2 | (2048 if internal else 0) | (256 if payload or kind in (3, 4) else 0)
    if internal and sdk:
        flags |= 4
    struct.pack_into('<IIQQQqiIQQ', b, 0, 2176, op, 2 * slot + 2, tick, tick + 1,
                     value, 0, flags, args[0], args[1])
    struct.pack_into('<6IQ', b, 64, kind, len(payload), module, resolution, ordinal, 7, args[2])
    b[96:96 + len(payload)] = payload
    if sdk:
        struct.pack_into('<qiIQQ', b, 2144, value, 0, 7, tick, tick + 1)
    return bytes(b)


def bootstrap_fixture():
    private = 'C:\\owned\\windows_identity_lpac_curl_ws2_shim.dll'
    directory = 'C:\\Windows\\System32'
    entries = [
        (300, 1, (0, 0, 0), struct.pack('<Q', 1000), 9),
        (301, 1, (0, 0, 0), struct.pack('<5Q8I', 110005, 110006, 0x1000000,
            0x1000000 + 456, 2504, 5, 1, 1, 1, 4096, 256, 64, 0), 8),
        (302, 1, (0, 0, 0), framing_fixture(), 7),
        (303, 1, (0, 0, 0), config_fixture(), 6),
        (304, 1024, (0, 0, 0), b'', 0),
        (305, 1, (0, 0, 0), struct.pack('<4Q', 123456, 0, 10, 20), 9),
        (306, 1, (0x100, 0, 0), struct.pack('<I', 1), 9),
        (307, 1, (0x100, 0, 0), b'', 0),
        (308, 1, (0x100, 0, 0), struct.pack('<I', 0), 9),
        (309, 0xa00000, (0x100, 0, 0), b'', 0),
        (310, 1, (0x100, 0, 0), b'', 0),
        (322, len(directory), (0, 0, 0), wide_buffer(directory, 520), 9),
        (311, len(private), (0x500000, 0, 0), wide_buffer(private, 2048), 9),
        (312, 0x600000, (0x100000, 0, 0), b'', 0),
        (313, len(directory + '\\kernel32.dll'), (0x600000, 0, 0), wide_buffer(directory + '\\kernel32.dll', 2048), 9),
        (314, 0x700000, (0x100020, 0, 0), b'', 0),
        (315, len(directory + '\\kernelbase.dll'), (0x700000, 0, 0), wide_buffer(directory + '\\kernelbase.dll', 2048), 9),
        (316, 0x800000, (0x100040, 0, 0), b'', 0),
        (317, len(directory + '\\ntdll.dll'), (0x800000, 0, 0), wide_buffer(directory + '\\ntdll.dll', 2048), 9),
        (321, 0x900000, (0, 0, 0), b'', 0),
        (318, 0xa10000, (0x600000, 0x200000, 0), b'', 0),
        (319, 0xa20000, (0x800000, 0x200040, 0), b'', 0)]
    rows = []
    for i, (op, value, args, payload, kind) in enumerate(entries):
        tick = 110005 if op in (301, 302, 303) else 110001 + i * 4
        rows.append(row_fixture(op, i, tick, value=value, args=args, payload=payload,
                                kind=kind, sdk=op not in (301, 302, 303)))
    rows.append(row_fixture(115, len(rows), 110100, value=0, args=(0x0202, 0x300000, 0),
                            payload=startup_data_fixture(), kind=5, sdk=False))
    rows.append(row_fixture(116, len(rows), 110110, value=0, sdk=False))
    return rows


def trace_fixture(rows=None, *, state=0, refs=0):
    rows = bootstrap_fixture() if rows is None else rows
    c, b = config_fixture(), bytearray(557312)
    b[:4] = b'A4T1'
    struct.pack_into('<HH5I', b, 4, 1, 256, 557312, 256, 2176, len(rows), 0)
    b[32:48], b[48:80] = c[8:24], c[56:88]
    b[80:112], b[112:144] = c[24:56], c[120:152]
    struct.pack_into('<I', b, 144, 1024)
    struct.pack_into('<Q', b, 152, 123456)
    b[160:208] = c[152:200]
    struct.pack_into('<QQII', b, 208, 2 * len(rows), 0, refs, state)
    b[232:248] = c[240:256]
    for i, row in enumerate(rows):
        b[256 + i * 2176:256 + (i + 1) * 2176] = row
    return bytes(b)


def decode(trace):
    return reader.decode_trace(trace, expected_config2048=config_fixture(),
                               schema_metadata=reader.SCHEMA_METADATA)


def load_release_fixture():
    rows = bootstrap_fixture()
    name = 'WS2_32.dll'.encode('utf-16-le') + b'\0\0'
    load = bytearray(row_fixture(202, len(rows), 110120, value=0x500000,
        args=(0x400000, 0, 0), payload=name, kind=1, module=2))
    struct.pack_into('<Q', load, 24, 110130)
    struct.pack_into('<QQ', load, 2160, 110121, 110122)
    rows.append(bytes(load))
    private = 'C:\\owned\\windows_identity_lpac_curl_ws2_shim.dll'
    rows.append(row_fixture(320, len(rows), 110123, value=len(private),
        args=(0x500000, 0, 0), payload=wide_buffer(private, 2048), kind=9))
    rows.append(row_fixture(203, len(rows), 110140, value=1,
                            args=(0x500000, 0, 0)))
    return rows


def resequence(rows):
    result = []
    for slot, row in enumerate(rows):
        b = bytearray(row)
        struct.pack_into('<Q', b, 8, 2 * slot + 2)
        result.append(bytes(b))
    return result


class ConfigTests(unittest.TestCase):
    def test_exact_original_epoch_and_owned_paths(self):
        c = reader.validate_config(config_fixture(), schema_metadata=reader.SCHEMA_METADATA)
        self.assertEqual(c['root_deadline'] - c['root_start'], 120 * c['frequency'])
        self.assertEqual(c['work_deadline'] - c['root_start'], 85 * c['frequency'])
        self.assertEqual(c['window_end'], min(c['window_start'] + 8 * c['frequency'], c['work_deadline']))
        self.assertEqual(c['private_path'], 'C:\\owned\\windows_identity_lpac_curl_ws2_shim.dll')

    def test_truncated_reserved_and_extended_window_rejected(self):
        with self.assertRaises(reader.ReaderError):
            reader.validate_config(config_fixture()[:-1], schema_metadata=reader.SCHEMA_METADATA)
        for offset, raw in ((2047, b'\1'), (192, struct.pack('<Q', 118001))):
            b = bytearray(config_fixture())
            b[offset:offset + len(raw)] = raw
            with self.subTest(offset=offset), self.assertRaises(reader.ReaderError):
                reader.validate_config(bytes(b), schema_metadata=reader.SCHEMA_METADATA)

    def test_owned_transient_name_not_recorded_pointer(self):
        c = reader.validate_config(config_fixture(), schema_metadata=reader.SCHEMA_METADATA)
        row = bytearray(2176)
        name = 'WS2_32.dll'.encode('utf-16-le') + b'\0\0'
        struct.pack_into('<II', row, 64, 1, len(name))
        row[96:96 + len(name)] = name
        struct.pack_into('<Q', row, 48, 0xffffffffffffffff)
        captured = reader._capture_payload(bytes(row), 256)
        self.assertEqual(reader._module_name(captured['content'], c), 2)
        # No interface accepts a new caller-memory buffer after the capture.
        name = 'other.dll'.encode('utf-16-le')
        self.assertEqual(reader._module_name(captured['content'], c), 2)
        self.assertNotEqual(captured['content'], name)


class TraceTests(unittest.TestCase):
    def test_cleanup_success_before_first_startup_cannot_be_balanced_by_a_later_start(self):
        rows = bootstrap_fixture()[:22]
        rows.append(row_fixture(116, len(rows), 110100, value=0, sdk=False))
        rows.append(row_fixture(115, len(rows), 110110, value=0,
            args=(0x0202, 0x300000, 0), payload=startup_data_fixture(),
            kind=5, sdk=False))
        d = decode(trace_fixture(rows, refs=0))
        self.assertEqual(d['resources']['startup_delta'], 0)
        self.assertFalse(d['resources']['startup_prefix_valid'])
        self.assertTrue(d['resources']['startup_reference_state_unknown'])
        self.assertFalse(d['diagnostic_candidate_complete'])

    def test_65_successful_startups_before_cleanup_exceed_production_capacity(self):
        rows = bootstrap_fixture()[:22]
        for i in range(65):
            rows.append(row_fixture(115, len(rows), 110100 + 2 * i, value=0,
                args=(0x0202, 0x300000, 0), payload=startup_data_fixture(),
                kind=5, sdk=False))
        for i in range(65):
            rows.append(row_fixture(116, len(rows), 110300 + 2 * i,
                                    value=0, sdk=False))
        self.assertLess(len(rows), 256)
        d = decode(trace_fixture(rows, refs=0))
        self.assertEqual(d['resources']['startup_delta'], 0)
        self.assertEqual(d['resources']['startup_claimed_prefix_max'], 65)
        self.assertFalse(d['resources']['startup_references_known_balanced'])
        self.assertFalse(d['diagnostic_candidate_complete'])

    def test_primary_SDK_after_delivery_is_partial_but_keeps_acquisition_and_release(self):
        rows = load_release_fixture()
        self.assertTrue(decode(trace_fixture(rows))['diagnostic_candidate_complete'])
        load = bytearray(rows[24])
        struct.pack_into('<QQ', load, 2160, 110135, 110136)
        rows[24] = bytes(load)
        d = decode(trace_fixture(rows))
        self.assertFalse(d['rows'][24]['primary_SDK_within_delivery'])
        self.assertEqual(d['resources']['SDK_acquisition_count'], 1)
        self.assertEqual(d['resources']['SDK_release_count'], 1)
        self.assertFalse(d['diagnostic_candidate_complete'])

    def test_failed_valid_resolution_delivery_derives_unsupported_without_header_self_report(self):
        rows = bootstrap_fixture()
        rows.append(row_fixture(200, len(rows), 110120, value=0,
            args=(0x500000, 0x400000, 0), payload=b'WSAStartup\0', kind=2,
            module=2, resolution=1, ordinal=115, sdk=False))
        d = decode(trace_fixture(rows))
        self.assertEqual(d['header']['unsupported_mask'], 0)
        self.assertNotEqual(d['derived_unsupported_mask'], 0)
        self.assertIn('closed_gateway_failed_delivery', d['reasons'])
        self.assertFalse(d['diagnostic_candidate_complete'])

    def test_nonnull_load_requires_exact_one_fresh_bounded_name_proof(self):
        good = load_release_fixture()
        self.assertTrue(decode(trace_fixture(good))['diagnostic_candidate_complete'])
        variations = {}
        variations['missing'] = resequence(good[:25] + good[26:])
        variations['duplicate'] = resequence(good[:26] + [good[25]] + good[26:])
        wrong = bytearray(good[25])
        wrong_path = 'C:\\other\\windows_identity_lpac_curl_ws2_shim.dll'
        struct.pack_into('<q', wrong, 32, len(wrong_path))
        struct.pack_into('<q', wrong, 2144, len(wrong_path))
        wrong[96:2144] = wide_buffer(wrong_path, 2048)
        variations['wrong-path'] = good[:25] + [bytes(wrong)] + good[26:]
        late = bytearray(good[25])
        struct.pack_into('<QQ', late, 16, 110131, 110132)
        struct.pack_into('<QQ', late, 2160, 110131, 110132)
        variations['outside-delivery'] = good[:25] + [bytes(late)] + good[26:]
        for label, rows in variations.items():
            with self.subTest(label=label):
                d = decode(trace_fixture(rows))
                self.assertEqual(d['resources']['SDK_acquisition_count'], 1)
                self.assertEqual(d['resources']['SDK_release_count'], 1)
                self.assertFalse(d['diagnostic_candidate_complete'])

    def test_unentered_SDK_must_be_all_zero_after_native07_admission_fix(self):
        rows = bootstrap_fixture()
        bad = bytearray(rows[4])
        bad[2144:2176] = bytes(32)
        struct.pack_into('<I', bad, 2156, 16)
        rows[4] = bytes(bad)
        with self.assertRaises(reader.ReaderError):
            decode(trace_fixture(rows))

    def test_complete_synthetic_trace_is_only_inner_candidate(self):
        d = decode(trace_fixture())
        self.assertTrue(d['diagnostic_candidate_complete'])
        self.assertEqual(d['bootstrap']['scanner']['regions'], 5)
        p = reader.review(trace_fixture(), expected_config2048=config_fixture(),
                          schema_metadata=reader.SCHEMA_METADATA)
        self.assertFalse(p['fixed_false_claims']['external_cleanup_qualified'])
        self.assertFalse(p['resources']['all_resources_closed_or_empty'])
        self.assertFalse(p['fixed_false_claims']['actual_OS_TLS_verified'])

    def test_truncation_binding_and_owned_name_tamper(self):
        with self.assertRaises(reader.ReaderError):
            decode(trace_fixture()[:-1])
        b = bytearray(trace_fixture())
        b[232] ^= 1
        with self.assertRaises(reader.ReaderError):
            decode(bytes(b))
        rows = bootstrap_fixture()
        name = 'WS2_32.dll'.encode('utf-16-le') + b'\0\0'
        rows.append(row_fixture(201, len(rows), 110120, value=0x500000,
                                args=(0xffffffffffffffff, 0, 0), payload=name,
                                kind=1, module=2, sdk=False))
        self.assertTrue(decode(trace_fixture(rows))['classifications'][-1]['owned_input_reclassified'])
        bad = bytearray(rows[-1])
        struct.pack_into('<I', bad, 72, 3)
        rows[-1] = bytes(bad)
        with self.assertRaises(reader.ReaderError):
            decode(trace_fixture(rows))

    def test_SDK_nonnull_delivery_NULL_keeps_one_reference(self):
        rows = bootstrap_fixture()
        name = 'WS2_32.dll'.encode('utf-16-le') + b'\0\0'
        load = bytearray(row_fixture(202, len(rows), 110120, value=0,
                                     args=(0x400000, 0, 0), payload=name, kind=1,
                                     module=2, sdk=False))
        struct.pack_into('<I', load, 44, 1 | 2 | 256 | 1024)
        struct.pack_into('<Q', load, 24, 118000)
        struct.pack_into('<qiIQQ', load, 2144, 0x500000, 0, 7 | 32, 110121, 118000)
        rows.append(bytes(load))
        d = decode(trace_fixture(rows, state=2))
        self.assertFalse(d['diagnostic_candidate_complete'])
        self.assertEqual(d['resources']['SDK_acquisition_count'], 1)
        self.assertEqual(d['resources']['known_module_reference_lower_bound'], 1)
        self.assertEqual(d['rows'][-1]['raw_return'], 0)
        self.assertEqual(d['rows'][-1]['SDK']['raw_return'], 0x500000)

    def test_FALSE_error0_close_and_uncommitted_storage_are_unknown(self):
        rows = bootstrap_fixture()
        close = bytearray(rows[10])
        struct.pack_into('<q', close, 32, 0)
        struct.pack_into('<q', close, 2144, 0)
        rows[10] = bytes(close)
        d = decode(trace_fixture(rows, state=1))
        self.assertFalse(d['resources']['trace_handle_close_confirmed'])
        self.assertTrue(d['resources']['module_reference_state_unknown'])
        self.assertEqual(d['rows'][10]['SDK']['error'], 0)
        b = bytearray(trace_fixture())
        struct.pack_into('<Q', b, 256 + 8, 1)
        d = decode(bytes(b))
        self.assertFalse(d['stable'])
        self.assertFalse(d['diagnostic_candidate_complete'])
        b = bytearray(trace_fixture())
        b[-1] = 1
        self.assertTrue(decode(bytes(b))['unused_nonzero_rows'])

    def test_resolver_stub_direct_result_not_TLS_or_SDK(self):
        rows = bootstrap_fixture()
        row = bytearray(row_fixture(192, len(rows), 110120, value=11003, sdk=False))
        struct.pack_into('<iI', row, 40, 0, 1 | 2 | 8)
        rows.append(bytes(row))
        rows.append(row_fixture(111, len(rows), 110125, value=10093, sdk=False))
        b = bytearray(trace_fixture(rows, state=4))
        index = next(i for i, (_, ordinal) in enumerate(reader.EXPORTS) if ordinal == 192)
        struct.pack_into('<Q', b, 216, 1 << index)
        p = reader.review(bytes(b), expected_config2048=config_fixture(), schema_metadata=reader.SCHEMA_METADATA)
        self.assertEqual(p['calls'][-2]['direct_resolver_stub_result'], 11003)
        self.assertIsNone(p['calls'][-2]['delivery_error'])
        self.assertEqual(p['calls'][-1]['private_error_getter_result'], 10093)
        self.assertFalse(p['calls'][-1]['SDK']['entered'])
        self.assertFalse(p['diagnostic_candidate_complete'])
