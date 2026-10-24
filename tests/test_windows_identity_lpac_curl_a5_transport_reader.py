"""Synthetic byte inputs only; source author has not executed this suite."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from test_windows_identity_lpac_curl_a5_binary_reader import (
    reader, config_fixture, bootstrap_fixture, row_fixture, trace_fixture, resequence)


SOCKET = 0xa500


def delivery(op, slot, tick, *, value=0, args=(0, 0, 0), error=0,
             payload=b'', kind=0, module=0, unsupported=False):
    row = bytearray(row_fixture(op, slot, tick, value=value, args=args,
        payload=payload, kind=kind, module=module, sdk=False))
    flags = struct.unpack_from('<I', row, 44)[0] | 4 | (8 if unsupported else 0)
    struct.pack_into('<iI', row, 40, error, flags)
    return bytes(row)


def pipe_payload(**changes):
    fields = dict(read_bytes=13000, write_bytes=8500, read_calls=14,
        write_calls=9, peek_calls=16, prepared_qpc=110120, last_qpc=110399,
        failure=0, winerror=0, flags=255, core_failed=0, request_accepted=8193,
        response_delivered=12289, transport_complete=1, close_ready=1)
    fields.update(changes)
    raw = bytearray(128)
    struct.pack_into('<4sHH7Q8I', raw, 0, b'A5PF', 1, 128, *fields.values())
    return bytes(raw)


def transport_rows():
    rows = bootstrap_fixture()[:22]
    for name in ('api-ms-win-core-synch-l1-2-0', 'kernel32', 'api-ms-win-core-fibers-l1-1-1'):
        rows.append(delivery(202, len(rows), 110090 + len(rows), value=0,
            args=(0x400000, 0, 0x800), error=126,
            payload=name.encode('utf-16-le') + b'\0\0', kind=1,
            module=3 if name == 'kernel32' else 0, unsupported=True))
    rows.append(delivery(200, len(rows), 110116, value=0,
        args=(0x800000, 0x500000, 0), error=127,
        payload=b'wine_get_version\0', kind=2, module=5, unsupported=True))
    rows.append(bootstrap_fixture()[22])
    calls = [
        (23, SOCKET, (2, 1, 6), 0),
        (4, 0, (SOCKET, 0x600000, 16), 0),
        (19, 4000, (SOCKET, 0x610000, 8193), 0),
        (19, -1, (SOCKET, 0x611000, 4193), 10035),
        (19, 4193, (SOCKET, 0x611000, 4193), 0),
        (16, -1, (SOCKET, 0x620000, 8192), 10035),
        (16, 8192, (SOCKET, 0x620000, 8192), 0),
        (16, 4097, (SOCKET, 0x622000, 8192), 0),
        (3, 0, (SOCKET, 0, 0), 0)]
    for op, value, args, error in calls:
        rows.append(delivery(op, len(rows), 110140 + len(rows), value=value,
                              args=args, error=error))
    rows.append(delivery(116, len(rows), 110250))
    rows.append(delivery(400, len(rows), 110400, value=1,
                          payload=pipe_payload(), kind=10))
    return resequence(rows)


def make_trace(rows=None, *, state=4, mask=None):
    rows = transport_rows() if rows is None else resequence(rows)
    trace = bytearray(trace_fixture(rows, state=state))
    if mask is None:
        mask = sum(1 << index for index, (_, op) in enumerate(reader.EXPORTS) if op in (200, 202))
    struct.pack_into('<Q', trace, 216, mask)
    return bytes(trace)


def binding(trace):
    c = reader.validate_config(config_fixture(), schema_metadata=reader.SCHEMA_METADATA)
    return dict(scope=reader.SCOPE, config_bytes_sha256=c['sha256'],
        source_sha256=c['source_sha256'].hex(), trace_sha256=hashlib.sha256(trace).hexdigest(),
        run=c['run'].hex(), case_id=c['case_id'].hex(), target_pid=c['target_pid'],
        target_creation=c['target_creation'], inherited_handles=[0x100, 0x104, 0x108, 0x110, 0x114, 0x118],
        observed_inherited_handles=[0x100, 0x104, 0x108, 0x110, 0x114, 0x118],
        window_start=c['window_start'], window_end=c['window_end'],
        endpoint=dict(family='IPv4', address='127.0.0.1', port=50123, protocol='TCP'))


def decode(rows=None, **kw):
    trace = make_trace(rows, **kw)
    return reader.decode_trace(trace, expected_config2048=config_fixture(),
        schema_metadata=reader.SCHEMA_METADATA, transport_binding=binding(trace))


class ConfigTailTests(unittest.TestCase):
    def test_fixed_tail_decodes_without_calling_encoder(self):
        c = reader.validate_config(config_fixture(), schema_metadata=reader.SCHEMA_METADATA)
        self.assertEqual((c['pipe_read'], c['pipe_write'], c['origin_port']), (0x104, 0x108, 50123))
        self.assertEqual(c['case_id'], b'a' * 16)
        self.assertEqual(c['request_total'], 8193)
        self.assertEqual(c['response_total'], 12289)

    def test_old_magic_alias_case_reserved_and_profile_fail_closed(self):
        edits = [(0, b'A4P1'), (1800, struct.pack('<Q', 0x100)),
                 (1816, b'n' * 16), (1834, b'\2\0'),
                 (1836, struct.pack('<I', 8192)), (1856, struct.pack('<H', 50123)),
                 (1858, b'\1'), (1860, b'\1')]
        for offset, value in edits:
            raw = bytearray(config_fixture()); raw[offset:offset + len(value)] = value
            with self.subTest(offset=offset), self.assertRaises(reader.ReaderError):
                reader.validate_config(bytes(raw), schema_metadata=reader.SCHEMA_METADATA)

    def test_scope_and_metadata_are_closed_and_separate_from_A4(self):
        self.assertEqual(reader.SCOPE, 'local-lpac-curl-a5-http')
        metadata = copy.deepcopy(reader.SCHEMA_METADATA)
        metadata['scope'] = 'local-lpac-curl-a4-loader'
        with self.assertRaises(reader.ReaderError):
            reader.validate_config(config_fixture(), schema_metadata=metadata)
        path = Path(__file__).resolve().parents[1] / '.github/windows_identity_lpac_curl_a5_trace_abi.json'
        self.assertEqual(json.loads(path.read_text()), reader.SCHEMA_METADATA)


class TransportTests(unittest.TestCase):
    def test_single_nonblocking_connect_keeps_pending_raw_then_actual_byte_deliveries(self):
        rows = transport_rows()
        index = next(i for i, raw in enumerate(rows) if struct.unpack_from('<I', raw, 4)[0] == 4)
        raw = bytearray(rows[index]); struct.pack_into('<q', raw, 32, -1)
        struct.pack_into('<i', raw, 40, 10035); rows[index] = bytes(raw)
        d = decode(rows)
        self.assertTrue(d['transport']['transport_candidate'])
        self.assertTrue(d['transport']['connect_delivery_WSAEWOULDBLOCK'])
        self.assertFalse(d['transport']['connect_delivery_returned_zero'])
        self.assertEqual(d['rows'][index]['raw_return'], -1)
        self.assertEqual(d['rows'][index]['error'], 10035)
        self.assertTrue(d['rows'][index]['SDK']['absent'])
        self.assertEqual(d['transport']['successful_send_total'], 8193)
        self.assertEqual(d['transport']['successful_recv_total'], 12289)

    def test_connect_zero_or_pending_without_real_delivery_neither_qualifies(self):
        for result, error in ((0, 0), (-1, 10035), (-1, 10036)):
            rows = transport_rows()
            index = next(i for i, raw in enumerate(rows) if struct.unpack_from('<I', raw, 4)[0] == 4)
            raw = bytearray(rows[index]); struct.pack_into('<q', raw, 32, result)
            struct.pack_into('<i', raw, 40, error); rows[index] = bytes(raw)
            rows = [raw for raw in rows if struct.unpack_from('<I', raw, 4)[0] not in (16, 19)]
            with self.subTest(result=result, error=error):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_pending_connect_requires_error_valid_and_exact_error(self):
        for error, error_valid in ((10036, True), (10035, False)):
            rows = transport_rows()
            index = next(i for i, raw in enumerate(rows) if struct.unpack_from('<I', raw, 4)[0] == 4)
            raw = bytearray(rows[index]); struct.pack_into('<q', raw, 32, -1)
            struct.pack_into('<i', raw, 40, error)
            if not error_valid:
                struct.pack_into('<I', raw, 44, struct.unpack_from('<I', raw, 44)[0] & ~4)
            rows[index] = bytes(raw)
            with self.subTest(error=error, error_valid=error_valid):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_synthetic_candidate_keeps_all_four_raw_rejections_and_full_diagnostic_false(self):
        rows = transport_rows(); d = decode(rows)
        self.assertTrue(d['transport']['transport_candidate'])
        self.assertFalse(d['diagnostic_candidate_complete'])
        self.assertEqual(d['header']['state_flags'], 4)
        self.assertNotEqual(d['header']['unsupported_mask'], 0)
        self.assertEqual([r['raw'] for r in d['transport']['closed_loader_probes']['rows']], rows[22:26])
        self.assertTrue(all(r['unsupported'] and r['SDK']['absent'] for r in d['rows'][22:26]))
        self.assertEqual(d['transport']['nonblocking_pending_count'], 2)
        self.assertFalse(d['transport']['actual_Winsock_OS_calls_verified'])
        self.assertFalse(d['resources']['all_resources_closed_or_empty'])

    def test_missing_summary_binding_or_HTTP_controls_never_infers_success(self):
        self.assertFalse(decode(transport_rows()[:-1])['transport']['transport_candidate'])
        trace = make_trace()
        d = reader.decode_trace(trace, expected_config2048=config_fixture(), schema_metadata=reader.SCHEMA_METADATA)
        self.assertFalse(d['transport']['transport_candidate'])
        p = reader.review(trace, expected_config2048=config_fixture(), schema_metadata=reader.SCHEMA_METADATA,
                          transport_binding=binding(trace))
        self.assertTrue(p['transport']['transport_candidate'])
        self.assertFalse(p['transport_with_HTTP_byte_controls_candidate'])
        self.assertFalse(p['ordinary_HTTP_byte_controls']['byte_controls_candidate'])
        self.assertTrue(all(value is False for value in p['fixed_false_claims'].values()))

    def test_HANDLE_LIST_mismatch_extra_alias_bool_and_epoch_are_rejected(self):
        trace = make_trace()
        changes = [('scope', 'wrong'), ('config_bytes_sha256', '0' * 64),
                   ('inherited_handles', [0x100, 0x104, 0x108, 0x110, 0x114, 0x114]),
                   ('observed_inherited_handles', [0x100, 0x104, 0x108, 0x110, 0x114, 0x119]),
                   ('window_end', 118001), ('target_pid', True),
                   ('endpoint', dict(family='IPv4', address='127.0.0.2', port=50123, protocol='TCP'))]
        for key, value in changes:
            b = binding(trace); b[key] = value
            with self.subTest(key=key):
                d = reader.decode_trace(trace, expected_config2048=config_fixture(),
                    schema_metadata=reader.SCHEMA_METADATA, transport_binding=b)
                self.assertFalse(d['transport']['transport_candidate'])

    def test_clearing_original_unsupported_mask_does_not_make_new_candidate(self):
        d = decode(mask=0, state=0)
        self.assertFalse(d['transport']['transport_candidate'])
        self.assertFalse(d['diagnostic_candidate_complete'])
        self.assertIn('unsupported_header_missing_observed_bit', d['reasons'])

    def test_unflagged_extra_unsupported_call_cannot_hide_under_preserved_loader_bits(self):
        rows = transport_rows()
        rows.insert(-1, delivery(192, len(rows), 110300, value=11003))
        self.assertFalse(decode(rows)['transport']['transport_candidate'])
        rows = transport_rows()
        rows.insert(-1, delivery(200, len(rows), 110300, value=0,
            args=(0x800000, 0x510000, 0), error=127,
            payload=b'wine_get_version\0', kind=2, module=5, unsupported=False))
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_wouldblock_is_not_unsupported_or_OS_denial(self):
        d = decode()
        row = next(r for r in d['rows'] if r['error'] == 10035)
        kind = reader.delivery_kind(row)
        self.assertTrue(kind['nonblocking_pending'])
        self.assertTrue(kind['SDK_absent'])
        self.assertFalse(kind['unsupported'])
        self.assertFalse(kind['OS_denial_observed'])
        self.assertEqual(row['raw_return'], -1)
        self.assertEqual(row['raw'][2144:], bytes(32))

    def test_changed_send_total_socket_alias_and_duplicate_close_fail(self):
        for mutation in ('send_total', 'socket_alias', 'duplicate_close'):
            rows = transport_rows()
            if mutation == 'duplicate_close':
                rows.insert(-1, rows[-3])
            else:
                index = next(i for i, raw in enumerate(rows) if struct.unpack_from('<I', raw, 4)[0] == 19)
                raw = bytearray(rows[index])
                struct.pack_into('<q' if mutation == 'send_total' else '<Q', raw,
                                 32 if mutation == 'send_total' else 48,
                                 3999 if mutation == 'send_total' else SOCKET + 1)
                rows[index] = bytes(raw)
            with self.subTest(mutation=mutation):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_summary_fields_and_count_bounds_are_authoritative(self):
        for change in (dict(flags=255 | 256), dict(core_failed=1), dict(failure=1),
                       dict(winerror=5), dict(read_bytes=14337), dict(write_bytes=9793),
                       dict(peek_calls=13), dict(request_accepted=8192),
                       dict(response_delivered=12288), dict(close_ready=0)):
            rows = transport_rows()
            rows[-1] = delivery(400, len(rows)-1, 110400, value=1, payload=pipe_payload(**change), kind=10)
            with self.subTest(change=change):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_late_summary_keeps_raw_cleanup_facts_but_cannot_qualify(self):
        rows = transport_rows()
        rows[-1] = delivery(400, len(rows)-1, 118010, value=1,
            payload=pipe_payload(last_qpc=118009), kind=10)
        d = decode(rows)
        self.assertFalse(d['transport']['transport_candidate'])
        self.assertEqual(d['transport']['pipe_facts']['flags'], 255)
        self.assertEqual(d['transport']['pipe_facts']['last_qpc'], 118009)
        self.assertFalse(d['rows'][-1]['timely'])

    def test_duplicate_summary_reserved_and_uncommitted_tail_do_not_pass(self):
        rows = transport_rows(); rows.append(rows[-1])
        self.assertFalse(decode(rows)['transport']['transport_candidate'])
        rows = transport_rows(); raw = bytearray(rows[-1]); raw[96 + 96] = 1; rows[-1] = bytes(raw)
        with self.assertRaises(reader.ReaderError):
            decode(rows)
        trace = bytearray(make_trace()); struct.pack_into('<Q', trace, 256 + (len(transport_rows())-1)*2176 + 8, 1)
        d = reader.decode_trace(bytes(trace), expected_config2048=config_fixture(),
            schema_metadata=reader.SCHEMA_METADATA, transport_binding=binding(bytes(trace)))
        self.assertFalse(d['transport']['transport_candidate'])
        self.assertTrue(d['uncommitted_rows'])

    def test_real_SDK_receipt_cannot_be_invented_for_virtual_socket(self):
        rows = transport_rows()
        index = next(i for i, raw in enumerate(rows) if struct.unpack_from('<I', raw, 4)[0] == 23)
        raw = bytearray(rows[index]); struct.pack_into('<qiIQQ', raw, 2144, SOCKET, 0, 7, 110167, 110168)
        rows[index] = bytes(raw)
        with self.assertRaises(reader.ReaderError):
            decode(rows)


class OrdinaryByteControlTests(unittest.TestCase):
    def records(self):
        result = []
        for case in (b'b' * 16, b'c' * 16):
            header = (f'POST /ruleproxy-a2/{case.hex()} HTTP/1.1\r\nHost: 127.0.0.1:50123\r\n'
                      'Content-Length: 8065\r\nConnection: close\r\n\r\n').encode('ascii')
            result.append(dict(case_id=case, origin_port=50123,
                request=header + bytes((i*73+17)%256 for i in range(8065)),
                stdout=bytes((i*29+211)%256 for i in range(12176)), stderr=b'', stdin=b'',
                natural_exit_code=0, curl_sha256='73d24149ff289afc49ec41f08918ef9faa727d39ad993e929757dc2ddafab805'))
        return result

    def test_two_exact_controls_are_separate_from_transport(self):
        p = reader.review_HTTP_byte_controls(self.records())
        self.assertTrue(p['byte_controls_candidate'])
        self.assertFalse(p['transport_candidate'])
        self.assertFalse(p['selected_LPAC_qualified'])

    def test_absent_mutated_duplicate_or_wrong_image_controls_fail(self):
        self.assertFalse(reader.review_HTTP_byte_controls(None)['byte_controls_candidate'])
        for key, value in (('stdout', b'x'), ('stderr', b'x'), ('stdin', b'x'),
                           ('natural_exit_code', True), ('curl_sha256', '0'*64)):
            records = self.records(); records[0][key] = value
            with self.subTest(key=key):
                self.assertFalse(reader.review_HTTP_byte_controls(records)['byte_controls_candidate'])
        records = self.records(); records[1] = records[0]
        self.assertFalse(reader.review_HTTP_byte_controls(records)['byte_controls_candidate'])
