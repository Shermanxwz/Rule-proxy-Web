"""Pure synthetic native05 receipts. Source author does not execute tests."""
import json
import struct
import unittest

from test_windows_identity_lpac_curl_a5_transport_reader import (
    reader, SOCKET, EVENT, delivery, kernel_delivery, transport_rows, decode,
    make_trace, binding, config_fixture)


def op(raw):
    return struct.unpack_from('<I', raw, 4)[0]


def replace(rows, operation, offset, fmt, value):
    index = next(i for i, raw in enumerate(rows) if op(raw) == operation)
    raw = bytearray(rows[index]); struct.pack_into(fmt, raw, offset, value)
    rows[index] = bytes(raw)


def insert_before_close(rows, extra):
    index = next(i for i, raw in enumerate(rows) if op(raw) == 3)
    raw = bytearray(rows[index]); struct.pack_into('<QQ', raw, 16, 110210, 110211)
    rows[index] = bytes(raw)
    return rows[:index] + extra + rows[index:]


def network(mask, *, error_index=None):
    errors = [0] * 10
    if error_index is not None:
        errors[error_index] = 10054
    return struct.pack('<I10i', mask, *errors)


def event_cycle(*, enum_event=0, wait=True, select_event=EVENT, cancel_event=0):
    rows = [delivery(67, 0, 110180, args=(SOCKET, select_event, 0x29))]
    if wait:
        rows.append(kernel_delivery(124, 0, 110184, value=0,
            args=(1, 0x700000, 0), payload=struct.pack('<Q4I', EVENT, 1000, 0, 0, 0), kind=12))
    enum = kernel_delivery if enum_event else delivery
    kw = {'sdk_value': 1} if enum_event else {}
    rows.append(enum(64, 0, 110188, value=0, args=(SOCKET, enum_event, 0x700100),
        payload=network(1), kind=11, **kw))
    rows.append(delivery(67, 0, 110190, args=(SOCKET, cancel_event, 0)))
    rows.append(kernel_delivery(95, 0, 110192, args=(EVENT, 0, 0)))
    return rows


def reuse_event_number(rows, handle):
    replace(rows, 50, 32, '<q', handle)
    replace(rows, 50, 2144, '<q', handle)
    replace(rows, 45, 48, '<Q', handle)
    return rows


def safe_review(rows):
    trace = make_trace(rows)
    return reader.review(trace, expected_config2048=config_fixture(),
        schema_metadata=reader.SCHEMA_METADATA, transport_binding=binding(trace))


def backlog_query(*, args=(SOCKET, 0x4004747B, 0),
                  inputs=(0, 0, 4, 0x700200, 0x700300, 0, 0), error=10045):
    return delivery(78, 0, 110200, value=-1, args=args, error=error,
                    payload=struct.pack('<QIIQQQQ', *inputs), kind=13)


class EventReaderTests(unittest.TestCase):
    def test_closed_inherited_trace_number_is_reusable_with_actual_nonzero_BOOL(self):
        for raw_return in (1, 7):
            rows = reuse_event_number(transport_rows(), 0x100)
            replace(rows, 310, 32, '<q', raw_return)
            replace(rows, 310, 2144, '<q', raw_return)
            d = decode(rows)
            with self.subTest(raw_return=raw_return):
                self.assertTrue(d['transport']['transport_candidate'])
                self.assertEqual(d['transport']['events']['generations'][0]['handle'], 0x100)
                self.assertEqual(next(r for r in d['rows'] if r['operation'] == 310)['SDK']['raw_return'], raw_return)

    def test_trace_handle_reuse_needs_unique_prior_successful_physical_close(self):
        base = reuse_event_number(transport_rows(), 0x100)
        close = next(raw for raw in base if op(raw) == 310)
        for mode in ('missing', 'FALSE', 'duplicate', 'after_create', 'unreturned'):
            rows = list(base)
            if mode == 'missing':
                rows = [raw for raw in rows if op(raw) != 310]
            elif mode == 'FALSE':
                replace(rows, 310, 32, '<q', 0); replace(rows, 310, 2144, '<q', 0)
            elif mode == 'duplicate':
                rows.insert(11, close)
            elif mode == 'after_create':
                replace(rows, 310, 16, '<Q', 110132); replace(rows, 310, 24, '<Q', 110133)
                replace(rows, 310, 2160, '<Q', 110132); replace(rows, 310, 2168, '<Q', 110133)
            else:
                replace(rows, 310, 24, '<Q', 0); replace(rows, 310, 32, '<q', 0)
                replace(rows, 310, 44, '<I', 2048 | 1)
                replace(rows, 310, 2144, '<32s', struct.pack('<qiIQQ', 0, 0, 1, 110041, 0))
            with self.subTest(mode=mode):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_other_five_inherited_handle_numbers_remain_forbidden(self):
        for handle in (0x104, 0x108, 0x110, 0x114, 0x118):
            rows = reuse_event_number(transport_rows(), handle)
            with self.subTest(handle=handle):
                facts = decode(rows)['transport']
                self.assertFalse(facts['transport_candidate'])
                self.assertIn('event_live_alias_or_inherited_handle', facts['events']['reasons'])

    def test_trace_number_reuse_still_obeys_event_generation_once_close(self):
        rows = reuse_event_number(transport_rows(), 0x100)
        rows[-2:-2] = [kernel_delivery(50, 0, 110230, value=0x100),
                       kernel_delivery(45, 0, 110235, args=(0x100, 0, 0))]
        facts = decode(rows)['transport']
        self.assertTrue(facts['transport_candidate'])
        self.assertEqual(facts['events']['confirmed_close_count'], 2)
        rows[-2:-2] = [kernel_delivery(45, 0, 110240, args=(0x100, 0, 0))]
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_safe_event_projection_contains_only_closed_booleans_and_counts(self):
        handle = 0x6ABCDE7012377
        rows = reuse_event_number(transport_rows(), handle)
        raw = decode(rows)
        self.assertEqual(raw['transport']['events']['generations'][0]['handle'], handle)
        result = safe_review(rows); safe = result['transport']['events']
        self.assertEqual(safe, dict(candidate=True, all_generations_closed=True,
            acquisition_count=1, confirmed_close_count=1,
            actual_Winsock_OS_calls_verified=False,
            event_readiness_independently_wire_verified=False))
        self.assertTrue(all(type(value) in (bool, int) for value in safe.values()))
        self.assertNotIn(str(handle), json.dumps(result, sort_keys=True))
        self.assertNotIn('"generations":', json.dumps(result, sort_keys=True))
        replace(rows, 45, 32, '<q', 0); replace(rows, 45, 2144, '<q', 0)
        failed = safe_review(rows)['transport']['events']
        self.assertFalse(failed['candidate']); self.assertFalse(failed['all_generations_closed'])
        self.assertEqual((failed['acquisition_count'], failed['confirmed_close_count']), (1, 0))

    def test_known_capability_and_pending_state_errors_are_projected_without_OS_denial(self):
        rows = transport_rows()
        rows[-2:-2] = [delivery(111, 0, 110230, value=10047),
                       delivery(111, 0, 110235, value=10057)]
        result = safe_review(rows)
        getters = [call for call in result['calls'] if call['operation'] == 111]
        self.assertEqual([call['private_error_getter_result'] for call in getters], [10047, 10057])
        self.assertTrue(all(not call['unclassified_private_error_value_present'] for call in getters))

    def test_trace_handle_fix_does_not_clear_actual_failed_socket_state(self):
        rows = reuse_event_number(transport_rows(), 0x100)
        rows = insert_before_close(rows, [delivery(6, 0, 110200, value=-1,
            args=(SOCKET, 0x700000, 0x700010), error=10057, unsupported=True)])
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_exact_optional_backlog_query_is_nonfatal_after_delivered_bytes(self):
        rows = insert_before_close(transport_rows(), [backlog_query(),
            delivery(111, 0, 110202, value=10045)])
        d = decode(rows); t = d['transport']
        self.assertTrue(t['transport_candidate'])
        self.assertEqual(t['ideal_send_backlog_query_count'], 1)
        self.assertFalse(t['ideal_send_backlog_query_OS_denial_observed'])
        row = next(r for r in d['rows'] if r['operation'] == 78)
        self.assertEqual((row['raw_return'], row['error'], row['capture']['captured_bytes']), (-1, 10045, 48))
        self.assertTrue(row['SDK']['absent']); self.assertFalse(row['unsupported'])
        result = safe_review(rows)
        self.assertEqual(next(c for c in result['calls'] if c['operation'] == 111)['private_error_getter_result'], 10045)

    def test_backlog_query_rejects_every_other_captured_argument_shape(self):
        good = (0, 0, 4, 0x700200, 0x700300, 0, 0)
        for index, value in ((0, 1), (1, 1), (2, 3), (2, 5), (3, 0), (4, 0), (5, 1), (6, 1)):
            fields = list(good); fields[index] = value
            rows = insert_before_close(transport_rows(), [backlog_query(inputs=fields)])
            with self.subTest(index=index, value=value):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])
        for args in ((SOCKET + 1, 0x4004747B, 0), (SOCKET, 0x4004747A, 0), (SOCKET, 0x4004747B, 1)):
            with self.subTest(args=args):
                self.assertFalse(decode(insert_before_close(transport_rows(), [backlog_query(args=args)]))['transport']['transport_candidate'])

    def test_backlog_query_needs_exact_raw_decline_and_full_owned_input(self):
        for offset, fmt, value in ((32, '<q', 0), (40, '<i', 10057), (44, '<I', 1 | 2 | 256),
                                   (44, '<I', 1 | 2 | 4 | 8 | 256), (68, '<I', 47), (64, '<I', 0)):
            rows = insert_before_close(transport_rows(), [backlog_query()])
            replace(rows, 78, offset, fmt, value)
            with self.subTest(offset=offset, value=value):
                try:
                    self.assertFalse(decode(rows)['transport']['transport_candidate'])
                except reader.ReaderError:
                    pass  # Malformed capture extents fail before qualification.
        rows = insert_before_close(transport_rows(), [backlog_query()])
        replace(rows, 78, 2144, '<32s', struct.pack('<qiIQQ', -1, 10045, 7, 110200, 110201))
        with self.assertRaises(reader.ReaderError):
            decode(rows)

    def test_backlog_query_before_payload_or_after_once_close_cannot_qualify(self):
        for where in ('before_payload', 'after_close'):
            rows = transport_rows()
            operation = 19 if where == 'before_payload' else 45
            index = next(i for i, raw in enumerate(rows) if op(raw) == operation)
            rows.insert(index, backlog_query())
            with self.subTest(where=where):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_kernel_events_are_separate_from_absent_Winsock_provider(self):
        d = decode(); facts = d['transport']['events']
        self.assertTrue(d['transport']['transport_candidate'])
        self.assertEqual((facts['acquisition_count'], facts['confirmed_close_count']), (1, 1))
        self.assertEqual(facts['SDK_domain'], 'kernel32_event_not_Winsock_provider')
        self.assertFalse(facts['actual_Winsock_OS_calls_verified'])
        self.assertFalse(facts['event_readiness_independently_wire_verified'])

    def test_missing_event_SDK_cannot_make_nonzero_delivery_an_acquisition(self):
        rows = transport_rows(); replace(rows, 50, 2144, '<32s', bytes(32))
        d = decode(rows)
        self.assertFalse(d['transport']['transport_candidate'])
        self.assertEqual(d['transport']['events']['acquisition_count'], 0)

    def test_primary_BOOL_delivery_is_canonical_but_raw_kernel_BOOL_is_preserved(self):
        for raw_return in (2, 7):
            rows = insert_before_close(transport_rows(), event_cycle())
            replace(rows, 45, 2144, '<q', raw_return)
            replace(rows, 95, 2144, '<q', raw_return)
            d = decode(rows)
            with self.subTest(raw_return=raw_return):
                self.assertTrue(d['transport']['transport_candidate'])
                for operation in (45, 95):
                    row = next(row for row in d['rows'] if row['operation'] == operation)
                    self.assertEqual(row['raw_return'], 1)
                    self.assertEqual(row['SDK']['raw_return'], raw_return)

    def test_FALSE_close_keeps_unknown_generation_and_cannot_be_retried(self):
        rows = transport_rows(); replace(rows, 45, 2144, '<q', 0)
        replace(rows, 45, 32, '<q', 0)
        d = decode(rows); g = d['transport']['events']['generations'][0]
        self.assertTrue(g['close_attempted']); self.assertFalse(g['close_confirmed'])
        self.assertTrue(g['state_unknown']); self.assertFalse(d['transport']['transport_candidate'])
        rows.insert(-2, kernel_delivery(45, 0, 110225, args=(EVENT, 0, 0)))
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_closed_handle_number_can_be_reused_by_a_new_generation(self):
        rows = transport_rows()
        rows[-2:-2] = [kernel_delivery(50, 0, 110230, value=EVENT),
                       kernel_delivery(45, 0, 110235, args=(EVENT, 0, 0))]
        facts = decode(rows)['transport']
        self.assertTrue(facts['transport_candidate'])
        self.assertEqual(facts['events']['acquisition_count'], 2)
        self.assertEqual(facts['events']['confirmed_close_count'], 2)

    def test_two_live_or_inherited_event_handles_fail(self):
        rows = transport_rows(); index = next(i for i, raw in enumerate(rows) if op(raw) == 50)
        rows.insert(index + 1, kernel_delivery(50, 0, 110135, value=EVENT + 4))
        self.assertFalse(decode(rows)['transport']['transport_candidate'])
        rows = transport_rows(); replace(rows, 50, 32, '<q', 0x104); replace(rows, 50, 2144, '<q', 0x104)
        replace(rows, 45, 48, '<Q', 0x104)
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_enum_NULL_and_NULL_mask_zero_cancellation_are_valid(self):
        d = decode(insert_before_close(transport_rows(), event_cycle()))
        self.assertTrue(d['transport']['transport_candidate'])
        enum = next(row for row in d['rows'] if row['operation'] == 64)
        self.assertTrue(enum['SDK']['absent'])
        self.assertEqual(enum['capture']['captured_bytes'], 44)

    def test_enum_nonnull_requires_actual_ResetEvent_receipt(self):
        rows = insert_before_close(transport_rows(), event_cycle(enum_event=EVENT))
        self.assertTrue(decode(rows)['transport']['transport_candidate'])
        replace(rows, 64, 2144, '<32s', bytes(32))
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_enum_NULL_must_not_invent_a_ResetEvent_call(self):
        rows = insert_before_close(transport_rows(), event_cycle())
        replace(rows, 64, 2144, '<32s', struct.pack('<qiIQQ', 1, 0, 7, 110188, 110189))
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_FD_ACCEPT_subscription_does_not_authorize_listener_event_or_error(self):
        for payload in (network(8), network(2), network(1, error_index=0)):
            rows = insert_before_close(transport_rows(), event_cycle())
            replace(rows, 64, 96, '<44s', payload)
            with self.subTest(payload=payload):
                self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_wait_is_exact_one_event_nonalertable_wait_any(self):
        rows = insert_before_close(transport_rows(), event_cycle())
        for offset, value in ((48, 2), (88, 1), (96, EVENT + 4), (108, 1), (112, 1), (116, 1)):
            mutated = list(rows)
            replace(mutated, 124, offset, '<Q' if offset in (48, 88, 96) else '<I', value)
            with self.subTest(offset=offset):
                self.assertFalse(decode(mutated)['transport']['transport_candidate'])

    def test_wait_timeout_is_actual_258_not_a_fabricated_signal(self):
        rows = insert_before_close(transport_rows(), event_cycle())
        replace(rows, 124, 32, '<q', 258); replace(rows, 124, 2144, '<q', 258)
        self.assertTrue(decode(rows)['transport']['transport_candidate'])
        replace(rows, 124, 32, '<q', 0)
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_internal_signal_and_reset_need_known_actual_kernel_success(self):
        rows = insert_before_close(transport_rows(), [kernel_delivery(331, 0, 110180, args=(EVENT, 0, 0)),
            kernel_delivery(332, 0, 110182, args=(EVENT, 0, 0))])
        self.assertTrue(decode(rows)['transport']['transport_candidate'])
        replace(rows, 331, 32, '<q', 0); replace(rows, 331, 2144, '<q', 0)
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_close_after_summary_or_work_cutoff_keeps_fact_without_qualification(self):
        for tick in (110410, 118010):
            rows = transport_rows(); index = next(i for i, raw in enumerate(rows) if op(raw) == 45)
            rows[index] = kernel_delivery(45, index, tick, args=(EVENT, 0, 0))
            d = decode(rows)
            with self.subTest(tick=tick):
                self.assertFalse(d['transport']['transport_candidate'])
                self.assertTrue(d['transport']['events']['generations'][0]['close_confirmed'])

    def test_exact_IPv6_capability_probe_is_closed_not_OS_denial(self):
        rows = transport_rows(); index = next(i for i, raw in enumerate(rows) if op(raw) == 23)
        rows.insert(index, delivery(23, 0, 110145, value=-1, args=(23, 2, 0), error=10047))
        t = decode(rows)['transport']
        self.assertTrue(t['transport_candidate']); self.assertEqual(t['socket_calls'], 1)
        self.assertEqual(t['IPv6_capability_probe_count'], 1)
        self.assertFalse(t['IPv6_capability_probe_OS_denial_observed'])
        self.assertFalse(t['IPv6_isolation_qualified'])
        for args, error in (((23, 2, 0), 10013), ((23, 1, 0), 10047), ((23, 2, 17), 10047)):
            mutated = list(rows); mutated[index] = delivery(23, 0, 110145, value=-1, args=args, error=error)
            with self.subTest(args=args, error=error):
                self.assertFalse(decode(mutated)['transport']['transport_candidate'])
        rows.insert(index, rows[index]); self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_send_zero_nonsticky_not_connected_only_after_pending_connect_before_data(self):
        rows = transport_rows(); replace(rows, 4, 32, '<q', -1); replace(rows, 4, 40, '<i', 10035)
        index = next(i for i, raw in enumerate(rows) if op(raw) == 19)
        rows.insert(index, delivery(19, 0, 110171, value=-1, args=(SOCKET, 0, 0), error=10057))
        d = decode(rows)
        self.assertTrue(d['transport']['transport_candidate'])
        self.assertEqual(d['transport']['zero_send_not_connected_count'], 1)
        self.assertEqual(d['transport']['successful_send_total'], 8193)
        replace(rows, 4, 32, '<q', 0); replace(rows, 4, 40, '<i', 0)
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_successful_send_zero_does_not_count_as_HTTP_payload(self):
        rows = insert_before_close(transport_rows(), [delivery(19, 0, 110180, args=(SOCKET, 0, 0))])
        d = decode(rows)
        self.assertTrue(d['transport']['transport_candidate'])
        self.assertEqual(d['transport']['successful_send_total'], 8193)

    def test_recv_caller_capacity_1MiB_and_send_64KiB_are_separate_bounds(self):
        rows = transport_rows()
        for index, raw in enumerate(rows):
            if op(raw) == 16:
                value = bytearray(raw); struct.pack_into('<Q', value, 88, 1048576)
                rows[index] = bytes(value)
        self.assertTrue(decode(rows)['transport']['transport_candidate'])
        index = next(i for i, raw in enumerate(rows) if op(raw) == 16 and struct.unpack_from('<q', raw, 32)[0] > 0)
        raw = bytearray(rows[index]); struct.pack_into('<Q', raw, 88, 1048577); rows[index] = bytes(raw)
        self.assertFalse(decode(rows)['transport']['transport_candidate'])
        rows = transport_rows(); replace(rows, 19, 88, '<Q', 65537)
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_wait_capacity_above_native_8000ms_is_rejected(self):
        rows = insert_before_close(transport_rows(), event_cycle())
        replace(rows, 124, 104, '<I', 8000)
        self.assertTrue(decode(rows)['transport']['transport_candidate'])
        replace(rows, 124, 104, '<I', 8001)
        self.assertFalse(decode(rows)['transport']['transport_candidate'])

    def test_missing_events_and_seventeenth_generation_cannot_qualify(self):
        rows = [raw for raw in transport_rows() if op(raw) not in reader.EVENT_EXPORTS]
        self.assertFalse(decode(rows)['transport']['transport_candidate'])
        rows = transport_rows(); extra = []
        for index in range(16):
            tick = 110225 + index * 4
            extra.extend([kernel_delivery(50, 0, tick, value=EVENT),
                kernel_delivery(45, 0, tick + 2, args=(EVENT, 0, 0))])
        rows[-2:-2] = extra
        index = next(i for i, raw in enumerate(rows) if op(raw) == 116)
        rows[index] = delivery(116, 0, 110350)
        d = decode(rows)
        self.assertEqual(d['transport']['events']['acquisition_count'], 17)
        self.assertFalse(d['transport']['transport_candidate'])

