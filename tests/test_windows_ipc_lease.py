"""Pure ctypes/mock tests: no DLL load, application launch or WFP operation."""
import copy
import ctypes as C
from dataclasses import replace
import struct
import unittest
from unittest.mock import patch
import uuid

from ruleproxy import windows_ipc_lease as ipc

wfp = ipc.wfp
PROVIDER = uuid.UUID('aca2caba-f499-4000-8000-000000000001')
SUBLAYER = uuid.UUID('aca2caba-f499-4000-8000-000000000002')


def sd(rid=1001):
    sid = bytes([1, 2]) + bytes.fromhex('000000000005') + struct.pack('<II', 21, rid)
    ace = struct.pack('<BBHI', 0, 0, 8 + len(sid), 1) + sid
    acl = struct.pack('<BBHHH', 2, 0, 8 + len(ace), 1, 0) + ace
    return struct.pack('<BBHIIII', 1, 0, 0x8004, 0, 0, 0, 20) + acl


def endpoint(port=54321, client='client.exe', server='server.exe', owner=1001):
    return ipc.Endpoint(('\\device\\volume\\' + server + '\0').encode('utf-16-le'),
                        ('\\device\\volume\\' + client + '\0').encode('utf-16-le'), sd(owner), port)


def native_filter(key, snapshot):
    layer, flags, provider, sublayer, marker, data, action, kind, weight, conditions, context, reserved = snapshot
    keep = []
    value = wfp._Filter()
    value.key, value.layer, value.sublayer = map(wfp._GUID.of, (key, layer, sublayer))
    value.flags = flags
    if provider:
        owner = wfp._GUID.of(provider)
        keep.append(owner)
        value.provider = C.pointer(owner)
    value.display = wfp._Display('mock', marker)
    blob = C.create_string_buffer(data)
    keep.append(blob)
    value.data = wfp._Blob(len(data), C.cast(blob, wfp._P))
    value.action.type = action
    value.weight = wfp._value(kind, weight, keep)
    array = (wfp._Condition * len(conditions))()
    for index, (field, match, typ, content) in enumerate(conditions):
        array[index] = wfp._Condition(wfp._GUID.of(field), match, wfp._value(typ, content, keep))
    value.count, value.conditions = len(array), array
    value.context.raw = context
    if reserved:
        key_value = wfp._GUID.of(PROVIDER)
        keep.append(key_value)
        value.reserved = C.pointer(key_value)
    keep.extend((array, value))
    return value, keep


class Function:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class DLL:
    """SDK-shaped fake with detached storage and transaction rollback semantics."""
    def __init__(self):
        self.records, self.heap, self.events = {}, [], []
        self.fail, self.close_error = '', 0
        self.add_count = self.opens = self.closes = self.frees = self.enum_closes = 0
        self.base = {'persistent-base-block': b'unchanged'}
        self.committed_corruption = None
        self.get_corruption = None
        self.tx = None
        self.funcs = {}

    def __getattr__(self, name):
        if name not in self.funcs:
            try:
                function = object.__getattribute__(self, '_' + name)
            except AttributeError:
                def function(*_args):
                    raise AssertionError('Unexpected native call: ' + name)
            self.funcs[name] = Function(function)
        return self.funcs[name]

    def _FwpmEngineOpen0(self, _server, auth, _identity, session, output):
        self.opens += 1
        self.events.append('open')
        value = C.cast(session, C.POINTER(wfp._Session)).contents
        assert value.flags == 1 and value.timeout == 5000 and auth == 0xFFFFFFFF
        if self.fail == 'open':
            return 5
        C.cast(output, C.POINTER(wfp._P))[0] = wfp._P(123)
        return 0

    def _FwpmEngineClose0(self, handle):
        assert handle.value == 123
        self.closes += 1
        self.events.append('close')
        if self.close_error:
            return self.close_error
        self.records.clear()
        return 0

    def _FwpmTransactionBegin0(self, _handle, flags):
        self.events.append('begin')
        if self.fail == 'begin':
            return 5
        assert flags == 0 and self.tx is None
        self.tx = copy.deepcopy(self.records)
        return 0

    def _FwpmTransactionCommit0(self, _handle):
        self.events.append('commit')
        if self.fail == 'commit':
            return 5
        self.tx = None
        if self.committed_corruption:
            self.committed_corruption(self.records)
        return 0

    def _FwpmTransactionAbort0(self, _handle):
        self.events.append('abort')
        if self.tx is not None:
            self.records, self.tx = self.tx, None
        return 0

    def _FwpmFilterAdd0(self, _handle, pointer, descriptor, ident):
        self.add_count += 1
        self.events.append('add')
        if self.fail == 'add' or self.fail == 'add' + str(self.add_count):
            return 5
        assert descriptor is None
        value = C.cast(pointer, C.POINTER(wfp._Filter)).contents
        assert value.key.text() not in self.records
        self.records[value.key.text()] = ipc._read_filter(value)
        C.cast(ident, C.POINTER(wfp._U64))[0] = self.add_count
        return 0

    def _FwpmFilterDeleteByKey0(self, _handle, pointer):
        self.events.append('delete')
        if self.fail == 'delete':
            return 5
        key = C.cast(pointer, C.POINTER(wfp._GUID)).contents.text()
        assert key in self.records
        del self.records[key]
        return 0

    def _FwpmFilterGetByKey0(self, _handle, pointer, output):
        if self.fail == 'read':
            return 5
        key = C.cast(pointer, C.POINTER(wfp._GUID)).contents.text()
        if key not in self.records:
            return wfp._NOT_FOUND['Filter']
        snapshot = self.records[key]
        if self.get_corruption:
            snapshot = self.get_corruption(snapshot)
        value, keep = native_filter(key, snapshot)
        self.heap.append(keep)
        C.cast(output, C.POINTER(C.POINTER(wfp._Filter)))[0] = C.pointer(value)
        return 0

    def _FwpmFilterCreateEnumHandle0(self, _handle, pointer, output):
        if self.fail == 'enum_open':
            return 5
        # Regression: the real engine rejects a non-NULL GUID_NULL-layer
        # template with FWP_E_LAYER_NOT_FOUND. This fake used to bless it.
        if pointer:
            return 0x80320004
        self.enum_values = list(self.records.items())
        C.cast(output, C.POINTER(wfp._P))[0] = wfp._P(456)
        return 0

    def _FwpmFilterEnum0(self, _handle, _enum, requested, output, count):
        if self.fail == 'enum':
            return 5
        batch, self.enum_values = self.enum_values[:requested], self.enum_values[requested:]
        array = (C.POINTER(wfp._Filter) * len(batch))()
        for index, (key, snapshot) in enumerate(batch):
            value, keep = native_filter(key, snapshot)
            self.heap.append(keep)
            array[index] = C.pointer(value)
        self.heap.append(array)
        C.cast(output, C.POINTER(C.POINTER(C.POINTER(wfp._Filter))))[0] = C.cast(array, C.POINTER(C.POINTER(wfp._Filter)))
        C.cast(count, C.POINTER(wfp._U32))[0] = len(batch)
        return 0

    def _FwpmFilterDestroyEnumHandle0(self, _handle, _enum):
        self.enum_closes += 1
        return 5 if self.fail == 'enum_close' else 0

    def _FwpmFreeMemory0(self, _pointer):
        self.frees += 1


class Guard:
    provider, sublayer = PROVIDER, SUBLAYER

    def __init__(self):
        self.provider_ok = self.sublayer_ok = True

    def _owned_provider(self, _engine):
        return self.provider_ok

    def _owned_sublayer(self, _engine):
        return self.sublayer_ok


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.dll, self.guard = DLL(), Guard()
        self.patch = patch.object(C, 'WinDLL', return_value=self.dll, create=True)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.platform_patch = patch.object(wfp.os, 'name', 'nt')
        self.platform_patch.start()
        self.addCleanup(self.platform_patch.stop)
        self.lease = ipc.LeaseSet(self.guard)

    def test_exact_three_rule_plan_and_typed_native_roundtrip(self):
        ep = endpoint()
        keys = self.lease.replace([ep])
        self.assertEqual(len(keys), 3)
        rules = ipc._plan([ep], self.lease.epoch)
        self.assertEqual([r.layer for r in rules], [ipc._CONNECT4, ipc._ACCEPT4, ipc._ACCEPT4])
        self.assertEqual([r.weight for r in rules], [14, 14, 13])
        self.assertEqual([r.action for r in rules], [wfp._PERMIT, wfp._PERMIT, wfp._BLOCK])
        self.assertEqual([len(r.conditions) for r in rules], [5, 5, 3])
        self.assertIn(('app', 0, 12, ep.client_app_id), rules[0].conditions)
        self.assertIn(('app', 0, 12, ep.server_app_id), rules[1].conditions)
        for rule in rules[:2]:
            self.assertIn(('user', 0, 14, ep.owner_sd), rule.conditions)
        self.assertEqual(set(rules[2].conditions), {('protocol', 0, 1, 6), ('local', 0, 3, 0x7f000001), ('local_port', 0, 2, ep.port)})
        self.assertEqual(keys, self.lease.verify())
        self.assertEqual(self.dll.opens, 1)
        self.assertEqual(self.dll.base, {'persistent-base-block': b'unchanged'})

    def test_replace_reuses_session_and_is_atomic(self):
        old = self.lease.replace([endpoint()])
        self.dll.events.clear()
        new = self.lease.replace([endpoint(54322)])
        self.assertTrue(set(old).isdisjoint(new))
        self.assertEqual(set(self.dll.records), set(new))
        self.assertEqual(self.dll.events, ['begin'] + ['delete'] * 3 + ['add'] * 3 + ['commit', 'begin', 'commit'])
        self.assertEqual(self.dll.opens, 1)
        self.assertEqual(self.dll.closes, 0)

    def test_same_endpoint_reproducible_keys_epoch_distinct(self):
        first = self.lease.replace([endpoint()])
        self.assertEqual(first, self.lease.replace([endpoint()]))
        other = ipc.LeaseSet(self.guard)
        self.assertNotEqual(self.lease.epoch, other.epoch)
        self.assertTrue(set(first).isdisjoint(r.key for r in ipc._plan([endpoint()], other.epoch)))

    def test_clear_keeps_session_purge_closes_terminally(self):
        self.lease.replace([endpoint()])
        self.assertEqual(self.lease.replace([]), ())
        self.assertFalse(self.lease.closed)
        self.assertEqual(self.dll.records, {})
        self.lease.replace([endpoint()])
        self.lease.purge()
        self.assertTrue(self.lease.closed)
        self.assertEqual(self.dll.records, {})
        self.lease.close()
        self.assertEqual(self.dll.closes, 1)
        with self.assertRaises(ipc.ProxyError):
            self.lease.replace([])

    def test_invalid_replacement_preserves_verified_rules(self):
        keys = self.lease.replace([endpoint()])
        for values in ([endpoint(), endpoint(client='different.exe')], [endpoint(p + 1) for p in range(17)],
                       [object()], iter([endpoint()]), None):
            with self.subTest(values=type(values).__name__), self.assertRaises(ValueError):
                self.lease.replace(values)
        self.assertEqual(keys, self.lease.verify())
        self.assertEqual(self.dll.closes, 0)

    def test_max_sixteen_endpoints(self):
        self.assertEqual(len(self.lease.replace([endpoint(p + 1) for p in range(16)])), 48)

    def test_missing_base_never_adds_rules(self):
        self.guard.provider_ok = False
        with self.assertRaises(ipc.ProxyError):
            self.lease.replace([endpoint()])
        self.assertEqual(self.dll.add_count, 0)
        self.assertTrue(self.lease.closed)

    def test_missing_sublayer_never_adds_rules(self):
        self.guard.sublayer_ok = False
        with self.assertRaises(ipc.ProxyError):
            self.lease.replace([endpoint()])
        self.assertEqual(self.dll.add_count, 0)

    def test_native_failures_close_dynamic_session(self):
        for phase in ('open', 'begin', 'add1', 'add2', 'add3', 'read', 'commit', 'enum_open', 'enum', 'enum_close'):
            with self.subTest(phase=phase):
                self.dll.__init__()
                self.dll.fail = phase
                lease = ipc.LeaseSet(self.guard)
                with self.assertRaises(ipc.ProxyError):
                    lease.replace([endpoint()])
                self.assertTrue(lease.closed)
                self.assertTrue(lease.fault)
                self.assertEqual(self.dll.records, {})
                self.assertEqual(self.dll.base, {'persistent-base-block': b'unchanged'})
                self.assertEqual(self.dll.closes, 0 if phase == 'open' else 1)

    def test_delete_failure_rolls_back_then_closes_old_rules(self):
        self.lease.replace([endpoint()])
        self.dll.fail = 'delete'
        with self.assertRaises(ipc.ProxyError):
            self.lease.replace([endpoint(54322)])
        self.assertIn('abort', self.dll.events)
        self.assertEqual(self.dll.records, {})

    def test_postcommit_readback_failure_closes(self):
        self.dll.committed_corruption = lambda records: records.pop(next(iter(records)))
        with self.assertRaises(ipc.ProxyError):
            self.lease.replace([endpoint()])
        self.assertEqual(self.dll.records, {})
        self.assertIn('commit', self.dll.events)
        self.assertTrue(self.lease.closed)

    def test_close_failure_retains_handle_and_fault_can_retry(self):
        keys = self.lease.replace([endpoint()])
        self.dll.close_error = 5
        with self.assertRaises(ipc.ProxyError):
            self.lease.close()
        self.assertFalse(self.lease.closed)
        self.assertEqual(self.lease._engine.handle.value, 123)
        self.assertEqual(set(self.dll.records), set(keys))
        with self.assertRaises(ipc.ProxyError):
            self.lease.replace([])
        self.dll.close_error = 0
        self.lease.close()
        self.assertTrue(self.lease.closed)
        self.assertEqual(self.dll.records, {})

    def test_readback_and_close_failure_reports_unconfirmed_revocation(self):
        self.lease.replace([endpoint()])
        self.dll.records.pop(next(iter(self.dll.records)))
        self.dll.close_error = 5
        with self.assertRaisesRegex(ipc.ProxyError, 'revocation unconfirmed'):
            self.lease.verify()
        self.assertFalse(self.lease.closed)
        self.assertIsNotNone(self.lease._engine)
        self.dll.close_error = 0
        self.lease.purge()

    def test_every_typed_field_is_checked_independently(self):
        changes = {0: ipc._ACCEPT4, 1: 1, 2: str(SUBLAYER), 3: str(PROVIDER), 4: 'wrong-marker',
                   5: b'wrong-data', 6: wfp._BLOCK, 7: 2, 8: 13, 9: (), 10: 1, 11: True}
        for index, replacement in changes.items():
            with self.subTest(field=index):
                self.dll.__init__()
                lease = ipc.LeaseSet(self.guard)
                lease.replace([endpoint()])
                key = next(iter(self.dll.records))
                record = list(self.dll.records[key])
                record[index] = replacement
                self.dll.records[key] = tuple(record)
                with self.assertRaises(ipc.ProxyError):
                    lease.verify()
                self.assertTrue(lease.closed)

    def test_condition_data_match_type_and_field_mismatches(self):
        for component, new in ((0, ipc._FIELDS['flags']), (1, 1), (2, 2), (3, 17)):
            with self.subTest(component=component):
                self.dll.__init__()
                lease = ipc.LeaseSet(self.guard)
                lease.replace([endpoint()])
                key = next(iter(self.dll.records))
                record = list(self.dll.records[key])
                conditions = list(record[9])
                index = next(i for i, cond in enumerate(conditions) if cond[0] == ipc._FIELDS['protocol'])
                condition = list(conditions[index])
                condition[component] = new
                conditions[index] = tuple(condition)
                record[9] = tuple(conditions)
                self.dll.records[key] = tuple(record)
                with self.assertRaises(ipc.ProxyError):
                    lease.verify()

    def test_indexed_flag_only_is_accepted(self):
        self.lease.replace([endpoint()])
        for key, value in list(self.dll.records.items()):
            value = list(value)
            value[1] = wfp._INDEXED
            self.dll.records[key] = tuple(value)
        self.assertEqual(len(self.lease.verify()), 3)

    def test_unknown_same_epoch_filter_detected(self):
        self.lease.replace([endpoint()])
        self.dll.records[str(uuid.uuid4())] = next(iter(self.dll.records.values()))
        with self.assertRaisesRegex(ipc.ProxyError, 'inventory mismatch'):
            self.lease.verify()
        self.assertEqual(self.dll.records, {})

    def test_orphan_permit_after_server_constraint_removed_detected(self):
        self.lease.replace([endpoint()])
        block = next(key for key, value in self.dll.records.items() if value[6] == wfp._BLOCK)
        del self.dll.records[block]
        with self.assertRaises(ipc.ProxyError):
            self.lease.verify()
        self.assertEqual(self.dll.records, {})

    def test_unknown_epoch_marker_in_data_even_description_changed(self):
        self.lease.replace([endpoint()])
        value = list(next(iter(self.dll.records.values())))
        value[4] = 'different'
        self.dll.records[str(uuid.uuid4())] = tuple(value)
        with self.assertRaises(ipc.ProxyError):
            self.lease.verify()

    def test_other_epoch_ignored_and_enumeration_paginates(self):
        keys = self.lease.replace([endpoint()])
        rule = ipc._plan([endpoint()], uuid.uuid4())[0]
        for _ in range(257):
            self.dll.records[str(uuid.uuid4())] = ipc._expected(rule, PROVIDER, SUBLAYER)
        before = self.dll.frees
        self.assertEqual(keys, self.lease.verify())
        self.assertEqual(self.dll.frees - before, 6)  # Three Get allocations + three enum pages.

    def test_null_template_regression_fake_rejects_guid_null_template(self):
        template, handle = ipc._EnumTemplate(), wfp._P()
        self.assertEqual(self.dll.FwpmFilterCreateEnumHandle0(
            wfp._P(123), C.byref(template), C.byref(handle)), 0x80320004)
        self.assertFalse(handle)
        # Actual module must use NULL, so a full replace/verify remains valid.
        self.assertEqual(len(self.lease.replace([endpoint()])), 3)
        self.assertEqual(len(self.lease.verify()), 3)

    def test_unknown_epoch_on_other_layer_and_provider_rejected(self):
        for provider in (str(PROVIDER), str(uuid.uuid4()), None):
            with self.subTest(provider=provider):
                self.dll.__init__()
                lease = ipc.LeaseSet(self.guard)
                lease.replace([endpoint()])
                value = list(next(iter(self.dll.records.values())))
                value[0], value[2] = str(uuid.uuid4()), provider
                self.dll.records[str(uuid.uuid4())] = tuple(value)
                before_free, before_close = self.dll.frees, self.dll.enum_closes
                with self.assertRaises(ipc.ProxyError):
                    lease.verify()
                self.assertTrue(lease.closed)
                self.assertGreater(self.dll.frees, before_free)
                self.assertEqual(self.dll.enum_closes, before_close + 1)

    def test_unrelated_foreign_provider_and_layer_ignored(self):
        keys = self.lease.replace([endpoint()])
        rule = ipc._plan([endpoint()], uuid.uuid4())[0]
        value = list(ipc._expected(rule, uuid.uuid4(), uuid.uuid4()))
        value[0] = str(uuid.uuid4())
        self.dll.records[str(uuid.uuid4())] = tuple(value)
        value[2] = None
        self.dll.records[str(uuid.uuid4())] = tuple(value)
        self.assertEqual(self.lease.verify(), keys)

    def test_enumeration_page_bound_preserves_free_and_destroy(self):
        self.lease.replace([endpoint()])
        original = self.dll._FwpmFilterEnum0
        def oversized(handle, enum, requested, output, count):
            result = original(handle, enum, requested, output, count)
            C.cast(count, C.POINTER(wfp._U32))[0] = 129
            return result
        before_free, before_close = self.dll.frees, self.dll.enum_closes
        self.dll.FwpmFilterEnum0.function = oversized
        with self.assertRaisesRegex(ipc.ProxyError, 'bounded snapshot'):
            self.lease.verify()
        self.assertTrue(self.lease.closed)
        self.assertEqual(self.dll.frees, before_free + 4)  # Three Gets + allocated enum page.
        self.assertEqual(self.dll.enum_closes, before_close + 1)

    def test_get_readback_mismatch_even_if_enumeration_is_valid(self):
        self.lease.replace([endpoint()])
        self.dll.get_corruption = lambda value: value[:8] + (13,) + value[9:]
        with self.assertRaises(ipc.ProxyError):
            self.lease.verify()

    def test_condition_order_not_semantic_duplicate_field_rejected(self):
        self.lease.replace([endpoint()])
        key = next(iter(self.dll.records))
        value = list(self.dll.records[key])
        value[9] = tuple(reversed(value[9]))
        self.dll.records[key] = tuple(value)
        self.lease.verify()
        value[9] += (value[9][0],)
        self.dll.records[key] = tuple(value)
        with self.assertRaisesRegex(ipc.ProxyError, 'Duplicate'):
            self.lease.verify()

    def test_close_without_open_is_pure_and_idempotent(self):
        self.lease.close()
        self.lease.close()
        self.assertEqual(self.dll.opens, 0)
        self.assertEqual(self.dll.closes, 0)

    def test_verify_unopened_reports_not_ready(self):
        with self.assertRaisesRegex(ipc.ProxyError, 'not been opened'):
            self.lease.verify()
        self.assertEqual(self.dll.opens, 0)

    def test_sdk_enum_layout_and_binding(self):
        engine = ipc._DynamicEngine()
        self.assertEqual(C.sizeof(ipc._EnumTemplate), 72)
        self.assertEqual(ipc._EnumTemplate.action_mask.offset, 56)
        self.assertEqual(len(engine.api.FwpmFilterEnum0.argtypes), 5)
        self.assertEqual(engine.api.FwpmFilterEnum0.argtypes[3], C.POINTER(C.POINTER(C.POINTER(wfp._Filter))))


class RawReadbackTests(unittest.TestCase):
    def value(self):
        rule = ipc._plan([endpoint()], uuid.uuid4())[0]
        return native_filter(rule.key, ipc._expected(rule, PROVIDER, SUBLAYER))

    def test_oversized_condition_count_rejected_before_dereference(self):
        value, keep = self.value()
        value.count = 17
        with self.assertRaises(ipc.ProxyError):
            ipc._read_filter(value)

    def test_null_condition_array_rejected(self):
        value, keep = self.value()
        value.conditions = C.POINTER(wfp._Condition)()
        with self.assertRaises(ipc.ProxyError):
            ipc._read_filter(value)

    def test_oversized_and_null_provider_blob_rejected(self):
        for size, pointer in ((1025, 0), (1, 0)):
            value, keep = self.value()
            value.data = wfp._Blob(size, pointer)
            with self.subTest(size=size), self.assertRaises(ipc.ProxyError):
                ipc._read_filter(value)

    def test_null_appid_blob_and_unknown_condition_type_rejected(self):
        for typ in (12, 999):
            value, keep = self.value()
            condition = next(value.conditions[i] for i in range(value.count)
                             if value.conditions[i].field.text() == ipc._FIELDS['app'])
            condition.value.type = typ
            condition.value.value.pointer = None
            with self.subTest(typ=typ), self.assertRaises(ipc.ProxyError):
                ipc._read_filter(value)


class InputTests(unittest.TestCase):
    def test_reject_invalid_ports(self):
        for value in (True, False, 0, -1, 65536, '54321', 1.2, None):
            with self.subTest(port=value), self.assertRaises(ValueError):
                replace(endpoint(), port=value)

    def test_reject_invalid_app_blobs(self):
        for value in (b'', b'x', b'a\0', b'a\0b\0', b'\x00\xd8\x00\x00', b'a' * 65538,
                      'path', bytearray(b'a\0\0\0'), ('x\0y\0').encode('utf-16-le')):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                replace(endpoint(), client_app_id=value)

    def test_reject_invalid_sd_blobs(self):
        for value in (b'', b'x', bytes(100), b'a' * 65537, 'owner', bytearray(sd()),
                      sd()[:19], sd()[:-1]):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                replace(endpoint(), owner_sd=value)

    def test_reject_null_absolute_dacl_and_wrong_ace(self):
        for offset, value in ((3, 0), (16, 0), (20, 4), (28, 1), (29, 2), (32, 2), (36, 2)):
            corrupt = bytearray(sd())
            corrupt[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                replace(endpoint(), owner_sd=bytes(corrupt))

    def test_api_has_no_layer_ip_or_weight_override(self):
        for extra in ({'layer': ipc._ACCEPT4}, {'ip': '0.0.0.0'}, {'weight': 255}):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                ipc.Endpoint(endpoint().server_app_id, endpoint().client_app_id, sd(), 54321, **extra)

    def test_plan_revalidates_mutated_frozen_input(self):
        value = endpoint()
        object.__setattr__(value, 'port', True)
        with self.assertRaises(ValueError):
            ipc._plan([value], uuid.uuid4())


if __name__ == '__main__':
    unittest.main()
