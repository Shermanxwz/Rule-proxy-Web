"""Inert API-shaped source fixtures; no real kernel binding or target.

Not run by the author of this revision. The only optional external fixture is
the exact pinned PE file; it is read as bytes and never executed. Missing or
different file means an explicit skip, not fabricated production input.
"""
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / '.github'
sys.path.insert(0, str(SOURCE))
with mock.patch.object(C, 'WinDLL', side_effect=AssertionError('WinDLL forbidden'),
                       create=True):
    import windows_identity_lpac_curl_a4_memory as m


def number(value):
    return value.value if isinstance(value, C.c_void_p) else value


def size_output(pointer, value):
    C.cast(pointer, C.POINTER(C.c_size_t))[0] = value


class Clock:
    def __init__(self, events):
        self.q, self.events = 10_000, events
        self.late = self.fail = False

    def __call__(self):
        self.events.append(('clock',))
        if self.fail:
            self.fail = False
            raise RuntimeError('post-call clock unavailable')
        if self.late:
            return 18_000
        self.q += 1
        return self.q


class Journal:
    def __init__(self, events):
        self.events, self.rows = events, []

    def __call__(self, record, raw):
        self.events.append(('journal', record['kind']))
        # Copy the private record so later caller mutation cannot help tests.
        text = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        self.rows.append((json.loads(text), bytes(raw)))
        return hashlib.sha256(text).hexdigest()


class Kernel:
    def __init__(self, image, events, clock, mode='happy'):
        self.events, self.clock, self.mode = events, clock, mode
        self.base, self.arena = 0x180000000, 0x1800D0000
        self.pe = m.builder.verify_fixed_pe(image)
        self.image = bytearray(m.builder.SIZE_IMAGE)
        self.image[:1024] = self.pe.header
        # Independent fixture oracle: a mapped image stores the actual base.
        # Do not use the production mapped-header helper to build this sample.
        struct.pack_into('<Q', self.image, 304, self.base)
        self.image[m.builder.IMPORT_RVA:m.builder.IMPORT_RVA + 860] = (
            self.pe.original_tables.descriptors)
        for index in range(42):
            entry = struct.unpack_from('<IIIII', self.pe.original_tables.descriptors,
                                       index * 20)
            for rva, raw in ((entry[0], self.pe.original_tables.lookup_tables[index]),
                             (entry[4], self.pe.original_tables.IAT_tables[index])):
                self.image[rva:rva + len(raw)] = raw
        self.allocated, self.data = False, bytearray(4096)
        self.header_protect, self.arena_protect = 2, 4
        self.error = 0

    def enter(self, name):
        self.events.append(('native', name))
        self.error = 0  # deliberately retain meaningful FALSE+error0 cases

    def last_error(self):
        self.events.append(('error',))
        return self.error

    def VirtualQueryEx(self, process, address, output, requested):
        self.enter('query')
        address = number(address)
        if address == self.base:
            values = (self.base, self.base, 2, 4096, 0x1000,
                      self.header_protect, 0x1000000)
        elif address == self.arena and not self.allocated:
            values = (self.arena, 0, 0, 65536, 0x10000, 0, 0)
        elif address == self.arena:
            values = (self.arena, self.arena, 4, 4096, 0x1000,
                      self.arena_protect, 0x20000)
        else:
            raise AssertionError('unexpected query address')
        b = bytearray(48)
        for offset, fmt, value in zip((0, 8, 16, 24, 32, 36, 40),
                                     ('<Q', '<Q', '<I', '<Q', '<I', '<I', '<I'),
                                     values):
            struct.pack_into(fmt, b, offset, value)
        C.memmove(output, bytes(b), 48)
        return 48

    def VirtualAllocEx(self, process, address, size, flags, protection):
        self.enter('allocate')
        assert (number(address), size, flags, protection) == (self.arena, 4096,
                                                             0x3000, 4)
        if self.mode == 'allocation-null':
            return None
        self.allocated = True
        if self.mode == 'allocation-late':
            self.clock.late = True
        elif self.mode == 'allocation-clock-exception':
            self.clock.fail = True
        return self.arena + (4096 if self.mode == 'wrong-address' else 0)

    def locate(self, address, size):
        if self.base <= address and address + size <= self.base + len(self.image):
            return self.image, address - self.base
        if self.allocated and self.arena <= address and address + size <= self.arena + 4096:
            return self.data, address - self.arena
        raise AssertionError('unexpected range')

    def ReadProcessMemory(self, process, address, output, size, count):
        self.enter('read')
        data, offset = self.locate(number(address), size)
        C.memmove(output, bytes(data[offset:offset + size]), size)
        size_output(count, size)
        return 1

    def WriteProcessMemory(self, process, address, source, size, count):
        self.enter('write')
        address = number(address)
        data, offset = self.locate(address, size)
        amount = 17 if self.mode in ('partial-write', 'exception-write') and address == self.arena else size
        data[offset:offset + amount] = C.string_at(source, amount)
        size_output(count, amount)
        if self.mode == 'exception-write' and address == self.arena:
            raise OSError('partial output then no native return')
        return 0 if amount != size else 1

    def VirtualProtectEx(self, process, address, size, protection, old):
        self.enter('protect')
        address = number(address)
        assert size == 4096
        if address == self.base:
            previous = self.header_protect
            C.cast(old, C.POINTER(C.c_uint32))[0] = previous
            if self.mode == 'restore-false' and protection == 2:
                return 0
            self.header_protect = protection
        else:
            assert address == self.arena
            previous = self.arena_protect
            C.cast(old, C.POINTER(C.c_uint32))[0] = previous
            self.arena_protect = protection
        return 1


class MemorySequenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ.get('A4_FIXED_CURL_FIXTURE',
            str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32' / 'curl.exe')))
        try:
            cls.image = path.read_bytes()
        except OSError:
            raise unittest.SkipTest('exact fixed curl file fixture unavailable')
        if len(cls.image) != 818512 or hashlib.sha256(cls.image).hexdigest() != m.builder.CURL_SHA256:
            raise unittest.SkipTest('file fixture differs from the fixed source commitment')

    def fixture(self, mode='happy'):
        events = []
        clock = Clock(events)
        k = Kernel(self.image, events, clock, mode)
        journal = Journal(events)
        epoch = m.Epoch(1000, 0, 120000, 85000, 10000, 18000)
        bindings = m.Bindings('01' * 16, *('02' * 32 for _ in range(5)))
        def gate(label, original_epoch, original_bindings):
            events.append(('gate', label))
            self.assertIs(original_epoch, epoch)
            self.assertIs(original_bindings, bindings)
            return hashlib.sha256(label.encode()).hexdigest()
        coordinator = m.Coordinator(m.KernelMemory(k, k.last_error), 0x1234,
            self.image, k.base, r'C:\owned\windows_identity_lpac_curl_ws2_shim.dll',
            epoch, bindings, clock=clock, gate=gate, journal=journal)
        return coordinator, k, events, journal

    def assert_stopped_once(self, coordinator, outcome, events):
        self.assertFalse(outcome.memory_sequence_complete)
        self.assertFalse(outcome.resume_authorized)
        self.assertFalse(outcome.actual_ready)
        before = list(events)
        with self.assertRaises(m.MemorySequenceError):
            coordinator.run()
        self.assertEqual(before, events)

    def test_exact_sequence_only_mutates_allowed_bytes_and_does_not_authorize_resume(self):
        c, k, events, journal = self.fixture()
        out = c.run()
        self.assertTrue(out.memory_sequence_complete)
        self.assertTrue(out.memory_bytes_match)
        self.assertFalse(out.controls_unknown)
        self.assertFalse(out.external_identity_gates_verified_by_this_module)
        self.assertFalse(out.config_GUID_injection_complete)
        self.assertFalse(out.resume_authorized)
        self.assertEqual(len(out.calls), 23)
        self.assertEqual(k.header_protect, 2)
        self.assertEqual(k.arena_protect, 2)
        self.assertEqual(k.image[:1024], c.patch.expected_header)
        self.assertEqual(bytes(k.data), c.patch.arena)
        self.assertEqual(struct.unpack_from('<Q', k.image, 304)[0], k.base)
        writes = [(dict(call.arguments)['address'], dict(call.arguments)['bytes'])
                  for call in out.calls if call.operation == 'write']
        self.assertEqual(writes, [(k.arena, 4096), (k.base + 400, 4)])
        mutation = next(row for row, _ in journal.rows
                        if row['kind'] == 'remote-mutation-intent')
        self.assertEqual(mutation['header_before_sha256'],
                         hashlib.sha256(c.mapped_header).hexdigest())
        self.assertEqual(mutation['header_after_sha256'],
                         hashlib.sha256(c.patch.expected_header).hexdigest())
        self.assertEqual([g[0] for g in out.gates], ['before-memory', 'after-publication'])
        for i, event in enumerate(events):
            if event[0] == 'native':
                self.assertEqual(events[i + 1][0], 'error')
        for call in out.calls:
            self.assertLessEqual(call.entered_qpc, call.returned_qpc)
            self.assertTrue(call.return_receipt_sha256)
        for corrupt in ('preferred', 'wrong-base', 0, 303, 312, 400, 1023):
            with self.subTest(initial_header=corrupt):
                bad_c, bad_k, bad_events, _ = self.fixture()
                if corrupt in ('preferred', 'wrong-base'):
                    wrong = (bad_k.pe.preferred_image_base if corrupt == 'preferred'
                             else bad_k.base + 65536)
                    struct.pack_into('<Q', bad_k.image, 304, wrong)
                else:bad_k.image[corrupt] ^= 1
                stopped = bad_c.run()
                self.assert_stopped_once(bad_c, stopped, bad_events)
                self.assertIn('original_readback_mismatch', stopped.failure)
                self.assertFalse(stopped.mutation_attempted)
                self.assertFalse(bad_k.allocated)
                self.assertFalse(any(call.operation in ('allocate', 'write', 'protect')
                                     for call in stopped.calls))
        # Model a contradictory final sample after the only four-byte header
        # write. The coordinator must preserve the mutation and stop, not
        # accept a header whose ImageBase reverted to the disk preferred base.
        bad_c, bad_k, bad_events, _ = self.fixture()
        original_read = bad_k.ReadProcessMemory
        def revert_preferred(process, address, output, size, count):
            if (number(address) == bad_k.base and size == 1024
                    and bad_k.image[400:404] == bad_c.patch.header_patch):
                struct.pack_into('<Q', bad_k.image, 304, bad_k.pe.preferred_image_base)
            return original_read(process, address, output, size, count)
        bad_k.ReadProcessMemory = revert_preferred
        stopped = bad_c.run()
        self.assert_stopped_once(bad_c, stopped, bad_events)
        self.assertIn('BuilderError', stopped.failure)
        self.assertTrue(stopped.mutation_attempted)
        self.assertEqual(stopped.allocation_state, 'known-exact-retained')
        self.assertEqual([(dict(call.arguments)['address'], dict(call.arguments)['bytes'])
                          for call in stopped.calls if call.operation == 'write'],
                         [(bad_k.arena, 4096), (bad_k.base + 400, 4)])

    def test_partial_write_FALSE_error0_keeps_count_and_stops_without_readback_retry(self):
        c, k, events, _ = self.fixture('partial-write')
        out = c.run()
        self.assert_stopped_once(c, out, events)
        raw = out.calls[-1].raw
        self.assertEqual((raw.operation, raw.value, raw.error), ('write', 0, 0))
        self.assertTrue(raw.record()['failure_error_valid'])
        self.assertEqual(raw.field('transferred'), 17)
        self.assertTrue(out.controls_unknown)
        self.assertEqual([e for e in events if e == ('native', 'write')], [('native', 'write')])
        self.assertEqual(k.header_protect, 2)

    def test_late_exact_allocation_return_is_retained_but_no_next_native_call(self):
        c, k, events, _ = self.fixture('allocation-late')
        out = c.run()
        self.assert_stopped_once(c, out, events)
        self.assertEqual(out.allocation_state, 'known-exact-retained')
        self.assertEqual(out.calls[-1].raw.value, k.arena)
        self.assertTrue(out.calls[-1].raw.returned)
        self.assertTrue(out.calls[-1].return_clock_known)
        self.assertFalse(out.calls[-1].timely)
        self.assertTrue(out.controls_unknown)
        self.assertEqual([e for e in events if e[0] == 'native'][-1][1], 'allocate')

    def test_wrong_returned_allocation_is_unknown_and_never_freed_or_retried(self):
        c, k, events, _ = self.fixture('wrong-address')
        out = c.run()
        self.assert_stopped_once(c, out, events)
        self.assertEqual(out.allocation_state, 'unknown-wrong-address')
        self.assertEqual(out.calls[-1].raw.value, k.arena + 4096)
        self.assertTrue(out.controls_unknown)
        self.assertEqual([e for e in events if e[0] == 'native'][-1][1], 'allocate')

    def test_restore_FALSE_error0_does_not_wash_successful_header_write(self):
        c, k, events, _ = self.fixture('restore-false')
        out = c.run()
        self.assert_stopped_once(c, out, events)
        raw = out.calls[-1].raw
        self.assertEqual((raw.operation, raw.value, raw.error, raw.field('old_protect')),
                         ('protect', 0, 0, 4))
        self.assertTrue(out.controls_unknown)
        self.assertFalse(out.memory_bytes_match)
        self.assertEqual(k.image[400:404], c.patch.header_patch)
        self.assertEqual(k.header_protect, 4)
        self.assertEqual([e for e in events if e[0] == 'native'][-1][1], 'protect')

    def test_post_clock_exception_retains_raw_allocation_and_return_receipt(self):
        c, k, events, journal = self.fixture('allocation-clock-exception')
        out = c.run()
        self.assert_stopped_once(c, out, events)
        call = out.calls[-1]
        self.assertTrue(call.raw.returned)
        self.assertEqual(call.raw.value, k.arena)
        self.assertFalse(call.return_clock_known)
        self.assertIsNone(call.returned_qpc)
        self.assertTrue(call.return_receipt_sha256)
        self.assertEqual(out.allocation_state, 'known-exact-retained')

    def test_native_exception_keeps_partial_count_without_inventing_api_or_error_return(self):
        c, k, events, _ = self.fixture('exception-write')
        out = c.run()
        self.assert_stopped_once(c, out, events)
        raw = out.calls[-1].raw
        self.assertFalse(raw.returned)
        self.assertIsNone(raw.value)
        self.assertFalse(raw.error_captured)
        self.assertIsNone(raw.error)
        self.assertEqual(raw.field('transferred'), 17)
        self.assertTrue(out.controls_unknown)


if __name__ == '__main__':
    unittest.main()
