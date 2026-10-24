"""A4 fixed-image memory sequence, source prototype with no autonomous backend.

The caller supplies already verified AMD64 kernel32 bindings, GetLastError,
one retained exact process HANDLE, original QPC epoch, real held-state gate,
and durable private journal callbacks. This module never loads a library,
opens/closes a process, creates a Job/profile, scans for a base, frees remote
memory, restores live imports, resumes a target, or grants actual acceptance.

Native raw returns/outputs are sealed in an immutable Raw object BEFORE the
post-call clock callback. The durable return record then binds that Raw and
the post-clock result, including late/unknown clocks. Failure stops the one
sequence: no same-target retry, alternate address, rollback or early free.
"""
from dataclasses import dataclass, replace
import ctypes as C
import hashlib
import re
import struct

import windows_identity_lpac_curl_import_builder as builder

ACTUAL_READY = False
INTERFACE_VERSION = 1
MEMORY_IMPLEMENTATION_AUTHORIZED = True
BUILDER_BYTES = 29552
BUILDER_SHA256 = '886f947f9fe748042dc694364ec68e1ed97d3749782c4a9e96996ff5261a089c'
MAX_U64 = (1 << 64) - 1
PAGE_BYTES = 4096
MBI_BYTES = 48
PAGE_READONLY, PAGE_READWRITE = 2, 4
MEM_COMMIT, MEM_RESERVE, MEM_FREE = 0x1000, 0x2000, 0x10000
MEM_PRIVATE, MEM_IMAGE = 0x20000, 0x1000000
MAX_CALLS = 32
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_RUN = re.compile(r'[0-9a-f]{32}\Z')
_MUTATING = frozenset(('allocate', 'write', 'protect'))


class MemorySequenceError(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise MemorySequenceError('a4_memory_' + reason)


def _uint(value, maximum=MAX_U64):
    return type(value) is int and 0 <= value <= maximum


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


@dataclass(frozen=True)
class Epoch:
    frequency: int
    root_start: int
    root_deadline: int
    work_deadline: int
    window_start: int
    window_end: int

    def validate(self):
        values = tuple(self.__dict__.values())
        _need(all(_uint(v, (1 << 63) - 1) for v in values), 'epoch_type')
        f, start = self.frequency, self.root_start
        _need(f > 0 and start <= ((1 << 63) - 1) - 120 * f, 'epoch_overflow')
        _need(self.root_deadline == start + 120 * f
              and self.work_deadline == start + 85 * f, 'original_epoch')
        _need(start <= self.window_start < self.work_deadline
              and self.window_start <= ((1 << 63) - 1) - 8 * f
              and self.window_end == min(self.window_start + 8 * f,
                                         self.work_deadline), 'original_window')


@dataclass(frozen=True)
class Bindings:
    run: str
    source_sha256: str
    config_sha256: str
    plan_sha256: str
    pi_returned_sha256: str
    base_provenance_sha256: str

    def validate(self):
        _need(type(self.run) is str and _RUN.fullmatch(self.run) is not None,
              'run')
        _need(all(_digest(v) for k, v in self.__dict__.items() if k != 'run'),
              'commitments')


@dataclass(frozen=True)
class Raw:
    operation: str
    returned: bool
    value: object
    error_captured: bool
    error: object
    exception: object
    fields: tuple
    data: bytes

    def field(self, name):
        return dict(self.fields)[name]

    def record(self):
        return {'operation': self.operation, 'returned': self.returned,
                'value': self.value, 'error_captured': self.error_captured,
                'failure_error_valid': (self.returned and self.exception is None
                                        and self.error_captured and self.value == 0),
                'error': self.error, 'exception': self.exception,
                'fields': dict(self.fields), 'raw_bytes': len(self.data),
                'raw_sha256': _sha(self.data)}


@dataclass(frozen=True)
class Call:
    index: int
    operation: str
    arguments: tuple
    intent_sha256: str
    entered_qpc: int
    raw: Raw
    returned_qpc: object
    return_clock_known: bool
    timely: bool
    clock_error: object
    return_receipt_sha256: object


@dataclass(frozen=True)
class Outcome:
    status: str
    failure: object
    calls: tuple
    gates: tuple
    mutation_intent_sha256: object
    mutation_attempted: bool
    allocation_state: str
    memory_bytes_match: bool
    memory_sequence_complete: bool
    controls_unknown: bool
    epoch: Epoch
    bindings: Bindings
    actual_base: int
    arena_address: int
    remote_lifetime: str
    actual_ready: bool = False
    resume_authorized: bool = False
    config_GUID_injection_complete: bool = False
    external_identity_gates_verified_by_this_module: bool = False
    actual_loader_or_transport_qualified: bool = False


class KernelMemory:
    """Thin calls through supplied, previously checked AMD64 bindings.

    The owner must check signatures/restypes and retained HANDLE provenance
    before supplying this object. There is no GetLastError fallback and no
    ctypes.WinDLL construction. Success captures the actual last-error value
    too, but it is explicitly not valid API failure information on success.
    """
    def __init__(self, kernel32, get_last_error):
        _need(C.sizeof(C.c_void_p) == 8, 'amd64_host')
        names = ('VirtualAllocEx', 'VirtualQueryEx', 'ReadProcessMemory',
                 'WriteProcessMemory', 'VirtualProtectEx')
        _need(all(callable(getattr(kernel32, n, None)) for n in names)
              and callable(get_last_error), 'supplied_bindings')
        self.k = kernel32
        self.get_last_error = get_last_error

    def invoke(self, operation, process, address, size, argument=0):
        _need(operation in ('allocate', 'query', 'read', 'write', 'protect'),
              'operation')
        _need(_uint(process) and 0 < process < MAX_U64
              and _uint(address) and address > 0 and _uint(size)
              and 0 < size <= PAGE_BYTES and address <= MAX_U64 - size,
              'call_arguments')
        count = C.c_size_t(0)
        old = C.c_uint32(0)
        buffer = (C.c_ubyte * (MBI_BYTES if operation == 'query' else size))()
        if operation == 'write':
            _need(type(argument) is bytes and len(argument) == size,
                  'write_input')
            C.memmove(buffer, argument, size)
        if operation == 'protect':
            _need(argument in (PAGE_READONLY, PAGE_READWRITE)
                  and type(argument) is int, 'protection')
        value, returned, error, captured, exception = None, False, None, False, None
        try:
            if operation == 'allocate':
                value = self.k.VirtualAllocEx(C.c_void_p(process),
                    C.c_void_p(address), size, MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE)
            elif operation == 'query':
                value = self.k.VirtualQueryEx(C.c_void_p(process),
                    C.c_void_p(address), C.byref(buffer), MBI_BYTES)
            elif operation == 'read':
                value = self.k.ReadProcessMemory(C.c_void_p(process),
                    C.c_void_p(address), C.byref(buffer), size, C.byref(count))
            elif operation == 'write':
                value = self.k.WriteProcessMemory(C.c_void_p(process),
                    C.c_void_p(address), C.byref(buffer), size, C.byref(count))
            else:
                value = self.k.VirtualProtectEx(C.c_void_p(process),
                    C.c_void_p(address), size, argument, C.byref(old))
            returned = True
            # This is the first callback after the supplied native function.
            # It runs before buffer conversion, dataclass creation or QPC.
            try:
                error = self.get_last_error()
                captured = _uint(error, 0xffffffff)
            except BaseException as exc:
                exception = 'last_error_' + type(exc).__name__
            if operation == 'allocate' and value is None:
                value = 0
            if type(value) is not int or not _uint(value):
                # BOOL is a signed 32-bit native type; preserve negative TRUE.
                if not (type(value) is int and -(1 << 31) <= value < 0
                        and operation in ('read', 'write', 'protect')):
                    exception = 'native_return_type'
            if not captured and exception is None:
                exception = 'last_error_type'
        except BaseException as exc:
            exception = 'native_' + type(exc).__name__
        fields = []
        if operation in ('read', 'write'):
            fields.append(('transferred', int(count.value)))
        if operation == 'protect':
            fields.append(('old_protect', int(old.value)))
        if operation == 'query':
            # Fixed AMD64 SDK offsets; raw48 is retained even for short/FALSE.
            raw_buffer = bytes(buffer)
            for name, offset, fmt in (
                ('base', 0, '<Q'), ('allocation_base', 8, '<Q'),
                ('allocation_protect', 16, '<I'), ('partition_id', 20, '<H'),
                ('region_bytes', 24, '<Q'), ('state', 32, '<I'),
                ('protect', 36, '<I'), ('type', 40, '<I')):
                fields.append((name, struct.unpack_from(fmt, raw_buffer, offset)[0]))
        data = bytes(buffer) if operation in ('read', 'query') else b''
        # Frozen Raw is built before Coordinator is allowed to sample QPC.
        return Raw(operation, returned, value, captured, error if captured else None,
                   exception, tuple(fields), data)


def _table_span(descriptors, tables, word):
    """Derive one exact contiguous original ILT/IAT span from verified bytes."""
    entries = []
    for index, table in enumerate(tables):
        rva = struct.unpack_from('<IIIII', descriptors, index * 20)[word]
        entries.append((rva, len(table), index))
    ordered = sorted(entries)
    start = cursor = ordered[0][0]
    for rva, size, _ in ordered:
        _need(rva == cursor and rva % 8 == 0 and size % 8 == 0,
              'original_table_geometry')
        cursor += size
    _need(0 < cursor - start <= PAGE_BYTES, 'original_table_extent')
    return start, cursor - start, tuple(entries)


class Coordinator:
    """One-shot memory sequence; all OS/state authority remains external.

    gate(label, epoch, bindings) must execute/validate the real original held
    generation, image, cap0 primary, SD, two Jobs, suspended state and semantic
    proof gates, then return its physical receipt SHA256. A qualified dict is
    not accepted as evidence. This module can only bind the returned reference;
    future owner/reader MUST revalidate it independently before any Resume.

    journal(record, raw_bytes) must durably save raw_bytes (if nonempty), bind
    it to record, and return the physical record SHA256. Return records contain
    known/unknown post-QPC without replacing an earlier native return. Callback
    failures stop the sequence; local Outcome retains any sealed native Raw.
    """
    def __init__(self, memory, process_handle, image, actual_base, private_path,
                 epoch, bindings, *, clock, gate, journal):
        _need(type(epoch) is Epoch and type(bindings) is Bindings, 'input_types')
        epoch.validate()
        bindings.validate()
        _need(_uint(process_handle) and 0 < process_handle < MAX_U64,
              'retained_process_handle')
        _need(callable(clock) and callable(gate) and callable(journal)
              and callable(getattr(memory, 'invoke', None)), 'callbacks')
        self.patch = builder.build_import_patch(image, actual_base, private_path)
        self.pe = builder.verify_fixed_pe(image)
        self.image, self.base, self.path = image, actual_base, private_path
        self.memory, self.process = memory, process_handle
        self.epoch, self.bindings = epoch, bindings
        self.clock, self.gate, self.journal = clock, gate, journal
        self.lookup_span = _table_span(self.pe.original_tables.descriptors,
                                      self.pe.original_tables.lookup_tables, 0)
        self.iat_span = _table_span(self.pe.original_tables.descriptors,
                                   self.pe.original_tables.IAT_tables, 4)
        self.calls, self.gates = [], []
        self.mutation_intent = None
        self.attempted = False
        self.allocation = 'not-entered'
        self.bytes_match = False
        self.unknown = False
        self.started = False
        self.last_qpc = epoch.window_start

    def _tick(self):
        q = self.clock()
        _need(_uint(q, (1 << 63) - 1) and q >= self.last_qpc, 'clock_unknown')
        self.last_qpc = q
        _need(self.epoch.window_start <= q < self.epoch.window_end,
              'original_cutoff')
        return q

    def _persist(self, record, raw=b''):
        _need(type(raw) is bytes, 'journal_raw')
        payload = dict(record)
        payload.update(schema_version=1, scope='A4-fixed-two-descriptor-memory-v1',
                       bindings=dict(self.bindings.__dict__),
                       epoch=dict(self.epoch.__dict__))
        reference = self.journal(payload, raw)
        _need(_digest(reference), 'journal_receipt')
        return reference

    def _held_gate(self, label):
        before = self._tick()
        reference = self.gate(label, self.epoch, self.bindings)
        _need(_digest(reference), 'external_gate_receipt')
        after = self._tick()
        bound = self._persist({'kind': 'external-held-gate', 'label': label,
                               'gate_sha256': reference, 'before_qpc': before,
                               'after_qpc': after})
        self.gates.append((label, reference, bound))

    def _call(self, operation, address, size, argument=0):
        _need(len(self.calls) < MAX_CALLS, 'call_capacity')
        before = self._tick()
        arguments = (('process', self.process), ('address', address),
                     ('bytes', size))
        if operation == 'allocate':
            arguments += (('allocation_type', MEM_RESERVE | MEM_COMMIT),
                          ('protection', PAGE_READWRITE))
        elif operation == 'protect':
            arguments += (('new_protection', argument),)
        elif operation == 'query':
            arguments += (('buffer_bytes', MBI_BYTES),)
        extra = ({'input_sha256': _sha(argument)} if type(argument) is bytes
                 else {'argument': argument})
        intent = self._persist({'kind': 'memory-call-intent',
            'index': len(self.calls), 'operation': operation,
            'arguments': dict(arguments), 'qpc': before, **extra})
        entered = self._tick()  # after the durable intent, before native call
        if operation in _MUTATING:
            self.attempted = True
        if operation == 'allocate':
            self.allocation = 'entered-outcome-unknown'
        raw = self.memory.invoke(operation, self.process, address, size, argument)
        _need(type(raw) is Raw and raw.operation == operation, 'raw_adapter')
        if operation == 'allocate' and raw.returned and _uint(raw.value):
            if raw.value == 0:
                self.allocation = 'known-null-return'
            elif raw.value == address:
                self.allocation = 'known-exact-retained'
            else:
                self.allocation = 'unknown-wrong-address'
                self.unknown = True
        # No QPC, journal or subsequent API occurs before this immutable Raw.
        call = Call(len(self.calls), operation, arguments, intent, entered, raw,
                    None, False, False, None, None)
        self.calls.append(call)
        try:
            returned = self.clock()
            known = _uint(returned, (1 << 63) - 1) and returned >= self.last_qpc
            if known:
                self.last_qpc = returned
            timely = known and returned < self.epoch.window_end
            clock_error = None if known else 'clock_unknown'
            call = replace(call, returned_qpc=returned if known else None,
                           return_clock_known=known, timely=timely,
                           clock_error=clock_error)
        except BaseException as exc:
            call = replace(call, clock_error=type(exc).__name__)
        self.calls[-1] = call
        try:
            reference = self._persist({'kind': 'memory-call-return',
                'index': call.index, 'intent_sha256': intent,
                'entered_qpc': entered, 'returned_qpc': call.returned_qpc,
                'return_clock_known': call.return_clock_known,
                'timely': call.timely, 'clock_error': call.clock_error,
                'raw': raw.record()}, raw.data)
            call = replace(call, return_receipt_sha256=reference)
            self.calls[-1] = call
        except BaseException:
            self.unknown = True
            raise MemorySequenceError('a4_memory_return_journal_failed')
        if not raw.returned or raw.exception is not None or not raw.error_captured:
            self.unknown = True
            raise MemorySequenceError('a4_memory_native_unknown')
        if not call.return_clock_known or not call.timely:
            self.unknown = True
            raise MemorySequenceError('a4_memory_native_clock')
        return raw

    def _query(self, address):
        raw = self._call('query', address, MBI_BYTES)
        _need(raw.value == MBI_BYTES, 'query_returned_size')
        return dict(raw.fields)

    @staticmethod
    def _covers(region, address, size):
        return (region['base'] <= address and region['region_bytes'] > 0
                and region['base'] <= MAX_U64 - region['region_bytes']
                and address - region['base'] <= region['region_bytes']
                and size <= region['region_bytes'] - (address - region['base']))

    def _header_region(self):
        r = self._query(self.base)
        _need(self._covers(r, self.base, PAGE_BYTES)
              and r['allocation_base'] == self.base
              and r['state'] == MEM_COMMIT and r['type'] == MEM_IMAGE
              and r['protect'] == PAGE_READONLY, 'header_page_policy')

    def _arena_region(self, protection):
        address = self.patch.metadata.arena_address
        r = self._query(address)
        _need(r['base'] == address and r['allocation_base'] == address
              and self._covers(r, address, PAGE_BYTES)
              and r['state'] == MEM_COMMIT and r['type'] == MEM_PRIVATE
              and r['allocation_protect'] == PAGE_READWRITE
              and r['protect'] == protection, 'arena_page_policy')

    def _read(self, address, size):
        raw = self._call('read', address, size)
        _need(raw.value != 0 and raw.field('transferred') == size
              and len(raw.data) == size, 'read_partial_or_false')
        return raw.data

    def _write(self, address, data):
        raw = self._call('write', address, len(data), data)
        _need(raw.value != 0 and raw.field('transferred') == len(data),
              'write_partial_or_false')

    def _protect(self, address, protection, expected_old):
        raw = self._call('protect', address, PAGE_BYTES, protection)
        _need(raw.value != 0 and raw.field('old_protect') == expected_old,
              'protection_false_or_old_mismatch')

    def _tables(self, span):
        rva, size, entries = span
        raw = self._read(self.base + rva, size)
        result = [None] * len(entries)
        for at, count, index in entries:
            result[index] = raw[at - rva:at - rva + count]
        return tuple(result)

    def _original_readback(self):
        header = self._read(self.base, builder.SIZE_HEADERS)
        descriptors = self._read(self.base + builder.IMPORT_RVA,
                                 builder.IMPORT_BYTES)
        lookup = self._tables(self.lookup_span)
        iat = self._tables(self.iat_span)
        original = self.pe.original_tables
        _need(header == self.pe.header and descriptors == original.descriptors
              and lookup == original.lookup_tables and iat == original.IAT_tables,
              'original_readback_mismatch')

    def _final_readback(self):
        header = self._read(self.base, builder.SIZE_HEADERS)
        arena = self._read(self.patch.metadata.arena_address, builder.ARENA_BYTES)
        descriptors = self._read(self.base + builder.IMPORT_RVA,
                                 builder.IMPORT_BYTES)
        lookup = self._tables(self.lookup_span)
        iat = self._tables(self.iat_span)
        builder.verify_readback_model(self.image, self.base, self.path,
            header=header, arena=arena, old_descriptors=descriptors,
            old_lookup_tables=lookup, old_IAT_tables=iat)
        self.bytes_match = True

    def _outcome(self, failure=None):
        complete = failure is None
        return Outcome('complete-memory-sequence' if complete else 'stopped',
            failure, tuple(self.calls), tuple(self.gates), self.mutation_intent,
            self.attempted, self.allocation, self.bytes_match, complete,
            self.unknown or (not complete and self.attempted
                            and self.allocation != 'known-null-return'),
            self.epoch, self.bindings, self.base,
            self.patch.metadata.arena_address,
            'retained-until-exact-supervised-target-exit' if self.attempted
            else 'no-mutation-entered')

    def run(self):
        _need(not self.started, 'once_consumed')
        self.started = True  # consumed even if the first callback fails
        try:
            self._held_gate('before-memory')
            self._header_region()
            free = self._query(self.patch.metadata.arena_address)
            _need(free['state'] == MEM_FREE
                  and self._covers(free, self.patch.metadata.arena_address,
                                   builder.ARENA_BYTES), 'arena_not_free')
            self._original_readback()
            self.mutation_intent = self._persist({
                'kind': 'remote-mutation-intent', 'qpc': self._tick(),
                'actual_base': self.base, 'arena_address': self.patch.metadata.arena_address,
                'arena_bytes': builder.ARENA_BYTES,
                'arena_sha256': _sha(self.patch.arena),
                'header_before_sha256': _sha(self.pe.header),
                'header_after_sha256': _sha(self.patch.expected_header),
                'private_path_sha256': self.patch.metadata.private_path_sha256,
                'base_provenance_sha256': self.bindings.base_provenance_sha256,
                'gate_sha256': self.gates[-1][1]}, self.patch.arena)
            raw = self._call('allocate', self.patch.metadata.arena_address,
                             builder.ARENA_BYTES)
            if raw.value == 0:
                self.allocation = 'known-null-return'
                raise MemorySequenceError('a4_memory_allocation_failed')
            if raw.value != self.patch.metadata.arena_address:
                self.allocation = 'unknown-wrong-address'
                self.unknown = True
                raise MemorySequenceError('a4_memory_allocation_wrong_address')
            self.allocation = 'known-exact-retained'
            self._arena_region(PAGE_READWRITE)
            self._write(self.patch.metadata.arena_address, self.patch.arena)
            _need(self._read(self.patch.metadata.arena_address,
                            builder.ARENA_BYTES) == self.patch.arena,
                  'arena_readback_mismatch')
            self._protect(self.patch.metadata.arena_address,
                          PAGE_READONLY, PAGE_READWRITE)
            self._arena_region(PAGE_READONLY)
            self._protect(self.base, PAGE_READWRITE, PAGE_READONLY)
            address = self.base + builder.IMPORT_HEADER_OFFSET
            self._write(address, self.patch.header_patch)
            _need(self._read(address, 4) == self.patch.header_patch,
                  'header_pointer_readback_mismatch')
            self._protect(self.base, PAGE_READONLY, PAGE_READWRITE)
            self._header_region()
            self._final_readback()
            self._arena_region(PAGE_READONLY)
            self._held_gate('after-publication')
            self._tick()
            return self._outcome()
        except BaseException as exc:
            if not isinstance(exc, (MemorySequenceError, builder.BuilderError)):
                self.unknown = True
            # No finally block invokes a second memory API, rollback or free.
            # A late successful mutation cannot be erased by later readback.
            return self._outcome(type(exc).__name__ + ':' +
                                 (str(exc) if isinstance(exc, (MemorySequenceError,
                                                            builder.BuilderError))
                                  else 'callback_or_adapter_exception'))
