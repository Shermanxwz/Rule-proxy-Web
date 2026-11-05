"""Broker-owned, dynamic IPv4 IPC exceptions to an existing AppGuard.

Only three rules per endpoint: exact client CONNECT permit and exact server
RECV_ACCEPT permit above a 127.0.0.1/port/TCP RECV_ACCEPT block. No bind
reservation, IPv6 rule, LAN exception, discovery, persistence or qualification.
The broker must validate identities, owner SID, exclusive endpoint ownership,
and continued process liveness before supplying Endpoint values. A valid binary
blob is not evidence of a trusted process. This module never changes base rules.

SDK references (structures, GUIDs, signatures and allocation ownership):
https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/fwpmtypes.h
https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/fwpmu.h
https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import hashlib
import struct
import threading
import uuid

from . import windows_global_guard as wfp
from .windows_proxy_policy import ProxyError

_CONNECT4 = wfp._LAYERS[4]
_ACCEPT4 = 'e1cd9fe7-f4b5-4273-96c0-592e487b8650'
_FIELDS = dict(wfp._FIELDS, local='d9ee00de-c1ef-4617-bfe3-ffd8f5a08957')
_LOOPBACK = 0x7f000001  # FWP_UINT32 IPv4 is host-order numeric, not htonl().
_MAX_ENDPOINTS = 16


def _fail(message):
    raise ProxyError('ipc_lease_failed', message)


def _check(code, operation):
    if code:
        _fail(f'IPC lease {operation} failed (0x{code:08x})')


def _blob(value):
    if type(value) is not bytes or not 1 <= len(value) <= 65536:
        raise ValueError('IPC identity must be nonempty bounded immutable bytes')


def _app_blob(value):
    _blob(value)
    try:
        text = value.decode('utf-16-le')
    except UnicodeError as exc:
        raise ValueError('Invalid UTF-16 AppID blob') from exc
    if len(text) < 2 or not text.endswith('\0') or '\0' in text[:-1]:
        raise ValueError('AppID must be exactly one NUL-terminated path')


def _owner_blob(value):
    """Bounded self-relative SD with a non-NULL DACL; SID policy is broker-owned.

    Accept the simple access-allowed ACE form produced by shared _descriptor.
    Reject malformed/absolute descriptors and unsupported ACE forms rather than
    handing arbitrary pointer-shaped input to BFE. This is not SID authorization.
    """
    _blob(value)
    if len(value) < 20:
        raise ValueError('Truncated owner security descriptor')
    revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from('<BBHIIII', value)
    if revision != 1 or reserved or control & 0x8004 != 0x8004 or sacl or not dacl:
        raise ValueError('Expected self-relative owner SD with a non-NULL DACL')

    def sid_at(offset, end):
        if offset < 20 or offset % 4 or offset + 8 > end:
            raise ValueError('Invalid owner SID offset')
        count = value[offset + 1]
        size = 8 + 4 * count
        if value[offset] != 1 or not 1 <= count <= 15 or offset + size > end:
            raise ValueError('Invalid owner SID structure')
        return size

    for offset in (owner, group):
        if offset:
            sid_at(offset, len(value))
    if dacl < 20 or dacl % 4 or dacl + 8 > len(value):
        raise ValueError('Invalid DACL offset')
    rev, zero, size, count, zero2 = struct.unpack_from('<BBHHH', value, dacl)
    if rev != 2 or zero or zero2 or size < 8 or dacl + size > len(value) or not count:
        raise ValueError('Invalid DACL header')
    cursor = dacl + 8
    for _ in range(count):
        if cursor + 8 > dacl + size:
            raise ValueError('Truncated DACL ACE')
        kind, flags, length, mask = struct.unpack_from('<BBHI', value, cursor)
        if kind != 0 or flags or mask != 1 or length < 20 or length % 4 or cursor + length > dacl + size:
            raise ValueError('Expected explicit access-allowed FWP_ACTRL_MATCH_FILTER ACE')
        if 8 + sid_at(cursor + 8, cursor + length) != length:
            raise ValueError('Invalid ACE SID length')
        cursor += length
    if cursor != dacl + size:
        raise ValueError('Unexpected DACL trailing data')


@dataclass(frozen=True)
class Endpoint:
    server_app_id: bytes
    client_app_id: bytes
    owner_sd: bytes
    port: int

    def __post_init__(self):
        _app_blob(self.server_app_id)
        _app_blob(self.client_app_id)
        _owner_blob(self.owner_sd)
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError('IPC port must be an integer in 1..65535')


@dataclass(frozen=True)
class _Rule:
    key: str
    marker: str
    layer: str
    action: int
    weight: int
    conditions: tuple


def _plan(endpoints, epoch):
    if type(endpoints) not in (list, tuple) or len(endpoints) > _MAX_ENDPOINTS:
        raise ValueError('Expected at most 16 IPC endpoints')
    if any(type(endpoint) is not Endpoint for endpoint in endpoints):
        raise ValueError('Expected validated Endpoint objects')
    if len({endpoint.port for endpoint in endpoints}) != len(endpoints):
        raise ValueError('Duplicate or ambiguous IPC port')
    result = []
    for endpoint in sorted(endpoints, key=lambda item: item.port):
        endpoint.__post_init__()  # Defend even against object.__setattr__ misuse.
        digest = hashlib.sha256()
        for blob in (endpoint.server_app_id, endpoint.client_app_id, endpoint.owner_sd):
            digest.update(len(blob).to_bytes(4, 'little'))
            digest.update(blob)
        digest.update(endpoint.port.to_bytes(2, 'little'))
        lease = digest.hexdigest()
        prefix = f'RuleProxyIPC-v1:{epoch}/{lease}/'
        common = (('protocol', 0, 1, 6),)
        outbound = common + (('remote', 0, 3, _LOOPBACK), ('remote_port', 0, 2, endpoint.port))
        inbound = common + (('local', 0, 3, _LOOPBACK), ('local_port', 0, 2, endpoint.port))
        owner = (('user', 0, 14, endpoint.owner_sd),)
        for name, layer, action, weight, conditions in (
            ('connect', _CONNECT4, wfp._PERMIT, 14, (('app', 0, 12, endpoint.client_app_id),) + owner + outbound),
            ('accept', _ACCEPT4, wfp._PERMIT, 14, (('app', 0, 12, endpoint.server_app_id),) + owner + inbound),
            ('block', _ACCEPT4, wfp._BLOCK, 13, inbound),
        ):
            result.append(_Rule(str(uuid.uuid5(epoch, lease + '/' + name)), prefix + name,
                                layer, action, weight, conditions))
    return tuple(result)


# SDK FWPM_FILTER_ENUM_TEMPLATE0: x64 size=72, actionMask offset=56.
class _EnumTemplate(C.Structure):
    _fields_ = [('provider', C.POINTER(wfp._GUID)), ('layer', wfp._GUID),
                ('enum_type', wfp._U32), ('flags', wfp._U32),
                ('provider_context', wfp._P), ('count', wfp._U32),
                ('conditions', C.POINTER(wfp._Condition)), ('action_mask', wfp._U32),
                ('callout', C.POINTER(wfp._GUID))]


def _read_filter(value):
    """Detach all checked typed fields from the SDK-owned allocation."""
    if value.count > 16 or (value.count and not value.conditions):
        _fail('Malformed IPC filter condition array')
    conditions = tuple(sorted((value.conditions[i].field.text(), value.conditions[i].match,
                              value.conditions[i].value.type, wfp._data(value.conditions[i].value))
                             for i in range(value.count)))
    if len({condition[0] for condition in conditions}) != len(conditions):
        _fail('Duplicate IPC condition field')
    if value.data.size > 1024 or (value.data.size and not value.data.data):
        _fail('Malformed IPC provider data')
    data = C.string_at(value.data.data, value.data.size) if value.data.size else b''
    return (value.layer.text(), value.flags & ~wfp._INDEXED,
            value.provider.contents.text() if value.provider else None,
            value.sublayer.text(), value.display.description, data,
            value.action.type, value.weight.type, wfp._data(value.weight), conditions,
            value.context.raw, bool(value.reserved))


def _expected(rule, provider, sublayer):
    return (rule.layer, 0, str(provider), str(sublayer), rule.marker, rule.marker.encode('ascii'),
            rule.action, 1, rule.weight,
            tuple(sorted((_FIELDS[name], match, kind, data) for name, match, kind, data in rule.conditions)),
            0, False)


class _DynamicEngine(wfp._Engine):
    """Only this subclass is dynamic. Never creates provider or sublayer objects."""
    def __init__(self):
        super().__init__()
        self.fault = ''
        signatures = {
            'FwpmFilterCreateEnumHandle0': ([wfp._P, C.POINTER(_EnumTemplate), C.POINTER(wfp._P)], wfp._U32),
            'FwpmFilterEnum0': ([wfp._P, wfp._P, wfp._U32,
                                C.POINTER(C.POINTER(C.POINTER(wfp._Filter))), C.POINTER(wfp._U32)], wfp._U32),
            'FwpmFilterDestroyEnumHandle0': ([wfp._P, wfp._P], wfp._U32),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result

    def __enter__(self):
        if self.handle.value or self.fault:
            _fail('IPC engine already open or faulted')
        session = wfp._Session()
        session.flags, session.timeout = 1, 5000
        _check(self.api.FwpmEngineOpen0(None, 0xFFFFFFFF, None, C.byref(session), C.byref(self.handle)), 'open')
        return self

    def close(self):
        if self.handle.value:
            code = self.api.FwpmEngineClose0(self.handle)
            if code:
                self.fault = f'IPC dynamic session close failed (0x{code:08x}); revocation unconfirmed'
                _fail(self.fault)
            self.handle = wfp._P()

    def __exit__(self, *_args):
        self.close()

    def add(self, rule, provider, sublayer):
        keep = []
        value = wfp._Filter()
        value.key = wfp._GUID.of(rule.key)
        value.display = wfp._Display('RuleProxy IPC ' + rule.key, rule.marker)
        value.flags = 0
        owner = wfp._GUID.of(provider)
        value.provider = C.pointer(owner)
        marker = C.create_string_buffer(rule.marker.encode('ascii'))
        value.data = wfp._Blob(len(rule.marker), C.cast(marker, wfp._P))
        value.layer, value.sublayer = wfp._GUID.of(rule.layer), wfp._GUID.of(sublayer)
        value.weight = wfp._value(1, rule.weight, keep)
        conditions = (wfp._Condition * len(rule.conditions))()
        for index, (name, match, kind, data) in enumerate(rule.conditions):
            conditions[index] = wfp._Condition(wfp._GUID.of(_FIELDS[name]), match, wfp._value(kind, data, keep))
        value.count, value.conditions = len(conditions), conditions
        value.action.type = rule.action
        ident = wfp._U64()
        _check(self.api.FwpmFilterAdd0(self.handle, C.byref(value), None, C.byref(ident)), 'add')

    def delete(self, key):
        _check(self.api.FwpmFilterDeleteByKey0(self.handle, C.byref(wfp._GUID.of(key))), 'delete')

    def read(self, key):
        with self.get('Filter', key, wfp._Filter) as value:
            if value is None:
                return None
            if value.key.text() != key:
                _fail('IPC readback returned the wrong key')
            return _read_filter(value)

    def scan(self, provider, prefix, expected_keys):
        """Fresh all-layer snapshot of filters readable by this caller.

        SDK FwpmFilterCreateEnumHandle0 documents NULL as returning all filters;
        a non-NULL template with GUID_NULL layer is NOT an all-layer wildcard.
        Select epoch/keys client-side, and reject selected foreign-provider rules.
        No separate disabled/boot-time coverage claim is made here. The caller
        holds an explicit transaction across creation and enumeration.
        Copy selected records BEFORE freeing each page. Detect unknown same-epoch
        rules, not just the known deterministic keys. Bound the scan fail-closed.
        """
        owner = str(provider)
        enum = wfp._P()
        _check(self.api.FwpmFilterCreateEnumHandle0(self.handle, None, C.byref(enum)), 'enumeration open')
        found, seen = {}, 0
        try:
            while True:
                entries = C.POINTER(C.POINTER(wfp._Filter))()
                count = wfp._U32()
                _check(self.api.FwpmFilterEnum0(self.handle, enum, 128, C.byref(entries), C.byref(count)), 'enumerate')
                try:
                    seen += count.value
                    if count.value > 128 or seen > 65536 or (count.value and not entries):
                        _fail('IPC enumeration exceeded bounded snapshot')
                    for index in range(count.value):
                        if not entries[index]:
                            _fail('Null IPC enumeration entry')
                        value = entries[index].contents
                        key, description = value.key.text(), value.display.description or ''
                        data = b''
                        if value.data.data and 0 < value.data.size <= 1024:
                            data = C.string_at(value.data.data, value.data.size)
                        if (key in expected_keys or description.startswith(prefix)
                                or data.startswith(prefix.encode('ascii'))):
                            if not value.provider or value.provider.contents.text() != owner:
                                _fail('IPC epoch inventory contains a foreign-provider filter')
                            if key in found:
                                _fail('Duplicate IPC enumeration key')
                            found[key] = _read_filter(value)
                finally:
                    if entries:
                        pointer = C.cast(entries, wfp._P)
                        self.api.FwpmFreeMemory0(C.byref(pointer))
                if count.value < 128:
                    return found
        finally:
            _check(self.api.FwpmFilterDestroyEnumHandle0(self.handle, enum), 'enumeration close')


class LeaseSet:
    """One long-lived broker epoch; close/purge are terminal and retryable.

    replace([]) atomically clears this epoch while keeping its session open.
    close()/purge() close the whole dynamic session and never delete base objects.
    After any native/readback fault only close() may be retried; construct a new
    LeaseSet only after confirmed close, and revalidate endpoints in the broker.
    """
    def __init__(self, app_guard, *, engine_factory=_DynamicEngine):
        self.guard = app_guard
        self.provider, self.sublayer = app_guard.provider, app_guard.sublayer
        self.epoch = uuid.uuid4()
        self.prefix = f'RuleProxyIPC-v1:{self.epoch}/'
        self._factory, self._engine = engine_factory, None
        self._rules = ()
        self.lock = threading.RLock()
        self.fault = ''
        self.closed = False

    def _ready(self):
        if self.closed or self.fault:
            _fail(self.fault or 'IPC lease set is closed')

    def _verify(self, rules):
        if not self.guard._owned_provider(self._engine) or not self.guard._owned_sublayer(self._engine):
            _fail('Existing persistent AppGuard provider/sublayer required')
        expected = {rule.key: _expected(rule, self.provider, self.sublayer) for rule in rules}
        for key, value in expected.items():
            if self._engine.read(key) != value:
                _fail('IPC exact typed filter readback mismatch: ' + key)
        if self._engine.scan(self.provider, self.prefix, set(expected)) != expected:
            _fail('IPC epoch inventory mismatch (missing, unknown or orphan filter)')
        return tuple(expected)

    def _abort(self, exc):
        self.fault = str(exc) or type(exc).__name__
        try:
            self.close()
        except BaseException as close_error:
            self.fault += '; revocation unconfirmed: ' + str(close_error)
            raise ProxyError('ipc_lease_close_failed', self.fault) from exc

    def replace(self, endpoints):
        with self.lock:
            self._ready()
            rules = _plan(endpoints, self.epoch)  # Invalid input leaves old verified lease unchanged.
            try:
                if self._engine is None:
                    self._engine = self._factory()
                    self._engine.__enter__()
                with self._engine.transaction():
                    self._verify(self._rules)
                    for old in self._rules:
                        self._engine.delete(old.key)
                    # Server restrictions and client exception commit as one group.
                    for rule in rules:
                        self._engine.add(rule, self.provider, self.sublayer)
                    self._verify(rules)
                # Verify a fresh committed inventory, not just transaction-local objects.
                with self._engine.transaction():
                    result = self._verify(rules)
                self._rules = rules
                return result
            except BaseException as exc:
                self._abort(exc)
                raise

    def verify(self):
        with self.lock:
            self._ready()
            if self._engine is None:
                _fail('IPC session has not been opened')
            try:
                with self._engine.transaction():
                    return self._verify(self._rules)
            except BaseException as exc:
                self._abort(exc)
                raise

    def close(self):
        with self.lock:
            if self._engine is not None:
                try:
                    self._engine.close()
                except BaseException as exc:
                    self.fault = self.fault or str(exc) or type(exc).__name__
                    raise
                self._engine = None
            self._rules = ()
            self.closed = True

    def purge(self):
        """Broker stop/revoke hook: confirmed close of this epoch only."""
        self.close()
