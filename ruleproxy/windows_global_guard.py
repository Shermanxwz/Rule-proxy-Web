"""Candidate independent WFP guard for the SYSTEM-owned global TUN core.

Persistent filters are installed in an owned sublayer at ALE_AUTH_CONNECT_V4/V6.
Explicit high-weight soft permits precede a default hard block *inside that
sublayer*. Windows Firewall rules and existing inbound ALE flows are untouched.
Core startup uses two phases: before the TUN exists only the protected SYSTEM
core, loopback and narrow link-maintenance traffic are permitted; a second
atomic apply permits the verified TUN interface. Crashes never delete filters.

Native qualification requires a protected release attestation bound to the
tested code/core and exact OS. None ships today. Object readback alone never
qualifies. The future runtime-only profile explicitly excludes early boot.

Sources checked for this implementation:
https://learn.microsoft.com/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
https://learn.microsoft.com/windows/win32/fwp/filter-arbitration
https://learn.microsoft.com/windows/win32/fwp/ale-re-authorization
https://learn.microsoft.com/windows/win32/fwp/object-management
https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0
https://github.com/MetaCubeX/sing-tun/blob/v0.4.27/tun_windows.go
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from dataclasses import dataclass
import hashlib
import ipaddress
import os
from pathlib import Path
import threading
import uuid

from .windows_proxy_policy import HASH_RE, SID_RE, SERVICE_NAME, ProxyError
from .windows_global_qualification import load_qualification


_P = C.c_void_p
_U8, _U16, _U32, _U64 = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64
_BLOCK, _PERMIT = 0x1001, 0x1002
# Readback may include BFE's INDEXED optimization flag. All behavioral bits
# (including DISABLED and CLEAR_ACTION_RIGHT) remain exact and are rejected.
# https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0#members
_PERSISTENT, _DISABLED, _INDEXED = 1, 0x20, 0x40
_NOT_FOUND = {'Filter': 0x80320003, 'Layer': 0x80320004,
              'Provider': 0x80320005, 'SubLayer': 0x80320007}
_TUN_NAME = 'RuleProxyTun'
_NAMESPACE = uuid.UUID('a7ab50d9-4ab9-4ca7-ac5a-2c6e5ecbb64c')
_LAYERS = {4: 'c38d57d1-05a7-4c33-904f-7fbceee60e82',
           6: '4a72393b-319f-44bc-84c3-ba54dcb3b6b4'}
_FIELDS = {
    'app': 'd78e1e87-8644-4ea5-9437-d809ecefc971',
    'user': 'af043a0a-b34d-4f86-979c-c90371af6e66',
    'flags': '632ce23b-5167-435c-86d7-e903684aa80c',
    'next': '93ae8f5b-7f6f-4719-98c8-14e97429ef04',
    'arrival': '618a9b6d-386b-4136-ad6e-b51587cfb1cd',
    'protocol': '3971ef2b-623e-4f9a-8cb1-6e79b806b9a7',
    'local_port': '0c1ba1af-5765-453f-af22-a8f791ac775b',
    'remote_port': 'c35a604d-d22b-4e1a-91b4-68f674ee674b',
    'remote': 'b235ae9a-1d64-49b8-a44c-5ff3d9095045',
}


class _GUID(C.Structure):
    _fields_ = [('a', _U32), ('b', _U16), ('c', _U16), ('d', _U8 * 8)]

    @classmethod
    def of(cls, value):
        return cls.from_buffer_copy(uuid.UUID(str(value)).bytes_le)

    def text(self):
        return str(uuid.UUID(bytes_le=bytes(self)))


class _Union(C.Union):
    _fields_ = [('u8', _U8), ('u16', _U16), ('u32', _U32), ('pointer', _P)]


class _Value(C.Structure):
    _fields_ = [('type', _U32), ('value', _Union)]


class _Blob(C.Structure):
    _fields_ = [('size', _U32), ('data', _P)]


class _V6Mask(C.Structure):
    _fields_ = [('address', _U8 * 16), ('prefix', _U8)]


class _Display(C.Structure):
    _fields_ = [('name', C.c_wchar_p), ('description', C.c_wchar_p)]


class _Session(C.Structure):
    _fields_ = [('key', _GUID), ('display', _Display), ('flags', _U32),
               ('timeout', _U32), ('pid', _U32), ('sid', _P),
               ('username', C.c_wchar_p), ('kernel', C.c_int32)]


class _Provider(C.Structure):
    _fields_ = [('key', _GUID), ('display', _Display), ('flags', _U32),
               ('data', _Blob), ('service', C.c_wchar_p)]


class _Sublayer(C.Structure):
    _fields_ = [('key', _GUID), ('display', _Display), ('flags', _U32),
               ('provider', C.POINTER(_GUID)), ('data', _Blob), ('weight', _U16)]


class _Condition(C.Structure):
    _fields_ = [('field', _GUID), ('match', _U32), ('value', _Value)]


class _Action(C.Structure):
    _fields_ = [('type', _U32), ('key', _GUID)]


class _Context(C.Union):
    _fields_ = [('raw', _U64), ('key', _GUID)]


class _Filter(C.Structure):
    _fields_ = [('key', _GUID), ('display', _Display), ('flags', _U32),
               ('provider', C.POINTER(_GUID)), ('data', _Blob), ('layer', _GUID),
               ('sublayer', _GUID), ('weight', _Value), ('count', _U32),
               ('conditions', C.POINTER(_Condition)), ('action', _Action),
               ('context', _Context), ('reserved', C.POINTER(_GUID)),
               ('id', _U64), ('effective_weight', _Value)]


class _Field(C.Structure):
    _fields_ = [('key', C.POINTER(_GUID)), ('type', _U32), ('data_type', _U32)]


class _Layer(C.Structure):
    _fields_ = [('key', _GUID), ('display', _Display), ('flags', _U32),
               ('count', _U32), ('fields', C.POINTER(_Field)),
               ('default_sublayer', _GUID), ('id', _U16)]


def _error(code, operation):
    if code:
        raise ProxyError('global_guard_failed', f'独立流量保护 {operation} 失败（0x{code:08x}）；未确认防直连保护。')


def _data(value: _Value):
    if value.type == 0:
        return None
    if value.type in (1, 2, 3):
        return getattr(value.value, {1: 'u8', 2: 'u16', 3: 'u32'}[value.type])
    if value.type == 4:
        if not value.value.pointer:
            raise ProxyError('global_guard_changed', '独立流量保护含有无效的接口身份。')
        return C.cast(value.value.pointer, C.POINTER(_U64)).contents.value
    if value.type == 11:
        if not value.value.pointer:
            raise ProxyError('global_guard_changed', '独立流量保护含有无效的 IPv6 条件。')
        return C.string_at(value.value.pointer, 16)
    if value.type == 257:
        if not value.value.pointer:
            raise ProxyError('global_guard_changed', '独立流量保护含有无效的 IPv6 范围。')
        mask = C.cast(value.value.pointer, C.POINTER(_V6Mask)).contents
        if mask.prefix > 128:
            raise ProxyError('global_guard_changed', '独立流量保护含有无效的 IPv6 范围。')
        return (bytes(mask.address), mask.prefix)
    if value.type in (12, 14):
        if not value.value.pointer:
            raise ProxyError('global_guard_changed', '独立流量保护含有无效的程序身份。')
        blob = C.cast(value.value.pointer, C.POINTER(_Blob)).contents
        if not blob.data or not 1 <= blob.size <= 65536:
            raise ProxyError('global_guard_changed', '独立流量保护程序身份超过安全上限。')
        return C.string_at(blob.data, blob.size)
    raise ProxyError('global_guard_changed', '独立流量保护含有不支持的条件类型。')


def _value(kind, data, keep):
    value = _Value()
    value.type = kind
    if kind == 0:
        return value
    if kind in (1, 2, 3):
        setattr(value.value, {1: 'u8', 2: 'u16', 3: 'u32'}[kind], data)
    elif kind == 4:
        number = _U64(data)
        keep.append(number)
        value.value.pointer = C.cast(C.pointer(number), _P)
    elif kind == 11:
        buffer = (_U8 * 16).from_buffer_copy(data)
        keep.append(buffer)
        value.value.pointer = C.cast(buffer, _P)
    elif kind == 257:
        address, prefix = data
        mask = _V6Mask((_U8 * 16).from_buffer_copy(address), prefix)
        keep.append(mask)
        value.value.pointer = C.cast(C.pointer(mask), _P)
    elif kind in (12, 14):
        buffer = C.create_string_buffer(data)
        blob = _Blob(len(data), C.cast(buffer, _P))
        keep.extend((buffer, blob))
        value.value.pointer = C.cast(C.pointer(blob), _P)
    else:
        raise ValueError('Unsupported WFP value')
    return value


@dataclass(frozen=True)
class _Rule:
    name: str
    family: int
    action: int
    weight: int
    conditions: tuple[tuple[str, int, int, object], ...]


def _plan(app_id: bytes, system_descriptor: bytes, luid: int | None,
          maintenance_descriptor: bytes | None = None) -> tuple[_Rule, ...]:
    """An explicit own-sublayer allowlist, with a catch-all hard block last."""
    if not app_id or not system_descriptor or (luid is not None and (type(luid) is not int or luid <= 0)):
        raise ValueError('Invalid fixed guard identities')
    rules = []
    maintenance_descriptor = maintenance_descriptor or system_descriptor
    for family in (4, 6):
        rules.extend((
            _Rule('loopback', family, _PERMIT, 15, (('flags', 6, 3, 1),)),
            _Rule('core-system', family, _PERMIT, 14,
                  (('app', 0, 12, app_id), ('user', 0, 14, system_descriptor))),
            _Rule('block', family, _BLOCK, 0, ()),
        ))
        if luid is not None:
            rules.extend((
                _Rule('tun-outbound', family, _PERMIT, 12, (('next', 0, 4, luid),)),
                # At inbound-packet reauthorization an outbound flow's next-hop
                # is EMPTY. Only a packet arriving from our TUN is exempt then.
                _Rule('tun-reauthorize', family, _PERMIT, 12,
                      (('next', 0, 0, None), ('arrival', 0, 4, luid))),
            ))
    # DHCP client broadcasts/renewals are necessary to keep underlay leases
    # alive. They require an OS service token; no general DNS,
    # process-name, LAN, route-exclusion or management-peer permit is created.
    rules.append(_Rule('dhcp4', 4, _PERMIT, 13, (
        ('user', 0, 14, maintenance_descriptor), ('protocol', 0, 1, 17),
        ('local_port', 0, 2, 68), ('remote_port', 0, 2, 67))))
    for index, address in enumerate(('ff02::1:2', 'ff05::1:3')):
        rules.append(_Rule('dhcp6-' + str(index), 6, _PERMIT, 13, (
            ('user', 0, 14, maintenance_descriptor), ('protocol', 0, 1, 17),
            ('local_port', 0, 2, 546), ('remote_port', 0, 2, 547),
            ('remote', 0, 11, ipaddress.IPv6Address(address).packed))))
    rules.append(_Rule('dhcp6-linklocal', 6, _PERMIT, 13, (
        ('user', 0, 14, maintenance_descriptor), ('protocol', 0, 1, 17),
        ('local_port', 0, 2, 546), ('remote_port', 0, 2, 547),
        ('remote', 0, 257, (ipaddress.IPv6Address('fe80::').packed, 10)))))
    # Link-local ICMPv6 neighbor/router maintenance is explicit. These exceptions
    # are not Internet application traffic and are reported in status below.
    for kind in (133, 135, 136):
        for scope, address, prefix in (('multicast', 'ff02::', 16), ('linklocal', 'fe80::', 10)):
            rules.append(_Rule('ndp-' + str(kind) + '-' + scope, 6, _PERMIT, 13, (
                ('protocol', 0, 1, 58), ('local_port', 0, 2, kind), ('remote_port', 0, 2, 0),
                ('remote', 0, 257, (ipaddress.IPv6Address(address).packed, prefix)))))
    return tuple(rules)


_ALL_RULES = tuple((family, name) for family in (4, 6)
    for name in ('loopback', 'core-system', 'block', 'tun-outbound', 'tun-reauthorize')) + (
    (4, 'dhcp4'), (6, 'dhcp6-0'), (6, 'dhcp6-1'), (6, 'dhcp6-linklocal')) + tuple(
    (6, 'ndp-' + str(kind) + '-' + scope) for kind in (133, 135, 136) for scope in ('multicast', 'linklocal'))


class _Engine:
    def __init__(self):
        if os.name != 'nt' or C.sizeof(_P) != 8:
            raise ProxyError('global_guard_unsupported', '独立全局保护仅支持原生 64 位 Windows。')
        self.api = C.WinDLL('fwpuclnt.dll', use_last_error=True)
        self.handle = _P()
        signatures = {
            'FwpmEngineOpen0': ([C.c_wchar_p, _U32, _P, C.POINTER(_Session), C.POINTER(_P)], _U32),
            'FwpmEngineClose0': ([_P], _U32),
            'FwpmFreeMemory0': ([C.POINTER(_P)], None),
            'FwpmTransactionBegin0': ([_P, _U32], _U32),
            'FwpmTransactionCommit0': ([_P], _U32),
            'FwpmTransactionAbort0': ([_P], _U32),
            'FwpmProviderAdd0': ([_P, C.POINTER(_Provider), _P], _U32),
            'FwpmSubLayerAdd0': ([_P, C.POINTER(_Sublayer), _P], _U32),
            'FwpmFilterAdd0': ([_P, C.POINTER(_Filter), _P, C.POINTER(_U64)], _U32),
            'FwpmFilterDeleteByKey0': ([_P, C.POINTER(_GUID)], _U32),
            'FwpmGetAppIdFromFileName0': ([C.c_wchar_p, C.POINTER(C.POINTER(_Blob))], _U32),
        }
        for name, structure in (('Provider', _Provider), ('SubLayer', _Sublayer),
                                ('Filter', _Filter), ('Layer', _Layer)):
            signatures['Fwpm' + name + 'GetByKey0'] = (
                [_P, C.POINTER(_GUID), C.POINTER(C.POINTER(structure))], _U32)
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result

    def __enter__(self):
        # Non-dynamic session: engine close/process death must retain filters.
        session = _Session()
        session.timeout = 5000
        _error(self.api.FwpmEngineOpen0(None, 0xFFFFFFFF, None, C.byref(session), C.byref(self.handle)), '连接 WFP')
        return self

    def __exit__(self, *_args):
        if self.handle.value:
            self.api.FwpmEngineClose0(self.handle)
            self.handle = _P()

    @contextmanager
    def transaction(self):
        _error(self.api.FwpmTransactionBegin0(self.handle, 0), '开启原子更新')
        try:
            yield
            _error(self.api.FwpmTransactionCommit0(self.handle), '提交原子更新')
        except BaseException:
            self.api.FwpmTransactionAbort0(self.handle)
            raise

    @contextmanager
    def get(self, kind, key, structure):
        result = C.POINTER(structure)()
        code = getattr(self.api, 'Fwpm' + kind + 'GetByKey0')(self.handle, C.byref(_GUID.of(key)), C.byref(result))
        if code == _NOT_FOUND[kind]:
            yield None
            return
        _error(code, '读取自有 ' + kind)
        try:
            yield result.contents
        finally:
            pointer = C.cast(result, _P)
            self.api.FwpmFreeMemory0(C.byref(pointer))

    def app_id(self, path):
        result = C.POINTER(_Blob)()
        _error(self.api.FwpmGetAppIdFromFileName0(str(path), C.byref(result)), '验证固定核心身份')
        try:
            blob = result.contents
            if not blob.data or not 1 <= blob.size <= 65536:
                raise ProxyError('global_guard_failed', '固定核心的 WFP 身份无效。')
            return C.string_at(blob.data, blob.size)
        finally:
            pointer = C.cast(result, _P)
            self.api.FwpmFreeMemory0(C.byref(pointer))

    def capability(self):
        required = {_FIELDS[name] for name in ('app', 'user', 'flags', 'next', 'arrival',
                                             'protocol', 'local_port', 'remote_port', 'remote')}
        for layer in _LAYERS.values():
            with self.get('Layer', layer, _Layer) as value:
                if value is None or not 1 <= value.count <= 256 or not value.fields:
                    raise ProxyError('global_guard_unsupported', 'Windows 未提供需要的 WFP 连接层。')
                found = {value.fields[index].key.contents.text() for index in range(value.count)
                         if value.fields[index].key}
                if not required.issubset(found):
                    raise ProxyError('global_guard_unsupported', 'Windows WFP 连接层缺少独立保护所需条件。')


def _descriptor(sddl):
    advapi = C.WinDLL('advapi32.dll', use_last_error=True)
    kernel = C.WinDLL('kernel32.dll', use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [C.c_wchar_p, _U32, C.POINTER(_P), C.POINTER(_U32)]
    convert.restype = C.c_int
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [_P], _P
    descriptor, size = _P(), _U32()
    if not convert(sddl, 1, C.byref(descriptor), C.byref(size)):
        raise C.WinError(C.get_last_error())
    try:
        if not 1 <= size.value <= 65536:
            raise ProxyError('global_guard_failed', 'SYSTEM 进程身份无效。')
        return C.string_at(descriptor, size.value)
    finally:
        kernel.LocalFree(descriptor)


def _system_descriptor():
    return _descriptor('O:SYG:SYD:(A;;CC;;;SY)')


def _maintenance_descriptor():
    return _descriptor('O:SYG:SYD:(A;;CC;;;SY)(A;;CC;;;LS)(A;;CC;;;NS)')


def _tun_luid():
    api = C.WinDLL('iphlpapi.dll', use_last_error=True)
    api.ConvertInterfaceAliasToLuid.argtypes = [C.c_wchar_p, C.POINTER(_U64)]
    api.ConvertInterfaceAliasToLuid.restype = _U32
    api.ConvertInterfaceLuidToGuid.argtypes = [C.POINTER(_U64), C.POINTER(_GUID)]
    api.ConvertInterfaceLuidToGuid.restype = _U32
    luid, identity = _U64(), _GUID()
    code = api.ConvertInterfaceAliasToLuid(_TUN_NAME, C.byref(luid))
    if code in (2, 87, 1168):  # Missing interface: safe pre-start phase.
        return None
    _error(code, '查询自有 TUN 接口')
    _error(api.ConvertInterfaceLuidToGuid(C.byref(luid), C.byref(identity)), '验证 TUN 接口身份')
    # Fixed sing-tun v0.4.27 derives its Wintun adapter GUID from these bytes.
    expected = uuid.UUID(bytes_le=hashlib.md5(('wintun' + _TUN_NAME).encode()).digest())
    if identity.text() != str(expected) or not luid.value:
        raise ProxyError('global_guard_conflict', '同名 TUN 接口不属于固定 Mihomo 后端，未放行该接口。')
    return luid.value


class Guard:
    def __init__(self, metadata):
        if (not isinstance(metadata, dict) or not isinstance(metadata.get('root'), str)
                or not metadata['root'] or '\0' in metadata['root']
                or not isinstance(metadata.get('owner_sid'), str) or not SID_RE.fullmatch(metadata['owner_sid'])):
            raise ProxyError('invalid_deployment', '独立保护缺少可信安装身份。')
        self.metadata = metadata
        self.root = Path(metadata['root'])
        self.qualification = load_qualification(metadata)
        self.identity = hashlib.sha256((metadata['owner_sid'] + '\0' + str(self.root).casefold()).encode()).hexdigest()
        self.provider = self._key('provider')
        self.sublayer = self._key('sublayer')
        self.marker = 'RuleProxyGuard-v1:' + self.identity
        self.lock = threading.RLock()

    def _key(self, name):
        return uuid.uuid5(_NAMESPACE, self.identity + '/' + name)

    def refresh_qualification(self):
        self.qualification = load_qualification(self.metadata)

    def _rule_key(self, family, name):
        return self._key(str(family) + '/' + name)

    @staticmethod
    def _system_only():
        from .windows_proxy_client import current_user_sid
        if os.name != 'nt' or current_user_sid() != 'S-1-5-18':
            raise ProxyError('global_guard_access_denied', '独立全局保护只能由已安装的 SYSTEM 控制服务管理。')

    @staticmethod
    def _restore_authority():
        """Allow an elevated administrator to recover/uninstall a crashed guard.

        Installation may elevate into a different administrator account. That
        account cannot use the desktop owner's pipe, but already has OS-level
        WFP authority. It receives only exact owned-filter removal here.
        """
        from .windows_proxy_client import current_user_sid
        if os.name != 'nt':
            raise ProxyError('global_guard_access_denied', '撤销独立保护需要 Windows 管理员权限。')
        if current_user_sid() == 'S-1-5-18':
            return
        from .windows_app_process import _KernelAPI
        if not _KernelAPI().is_elevated():
            raise ProxyError('global_guard_access_denied', '请使用已提升权限的管理员恢复独立保护。')
        advapi, kernel = C.WinDLL('advapi32.dll', use_last_error=True), C.WinDLL('kernel32.dll', use_last_error=True)
        advapi.ConvertStringSidToSidW.argtypes = [C.c_wchar_p, C.POINTER(_P)]
        advapi.ConvertStringSidToSidW.restype = C.c_int
        advapi.CheckTokenMembership.argtypes = [_P, _P, C.POINTER(C.c_int)]
        advapi.CheckTokenMembership.restype = C.c_int
        kernel.LocalFree.argtypes, kernel.LocalFree.restype = [_P], _P
        administrators, member = _P(), C.c_int()
        if not advapi.ConvertStringSidToSidW('S-1-5-32-544', C.byref(administrators)):
            raise C.WinError(C.get_last_error())
        try:
            if not advapi.CheckTokenMembership(None, administrators, C.byref(member)):
                raise C.WinError(C.get_last_error())
            if not member.value:
                raise ProxyError('global_guard_access_denied', '撤销独立保护需要有效的管理员组权限。')
        finally:
            kernel.LocalFree(administrators)

    def _fixed_core(self, path):
        expected = self.root / 'bin/windows-amd64/mihomo.exe'
        if os.path.normcase(str(Path(path).absolute())) != os.path.normcase(str(expected.absolute())):
            raise ProxyError('global_guard_invalid_core', '独立保护仅接受安装清单中的固定 Mihomo。')
        from .windows_proxy_service import protected_path, _file_hash
        digest = self.metadata.get('files', {}).get('bin/windows-amd64/mihomo.exe')
        if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
            raise ProxyError('invalid_deployment', '独立保护缺少固定核心文件摘要。')
        for item in (expected, *expected.parents):
            if item.is_symlink() or getattr(item.lstat(), 'st_file_attributes', 0) & 0x400:
                raise ProxyError('unsafe_installation', '固定核心路径不能包含重解析点。')
            if item == self.root.parent or item == self.root or self.root in item.parents:
                protected_path(item)
        if not expected.is_file() or _file_hash(expected) != digest:
            raise ProxyError('installation_changed', '固定 Mihomo 已改变，请修复安装。')
        return expected

    def _owned_provider(self, engine):
        with engine.get('Provider', self.provider, _Provider) as value:
            if value is None:
                return False
            if (value.display.description != self.marker or not value.flags & _PERSISTENT
                    or value.service != SERVICE_NAME):
                raise ProxyError('global_guard_conflict', '自有 WFP 提供程序身份冲突，未修改现有规则。')
        return True

    def _owned_sublayer(self, engine):
        with engine.get('SubLayer', self.sublayer, _Sublayer) as value:
            if value is None:
                return False
            if (value.display.description != self.marker or not value.flags & _PERSISTENT
                    or not value.provider or value.provider.contents.text() != str(self.provider)
                    or value.weight != 65535):
                raise ProxyError('global_guard_conflict', '自有 WFP 子层身份冲突，未修改现有规则。')
        return True

    def _filters(self, engine):
        result = {}
        for family, name in _ALL_RULES:
            with engine.get('Filter', self._rule_key(family, name), _Filter) as value:
                if value is None:
                    continue
                if (value.display.description != self.marker or not value.provider
                        or value.provider.contents.text() != str(self.provider)
                        or value.sublayer.text() != str(self.sublayer)
                        or value.layer.text() != _LAYERS[family]
                        or (value.flags & ~_INDEXED) != _PERSISTENT or value.count > 16):
                    raise ProxyError('global_guard_conflict', '自有 WFP 规则身份冲突，未修改现有规则。')
                conditions = tuple((value.conditions[index].field.text(), value.conditions[index].match,
                    value.conditions[index].value.type, _data(value.conditions[index].value))
                    for index in range(value.count))
                result[(family, name)] = (value.action.type, value.weight.type, _data(value.weight), conditions)
        return result

    def _ensure_objects(self, engine):
        provider = _GUID.of(self.provider)
        if not self._owned_provider(engine):
            value = _Provider()
            value.key, value.display, value.flags = provider, _Display('RuleProxy global guard', self.marker), _PERSISTENT
            value.service = SERVICE_NAME
            _error(engine.api.FwpmProviderAdd0(engine.handle, C.byref(value), None), '添加自有提供程序')
        if not self._owned_sublayer(engine):
            value = _Sublayer()
            value.key, value.display, value.flags = _GUID.of(self.sublayer), _Display('RuleProxy global guard', self.marker), _PERSISTENT
            value.provider, value.weight = C.pointer(provider), 65535
            _error(engine.api.FwpmSubLayerAdd0(engine.handle, C.byref(value), None), '添加自有子层')

    def _replace(self, engine, rules):
        # Identity checks precede any delete. Only exact owned keys are touched.
        previous = self._filters(engine)
        self._ensure_objects(engine)
        for family, name in previous:
            _error(engine.api.FwpmFilterDeleteByKey0(engine.handle,
                C.byref(_GUID.of(self._rule_key(family, name)))), '替换自有规则')
        for rule in rules:
            keep, provider = [], _GUID.of(self.provider)
            conditions = (_Condition * len(rule.conditions))()
            for index, (name, match, kind, data) in enumerate(rule.conditions):
                conditions[index] = _Condition(_GUID.of(_FIELDS[name]), match, _value(kind, data, keep))
            value = _Filter()
            value.key = _GUID.of(self._rule_key(rule.family, rule.name))
            value.display = _Display('RuleProxy ' + rule.name + ' IPv' + str(rule.family), self.marker)
            value.flags, value.provider = _PERSISTENT, C.pointer(provider)
            value.layer, value.sublayer = _GUID.of(_LAYERS[rule.family]), _GUID.of(self.sublayer)
            value.weight = _value(1, rule.weight, keep)
            value.count, value.conditions = len(rule.conditions), conditions if rule.conditions else None
            value.action.type = rule.action
            ident = _U64()
            _error(engine.api.FwpmFilterAdd0(engine.handle, C.byref(value), None, C.byref(ident)), '添加自有规则')

    @staticmethod
    def _expected(rules):
        return {(rule.family, rule.name): (rule.action, 1, rule.weight,
            tuple((_FIELDS[name], match, kind, data) for name, match, kind, data in rule.conditions))
            for rule in rules}

    def _snapshot(self, engine, *, luid=None):
        provider, sublayer = self._owned_provider(engine), self._owned_sublayer(engine)
        filters = self._filters(engine)
        active = False
        if filters:
            core = self.root / 'bin/windows-amd64/mihomo.exe'
            if luid is None and (4, 'tun-outbound') in filters:
                conditions = filters[(4, 'tun-outbound')][3]
                if len(conditions) == 1 and conditions[0][:3] == (_FIELDS['next'], 0, 4):
                    luid = conditions[0][3]
            expected = self._expected(_plan(engine.app_id(core), _system_descriptor(), luid, _maintenance_descriptor()))
            if not provider or not sublayer or filters != expected:
                raise ProxyError('global_guard_changed', '独立保护规则不完整或已改变，不能确认故障后阻断。')
            active = True
        qualified = self.qualification['native_qualified'] is True
        tun_ready = active and luid is not None and _tun_luid() == luid
        return {'supported': True, 'active': active, 'persistent': active,
            'strict_isolation': qualified and active and tun_ready, 'native_qualified': qualified,
            'qualification': dict(self.qualification), 'tun_ready': tun_ready,
            'state': 'candidate_active' if active else 'idle',
            'rule_count': len(filters),
            'detail': ('独立 WFP 持久规则已回读确认；资格仅覆盖显式启动后的运行期，不保证早期启动。' if qualified and active else
                       '运行期独立保护资格已核对，尚未启用；不保证早期启动。' if qualified else
                       '独立 WFP 持久规则已回读确认；尚未通过 Windows 原生不泄漏验收。'
                       if active else '独立保护未启用；Windows 原生不泄漏验收尚未完成。'),
            'exceptions': ['loopback', 'fixed_system_mihomo', 'verified_tun_interface',
                           'os_service_dhcp_client_ports', 'linklocal_icmpv6_neighbor_router_maintenance'],
            'limitations': ['仅控制本机出站 ALE 连接，不改变已建立入站管理会话的防火墙许可。',
                '运行期资格不涵盖系统早期启动窗口。' if qualified else
                '尚未验证已有连接重授权、TUN 接口身份复用、其他 WFP 提供程序仲裁及系统早期启动窗口。']}

    def apply(self, core_path: Path, tun: dict) -> dict:
        self._system_only()
        if (not isinstance(tun, dict) or tun.get('enable') is not True
                or tun.get('device') != _TUN_NAME or tun.get('auto-route') is not True):
            raise ProxyError('global_guard_invalid_tun', '独立保护仅接受服务生成的固定全局 TUN。')
        with self.lock:
            self.refresh_qualification()
            core = self._fixed_core(core_path)
            luid = _tun_luid()
            with _Engine() as engine:
                engine.capability()
                rules = _plan(engine.app_id(core), _system_descriptor(), luid, _maintenance_descriptor())
                with engine.transaction():
                    self._replace(engine, rules)
                return self._snapshot(engine, luid=luid)

    def status(self) -> dict:
        with self.lock:
            try:
                with _Engine() as engine:
                    engine.capability()
                    return self._snapshot(engine)
            except (OSError, ValueError, ProxyError) as error:
                return {'supported': False, 'active': False, 'persistent': False,
                    'strict_isolation': False, 'native_qualified': False, 'tun_ready': False,
                    'state': 'unavailable', 'code': getattr(error, 'code', 'global_guard_failed'),
                    'detail': str(error)}

    def normal_stop(self) -> dict:
        """Explicit user stop: remove only this installation's exact filters."""
        self._restore_authority()
        with self.lock, _Engine() as engine:
            filters = self._filters(engine)
            if filters and (not self._owned_provider(engine) or not self._owned_sublayer(engine)):
                raise ProxyError('global_guard_conflict', '独立保护归属无法验证，未删除现有规则。')
            with engine.transaction():
                for family, name in filters:
                    _error(engine.api.FwpmFilterDeleteByKey0(engine.handle,
                        C.byref(_GUID.of(self._rule_key(family, name)))), '撤销自有规则')
            result = self._snapshot(engine)
            result['stopped'] = True
            return result

    def crash_keep(self) -> dict:
        """Never delete/recreate filters on a crash; BFE owns their lifetime."""
        result = self.status()
        result['retained_after_failure'] = result.get('active') is True
        return result
